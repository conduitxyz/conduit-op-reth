//! Custom EVM configuration and block executor for ConduitOp state transitions.
//!
//! Wraps the standard OP EVM config and block executor to apply state overrides
//! at the `StateOverrideFork0` activation block.

use crate::{chainspec::ConduitOpChainSpec, state_override_fork0::ensure_state_override_fork0};
use alloy_consensus::Header;
use alloy_eips::Decodable2718;
use alloy_evm::{
    Database, Evm as EvmTrait, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        ExecutableTx, GasOutput, OnStateHook, StateDB,
    },
};
use alloy_op_evm::{
    OpBlockExecutionCtx, OpBlockExecutor, OpEvmFactory,
    block::OpTxEnv,
    post_exec::{
        PostExecEvmFactoryAdapter, PostExecEvmFactoryHooks, PostExecExecutorExt,
        WarmingRefundEvent, WarmingState,
    },
};
use alloy_primitives::{Bytes, U256};
use op_alloy_consensus::{
    EIP1559ParamError, OpTransaction as OpConsensusTransaction, SDMGasEntry,
    parse_post_exec_payload_from_transactions,
};
use op_revm::OpSpecId;
use reth_chainspec::EthChainSpec;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, EvmLimitParams, ExecutableTxIterator,
    ExecutionCtxFor,
    execute::{BasicBlockBuilder, BlockBuilder},
    precompiles::PrecompilesMap,
};
use reth_node_builder::{BuilderContext, NodeTypes, components::ExecutorBuilder};
use reth_optimism_evm::{
    ConfigurePostExecEvm, OpBlockAssembler, OpBlockExecutorFactory, OpEvmConfig,
    OpNextBlockEnvAttributes, OpRethReceiptBuilder, OpTx, PostExecMode,
    revm_spec_by_timestamp_after_bedrock,
};
use reth_optimism_forks::OpHardforks;
use reth_optimism_payload_builder::OpExecData;
use reth_optimism_primitives::{OpPrimitives, OpReceipt, OpTransactionSigned};
use reth_primitives_traits::{
    NodePrimitives, SealedBlock, SealedHeader, SignedTransaction, TxTy, WithEncoded,
};
use reth_storage_errors::any::AnyError;
use revm::{
    Inspector,
    context::{Block, BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::{DatabaseCommit, State},
    primitives::hardfork::SpecId,
};
use std::{fmt::Debug, sync::Arc};

/// Default EVM factory used by [`ConduitOpEvmConfig`].
pub type ConduitOpDefaultEvmFactory = OpEvmFactory<OpTx>;

type InnerBlockExecutorFactory<EvmF = ConduitOpDefaultEvmFactory> =
    OpBlockExecutorFactory<OpRethReceiptBuilder, Arc<ConduitOpChainSpec>, EvmF>;

/// Maximum bytecode size for deployed contracts (614,400 bytes).
pub const CONDUIT_MAX_CODE_SIZE: usize = 614_400;

/// Maximum initcode size for transactions (1,228,800 bytes).
pub const CONDUIT_MAX_INITCODE_SIZE: usize = 1_228_800;

/// Returns the Conduit EVM limit parameters.
pub const fn conduit_evm_limits() -> EvmLimitParams {
    EvmLimitParams {
        max_code_size: CONDUIT_MAX_CODE_SIZE,
        max_initcode_size: CONDUIT_MAX_INITCODE_SIZE,
        tx_gas_limit_cap: None,
    }
}

fn post_exec_mode_from_transactions<'a, I, T>(
    transactions: I,
    block_number: u64,
    sdm_active: bool,
) -> Result<PostExecMode, EIP1559ParamError>
where
    I: IntoIterator<Item = &'a T>,
    T: OpConsensusTransaction + 'a,
{
    parse_post_exec_payload_from_transactions(transactions, block_number, sdm_active)
        .map_err(|_| EIP1559ParamError::InvalidPostExecPayload)
        .map(|parsed| {
            parsed.map_or_else(PostExecMode::default, |parsed| PostExecMode::Verify(parsed.payload))
        })
}

/// Custom block executor wrapping the inner OP block executor.
///
/// Applies account state overrides when `StateOverrideFork0` first activates,
/// using the OP Stack 2-second block time heuristic to detect the transition block.
pub struct ConduitOpBlockExecutor<Inner> {
    inner: Inner,
    chain_spec: Arc<ConduitOpChainSpec>,
}

impl<Inner> BlockExecutor for ConduitOpBlockExecutor<Inner>
where
    Inner: BlockExecutor,
    Inner::Evm: EvmTrait,
    <Inner::Evm as EvmTrait>::DB: Database + DatabaseCommit,
{
    type Transaction = Inner::Transaction;
    type Receipt = Inner::Receipt;
    type Evm = Inner::Evm;
    type Result = Inner::Result;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()?;

        // Apply state overrides at the StateOverrideFork0 transition block.
        if let Some(ref config) = self.chain_spec.state_override_fork0 {
            ensure_state_override_fork0(
                self.chain_spec.as_ref(),
                self.inner.evm().block().timestamp().saturating_to(),
                config,
                self.inner.evm_mut().db_mut(),
            )
            .map_err(BlockExecutionError::other)?;
        }

        Ok(())
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
}

impl<Inner> PostExecExecutorExt for ConduitOpBlockExecutor<Inner>
where
    Inner: BlockExecutor + PostExecExecutorExt,
    Inner::Evm: EvmTrait,
    <Inner::Evm as EvmTrait>::DB: Database + DatabaseCommit,
{
    fn post_exec_entries(&self) -> &[SDMGasEntry] {
        self.inner.post_exec_entries()
    }

    fn take_post_exec_entries(&mut self) -> Vec<SDMGasEntry> {
        self.inner.take_post_exec_entries()
    }

    fn take_warming_events_by_tx(&mut self) -> Vec<Vec<WarmingRefundEvent>> {
        self.inner.take_warming_events_by_tx()
    }

    fn warming_state(&self) -> WarmingState {
        self.inner.warming_state()
    }

    fn seed_warming_state(&mut self, state: WarmingState) {
        self.inner.seed_warming_state(state);
    }
}

impl<EvmF> BlockExecutorFactory for ConduitOpEvmConfig<EvmF>
where
    EvmF: EvmFactory,
    InnerBlockExecutorFactory<EvmF>: for<'a> BlockExecutorFactory<
            EvmFactory = EvmF,
            ExecutionCtx<'a> = OpBlockExecutionCtx,
            Transaction = OpTransactionSigned,
            Receipt = OpReceipt,
        >,
{
    type EvmFactory = EvmF;
    type TxExecutionResult =
        <InnerBlockExecutorFactory<EvmF> as BlockExecutorFactory>::TxExecutionResult;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = OpTransactionSigned;
    type Receipt = OpReceipt;
    type Executor<'a, DB: StateDB, I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>> =
        ConduitOpBlockExecutor<
            <InnerBlockExecutorFactory<EvmF> as BlockExecutorFactory>::Executor<'a, DB, I>,
        >;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.executor_factory.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <Self::EvmFactory as EvmFactory>::Evm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>,
    {
        let inner = self.inner.executor_factory.create_executor(evm, ctx);
        ConduitOpBlockExecutor { inner, chain_spec: self.chain_spec.clone() }
    }
}

/// Custom EVM configuration wrapping [`OpEvmConfig`].
///
/// Delegates all standard OP behavior to the inner config but overrides
/// `create_executor` to wrap each [`OpBlockExecutor`] in a [`ConduitOpBlockExecutor`]
/// for custom state transitions.
#[derive(Debug, Clone)]
pub struct ConduitOpEvmConfig<EvmF = ConduitOpDefaultEvmFactory> {
    inner: OpEvmConfig<ConduitOpChainSpec, OpPrimitives, OpRethReceiptBuilder, EvmF>,
    chain_spec: Arc<ConduitOpChainSpec>,
    limits: Option<EvmLimitParams>,
}

impl ConduitOpEvmConfig {
    /// Creates a new [`ConduitOpEvmConfig`] with standard OP Stack defaults (no limit overrides).
    pub fn new(chain_spec: Arc<ConduitOpChainSpec>) -> Self {
        Self::with_limits(chain_spec, None)
    }

    /// Creates a new [`ConduitOpEvmConfig`] with standard OP Stack defaults (no limit overrides).
    pub fn optimism(chain_spec: Arc<ConduitOpChainSpec>) -> Self {
        Self::with_limits(chain_spec, None)
    }

    /// Creates a new [`ConduitOpEvmConfig`] with Conduit's higher EVM limits.
    pub fn conduit(chain_spec: Arc<ConduitOpChainSpec>) -> Self {
        Self::with_limits(chain_spec, Some(conduit_evm_limits()))
    }

    /// Creates a new [`ConduitOpEvmConfig`] with the given optional EVM limit overrides.
    pub fn with_limits(
        chain_spec: Arc<ConduitOpChainSpec>,
        limits: Option<EvmLimitParams>,
    ) -> Self {
        Self::with_limits_and_evm_factory(chain_spec, limits, ConduitOpDefaultEvmFactory::default())
    }
}

impl<EvmF> ConduitOpEvmConfig<EvmF> {
    /// Creates a new [`ConduitOpEvmConfig`] with the given optional EVM limit overrides and EVM
    /// factory.
    pub fn with_limits_and_evm_factory(
        chain_spec: Arc<ConduitOpChainSpec>,
        limits: Option<EvmLimitParams>,
        evm_factory: EvmF,
    ) -> Self {
        let inner = OpEvmConfig {
            block_assembler: OpBlockAssembler::new(chain_spec.clone()),
            executor_factory: OpBlockExecutorFactory::new(
                OpRethReceiptBuilder::default(),
                chain_spec.clone(),
                evm_factory,
            ),
            _pd: core::marker::PhantomData,
        };

        Self { inner, chain_spec, limits }
    }

    /// Returns the receipt builder used by the block executor factory.
    pub fn receipt_builder(&self) -> &OpRethReceiptBuilder {
        self.inner.executor_factory.receipt_builder()
    }

    /// Applies configured EVM limits to the given environment, if any.
    fn maybe_apply_limits(&self, env: EvmEnv<OpSpecId>) -> EvmEnv<OpSpecId> {
        match self.limits {
            Some(limits) => env.with_limits(limits),
            None => env,
        }
    }
}

impl<EvmF> ConfigureEvm for ConduitOpEvmConfig<EvmF>
where
    EvmF: EvmFactory<
            Tx: alloy_evm::TransactionEnvMut
                    + FromRecoveredTx<OpTransactionSigned>
                    + FromTxWithEncoded<OpTransactionSigned>
                    + OpTxEnv,
            Precompiles = PrecompilesMap,
            Spec = OpSpecId,
            BlockEnv = BlockEnv,
        > + Debug
        + Clone
        + Send
        + Sync
        + Unpin
        + 'static,
    InnerBlockExecutorFactory<EvmF>: for<'a> BlockExecutorFactory<
            EvmFactory = EvmF,
            ExecutionCtx<'a> = OpBlockExecutionCtx,
            Transaction = OpTransactionSigned,
            Receipt = OpReceipt,
        >,
    Self: for<'a> BlockExecutorFactory<
            EvmFactory = EvmF,
            ExecutionCtx<'a> = OpBlockExecutionCtx,
            Transaction = OpTransactionSigned,
            Receipt = OpReceipt,
        >,
    OpEvmConfig<ConduitOpChainSpec, OpPrimitives, OpRethReceiptBuilder, EvmF>: ConfigureEvm<
            Primitives = OpPrimitives,
            Error = EIP1559ParamError,
            NextBlockEnvCtx = OpNextBlockEnvAttributes,
            BlockExecutorFactory = InnerBlockExecutorFactory<EvmF>,
            BlockAssembler = OpBlockAssembler<ConduitOpChainSpec>,
        >,
{
    type Primitives = OpPrimitives;
    type Error = EIP1559ParamError;
    type NextBlockEnvCtx = OpNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = OpBlockAssembler<ConduitOpChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.inner.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<OpSpecId>, Self::Error> {
        self.inner.evm_env(header).map(|env| self.maybe_apply_limits(env))
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv<OpSpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes).map(|env| self.maybe_apply_limits(env))
    }

    fn context_for_block(
        &self,
        block: &'_ SealedBlock<<OpPrimitives as NodePrimitives>::Block>,
    ) -> Result<OpBlockExecutionCtx, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<<OpPrimitives as NodePrimitives>::BlockHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<OpBlockExecutionCtx, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl ConfigurePostExecEvm for ConduitOpEvmConfig {
    fn post_exec_executor_for_block<'a, DB: Database>(
        &'a self,
        db: &'a mut State<DB>,
        block: &'a SealedBlock<<Self::Primitives as NodePrimitives>::Block>,
        post_exec_mode: PostExecMode,
    ) -> Result<
        impl BlockExecutor<
            Transaction = <Self::Primitives as NodePrimitives>::SignedTx,
            Receipt = <Self::Primitives as NodePrimitives>::Receipt,
        > + PostExecExecutorExt
        + 'a,
        Self::Error,
    > {
        let evm = self.evm_for_block(db, block.header())?;
        let ctx = self.inner.context_for_block_with_post_exec_mode(block, Some(post_exec_mode));
        let inner = OpBlockExecutor::new(
            evm,
            ctx,
            self.inner.executor_factory.spec(),
            self.inner.executor_factory.receipt_builder(),
        );
        Ok(ConduitOpBlockExecutor { inner, chain_spec: self.chain_spec.clone() })
    }

    fn post_exec_builder_for_next_block<'a, DB: Database + 'a>(
        &'a self,
        db: &'a mut State<DB>,
        parent: &'a SealedHeader<<Self::Primitives as NodePrimitives>::BlockHeader>,
        attributes: Self::NextBlockEnvCtx,
        post_exec_mode: PostExecMode,
    ) -> Result<
        impl BlockBuilder<
            Primitives = Self::Primitives,
            Executor: PostExecExecutorExt
                          + BlockExecutor<
                Evm: alloy_evm::Evm<DB: core::ops::DerefMut<Target = State<DB>>>,
            >,
        > + 'a,
        Self::Error,
    > {
        let evm_env = self.next_evm_env(parent, &attributes)?;
        let evm = self.evm_with_env(db, evm_env);
        let ctx = self.inner.context_for_next_block_with_post_exec_mode(
            parent,
            attributes,
            post_exec_mode,
        );
        let inner = OpBlockExecutor::new(
            evm,
            ctx.clone(),
            self.inner.executor_factory.spec(),
            self.inner.executor_factory.receipt_builder(),
        );
        let executor = ConduitOpBlockExecutor { inner, chain_spec: self.chain_spec.clone() };

        Ok(BasicBlockBuilder::<'a, ConduitOpEvmConfig, _, _, OpPrimitives> {
            executor,
            transactions: Vec::new(),
            ctx,
            parent,
            assembler: self.block_assembler(),
        })
    }
}

impl<F> ConfigurePostExecEvm for ConduitOpEvmConfig<PostExecEvmFactoryAdapter<F>>
where
    F: PostExecEvmFactoryHooks<
            Tx: alloy_evm::TransactionEnvMut
                    + FromRecoveredTx<OpTransactionSigned>
                    + FromTxWithEncoded<OpTransactionSigned>
                    + OpTxEnv,
            Precompiles = PrecompilesMap,
            Spec = OpSpecId,
            BlockEnv = BlockEnv,
        > + Debug
        + Clone
        + Send
        + Sync
        + Unpin
        + 'static,
    InnerBlockExecutorFactory<PostExecEvmFactoryAdapter<F>>: for<'a> BlockExecutorFactory<
            EvmFactory = PostExecEvmFactoryAdapter<F>,
            ExecutionCtx<'a> = OpBlockExecutionCtx,
            Transaction = OpTransactionSigned,
            Receipt = OpReceipt,
        >,
    Self: ConfigureEvm<
            Primitives = OpPrimitives,
            Error = EIP1559ParamError,
            NextBlockEnvCtx = OpNextBlockEnvAttributes,
            BlockExecutorFactory = Self,
            BlockAssembler = OpBlockAssembler<ConduitOpChainSpec>,
        >,
{
    fn post_exec_executor_for_block<'a, DB: Database>(
        &'a self,
        db: &'a mut State<DB>,
        block: &'a SealedBlock<<Self::Primitives as NodePrimitives>::Block>,
        post_exec_mode: PostExecMode,
    ) -> Result<
        impl BlockExecutor<
            Transaction = <Self::Primitives as NodePrimitives>::SignedTx,
            Receipt = <Self::Primitives as NodePrimitives>::Receipt,
        > + PostExecExecutorExt
        + 'a,
        Self::Error,
    > {
        let evm = self.evm_for_block(db, block.header())?;
        let ctx = self.inner.context_for_block_with_post_exec_mode(block, Some(post_exec_mode));
        let inner = OpBlockExecutor::new(
            evm,
            ctx,
            self.inner.executor_factory.spec(),
            self.inner.executor_factory.receipt_builder(),
        );
        Ok(ConduitOpBlockExecutor { inner, chain_spec: self.chain_spec.clone() })
    }

    fn post_exec_builder_for_next_block<'a, DB: Database + 'a>(
        &'a self,
        db: &'a mut State<DB>,
        parent: &'a SealedHeader<<Self::Primitives as NodePrimitives>::BlockHeader>,
        attributes: Self::NextBlockEnvCtx,
        post_exec_mode: PostExecMode,
    ) -> Result<
        impl BlockBuilder<
            Primitives = Self::Primitives,
            Executor: PostExecExecutorExt
                          + BlockExecutor<
                Evm: alloy_evm::Evm<DB: core::ops::DerefMut<Target = State<DB>>>,
            >,
        > + 'a,
        Self::Error,
    > {
        let evm_env = self.next_evm_env(parent, &attributes)?;
        let evm = self.evm_with_env(db, evm_env);
        let ctx = self.inner.context_for_next_block_with_post_exec_mode(
            parent,
            attributes,
            post_exec_mode,
        );
        let inner = OpBlockExecutor::new(
            evm,
            ctx.clone(),
            self.inner.executor_factory.spec(),
            self.inner.executor_factory.receipt_builder(),
        );
        let executor = ConduitOpBlockExecutor { inner, chain_spec: self.chain_spec.clone() };

        Ok(BasicBlockBuilder::<'a, Self, _, _, OpPrimitives> {
            executor,
            transactions: Vec::new(),
            ctx,
            parent,
            assembler: self.block_assembler(),
        })
    }
}

impl<EvmF> ConfigureEngineEvm<OpExecData> for ConduitOpEvmConfig<EvmF>
where
    EvmF: EvmFactory<
            Tx: alloy_evm::TransactionEnvMut
                    + FromRecoveredTx<OpTransactionSigned>
                    + FromTxWithEncoded<OpTransactionSigned>
                    + OpTxEnv,
            Precompiles = PrecompilesMap,
            Spec = OpSpecId,
            BlockEnv = BlockEnv,
        > + Debug
        + Clone
        + Send
        + Sync
        + Unpin
        + 'static,
    InnerBlockExecutorFactory<EvmF>: for<'a> BlockExecutorFactory<
            EvmFactory = EvmF,
            ExecutionCtx<'a> = OpBlockExecutionCtx,
            Transaction = OpTransactionSigned,
            Receipt = OpReceipt,
        >,
    Self: ConfigureEvm<
            Primitives = OpPrimitives,
            Error = EIP1559ParamError,
            NextBlockEnvCtx = OpNextBlockEnvAttributes,
            BlockExecutorFactory = Self,
            BlockAssembler = OpBlockAssembler<ConduitOpChainSpec>,
        > + Send
        + Sync
        + Unpin
        + Clone
        + 'static,
    OpTransactionSigned: Decodable2718 + OpConsensusTransaction,
{
    fn evm_env_for_payload(&self, payload: &OpExecData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();
        let spec = revm_spec_by_timestamp_after_bedrock(&self.chain_spec, timestamp);

        let cfg_env = CfgEnv::new()
            .with_chain_id(self.chain_spec.chain().id())
            .with_spec_and_mainnet_gas_params(spec);

        let blob_excess_gas_and_price = spec
            .into_eth_spec()
            .is_enabled_in(SpecId::CANCUN)
            .then_some(BlobExcessGasAndPrice { excess_blob_gas: 0, blob_gasprice: 1 });

        let block_env = BlockEnv {
            number: U256::from(block_number),
            beneficiary: payload.payload.as_v1().fee_recipient,
            timestamp: U256::from(timestamp),
            difficulty: if spec.into_eth_spec() >= SpecId::MERGE {
                U256::ZERO
            } else {
                payload.payload.as_v1().prev_randao.into()
            },
            prevrandao: (spec.into_eth_spec() >= SpecId::MERGE)
                .then(|| payload.payload.as_v1().prev_randao),
            gas_limit: payload.payload.as_v1().gas_limit,
            basefee: payload.payload.as_v1().base_fee_per_gas.to(),
            blob_excess_gas_and_price,
            slot_num: 0,
        };

        Ok(self.maybe_apply_limits(EvmEnv { cfg_env, block_env }))
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a OpExecData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let transactions = payload
            .payload
            .transactions()
            .iter()
            .map(|encoded| TxTy::<Self::Primitives>::decode_2718_exact(encoded.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| EIP1559ParamError::InvalidPostExecPayload)?;
        let post_exec_mode = post_exec_mode_from_transactions(
            transactions.iter(),
            payload.payload.block_number(),
            self.chain_spec.is_interop_active_at_timestamp(payload.payload.timestamp()),
        )?;

        Ok(OpBlockExecutionCtx {
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            extra_data: payload.payload.as_v1().extra_data.clone(),
            post_exec_mode,
        })
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &OpExecData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let transactions = payload.payload.transactions().clone();
        let convert = |encoded: Bytes| {
            let tx = TxTy::<Self::Primitives>::decode_2718_exact(encoded.as_ref())
                .map_err(AnyError::new)?;
            let signer = tx.try_recover().map_err(AnyError::new)?;
            Ok::<_, AnyError>(WithEncoded::new(encoded, tx.with_signer(signer)))
        };

        Ok((transactions, convert))
    }
}

/// Executor builder that produces [`ConduitOpEvmConfig`].
///
/// Replaces [`OpExecutorBuilder`](reth_optimism_node::node::OpExecutorBuilder) to wire
/// custom state transitions into the node, with optional EVM limit overrides.
#[derive(Debug, Clone)]
pub struct ConduitOpExecutorBuilder<EvmF = ConduitOpDefaultEvmFactory> {
    /// Optional EVM limit overrides applied to every EVM environment.
    pub limits: Option<EvmLimitParams>,
    /// EVM factory used by the executor.
    pub evm_factory: EvmF,
}

impl ConduitOpExecutorBuilder {
    /// Creates a builder with standard OP Stack defaults (no limit overrides).
    pub fn optimism() -> Self {
        Self { limits: None, evm_factory: ConduitOpDefaultEvmFactory::default() }
    }

    /// Creates a builder with Conduit's higher EVM limits.
    pub fn conduit() -> Self {
        Self {
            limits: Some(conduit_evm_limits()),
            evm_factory: ConduitOpDefaultEvmFactory::default(),
        }
    }
}

impl Default for ConduitOpExecutorBuilder {
    fn default() -> Self {
        Self::optimism()
    }
}

impl<EvmF> ConduitOpExecutorBuilder<EvmF> {
    /// Creates a builder with the given optional EVM limit overrides and EVM factory.
    pub fn with_limits_and_evm_factory(limits: Option<EvmLimitParams>, evm_factory: EvmF) -> Self {
        Self { limits, evm_factory }
    }
}

impl<Node, EvmF> ExecutorBuilder<Node> for ConduitOpExecutorBuilder<EvmF>
where
    EvmF: EvmFactory<
            Tx: alloy_evm::TransactionEnvMut
                    + FromRecoveredTx<OpTransactionSigned>
                    + FromTxWithEncoded<OpTransactionSigned>
                    + OpTxEnv,
            Precompiles = PrecompilesMap,
            Spec = OpSpecId,
            BlockEnv = BlockEnv,
        > + Debug
        + Clone
        + Send
        + Sync
        + Unpin
        + 'static,
    InnerBlockExecutorFactory<EvmF>: for<'a> BlockExecutorFactory<
            EvmFactory = EvmF,
            ExecutionCtx<'a> = OpBlockExecutionCtx,
            Transaction = OpTransactionSigned,
            Receipt = OpReceipt,
        >,
    ConduitOpEvmConfig<EvmF>: ConfigureEvm<Primitives = OpPrimitives>,
    Node: reth_node_builder::node::FullNodeTypes<
            Types: NodeTypes<ChainSpec = ConduitOpChainSpec, Primitives = OpPrimitives>,
        >,
{
    type EVM = ConduitOpEvmConfig<EvmF>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(ConduitOpEvmConfig::with_limits_and_evm_factory(
            ctx.chain_spec(),
            self.limits,
            self.evm_factory,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainspec::ConduitOpChainSpecParser;
    use reth_cli::chainspec::ChainSpecParser;
    use reth_optimism_forks::OpHardforks;

    const KARST_GENESIS: &str = r#"{
        "config": {
            "chainId": 99999,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "muirGlacierBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "shanghaiTime": 0,
            "cancunTime": 0,
            "pragueTime": 0,
            "bedrockBlock": 0,
            "regolithTime": 0,
            "canyonTime": 0,
            "ecotoneTime": 0,
            "fjordTime": 0,
            "graniteTime": 0,
            "holoceneTime": 0,
            "isthmusTime": 0,
            "jovianTime": 0,
            "karstTime": 1000
        },
        "difficulty": "0x0",
        "gasLimit": "0x1c9c380",
        "alloc": {}
    }"#;

    /// Regression test for Karst readiness: a genesis `karstTime` must flow through
    /// [`ConduitOpChainSpec`] and [`ConduitOpEvmConfig`] into the `KARST` EVM spec
    /// (Osaka semantics, including the EIP-7825 transaction gas cap that the tx pool
    /// reads via `evm_env.cfg_env.tx_gas_limit_cap()`).
    #[test]
    fn karst_genesis_flows_through_wrapper() {
        let dir = std::env::temp_dir().join("conduit-op-reth-karst-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.json");
        std::fs::write(&path, KARST_GENESIS).unwrap();
        let spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        // Hardfork activation is delegated through ConduitOpChainSpec.
        assert!(!spec.is_karst_active_at_timestamp(999));
        assert!(spec.is_karst_active_at_timestamp(1000));
        assert!(spec.is_jovian_active_at_timestamp(999));

        // ConduitOpEvmConfig delegates evm_env, which selects the KARST spec id.
        let evm_config = ConduitOpEvmConfig::new(spec);
        let pre = Header { timestamp: 999, gas_limit: 30_000_000, ..Default::default() };
        let post = Header { timestamp: 1000, gas_limit: 30_000_000, ..Default::default() };
        let env_pre = evm_config.evm_env(&pre).unwrap();
        let env_post = evm_config.evm_env(&post).unwrap();
        assert_eq!(env_pre.cfg_env.spec, OpSpecId::JOVIAN);
        assert_eq!(env_post.cfg_env.spec, OpSpecId::KARST);

        // The EIP-7825 tx gas cap (2^24) activates exactly at Karst.
        use revm::context_interface::Cfg;
        assert_eq!(env_pre.cfg_env.tx_gas_limit_cap(), u64::MAX);
        assert_eq!(env_post.cfg_env.tx_gas_limit_cap(), 16_777_216);
    }

    /// Conduit EVM limits configured via [`ConduitOpEvmConfig::conduit`] must flow into
    /// every EVM environment; the default constructors must leave OP Stack defaults intact.
    #[test]
    fn conduit_limits_flow_through_evm_env() {
        let dir = std::env::temp_dir().join("conduit-op-reth-limits-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.json");
        std::fs::write(&path, KARST_GENESIS).unwrap();
        let spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        let header = Header { timestamp: 999, gas_limit: 30_000_000, ..Default::default() };

        let env = ConduitOpEvmConfig::conduit(spec.clone()).evm_env(&header).unwrap();
        assert_eq!(env.cfg_env.limit_contract_code_size, Some(CONDUIT_MAX_CODE_SIZE));
        assert_eq!(env.cfg_env.limit_contract_initcode_size, Some(CONDUIT_MAX_INITCODE_SIZE));

        for default_config in
            [ConduitOpEvmConfig::new(spec.clone()), ConduitOpEvmConfig::optimism(spec)]
        {
            let env = default_config.evm_env(&header).unwrap();
            assert_eq!(env.cfg_env.limit_contract_code_size, None);
            assert_eq!(env.cfg_env.limit_contract_initcode_size, None);
        }
    }
}
