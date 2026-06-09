//! Custom EVM configuration and block executor for ConduitOp state transitions.
//!
//! Wraps the standard OP EVM config and block executor to apply state overrides
//! at the `StateOverrideFork0` activation block.

use crate::{chainspec::ConduitOpChainSpec, state_override_fork0::ensure_state_override_fork0};
use alloy_consensus::Header;
use alloy_evm::{
    Database, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        ExecutableTx, GasOutput, OnStateHook, StateDB,
    },
};
use alloy_op_evm::{
    OpBlockExecutionCtx, OpBlockExecutor, OpEvmFactory,
    block::{OpTxEnv, receipt_builder::OpReceiptBuilder},
    post_exec::{PostExecEvm, PostExecExecutorExt, WarmingRefundEvent, WarmingState},
};
use op_alloy_consensus::{EIP1559ParamError, SDMGasEntry};
use op_revm::OpSpecId;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    execute::{BasicBlockBuilder, BlockBuilder},
};
use reth_node_builder::{BuilderContext, NodeTypes, components::ExecutorBuilder};
use reth_optimism_evm::{
    ConfigurePostExecEvm, OpBlockAssembler, OpBlockExecutorFactory, OpEvmConfig,
    OpNextBlockEnvAttributes, OpRethReceiptBuilder, OpTx, PostExecMode,
};
use reth_optimism_forks::OpHardforks;
use reth_optimism_payload_builder::OpExecData;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::{NodePrimitives, SealedBlock, SealedHeader};
use revm::{
    Inspector,
    context::Block,
    database::{DatabaseCommit, State},
};
use std::sync::Arc;

type InnerBlockExecutorFactory =
    OpBlockExecutorFactory<OpRethReceiptBuilder, Arc<ConduitOpChainSpec>, OpEvmFactory<OpTx>>;

/// Custom block executor wrapping [`OpBlockExecutor`].
///
/// Applies account state overrides when `StateOverrideFork0` first activates,
/// using the OP Stack 2-second block time heuristic to detect the transition block.
pub struct ConduitOpBlockExecutor<E, R: OpReceiptBuilder, Spec> {
    inner: OpBlockExecutor<E, R, Spec>,
    chain_spec: Arc<ConduitOpChainSpec>,
}

impl<E, R, Spec> BlockExecutor for ConduitOpBlockExecutor<E, R, Spec>
where
    E: PostExecEvm<
            DB: Database + DatabaseCommit + StateDB,
            Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction> + OpTxEnv,
            HaltReason: Send + 'static,
        >,
    R: OpReceiptBuilder<
            Transaction: alloy_consensus::Transaction
                             + alloy_eips::Encodable2718
                             + op_alloy_consensus::OpTransaction,
            Receipt: alloy_consensus::TxReceipt,
        >,
    Spec: OpHardforks,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;
    type Result = <OpBlockExecutor<E, R, Spec> as BlockExecutor>::Result;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()?;

        // Apply state overrides at the StateOverrideFork0 transition block.
        if let Some(ref config) = self.chain_spec.state_override_fork0 {
            ensure_state_override_fork0(
                self.chain_spec.as_ref(),
                self.inner.evm.block().timestamp().saturating_to(),
                config,
                self.inner.evm.db_mut(),
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

impl<E, R, Spec> PostExecExecutorExt for ConduitOpBlockExecutor<E, R, Spec>
where
    E: PostExecEvm,
    R: OpReceiptBuilder,
    Spec: OpHardforks + Clone,
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

impl BlockExecutorFactory for ConduitOpEvmConfig {
    type EvmFactory = <InnerBlockExecutorFactory as BlockExecutorFactory>::EvmFactory;
    type TxExecutionResult = <InnerBlockExecutorFactory as BlockExecutorFactory>::TxExecutionResult;
    type ExecutionCtx<'a> = OpBlockExecutionCtx;
    type Transaction = <InnerBlockExecutorFactory as BlockExecutorFactory>::Transaction;
    type Receipt = <InnerBlockExecutorFactory as BlockExecutorFactory>::Receipt;
    type Executor<'a, DB: StateDB, I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>> =
        ConduitOpBlockExecutor<
            <Self::EvmFactory as EvmFactory>::Evm<DB, I>,
            &'a OpRethReceiptBuilder,
            &'a Arc<ConduitOpChainSpec>,
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
pub struct ConduitOpEvmConfig {
    inner: OpEvmConfig<ConduitOpChainSpec, OpPrimitives>,
    chain_spec: Arc<ConduitOpChainSpec>,
}

impl ConduitOpEvmConfig {
    /// Creates a new [`ConduitOpEvmConfig`].
    pub fn new(chain_spec: Arc<ConduitOpChainSpec>) -> Self {
        let inner = OpEvmConfig::new(chain_spec.clone(), OpRethReceiptBuilder::default());
        Self { inner, chain_spec }
    }
}

impl ConfigureEvm for ConduitOpEvmConfig {
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
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv<OpSpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
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
        Ok(ConfigureEvm::create_executor(self, evm, ctx))
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
        let executor = ConfigureEvm::create_executor(self, evm, ctx.clone());

        Ok(BasicBlockBuilder::<'a, ConduitOpEvmConfig, _, _, OpPrimitives> {
            executor,
            transactions: Vec::new(),
            ctx,
            parent,
            assembler: self.block_assembler(),
        })
    }
}

impl ConfigureEngineEvm<OpExecData> for ConduitOpEvmConfig {
    fn evm_env_for_payload(&self, payload: &OpExecData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(&payload.0)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a OpExecData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_payload(&payload.0)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &OpExecData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(&payload.0)
    }
}

/// Executor builder that produces [`ConduitOpEvmConfig`].
///
/// Replaces [`OpExecutorBuilder`](reth_optimism_node::node::OpExecutorBuilder) to wire
/// custom state transitions into the node.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ConduitOpExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for ConduitOpExecutorBuilder
where
    Node: reth_node_builder::node::FullNodeTypes<
            Types: NodeTypes<ChainSpec = ConduitOpChainSpec, Primitives = OpPrimitives>,
        >,
{
    type EVM = ConduitOpEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(ConduitOpEvmConfig::new(ctx.chain_spec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainspec::ConduitOpChainSpecParser;
    use reth_cli::chainspec::ChainSpecParser;

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
}
