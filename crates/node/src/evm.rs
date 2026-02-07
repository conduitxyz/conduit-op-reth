//! Custom EVM configuration and block executor for ConduitOp state transitions.
//!
//! Wraps the standard OP EVM config and block executor to apply state overrides
//! at the `StateOverrideFork0` activation block.

use crate::chainspec::ConduitOpChainSpec;
use crate::hardforks::{ConduitOpHardfork, ConduitOpHardforks};
use crate::state_override_fork0::ensure_state_override_fork0;
use alloy_consensus::{BlockHeader, Header};
use alloy_eips::Decodable2718;
use alloy_evm::block::{
    BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
    BlockExecutorFor, ExecutableTx, OnStateHook, StateDB,
};
use alloy_evm::{Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded};
use alloy_op_evm::block::OpTxEnv;
use alloy_op_evm::block::receipt_builder::OpReceiptBuilder;
use alloy_op_evm::{OpBlockExecutionCtx, OpBlockExecutor, OpEvmFactory};
use alloy_primitives::Bytes;
use op_alloy_consensus::EIP1559ParamError;
use op_alloy_rpc_types_engine::OpExecutionData;
use op_revm::OpSpecId;
use reth_evm::execute::{BlockAssembler, BlockAssemblerInput};
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
};
use reth_node_builder::components::ExecutorBuilder;
use reth_node_builder::{BuilderContext, NodeTypes};
use reth_optimism_evm::{
    OpBlockAssembler, OpEvmConfig, OpNextBlockEnvAttributes, OpRethReceiptBuilder,
};
use reth_optimism_forks::OpHardforks;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::{NodePrimitives, SealedBlock, SealedHeader};
use reth_primitives_traits::{SignedTransaction, TxTy, WithEncoded};
use reth_storage_errors::any::AnyError;
use revm::Inspector;
use revm::context::Block;
use revm::context::result::ResultAndState;
use revm::database::{DatabaseCommit, State};
use std::sync::Arc;
use tracing::info;

/// Custom block executor wrapping [`OpBlockExecutor`].
///
/// Applies account state overrides when `StateOverrideFork0` first activates.
/// Uses the actual parent block timestamp to detect the transition block.
pub struct ConduitOpBlockExecutor<E, R: OpReceiptBuilder, Spec> {
    inner: OpBlockExecutor<E, R, Spec>,
    chain_spec: Arc<ConduitOpChainSpec>,
    parent_timestamp: u64,
}

impl<E, R, Spec> BlockExecutor for ConduitOpBlockExecutor<E, R, Spec>
where
    E: Evm<
            DB: Database + DatabaseCommit + StateDB,
            Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction> + OpTxEnv,
        >,
    R: OpReceiptBuilder<
            Transaction: alloy_consensus::Transaction + alloy_eips::Encodable2718,
            Receipt: alloy_consensus::TxReceipt,
        >,
    Spec: OpHardforks + Clone,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()?;

        // Apply state overrides at the StateOverrideFork0 transition block.
        if let Some(ref config) = self.chain_spec.state_override_fork0 {
            ensure_state_override_fork0(
                self.chain_spec.as_ref(),
                self.inner.evm.block().timestamp().saturating_to(),
                self.parent_timestamp,
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
    ) -> Result<ResultAndState<<Self::Evm as Evm>::HaltReason>, BlockExecutionError> {
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState<<Self::Evm as Evm>::HaltReason>,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        self.inner.commit_transaction(output, tx)
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

/// Execution context wrapping [`OpBlockExecutionCtx`] with `parent_timestamp`.
///
/// The parent timestamp is needed to detect fork activation transitions
/// (e.g., `StateOverrideFork0`) where the fork is active at the current block's
/// timestamp but was not active at the parent's timestamp.
#[derive(Clone, Debug)]
pub struct ConduitOpBlockExecutionCtx {
    /// The inner OP execution context.
    pub inner: OpBlockExecutionCtx,
    /// Parent block timestamp (0 when unavailable, e.g., re-execution or payload validation).
    pub parent_timestamp: u64,
}

impl From<ConduitOpBlockExecutionCtx> for OpBlockExecutionCtx {
    fn from(ctx: ConduitOpBlockExecutionCtx) -> Self {
        ctx.inner
    }
}

/// Block assembler wrapping [`OpBlockAssembler`] for use with [`ConduitOpEvmConfig`].
///
/// Needed because `OpBlockAssembler`'s `BlockAssembler<F>` trait impl requires
/// `ExecutionCtx<'a> = OpBlockExecutionCtx` exactly. This wrapper calls the inherent
/// `assemble_block` method which accepts `ExecutionCtx<'a>: Into<OpBlockExecutionCtx>`.
#[derive(Debug, Clone)]
pub struct ConduitOpBlockAssembler {
    inner: OpBlockAssembler<ConduitOpChainSpec>,
}

impl BlockAssembler<ConduitOpEvmConfig> for ConduitOpBlockAssembler {
    type Block = alloy_consensus::Block<
        <OpRethReceiptBuilder as OpReceiptBuilder>::Transaction,
    >;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, ConduitOpEvmConfig>,
    ) -> Result<Self::Block, BlockExecutionError> {
        self.inner.assemble_block(input)
    }
}

/// Custom EVM configuration wrapping [`OpEvmConfig`].
///
/// Implements [`BlockExecutorFactory`] directly (following the bera-reth pattern of
/// `type BlockExecutorFactory = Self`), wrapping each [`OpBlockExecutor`] in a
/// [`ConduitOpBlockExecutor`] for custom state transitions.
#[derive(Debug, Clone)]
pub struct ConduitOpEvmConfig {
    inner: OpEvmConfig<ConduitOpChainSpec, OpPrimitives>,
    chain_spec: Arc<ConduitOpChainSpec>,
    block_assembler: ConduitOpBlockAssembler,
}

impl ConduitOpEvmConfig {
    /// Creates a new [`ConduitOpEvmConfig`].
    pub fn new(chain_spec: Arc<ConduitOpChainSpec>) -> Self {
        let inner = OpEvmConfig::new(chain_spec.clone(), OpRethReceiptBuilder::default());
        let block_assembler = ConduitOpBlockAssembler {
            inner: OpBlockAssembler::new(chain_spec.clone()),
        };
        Self {
            inner,
            chain_spec,
            block_assembler,
        }
    }
}

impl BlockExecutorFactory for ConduitOpEvmConfig {
    type EvmFactory = OpEvmFactory;
    type ExecutionCtx<'a> = ConduitOpBlockExecutionCtx;
    type Transaction = <OpRethReceiptBuilder as OpReceiptBuilder>::Transaction;
    type Receipt = <OpRethReceiptBuilder as OpReceiptBuilder>::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.executor_factory.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <OpEvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<<OpEvmFactory as EvmFactory>::Context<&'a mut State<DB>>> + 'a,
    {
        let inner = OpBlockExecutor::new(
            evm,
            ctx.inner,
            self.inner.executor_factory.spec(),
            self.inner.executor_factory.receipt_builder(),
        );
        ConduitOpBlockExecutor {
            inner,
            chain_spec: self.chain_spec.clone(),
            parent_timestamp: ctx.parent_timestamp,
        }
    }
}

impl ConfigureEvm for ConduitOpEvmConfig {
    type Primitives = OpPrimitives;
    type Error = EIP1559ParamError;
    type NextBlockEnvCtx = OpNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = ConduitOpBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
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
    ) -> Result<ConduitOpBlockExecutionCtx, Self::Error> {
        // Re-execution path: we don't have the parent header, so use 0.
        // This is safe because fork activation is timestamp-based: active_at(t) && !active_at(0)
        // will correctly fire on the first block at or after fork_time.
        Ok(ConduitOpBlockExecutionCtx {
            inner: self.inner.context_for_block(block)?,
            parent_timestamp: 0,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<<OpPrimitives as NodePrimitives>::BlockHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ConduitOpBlockExecutionCtx, Self::Error> {
        Ok(ConduitOpBlockExecutionCtx {
            inner: self.inner.context_for_next_block(parent, attributes)?,
            parent_timestamp: parent.timestamp(),
        })
    }
}

impl ConfigureEngineEvm<OpExecutionData> for ConduitOpEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &OpExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a OpExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        Ok(ConduitOpBlockExecutionCtx {
            inner: self.inner.context_for_payload(payload)?,
            parent_timestamp: 0,
        })
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &OpExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let transactions = payload.payload.transactions().clone();
        let convert = |encoded: Bytes| {
            let tx =
                TxTy::<OpPrimitives>::decode_2718_exact(encoded.as_ref()).map_err(AnyError::new)?;
            let signer = tx.try_recover().map_err(AnyError::new)?;
            Ok::<_, AnyError>(WithEncoded::new(encoded, tx.with_signer(signer)))
        };

        Ok((transactions, convert))
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
        let chain_spec = ctx.chain_spec();

        if let Some(ref config) = chain_spec.state_override_fork0 {
            let activation =
                chain_spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0);
            info!(
                target: "conduit_op::executor",
                ?activation,
                num_updates = config.updates.len(),
                "StateOverrideFork0 configured"
            );
        }

        Ok(ConduitOpEvmConfig::new(chain_spec))
    }
}
