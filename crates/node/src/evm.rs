//! Custom EVM configuration and block executor for ConduitOp state transitions.
//!
//! Wraps the standard OP EVM config and block executor to apply state overrides
//! at the `StateOverrideFork0` activation block.

use crate::{
    chainspec::ConduitOpChainSpec,
    hardforks::{ConduitOpHardfork, ConduitOpHardforks},
    state_override_fork0::ensure_state_override_fork0,
};
use alloy_consensus::Header;
use alloy_eips::Decodable2718;
use alloy_evm::{
    Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFor, ExecutableTx,
        OnStateHook, StateDB,
    },
};
use alloy_op_evm::{
    OpBlockExecutionCtx, OpBlockExecutor, OpEvmFactory,
    block::{OpTxEnv, receipt_builder::OpReceiptBuilder},
};
use alloy_primitives::Bytes;
use op_alloy_consensus::EIP1559ParamError;
use op_alloy_rpc_types_engine::OpExecutionData;
use op_revm::OpSpecId;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    InspectorFor,
};
use reth_node_builder::{BuilderContext, NodeTypes, components::ExecutorBuilder};
use reth_optimism_evm::{
    OpBlockAssembler, OpBlockExecutorFactory, OpEvmConfig, OpNextBlockEnvAttributes,
    OpRethReceiptBuilder,
};
use reth_optimism_forks::OpHardforks;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::{
    NodePrimitives, SealedBlock, SealedHeader, SignedTransaction, TxTy, WithEncoded,
};
use reth_storage_errors::any::AnyError;
use revm::{
    context::{Block, result::ResultAndState},
    database::{DatabaseCommit, State},
};
use std::sync::Arc;
use tracing::info;

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
    type BlockExecutorFactory =
        OpBlockExecutorFactory<OpRethReceiptBuilder, Arc<ConduitOpChainSpec>, OpEvmFactory>;
    type BlockAssembler = OpBlockAssembler<ConduitOpChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.inner.executor_factory
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

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <OpEvmFactory as EvmFactory>::Evm<&'a mut State<DB>, I>,
        ctx: OpBlockExecutionCtx,
    ) -> impl BlockExecutorFor<'a, Self::BlockExecutorFactory, DB, I>
    where
        DB: alloy_evm::Database,
        I: InspectorFor<Self, &'a mut State<DB>> + 'a,
    {
        let inner = OpBlockExecutor::new(
            evm,
            ctx,
            self.inner.executor_factory.spec(),
            self.inner.executor_factory.receipt_builder(),
        );
        ConduitOpBlockExecutor { inner, chain_spec: self.chain_spec.clone() }
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
        self.inner.context_for_payload(payload)
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
        Ok(ConduitOpEvmConfig::new(ctx.chain_spec()))
    }
}
