//! Opt-in pool configuration not exposed by upstream's OP pool builder.

use reth_chainspec::{EthChainSpec, ForkCondition};
use reth_evm::ConfigureEvm;
use reth_node_builder::{BuilderContext, NodeTypes, components::PoolBuilder, node::FullNodeTypes};
use reth_optimism_forks::{OpHardfork, OpHardforks};
use reth_optimism_node::node::{OpPoolBuilder, OpValidatorWrapper};
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_txpool::{
    OpPool, OpTransactionPool, OpTransactionValidator, interop_filter::InteropFilterClient,
};
use reth_provider::CanonStateSubscriptions;
use reth_transaction_pool::{
    Pool, TransactionValidationTaskExecutor, blobstore::DiskFileBlobStore,
};
use tracing::{info, warn};

/// Keeps the stock pool path by default, with an explicit tracked-nonce opt-in.
///
/// Upstream's `OpPoolBuilder` does not expose this `PoolConfig` field. Keep the opt-in
/// construction below aligned with its `build_pool`, including OP maintenance tasks.
#[derive(Debug, Clone, Default)]
pub struct ConduitOpPoolBuilder {
    /// Standard OP settings, including pool overrides and interop configuration.
    pub inner: OpPoolBuilder,
    /// Trust tracked sender state over older validation snapshots. Reorgs can lower nonces.
    pub enforce_tracked_nonce: bool,
}

impl<Node, Evm> PoolBuilder<Node, Evm> for ConduitOpPoolBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: OpHardforks, Primitives = OpPrimitives>>,
    Evm: ConfigureEvm<Primitives = OpPrimitives> + Clone + 'static,
{
    type Pool = OpTransactionPool<Node::Provider, DiskFileBlobStore, Evm>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        if !self.enforce_tracked_nonce {
            return self.inner.build_pool(ctx, evm_config).await;
        }

        let builder = self.inner;
        let interop_client = if builder.interop_endpoints.is_empty() {
            None
        } else {
            let mut client = InteropFilterClient::builder(
                builder.interop_endpoints.clone(),
                ctx.chain_spec().chain_id(),
            )
            .minimum_safety(builder.interop_safety_level)
            .failsafe(builder.interop_failsafe.clone());
            if let Some(min) = builder.interop_min_responses {
                client = client.min_responses(min);
            }
            Some(client.build().await)
        };

        let blob_store = reth_node_builder::components::create_blob_store(ctx)?;
        let validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .no_eip4844()
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .kzg_settings(ctx.kzg_settings()?)
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
                .with_additional_tasks(
                    builder
                        .pool_config_overrides
                        .additional_validation_tasks
                        .unwrap_or(ctx.config().txpool.additional_validation_tasks),
                )
                .build_with_tasks(ctx.task_executor().clone(), blob_store.clone())
                .map(|validator| {
                    let validator = OpTransactionValidator::new(validator)
                        .require_l1_data_gas_fee(!ctx.config().dev.dev);
                    let validator = if let Some(client) = interop_client.clone() {
                        validator.with_interop(client)
                    } else {
                        validator
                    };
                    builder.validator_wrapper.wrap(validator, ctx.provider().clone())
                });

        // Set this on the final config, after every upstream builder override, before the
        // actual pool is constructed. Both the OP wrapper and maintenance share this pool.
        let config =
            builder.pool_config_overrides.apply(ctx.pool_config()).with_enforce_tracked_nonce(true);
        let inner = Pool::new(validator, builder.ordering, blob_store, config.clone());
        let interop_enabled =
            ctx.chain_spec().op_fork_activation(OpHardfork::Lagoon) != ForkCondition::Never;
        let pool = OpPool::new(inner, interop_enabled);
        reth_node_builder::components::spawn_maintenance_tasks(ctx, pool.clone(), &config)?;

        if interop_enabled && let Some(interop) = interop_client {
            ctx.task_executor().spawn_critical_task(
                "Op txpool failsafe polling task",
                reth_optimism_txpool::maintain::poll_failsafe_future(interop.clone(), pool.clone()),
            );
            ctx.task_executor().spawn_critical_task(
                "Op txpool interop maintenance task",
                reth_optimism_txpool::maintain::maintain_transaction_pool_interop_future(
                    pool.clone(),
                    ctx.provider().canonical_state_stream(),
                    interop,
                ),
            );
        }
        if builder.enable_tx_conditional {
            ctx.task_executor().spawn_critical_task(
                "Op txpool conditional maintenance task",
                reth_optimism_txpool::maintain::maintain_transaction_pool_conditional_future(
                    pool.clone(),
                    ctx.provider().canonical_state_stream(),
                ),
            );
        }

        warn!(target: "reth::cli", "Tracked nonce enforcement enabled; reorgs can cause valid transactions to be rejected until sender state is refreshed");
        info!(target: "reth::cli", enforce_tracked_nonce = pool.config().enforce_tracked_nonce, interop_enabled, "Transaction pool initialized");
        Ok(pool)
    }
}
