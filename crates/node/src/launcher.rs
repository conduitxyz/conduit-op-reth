//! Node launcher: wires the proof-history ExEx/RPC overrides and the flashblocks
//! pending-state RPC overrides onto the Conduit OP-Reth node.

// Keep this close to `reth_optimism_node::proof_history` from the pinned upstream op-reth tag.
// Upstream's launcher is concrete over `OpChainSpec`/`OpNode`, so Conduit needs this local adapter
// to preserve `ConduitOpChainSpec` and `ConduitOpNode` while reusing the same proof-history wiring.

use crate::{
    chainspec::ConduitOpChainSpec,
    evm::ConduitOpEvmConfig,
    flashblocks_state::{FlashblocksCallApiServer, FlashblocksCallExt, PendingFlashblockState},
    node::ConduitOpNode,
};
use eyre::ErrReport;
use futures_util::FutureExt;
use jsonrpsee::types::ErrorObject;
use reth_db::DatabaseEnv;
use reth_db_api::database_metrics::DatabaseMetrics;
use reth_node_builder::{
    FullNodeComponents, FullNodeTypes, NodeAdapter, NodeBuilder, NodeBuilderWithComponents,
    NodeComponents, NodeComponentsBuilder, NodeTypes, WithLaunchContext, rpc::RethRpcAddOns,
};
use reth_optimism_exex::OpProofsExEx;
use reth_optimism_node::args::{ProofsStorageVersion, RollupArgs};
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_rpc::{
    debug::{DebugApiExt, DebugApiOverrideServer},
    eth::proofs::{EthApiExt, EthApiOverrideServer},
};
use reth_optimism_trie::{
    OpProofsStorage, OpProofsStore,
    db::{MdbxProofsStorage, MdbxProofsStorageV2},
};
use reth_rpc_eth_api::{EthApiTypes, helpers::FullEthApi};
use reth_tasks::TaskExecutor;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::info;

/// Launches a Conduit OP-Reth node, optionally installing the proof-history ExEx and RPC
/// overrides.
pub async fn launch_node(
    builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
    args: RollupArgs,
) -> eyre::Result<(), ErrReport> {
    if !args.proofs_history {
        let flashblocks_enabled = args.flashblocks_url.is_some();
        let builder = install_flashblocks_call_overrides(
            builder.node(ConduitOpNode::new(args)),
            flashblocks_enabled,
        );
        let handle = builder.launch_with_debug_capabilities().await?;
        return handle.node_exit_future.await;
    }

    // Defaults to `<reth-data-dir>/historical-proofs` when not supplied.
    let path = args.history.resolve_storage_path(builder.config().datadir().as_ref());

    match args.history.storage_version {
        ProofsStorageVersion::V1 => {
            info!(target: "reth::cli", "Using on-disk storage for proofs history (v1)");
            let mdbx = Arc::new(
                MdbxProofsStorage::new(&path)
                    .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorage: {e}"))?,
            );
            launch_with_proof_history(builder, args, mdbx).await
        }
        ProofsStorageVersion::V2 => {
            info!(target: "reth::cli", "Using on-disk storage for proofs history (v2)");
            let mdbx = Arc::new(
                MdbxProofsStorageV2::new(&path)
                    .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorageV2: {e}"))?,
            );
            launch_with_proof_history(builder, args, mdbx).await
        }
    }
}

/// Installs the ExEx, RPC overrides, and metrics hook for proof history, then launches the node.
async fn launch_with_proof_history<S>(
    builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
    args: RollupArgs,
    mdbx: Arc<S>,
) -> eyre::Result<(), ErrReport>
where
    S: OpProofsStore + DatabaseMetrics + Send + Sync + 'static,
{
    let storage: OpProofsStorage<Arc<S>> = mdbx.clone().into();
    let storage_exec = storage.clone();

    let RollupArgs { proofs_history_window, proofs_history_verification_interval, .. } =
        args.clone();
    let proofs_history_window = proofs_history_window.window;
    let flashblocks_enabled = args.flashblocks_url.is_some();

    let builder = install_flashblocks_call_overrides(
        builder.node(ConduitOpNode::new(args)),
        flashblocks_enabled,
    );
    let handle = builder
        .on_node_started(move |node| {
            spawn_proofs_db_metrics(
                node.task_executor,
                mdbx,
                node.config.metrics.push_gateway_interval,
            );
            Ok(())
        })
        .install_exex("proofs-history", async move |exex_context| {
            Ok(OpProofsExEx::builder(exex_context, storage_exec)
                .with_proofs_history_window(proofs_history_window)
                .with_verification_interval(proofs_history_verification_interval)
                .build()
                .run()
                .boxed())
        })
        .extend_rpc_modules(move |ctx| {
            info!(target: "reth::cli", "Installing proofs-history RPC overrides (eth_getProof, debug_executePayload)");
            let api_ext = EthApiExt::new(ctx.registry.eth_api().clone(), storage.clone());
            let auth_api_ext = EthApiExt::new(ctx.registry.eth_api().clone(), storage.clone());
            let debug_ext = DebugApiExt::new(
                ctx.node().provider().clone(),
                ctx.registry.eth_api().clone(),
                storage,
                ctx.node().task_executor().clone(),
                ctx.node().evm_config().clone(),
            );
            let eth_replaced = ctx.modules.replace_configured(api_ext.into_rpc())?;
            let auth_eth_replaced = ctx.auth_module.replace_auth_methods(auth_api_ext.into_rpc())?;
            let debug_replaced = ctx.modules.replace_configured(debug_ext.into_rpc())?;
            info!(target: "reth::cli", eth_replaced, auth_eth_replaced, debug_replaced, "Proofs-history RPC overrides installed");
            Ok(())
        })
        .launch_with_debug_capabilities()
        .await?;

    handle.node_exit_future.await
}

/// Installs the flashblocks pending-state RPC overrides (`eth_call`, `eth_estimateGas`,
/// `eth_simulateV1`) when `flashblocks_enabled`, otherwise returns the builder unchanged.
///
/// Generic over the builder's node types / components / add-ons so both the no-proofs and
/// proofs-history launch paths share the exact same wiring. The caller is responsible for
/// calling `.launch*()` on the returned builder.
fn install_flashblocks_call_overrides<T, CB, AO>(
    builder: WithLaunchContext<NodeBuilderWithComponents<T, CB, AO>>,
    flashblocks_enabled: bool,
) -> WithLaunchContext<NodeBuilderWithComponents<T, CB, AO>>
where
    T: FullNodeTypes,
    T::Types: NodeTypes<Primitives = OpPrimitives, ChainSpec = ConduitOpChainSpec>,
    CB: NodeComponentsBuilder<T>,
    CB::Components: NodeComponents<T, Evm = ConduitOpEvmConfig>,
    AO: RethRpcAddOns<NodeAdapter<T, CB::Components>>,
    AO::EthApi: FullEthApi + PendingFlashblockState + Clone + Send + Sync + 'static,
    ErrorObject<'static>: From<<AO::EthApi as EthApiTypes>::Error>,
{
    if !flashblocks_enabled {
        return builder;
    }

    builder.extend_rpc_modules(move |ctx| {
        info!(target: "reth::cli", "Installing flashblocks pending-state RPC overrides (eth_call, eth_estimateGas, eth_simulateV1)");
        let ext = FlashblocksCallExt::new(ctx.registry.eth_api().clone());
        ctx.modules.add_or_replace_configured(ext.into_rpc())?;
        info!(target: "reth::cli", "Flashblocks pending-state RPC overrides installed");
        Ok(())
    })
}

/// Spawns a task that periodically reports metrics for the proofs DB.
fn spawn_proofs_db_metrics<S>(
    executor: TaskExecutor,
    storage: Arc<S>,
    metrics_report_interval: Duration,
) where
    S: DatabaseMetrics + Send + Sync + 'static,
{
    executor.spawn_critical_task("op-proofs-storage-metrics", async move {
        info!(
            target: "reth::cli",
            ?metrics_report_interval,
            "Starting op-proofs-storage metrics task"
        );

        loop {
            sleep(metrics_report_interval).await;
            storage.report_metrics();
        }
    });
}
