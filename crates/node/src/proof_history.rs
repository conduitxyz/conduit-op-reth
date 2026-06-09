//! Node launcher with proof history support.

// Keep this close to `reth_optimism_node::proof_history` from the pinned upstream op-reth tag.
// Upstream's launcher is concrete over `OpChainSpec`/`OpNode`, so Conduit needs this local adapter
// to preserve `ConduitOpChainSpec` and `ConduitOpNode` while reusing the same proof-history wiring.

use crate::{chainspec::ConduitOpChainSpec, node::ConduitOpNode};
use eyre::ErrReport;
use futures_util::FutureExt;
use reth_db::DatabaseEnv;
use reth_db_api::database_metrics::DatabaseMetrics;
use reth_node_builder::{FullNodeComponents, NodeBuilder, WithLaunchContext};
use reth_optimism_exex::OpProofsExEx;
use reth_optimism_node::args::{ProofsStorageVersion, RollupArgs};
use reth_optimism_rpc::{
    debug::{DebugApiExt, DebugApiOverrideServer},
    eth::proofs::{EthApiExt, EthApiOverrideServer},
};
use reth_optimism_trie::{
    OpProofsStorage, OpProofsStore,
    db::{MdbxProofsStorage, MdbxProofsStorageV2},
};
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
        let handle =
            builder.node(ConduitOpNode::new(args)).launch_with_debug_capabilities().await?;
        return handle.node_exit_future.await;
    }

    let path = args
        .proofs_history_storage_path
        .clone()
        .expect("Path must be provided if not using in-memory storage");

    match args.proofs_history_storage_version {
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

    let handle = builder
        .node(ConduitOpNode::new(args))
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
            let debug_ext = DebugApiExt::new(
                ctx.node().provider().clone(),
                ctx.registry.eth_api().clone(),
                storage,
                ctx.node().task_executor().clone(),
                ctx.node().evm_config().clone(),
            );
            let eth_replaced = ctx.modules.replace_configured(api_ext.into_rpc())?;
            let debug_replaced = ctx.modules.replace_configured(debug_ext.into_rpc())?;
            info!(target: "reth::cli", eth_replaced, debug_replaced, "Proofs-history RPC overrides installed");
            Ok(())
        })
        .launch_with_debug_capabilities()
        .await?;

    handle.node_exit_future.await
}

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
