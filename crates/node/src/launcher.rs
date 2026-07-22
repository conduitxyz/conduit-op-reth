//! Node launcher: wires the proof-history ExEx/RPC overrides and the flashblocks
//! pending-state RPC overrides onto the Conduit OP-Reth node.

// Keep this close to `reth_optimism_node::proof_history` from the pinned upstream op-reth tag.
// Upstream's launcher is concrete over `OpChainSpec`/`OpNode`, so Conduit needs this local adapter
// to preserve `ConduitOpChainSpec` and `ConduitOpNode` while reusing the same proof-history wiring.

use crate::{
    args::{ConduitArgs, SlipstreamArgs},
    chainspec::ConduitOpChainSpec,
    flashblocks_state::{FlashblocksCallApiServer, FlashblocksCallExt, PendingFlashblockState},
    node::ConduitOpNode,
    slipstream::{SlipstreamApiServer, SlipstreamConfig, SlipstreamRpcExt},
};
use eyre::ErrReport;
use futures_util::FutureExt;
use jsonrpsee::types::ErrorObject;
use op_alloy_network::Optimism;
use reth_db::DatabaseEnv;
use reth_db_api::database_metrics::DatabaseMetrics;
use reth_node_builder::{FullNodeComponents, NodeBuilder, WithLaunchContext, rpc::RpcContext};
use reth_optimism_exex::OpProofsExEx;
use reth_optimism_node::args::{ProofsStorageVersion, RollupArgs};
use reth_optimism_rpc::{
    SequencerClient,
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
    args: ConduitArgs,
) -> eyre::Result<(), ErrReport> {
    let ConduitArgs { rollup, slipstream } = args;
    let slipstream = if slipstream.experimental {
        let endpoint = rollup
            .sequencer
            .clone()
            .ok_or_else(|| eyre::eyre!("--experimental.slipstream requires --rollup.sequencer"))?;
        let client =
            SequencerClient::new_with_headers(endpoint, rollup.sequencer_headers.clone()).await?;
        Some((slipstream, client))
    } else {
        None
    };

    if !rollup.proofs_history {
        let flashblocks_enabled = rollup.flashblocks_url.is_some();
        let handle = builder
            .node(ConduitOpNode::new(rollup))
            .extend_rpc_modules(move |mut ctx| {
                install_rpc_overrides(&mut ctx, flashblocks_enabled, &slipstream)
            })
            .launch_with_debug_capabilities()
            .await?;
        return handle.node_exit_future.await;
    }

    // Defaults to `<reth-data-dir>/historical-proofs` when not supplied.
    let path = rollup.history.resolve_storage_path(builder.config().datadir().as_ref());

    match rollup.history.storage_version {
        ProofsStorageVersion::V1 => {
            info!(target: "reth::cli", "Using on-disk storage for proofs history (v1)");
            let mdbx = Arc::new(
                MdbxProofsStorage::new(&path)
                    .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorage: {e}"))?,
            );
            launch_with_proof_history(builder, rollup, slipstream, mdbx).await
        }
        ProofsStorageVersion::V2 => {
            info!(target: "reth::cli", "Using on-disk storage for proofs history (v2)");
            let mdbx = Arc::new(
                MdbxProofsStorageV2::new(&path)
                    .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorageV2: {e}"))?,
            );
            launch_with_proof_history(builder, rollup, slipstream, mdbx).await
        }
    }
}

/// Installs the ExEx, RPC overrides, and metrics hook for proof history, then launches the node.
async fn launch_with_proof_history<S>(
    builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
    args: RollupArgs,
    slipstream: Option<(SlipstreamArgs, SequencerClient)>,
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
        .extend_rpc_modules(move |mut ctx| {
            // Reth stores a single RPC-extension hook, so flashblocks, Slipstream, and proof
            // history overrides must be installed together.
            install_rpc_overrides(&mut ctx, flashblocks_enabled, &slipstream)?;

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
            let auth_eth_replaced =
                ctx.auth_module.replace_auth_methods(auth_api_ext.into_rpc())?;
            let debug_replaced = ctx.modules.replace_configured(debug_ext.into_rpc())?;
            info!(target: "reth::cli", eth_replaced, auth_eth_replaced, debug_replaced, "Proofs-history RPC overrides installed");
            Ok(())
        })
        .launch_with_debug_capabilities()
        .await?;

    handle.node_exit_future.await
}

/// Installs the flashblocks pending-state and Slipstream RPC overrides.
fn install_rpc_overrides<N, EthApi>(
    ctx: &mut RpcContext<'_, N, EthApi>,
    flashblocks_enabled: bool,
    slipstream: &Option<(SlipstreamArgs, SequencerClient)>,
) -> eyre::Result<()>
where
    N: FullNodeComponents,
    EthApi: FullEthApi<NetworkTypes = Optimism>
        + PendingFlashblockState
        + Clone
        + Send
        + Sync
        + 'static,
    ErrorObject<'static>: From<<EthApi as EthApiTypes>::Error>,
{
    if flashblocks_enabled {
        info!(target: "reth::cli", "Installing flashblocks pending-state RPC overrides (eth_call, eth_estimateGas, eth_simulateV1)");
        let ext = FlashblocksCallExt::new(ctx.registry.eth_api().clone());
        ctx.modules.add_or_replace_configured(ext.into_rpc())?;
        info!(target: "reth::cli", "Flashblocks pending-state RPC overrides installed");
    }

    if let Some((args, client)) = slipstream {
        let config = SlipstreamConfig {
            forward_concurrency: args.forward_concurrency,
            forward_timeout: Duration::from_millis(args.forward_timeout_ms),
            build_concurrency: args.hint_build_concurrency,
            build_timeout: Duration::from_millis(args.hint_build_timeout_ms),
            max_batch_bytes: args.max_hinted_batch_bytes,
        };
        let ext = SlipstreamRpcExt::new(
            client.clone(),
            ctx.registry.eth_api().clone(),
            args.compute_hints,
            config,
        );
        ctx.modules.add_or_replace_configured(ext.into_rpc())?;
        info!(target: "reth::cli", endpoint = client.endpoint(), compute_hints = args.compute_hints, "Slipstream forwarding RPC installed");
    }

    Ok(())
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
