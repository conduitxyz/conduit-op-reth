//! Node launcher: wires the proof-history ExEx/RPC overrides and the flashblocks
//! pending-state RPC overrides onto the Conduit OP-Reth node.

// Keep this close to `reth_optimism_node::proof_history` from the pinned upstream op-reth tag.
// Upstream's launcher is concrete over `OpChainSpec`/`OpNode`, so Conduit needs this local adapter
// to preserve `ConduitOpChainSpec` and `ConduitOpNode` while reusing the same proof-history wiring.

use crate::{
    chainspec::ConduitOpChainSpec,
    flashblocks_state::{FlashblocksCallApiServer, FlashblocksCallExt, PendingFlashblockState},
    hardforks::{ConduitOpHardfork, ConduitOpHardforks},
    node::ConduitOpNode,
    slipstream::SlipstreamProxy,
};
use conduit_op_reth_rpc_api::SlipstreamApiServer;
use eyre::ErrReport;
use futures_util::FutureExt;
use jsonrpsee::types::ErrorObject;
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
use tracing::{info, warn};

/// Launches a Conduit OP-Reth node, optionally installing the proof-history ExEx and RPC
/// overrides.
pub async fn launch_node(
    builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
    args: RollupArgs,
    slipstream_enabled: bool,
) -> eyre::Result<(), ErrReport> {
    validate_slipstream_config(&args, slipstream_enabled)?;
    let config = builder.config();
    if let Some(max_initcode_size) =
        config.chain.evm_limits_fork0.and_then(|limits| limits.max_initcode_size) &&
        max_initcode_size >= config.txpool.max_tx_input_bytes
    {
        let max_tx_input_bytes = config.txpool.max_tx_input_bytes;
        let activation = config.chain.conduit_op_fork_activation(ConduitOpHardfork::EvmLimitsFork0);
        warn!(
            target: "reth::cli",
            max_initcode_size,
            max_tx_input_bytes,
            ?activation,
            "EvmLimitsFork0 permits initcode that the configured transaction pool cannot admit; raise --txpool.max-tx-input-bytes and restart the node"
        );
    }

    if !args.proofs_history {
        let flashblocks_enabled = args.flashblocks_url.is_some();
        let handle = builder
            .node(ConduitOpNode::new(args))
            .extend_rpc_modules(move |mut ctx| {
                let sequencer_client = ctx.registry.eth_api().sequencer_client().cloned();
                install_flashblocks_call_overrides(&mut ctx, flashblocks_enabled)?;
                install_slipstream_batch_proxy(&mut ctx, slipstream_enabled, sequencer_client)
            })
            .launch_with_debug_capabilities()
            .await?;
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
            launch_with_proof_history(builder, args, mdbx, slipstream_enabled).await
        }
        ProofsStorageVersion::V2 => {
            info!(target: "reth::cli", "Using on-disk storage for proofs history (v2)");
            let mdbx = Arc::new(
                MdbxProofsStorageV2::new(&path)
                    .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorageV2: {e}"))?,
            );
            launch_with_proof_history(builder, args, mdbx, slipstream_enabled).await
        }
    }
}

/// Installs the ExEx, RPC overrides, and metrics hook for proof history, then launches the node.
async fn launch_with_proof_history<S>(
    builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
    args: RollupArgs,
    mdbx: Arc<S>,
    slipstream_enabled: bool,
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
            let sequencer_client = ctx.registry.eth_api().sequencer_client().cloned();
            install_flashblocks_call_overrides(&mut ctx, flashblocks_enabled)?;
            install_slipstream_batch_proxy(&mut ctx, slipstream_enabled, sequencer_client)?;

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

fn validate_slipstream_config(args: &RollupArgs, slipstream_enabled: bool) -> eyre::Result<()> {
    if !slipstream_enabled {
        return Ok(());
    }

    eyre::ensure!(args.sequencer.is_some(), "--conduit.slipstream requires --rollup.sequencer");
    Ok(())
}

/// Installs the flashblocks pending-state RPC overrides (`eth_call`, `eth_estimateGas`,
/// `eth_simulateV1`) when flashblocks are enabled.
fn install_flashblocks_call_overrides<N, EthApi>(
    ctx: &mut RpcContext<'_, N, EthApi>,
    flashblocks_enabled: bool,
) -> eyre::Result<()>
where
    N: FullNodeComponents,
    EthApi: FullEthApi + PendingFlashblockState + Clone + Send + Sync + 'static,
    ErrorObject<'static>: From<<EthApi as EthApiTypes>::Error>,
{
    if !flashblocks_enabled {
        return Ok(());
    }

    info!(target: "reth::cli", "Installing flashblocks pending-state RPC overrides (eth_call, eth_estimateGas, eth_simulateV1)");
    let ext = FlashblocksCallExt::new(ctx.registry.eth_api().clone());
    ctx.modules.add_or_replace_configured(ext.into_rpc())?;
    info!(target: "reth::cli", "Flashblocks pending-state RPC overrides installed");
    Ok(())
}

/// Proxies the public Slipstream batch API when the replica explicitly opts in.
fn install_slipstream_batch_proxy<N, EthApi>(
    ctx: &mut RpcContext<'_, N, EthApi>,
    slipstream_enabled: bool,
    sequencer_client: Option<SequencerClient>,
) -> eyre::Result<()>
where
    N: FullNodeComponents,
    EthApi: EthApiTypes,
{
    if !slipstream_enabled {
        return Ok(());
    }

    let sequencer_client = sequencer_client.ok_or_else(|| {
        eyre::eyre!("Slipstream enabled but the eth API has no configured sequencer client")
    })?;
    info!(
        target: "reth::cli",
        endpoint = sequencer_client.endpoint(),
        "Installing Slipstream batch proxy"
    );
    let proxy = SlipstreamProxy::new(sequencer_client);
    ctx.modules.add_or_replace_configured(SlipstreamApiServer::into_rpc(proxy))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slipstream_config_is_optional() {
        validate_slipstream_config(&RollupArgs::default(), false).unwrap();
    }

    #[test]
    fn slipstream_requires_sequencer() {
        let error = validate_slipstream_config(&RollupArgs::default(), true).unwrap_err();
        assert!(error.to_string().contains("--rollup.sequencer"));

        let args =
            RollupArgs { sequencer: Some("http://sequencer:80".to_string()), ..Default::default() };
        validate_slipstream_config(&args, true).unwrap();
    }
}
