#![allow(missing_docs, rustdoc::missing_crate_level_docs)]

use clap::Parser;
use conduit_op_reth_node::chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser};
use conduit_op_reth_node::evm::ConduitOpEvmConfig;
use conduit_op_reth_node::node::ConduitOpNode;
use reth_db::DatabaseEnv;
use reth_ethereum_cli::Cli;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_optimism_consensus::OpBeaconConsensus;
use reth_optimism_node::args::RollupArgs;
use std::sync::Arc;
use tracing::info;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() {
    reth_cli_util::sigsegv_handler::install();

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    if let Err(err) = Cli::<ConduitOpChainSpecParser, RollupArgs>::parse()
        .run_with_components::<ConduitOpNode>(
            |spec: Arc<ConduitOpChainSpec>| {
                (ConduitOpEvmConfig::new(spec.clone()), Arc::new(OpBeaconConsensus::new(spec)))
            },
            |builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, ConduitOpChainSpec>>, rollup_args| async move {
                info!(target: "reth::cli", "Launching conduit-op-reth node");
                let handle = builder
                    .node(ConduitOpNode::new(rollup_args))
                    .launch_with_debug_capabilities()
                    .await?;
                handle.node_exit_future.await
            },
        )
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
