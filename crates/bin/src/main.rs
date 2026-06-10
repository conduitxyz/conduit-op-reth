#![allow(missing_docs, rustdoc::missing_crate_level_docs)]

mod commands;
mod version;

use clap::Parser;
use commands::ConduitSubCommand;
use conduit_op_reth_node::{
    chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser},
    evm::ConduitOpEvmConfig,
    node::ConduitOpNode,
    proof_history,
};
use reth_db::DatabaseEnv;
use reth_ethereum_cli::Cli;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_optimism_consensus::OpBeaconConsensus;
use reth_optimism_node::args::RollupArgs;
use reth_rpc_server_types::DefaultRpcModuleValidator;
use std::sync::Arc;
use tracing::info;
use version::init_conduit_version;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Initialize conduit-op-reth version metadata before CLI parsing
    init_conduit_version().expect("Failed to initialize conduit-op-reth version metadata");

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    if let Err(err) = Cli::<
        ConduitOpChainSpecParser,
        RollupArgs,
        DefaultRpcModuleValidator,
        ConduitSubCommand,
    >::parse()
        .run_with_components::<ConduitOpNode>(
            |spec: Arc<ConduitOpChainSpec>| {
                (ConduitOpEvmConfig::new(spec.clone()), Arc::new(OpBeaconConsensus::new(spec)))
            },
            |builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
             rollup_args| async move {
                info!(target: "reth::cli", "Launching conduit-op-reth node");
                proof_history::launch_node(builder, rollup_args).await
            },
        )
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
