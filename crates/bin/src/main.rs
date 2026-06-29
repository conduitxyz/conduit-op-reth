#![allow(missing_docs, rustdoc::missing_crate_level_docs)]

mod commands;
mod version;

use clap::Parser;
use commands::ConduitSubCommand;
use conduit_op_reth_node::{
    chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser},
    evm::ConduitOpEvmConfig,
    launcher,
    node::ConduitOpNode,
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
                launcher::launch_node(builder, rollup_args).await
            },
        )
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type ConduitCli =
        Cli<ConduitOpChainSpecParser, RollupArgs, DefaultRpcModuleValidator, ConduitSubCommand>;

    /// Upgrade tripwire for the CLI surface of the upstream `proofs` commands: operators'
    /// runbooks depend on these subcommands and flag names. If an op-reth version bump
    /// renames or removes any of them, this fails at test time instead of in production.
    #[test]
    fn proofs_subcommand_surface_is_stable() {
        let cases: &[&[&str]] = &[
            &["proofs", "init", "--proofs-history.storage-path", "/tmp/p"],
            &[
                "proofs",
                "init",
                "--proofs-history.storage-path",
                "/tmp/p",
                "--proofs-history.storage-version",
                "v2",
            ],
            &[
                "proofs",
                "backfill",
                "--proofs-history.storage-path",
                "/tmp/p",
                "--proofs-history.target-earliest-block",
                "100",
                "--proofs-history.use-snapshot",
            ],
            &[
                "proofs",
                "prune",
                "--proofs-history.storage-path",
                "/tmp/p",
                "--proofs-history.window",
                "1000",
                "--proofs-history.prune-batch-size",
                "10",
            ],
            &["proofs", "unwind", "--proofs-history.storage-path", "/tmp/p", "--target", "5"],
            &[
                "proofs",
                "snapshot",
                "init",
                "--proofs-history.storage-path",
                "/tmp/p",
                "--proofs-history.snapshot-target-block",
                "7",
            ],
            &["proofs", "snapshot", "drop", "--proofs-history.storage-path", "/tmp/p"],
        ];
        for case in cases {
            let mut args = vec!["conduit-op-reth"];
            args.extend_from_slice(case);
            if let Err(err) = <ConduitCli as clap::Parser>::try_parse_from(&args) {
                panic!("failed to parse {case:?}: {err}");
            }
        }

        // The node command must also still accept the proofs-history runtime flags.
        let node_args = [
            "conduit-op-reth",
            "node",
            "--proofs-history",
            "--proofs-history.storage-path",
            "/tmp/p",
            "--proofs-history.window",
            "100",
            "--proofs-history.verification-interval",
            "1",
            "--proofs-history.storage-version",
            "v1",
        ];
        <ConduitCli as clap::Parser>::try_parse_from(node_args)
            .expect("node proofs-history flags must parse");
    }
}
