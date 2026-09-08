#![allow(missing_docs, rustdoc::missing_crate_level_docs)]

mod commands;
mod version;

use clap::{CommandFactory, FromArgMatches};
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
use std::{ffi::OsString, sync::Arc};
use tracing::info;
use version::init_conduit_version;

type ConduitCli =
    Cli<ConduitOpChainSpecParser, ConduitRollupArgs, DefaultRpcModuleValidator, ConduitSubCommand>;

/// Conduit-specific node arguments layered on the upstream OP-Reth rollup arguments.
#[derive(Debug, Clone, clap::Args)]
struct ConduitRollupArgs {
    /// Standard OP-Reth rollup configuration.
    #[command(flatten)]
    rollup: RollupArgs,

    /// Proxy the public Slipstream batch API to the configured sequencer.
    #[arg(long = "conduit.slipstream")]
    slipstream: bool,
}

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// Mirror op-reth's denied-argument parsing while retaining the generic Reth CLI's custom
/// subcommands and Conduit execution components. Reevaluate alongside upstream `DENIED_ARGS`.
fn try_parse_cli_from<I, T>(args: I) -> Result<ConduitCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut command = ConduitCli::command().mut_subcommands(|subcommand| {
        if subcommand.get_name() == "node" {
            subcommand.mut_args(|arg| if arg.get_id() == "minimal" { arg.hide(true) } else { arg })
        } else {
            subcommand
        }
    });
    let mut matches = command.try_get_matches_from_mut(args)?;
    if let Some(node) = matches.subcommand_matches("node") &&
        node.value_source("minimal") == Some(clap::parser::ValueSource::CommandLine)
    {
        return Err(command.error(
            clap::error::ErrorKind::ValueValidation,
            "--minimal is not supported by conduit-op-reth: pruning block bodies breaks op-node derivation.\n\
             Use --prune.minimum-distance, --prune.receipts.distance, \
             --prune.account-history.distance and --prune.storage-history.distance instead.\n\
             Do NOT prune block bodies. Resync datadirs previously pruned with --minimal.",
        ));
    }
    ConduitCli::from_arg_matches_mut(&mut matches)
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Initialize conduit-op-reth version metadata before CLI parsing
    init_conduit_version().expect("Failed to initialize conduit-op-reth version metadata");

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    if let Err(err) = try_parse_cli_from(std::env::args_os())
        .unwrap_or_else(|err| err.exit())
        .run_with_components::<ConduitOpNode>(
        |spec: Arc<ConduitOpChainSpec>| {
            (ConduitOpEvmConfig::new(spec.clone()), Arc::new(OpBeaconConsensus::new(spec)))
        },
        |builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
         args: ConduitRollupArgs| async move {
            info!(target: "reth::cli", "Launching conduit-op-reth node");
            launcher::launch_node(builder, args.rollup, args.slipstream).await
        },
    ) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_is_rejected_and_hidden_but_full_is_supported() {
        let error = try_parse_cli_from(["conduit-op-reth", "node", "--minimal"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(error.to_string().contains("pruning block bodies breaks op-node derivation"));
        assert!(error.to_string().contains("--prune.receipts.distance"));

        let help = try_parse_cli_from(["conduit-op-reth", "node", "--help"]).unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(!help.to_string().contains("--minimal"));
        assert!(help.to_string().contains("--full"));

        let cli = try_parse_cli_from(["conduit-op-reth", "node", "--full"]).unwrap();
        let reth_ethereum_cli::Commands::Node(command) = cli.command else {
            panic!("expected node command")
        };
        assert!(command.pruning.full);
        assert!(!command.pruning.minimal);
    }

    #[test]
    fn subblocks_aliases_preserve_flashblocks_configuration() {
        for url_flag in ["--flashblocks-url", "--websocket-url", "--subblocks-url"] {
            for consensus_flag in ["--flashblock-consensus", "--subblocks-consensus"] {
                let cli = try_parse_cli_from([
                    "conduit-op-reth",
                    "node",
                    url_flag,
                    "ws://localhost:8546",
                    consensus_flag,
                ])
                .unwrap();
                let reth_ethereum_cli::Commands::Node(command) = cli.command else {
                    panic!("expected node command")
                };
                assert_eq!(
                    command.ext.rollup.flashblocks_url.unwrap().as_str(),
                    "ws://localhost:8546/"
                );
                assert!(command.ext.rollup.flashblock_consensus);
            }
        }
        let error =
            try_parse_cli_from(["conduit-op-reth", "node", "--subblocks-consensus"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

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
                "--proofs-history.window",
                "100",
                "--proofs-history.storage-version",
                "v2",
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
            if let Err(err) = try_parse_cli_from(&args) {
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
        try_parse_cli_from(node_args).expect("node proofs-history flags must parse");
    }

    #[test]
    fn slipstream_batch_proxy_flag_parses() {
        let cli = try_parse_cli_from([
            "conduit-op-reth",
            "node",
            "--conduit.slipstream",
            "--rollup.sequencer",
            "http://sequencer:80",
        ])
        .expect("Slipstream node flags must parse");

        let reth_ethereum_cli::Commands::Node(command) = cli.command else {
            panic!("expected node command")
        };
        assert!(command.ext.slipstream);
    }
}
