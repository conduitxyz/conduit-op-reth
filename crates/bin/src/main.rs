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
use std::sync::Arc;
use tracing::info;
use version::init_conduit_version;

/// Conduit-specific node arguments layered on the upstream OP-Reth rollup arguments.
#[derive(Debug, Clone, clap::Args)]
struct ConduitRollupArgs {
    /// Standard OP-Reth rollup configuration.
    #[command(flatten)]
    rollup: RollupArgs,

    /// Proxy the public Slipstream batch API to the configured sequencer.
    #[arg(long = "conduit.slipstream")]
    slipstream: bool,

    /// Enforce the pool's tracked sender nonce over older validation snapshots.
    ///
    /// Disabled by default. A reorg can lower the canonical nonce, causing valid transactions
    /// to be rejected until tracked sender state is refreshed. OP sequencers can also reorg.
    #[arg(long = "txpool.enforce-tracked-nonce")]
    enforce_tracked_nonce: bool,

    /// Forward historical RPC requests below this block, overriding genesis migrationBlock or
    /// Bedrock. The cutoff block itself is served locally; does not change the chain's
    /// hardforks.
    #[arg(long = "rollup.historicalrpc.block", value_name = "BLOCK", requires = "historical_rpc")]
    historical_rpc_block: Option<u64>,
}

type ConduitCli =
    Cli<ConduitOpChainSpecParser, ConduitRollupArgs, DefaultRpcModuleValidator, ConduitSubCommand>;

/// Present Conduit's terminology while retaining upstream argument IDs for decoding.
fn cli_command() -> clap::Command {
    ConduitCli::command().mut_subcommand("node", |node| {
        node.mut_arg("flashblocks_url", |arg| {
            arg.long("milliblocks-url")
                .alias("flashblocks-url")
                .value_name("URL")
                .help("WebSocket URL providing milliblocks for pending state")
                .long_help("WebSocket URL providing milliblocks. Requests using the pending block tag observe the streamed preconfirmed state.")
        })
        .mut_arg("flashblock_consensus", |arg| {
            arg.long("milliblock-consensus")
                .alias("flashblock-consensus")
                .help("Advance the chain using the milliblock consensus client")
                .long_help("Process milliblock sequences through the Engine API to advance the chain. Requires --milliblocks-url.")
        })
    })
}

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Initialize conduit-op-reth version metadata before CLI parsing
    init_conduit_version().expect("Failed to initialize conduit-op-reth version metadata");

    // Match op-reth: masked state persistence is not supported for OP nodes. The launcher
    // also rejects a nonzero effective window supplied explicitly by an operator.
    reth_node_core::args::DefaultEngineValues::default()
        .with_num_state_masking_blocks(0)
        .try_init()
        .expect("engine defaults must be initialized before CLI parsing");

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    let cli = ConduitCli::from_arg_matches(&cli_command().get_matches())
        .unwrap_or_else(|error| error.exit());
    if let Err(err) = cli.run_with_components::<ConduitOpNode>(
        |spec: Arc<ConduitOpChainSpec>| {
            (ConduitOpEvmConfig::new(spec.clone()), Arc::new(OpBeaconConsensus::new(spec)))
        },
        |builder: WithLaunchContext<NodeBuilder<DatabaseEnv, ConduitOpChainSpec>>,
         args: ConduitRollupArgs| async move {
            info!(target: "reth::cli", "Launching conduit-op-reth node");
            launcher::launch_node(
                builder,
                args.rollup,
                args.slipstream,
                args.historical_rpc_block,
                args.enforce_tracked_nonce,
            )
            .await
        },
    ) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn milliblock_options_preserve_upstream_wiring_and_legacy_aliases() {
        for (url_flag, consensus_flag) in [
            ("--milliblocks-url", "--milliblock-consensus"),
            ("--flashblocks-url", "--flashblock-consensus"),
            ("--subblocks-url", "--subblocks-consensus"),
            ("--websocket-url", "--milliblock-consensus"),
        ] {
            let matches = cli_command()
                .try_get_matches_from([
                    "conduit-op-reth",
                    "node",
                    url_flag,
                    "ws://127.0.0.1:1234",
                    consensus_flag,
                ])
                .unwrap();
            let reth_ethereum_cli::Commands::Node(command) =
                ConduitCli::from_arg_matches(&matches).unwrap().command
            else {
                panic!("expected node command")
            };
            assert_eq!(
                command.ext.rollup.flashblocks_url.unwrap().as_str(),
                "ws://127.0.0.1:1234/"
            );
            assert!(command.ext.rollup.flashblock_consensus);
        }
        let error = cli_command()
            .try_get_matches_from(["conduit-op-reth", "node", "--milliblock-consensus"])
            .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(error.to_string().contains("--milliblocks-url"));
        let mut command = cli_command();
        let node = command.find_subcommand_mut("node").unwrap();
        for help in [node.render_help(), node.render_long_help()] {
            let help = help.to_string();
            assert!(help.contains("--milliblocks-url"));
            assert!(help.contains("--milliblock-consensus"));
            assert!(!help.to_lowercase().contains("flashblock"));
        }
    }

    #[test]
    fn tracked_nonce_enforcement_is_opt_in() {
        for enabled in [false, true] {
            let mut args = vec!["conduit-op-reth", "node"];
            if enabled {
                args.push("--txpool.enforce-tracked-nonce");
            }
            let reth_ethereum_cli::Commands::Node(command) =
                ConduitCli::try_parse_from(args).unwrap().command
            else {
                panic!("expected node command")
            };
            assert_eq!(command.ext.enforce_tracked_nonce, enabled);
        }
    }

    #[test]
    fn historical_rpc_block_flag() {
        let parse = |args: &[&str]| {
            ConduitCli::try_parse_from(
                ["conduit-op-reth", "node"].into_iter().chain(args.iter().copied()),
            )
        };
        let reth_ethereum_cli::Commands::Node(default) = parse(&[]).unwrap().command else {
            panic!("expected node command")
        };
        assert_eq!(default.ext.historical_rpc_block, None);
        for endpoint_flag in ["--rollup.historicalrpc", "--rollup.historical-rpc"] {
            let reth_ethereum_cli::Commands::Node(command) = parse(&[
                endpoint_flag,
                "http://localhost:8545",
                "--rollup.historicalrpc.block",
                "32956469",
            ])
            .unwrap()
            .command
            else {
                panic!("expected node command")
            };
            assert_eq!(command.ext.historical_rpc_block, Some(32956469));
        }
        assert!(parse(&["--rollup.historicalrpc.block", "42"]).is_err());
        for invalid in ["-1", "18446744073709551616", "not-a-block"] {
            assert!(
                parse(&[
                    "--rollup.historicalrpc",
                    "http://localhost:8545",
                    "--rollup.historicalrpc.block",
                    invalid,
                ])
                .is_err()
            );
        }
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
            "v2",
        ];
        <ConduitCli as clap::Parser>::try_parse_from(node_args)
            .expect("node proofs-history flags must parse");

        for command in [vec!["node"], vec!["proofs", "init"]] {
            let error = ConduitCli::try_parse_from(
                ["conduit-op-reth"]
                    .into_iter()
                    .chain(command)
                    .chain(["--proofs-history.storage-version", "v1"]),
            )
            .unwrap_err();
            assert!(error.to_string().contains("only `v2` is supported"));
        }
    }

    #[test]
    fn slipstream_batch_proxy_flag_parses() {
        let cli = <ConduitCli as clap::Parser>::try_parse_from([
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
