//! Conduit extension subcommands plugged into the reth CLI.
//!
//! Reuses the upstream `reth_optimism_cli` command implementations directly. Those commands
//! are bound to `ChainSpec = OpChainSpec`, which is fine for commands that only read the
//! datadir: [`ConduitOpChainSpec`](conduit_op_reth_node::chainspec::ConduitOpChainSpec) wraps
//! an inner [`OpChainSpec`] with an identical genesis, so we parse with Conduit's rules and
//! hand the inner spec to upstream.

use clap::Subcommand;
use conduit_op_reth_node::chainspec::ConduitOpChainSpecParser;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_runner::CliRunner;
use reth_ethereum_cli::ExtendedCommand;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::commands::op_proofs;
use reth_optimism_node::OpNode;
use std::sync::Arc;

/// Chain spec parser yielding the inner [`OpChainSpec`] of a Conduit chain spec.
///
/// The genesis JSON must still be parsed with Conduit's rules (legacy Canyon genesis-header
/// compatibility, tolerance of the `conduit` config section) so that the resulting genesis
/// hash matches the database written by the node. Conduit-specific fork data is dropped,
/// which is irrelevant for read-only datadir access.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct InnerOpChainSpecParser;

impl ChainSpecParser for InnerOpChainSpecParser {
    type ChainSpec = OpChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = ConduitOpChainSpecParser::SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        Ok(Arc::new(ConduitOpChainSpecParser::parse(s)?.inner.clone()))
    }
}

/// Conduit extension subcommands provided on top of the standard reth CLI.
#[derive(Debug, Subcommand)]
pub enum ConduitSubCommand {
    /// Manage storage of historical proofs in expanded trie db in fault proof window.
    #[command(name = "proofs")]
    Proofs(op_proofs::Command<InnerOpChainSpecParser>),
}

impl ExtendedCommand for ConduitSubCommand {
    fn execute(self, runner: CliRunner) -> eyre::Result<()> {
        match self {
            Self::Proofs(command) => {
                let runtime = runner.runtime();
                runner.run_blocking_until_ctrl_c(command.execute::<OpNode>(runtime))
            }
        }
    }
}
