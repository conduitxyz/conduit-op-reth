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

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::EthChainSpec;
    use reth_optimism_cli::chainspec::OpChainSpecParser;

    const SAIGON_GENESIS: &str =
        include_str!(concat!(env!("CARGO_WORKSPACE_DIR"), "/tests/fixtures/saigon-genesis.json"));

    fn write_genesis(name: &str, json: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("conduit-op-reth-cmd-test-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.json");
        std::fs::write(&path, json).unwrap();
        path
    }

    /// The adapter must yield exactly the chain spec the node runs with (its inner
    /// `OpChainSpec`), so upstream `proofs` commands see the same genesis identity —
    /// including when the genesis carries a `conduit` section.
    #[test]
    fn inner_parser_matches_conduit_parser_genesis_identity() {
        let mut genesis: serde_json::Value = serde_json::from_str(SAIGON_GENESIS).unwrap();
        genesis["config"]["conduit"] = serde_json::json!({
            "stateOverrideFork0": { "time": 1234567890, "updates": {} }
        });
        let path = write_genesis("conduit-section", &serde_json::to_string(&genesis).unwrap());

        let conduit_spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        let inner_spec = InnerOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(inner_spec.genesis_hash(), conduit_spec.genesis_hash());
        assert_eq!(inner_spec.chain(), conduit_spec.chain());
        assert_eq!(inner_spec.genesis_header(), conduit_spec.genesis_header());
    }

    /// The adapter must route through Conduit's parser, not upstream's: for legacy Canyon
    /// chains Conduit reseals the genesis header without Shanghai fields, producing a
    /// different genesis hash than a plain upstream parse. If someone "simplifies" the
    /// adapter to upstream's `OpChainSpecParser`, this test fails.
    #[test]
    fn inner_parser_preserves_legacy_canyon_genesis_reseal() {
        // Chain 1740 is in Conduit's LEGACY_CANYON_GENESIS_CHAIN_IDS.
        let mut genesis: serde_json::Value = serde_json::from_str(SAIGON_GENESIS).unwrap();
        let config = genesis["config"].as_object_mut().unwrap();
        config.insert("chainId".to_string(), serde_json::json!(1740));
        for key in [
            "shanghaiTime",
            "cancunTime",
            "pragueTime",
            "ecotoneTime",
            "fjordTime",
            "graniteTime",
            "holoceneTime",
            "isthmusTime",
            "jovianTime",
        ] {
            config.remove(key);
        }
        let path = write_genesis("legacy-canyon", &serde_json::to_string(&genesis).unwrap());

        let conduit_spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        let inner_spec = InnerOpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        let upstream_spec = OpChainSpecParser::parse(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        // The adapter agrees with the node...
        assert_eq!(inner_spec.genesis_hash(), conduit_spec.genesis_hash());
        // ...and the conduit reseal is load-bearing: a plain upstream parse differs.
        assert_ne!(
            inner_spec.genesis_hash(),
            upstream_spec.genesis_hash(),
            "legacy Canyon reseal no longer differs from upstream parse; \
             if upstream adopted it, the adapter may be simplifiable — re-verify",
        );
    }
}
