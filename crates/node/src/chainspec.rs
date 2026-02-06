use crate::hardforks::{ConduitOpHardfork, ConduitOpHardforks};
use alloy_consensus::Header;
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::Address;
use reth_chainspec::{
    Chain, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition,
    ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_cli::chainspec::{ChainSpecParser, parse_genesis};
use reth_optimism_chainspec::{OpChainSpec, generated_chain_value_parser, SUPPORTED_CHAINS};
use reth_optimism_forks::{OpHardfork, OpHardforks};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for the StateOverrideFork0 hardfork.
///
/// State updates use [`GenesisAccount`] from alloy-genesis, matching the standard `alloc`
/// representation. Each entry can set `code` (bytecode) and/or `storage` slots. Fields like
/// `balance` and `nonce` are available but typically unused for hardfork state transitions.
#[derive(Debug, Clone)]
pub struct StateOverrideFork0Config {
    /// Account state updates to apply at activation, keyed by address.
    pub updates: HashMap<Address, GenesisAccount>,
}

/// Custom chain spec wrapping [`OpChainSpec`] with ConduitOp-specific fork configuration.
///
/// Custom hardforks are registered in the inner [`OpChainSpec`] hardfork list so they
/// participate in fork IDs, fork filters, and `forks_iter()`. The `state_override_fork0`
/// field carries the associated state update data consumed by the block executor.
#[derive(Debug, Clone)]
pub struct ConduitOpChainSpec {
    /// Inner OP chain spec (handles all standard OP + Ethereum hardforks).
    pub inner: OpChainSpec,
    /// Configuration for StateOverrideFork0 (None if not configured).
    pub state_override_fork0: Option<StateOverrideFork0Config>,
}

impl EthChainSpec for ConduitOpChainSpec {
    type Header = Header;

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(
        &self,
        timestamp: u64,
    ) -> alloy_eips::eip1559::BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(
        &self,
        timestamp: u64,
    ) -> Option<alloy_eips::eip7840::BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.inner.deposit_contract()
    }

    fn genesis_hash(&self) -> alloy_primitives::B256 {
        self.inner.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn display_hardforks(&self) -> Box<dyn core::fmt::Display> {
        let inner = self.inner.display_hardforks().to_string();
        let conduit = match &self.state_override_fork0 {
            Some(config) => {
                let activation = self.conduit_op_fork_activation(
                    ConduitOpHardfork::StateOverrideFork0,
                );
                format!(
                    "\nConduit StateOverrideFork0: {activation:?}, updates={}",
                    config.updates.len()
                )
            }
            None => String::new(),
        };
        Box::new(format!("{inner}{conduit}"))
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn bootnodes(&self) -> Option<Vec<reth_network_peers::NodeRecord>> {
        self.inner.bootnodes()
    }

    fn is_optimism(&self) -> bool {
        true
    }

    fn final_paris_total_difficulty(&self) -> Option<alloy_primitives::U256> {
        self.inner.final_paris_total_difficulty()
    }

    fn next_block_base_fee(&self, parent: &Self::Header, target_timestamp: u64) -> Option<u64> {
        self.inner.next_block_base_fee(parent, target_timestamp)
    }
}

impl Hardforks for ConduitOpChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        self.inner.fork_id(head)
    }

    fn latest_fork_id(&self) -> ForkId {
        self.inner.latest_fork_id()
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        self.inner.fork_filter(head)
    }
}

impl EthereumHardforks for ConduitOpChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }
}

impl OpHardforks for ConduitOpChainSpec {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        self.inner.op_fork_activation(fork)
    }
}

impl ConduitOpHardforks for ConduitOpChainSpec {
    fn conduit_op_fork_activation(&self, fork: ConduitOpHardfork) -> ForkCondition {
        self.fork(fork)
    }
}

/// Top-level extra fields in genesis `config` containing the `"conduit"` key.
#[derive(Debug, Deserialize, Default)]
struct GenesisExtraFields {
    conduit: Option<ConduitOpGenesisConfig>,
}

/// Raw JSON structure for the `"conduit"` section in genesis `config`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConduitOpGenesisConfig {
    state_override_fork0: Option<StateOverrideFork0Raw>,
}

#[derive(Debug, Deserialize)]
struct StateOverrideFork0Raw {
    time: u64,
    updates: HashMap<Address, GenesisAccount>,
}

/// ConduitOp chain specification parser.
///
/// Parses standard OP chain specs and additionally extracts the `"conduit"` section
/// from genesis JSON (if present) into [`ConduitOpChainSpec`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ConduitOpChainSpecParser;

impl ChainSpecParser for ConduitOpChainSpecParser {
    type ChainSpec = ConduitOpChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        // Try known OP chain names first.
        if let Some(op_chain_spec) = generated_chain_value_parser(s) {
            return Ok(Arc::new(ConduitOpChainSpec {
                inner: (*op_chain_spec).clone(),
                state_override_fork0: None,
            }));
        }

        // Parse genesis JSON.
        let genesis: Genesis = parse_genesis(s)?;

        // Extract conduit config from extra_fields before converting to OpChainSpec.
        let extras: GenesisExtraFields = genesis
            .config
            .extra_fields
            .deserialize_as()
            .unwrap_or_default();

        let raw_fork0 = extras.conduit.and_then(|c| c.state_override_fork0);

        // Convert genesis to OpChainSpec (handles all OP hardfork parsing).
        let mut op_chain_spec: OpChainSpec = genesis.into();

        // Register custom hardfork in the inner hardfork list so it appears in
        // fork IDs, fork filters, and forks_iter().
        let state_override_fork0 = raw_fork0.map(|raw| {
            op_chain_spec.inner.hardforks.insert(
                ConduitOpHardfork::StateOverrideFork0,
                ForkCondition::Timestamp(raw.time),
            );
            StateOverrideFork0Config { updates: raw.updates }
        });

        Ok(Arc::new(ConduitOpChainSpec {
            inner: op_chain_spec,
            state_override_fork0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    const BASE_GENESIS: &str = r#"{
        "config": {
            "chainId": 99999,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "muirGlacierBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "shanghaiTime": 0,
            "cancunTime": 0,
            "bedrockBlock": 0,
            "regolithTime": 0,
            "canyonTime": 0,
            "ecotoneTime": 0,
            "fjordTime": 0,
            "graniteTime": 0,
            "holocene_time": 0
        },
        "difficulty": "0x0",
        "gasLimit": "0x1c9c380",
        "alloc": {}
    }"#;

    fn parse_spec(json: &str) -> Arc<ConduitOpChainSpec> {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("conduit-op-reth-test-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.json");
        std::fs::write(&path, json).unwrap();
        let spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap())
            .expect("failed to parse genesis");
        std::fs::remove_dir_all(&dir).ok();
        spec
    }

    fn with_conduit_fork(time: u64) -> String {
        let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
        genesis["config"]["conduit"] = serde_json::json!({
            "stateOverrideFork0": {
                "time": time,
                "updates": {
                    "0x4200000000000000000000000000000000000042": {
                        "balance": "0x0",
                        "code": "0x00"
                    }
                }
            }
        });
        serde_json::to_string(&genesis).unwrap()
    }

    fn head_at(timestamp: u64) -> Head {
        Head { number: 0, timestamp, ..Default::default() }
    }

    #[test]
    fn parse_known_chain_spec() {
        for &chain in ConduitOpChainSpecParser::SUPPORTED_CHAINS {
            let spec = ConduitOpChainSpecParser::parse(chain)
                .unwrap_or_else(|_| panic!("Failed to parse {chain}"));
            assert!(spec.state_override_fork0.is_none());
        }
    }

    #[test]
    fn parse_genesis_with_conduit_config() {
        let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
        genesis["config"]["conduit"] = serde_json::json!({
            "stateOverrideFork0": {
                "time": 1234567890,
                "updates": {
                    "0x4200000000000000000000000000000000000042": {
                        "balance": "0x0",
                        "code": "0x6080604052"
                    },
                    "0x4200000000000000000000000000000000000099": {
                        "balance": "0x0",
                        "storage": {
                            "0x0000000000000000000000000000000000000000000000000000000000000001":
                                "0x00000000000000000000000000000000000000000000000000000000000000ff"
                        }
                    }
                }
            }
        });
        let spec = parse_spec(&serde_json::to_string(&genesis).unwrap());

        let config = spec.state_override_fork0.as_ref().expect("should have conduit config");
        assert_eq!(config.updates.len(), 2);

        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0),
            ForkCondition::Timestamp(1234567890),
        );
        assert!(spec.op_fork_activation(OpHardfork::Bedrock).active_at_block(0));

        let addr0: Address = "0x4200000000000000000000000000000000000042".parse().unwrap();
        assert_eq!(
            config.updates[&addr0].code.as_ref().unwrap(),
            &alloy_primitives::Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52]),
        );

        let addr1: Address = "0x4200000000000000000000000000000000000099".parse().unwrap();
        let storage = config.updates[&addr1].storage.as_ref().expect("should have storage");
        let slot_key: alloy_primitives::B256 =
            "0x0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();
        let slot_val: alloy_primitives::B256 =
            "0x00000000000000000000000000000000000000000000000000000000000000ff"
                .parse()
                .unwrap();
        assert_eq!(storage[&slot_key], slot_val);
    }

    #[test]
    fn parse_genesis_without_conduit_config() {
        let spec = parse_spec(BASE_GENESIS);
        assert!(spec.state_override_fork0.is_none());
        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0),
            ForkCondition::Never,
        );
    }

    #[test]
    fn forks_iter_includes_custom_fork() {
        let spec = parse_spec(&with_conduit_fork(5000));
        let names: Vec<&str> = spec.forks_iter().map(|(f, _)| f.name()).collect();
        assert!(
            names.contains(&"StateOverrideFork0"),
            "forks_iter should include custom fork, got: {names:?}",
        );
    }

    #[test]
    fn fork_ids_match_plain_op_chain_spec() {
        use alloy_eips::eip2124::ForkHash;

        let conduit_spec = parse_spec(BASE_GENESIS);
        let op_spec: OpChainSpec = {
            let genesis: Genesis = serde_json::from_str(BASE_GENESIS).unwrap();
            genesis.into()
        };

        // Without a conduit fork, ConduitOpChainSpec must produce identical fork IDs
        // to a plain OpChainSpec from the same genesis.
        for ts in [0, 100, 10_000, u64::MAX / 2] {
            let h = head_at(ts);
            assert_eq!(
                conduit_spec.fork_id(&h),
                op_spec.fork_id(&h),
                "fork_id mismatch at timestamp {ts}",
            );
        }

        // All OP forks at genesis → single stable hash, no next fork.
        let base_hash = ForkHash([0x8b, 0x51, 0xa7, 0xf5]);
        assert_eq!(conduit_spec.fork_id(&head_at(0)), ForkId { hash: base_hash, next: 0 });
        assert_eq!(conduit_spec.latest_fork_id(), ForkId { hash: base_hash, next: 0 });
    }

    #[test]
    fn fork_ids_with_custom_fork() {
        use alloy_eips::eip2124::ForkHash;

        let spec = parse_spec(&with_conduit_fork(5000));

        let base_hash = ForkHash([0x8b, 0x51, 0xa7, 0xf5]);
        let post_fork_hash = ForkHash([0xd3, 0xcd, 0x38, 0xf6]);

        // Before activation: same base hash, next points to custom fork.
        assert_eq!(spec.fork_id(&head_at(0)), ForkId { hash: base_hash, next: 5000 });
        assert_eq!(spec.fork_id(&head_at(4999)), ForkId { hash: base_hash, next: 5000 });

        // At activation: hash changes, no further forks.
        assert_eq!(spec.fork_id(&head_at(5000)), ForkId { hash: post_fork_hash, next: 0 });
        assert_eq!(spec.fork_id(&head_at(10000)), ForkId { hash: post_fork_hash, next: 0 });

        assert_eq!(spec.latest_fork_id(), ForkId { hash: post_fork_hash, next: 0 });

        // fork_filter.current() must agree with fork_id() at each stage.
        assert_eq!(spec.fork_filter(head_at(0)).current(), spec.fork_id(&head_at(0)));
        assert_eq!(spec.fork_filter(head_at(5000)).current(), spec.fork_id(&head_at(5000)));
    }

}
