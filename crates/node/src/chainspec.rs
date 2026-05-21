use crate::hardforks::{ConduitOpHardfork, ConduitOpHardforks};
use alloy_consensus::Header;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes};
use reth_chainspec::{
    Chain, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition,
    ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_cli::chainspec::{ChainSpecParser, parse_genesis};
use reth_optimism_chainspec::{
    OpChainSpec, SUPPORTED_CHAINS, generated_chain_value_parser, make_op_genesis_header,
};
use reth_optimism_forks::{OpHardfork, OpHardforks};
use reth_primitives_traits::SealedHeader;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};

/// Account state to apply during a state override hardfork.
///
/// Only `code` and `storage` are supported — these are the fields relevant for
/// hardfork state transitions. Unlike `alloy_genesis::GenesisAccount`, all fields
/// are optional and there are no strict serde requirements.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateOverrideAccount {
    /// Bytecode to deploy at this address.
    #[serde(default)]
    pub code: Option<Bytes>,
    /// Storage slots to set at this address.
    #[serde(default)]
    pub storage: Option<std::collections::BTreeMap<B256, B256>>,
}

/// Configuration for the StateOverrideFork0 hardfork.
#[derive(Debug, Clone)]
pub struct StateOverrideFork0Config {
    /// Account state updates to apply at activation, keyed by address.
    pub updates: HashMap<Address, StateOverrideAccount>,
}

/// Custom chain spec wrapping [`OpChainSpec`] with ConduitOp-specific fork configuration.
///
/// Custom hardforks are registered in the inner [`OpChainSpec`] hardfork list by default so they
/// participate in fork IDs, fork filters, and `forks_iter()`. The `state_override_fork0` field
/// carries the associated state update data consumed by the block executor. The activation
/// condition is tracked separately because some legacy networks are excluded from registering the
/// custom fork for fork ID compatibility.
#[derive(Debug, Clone)]
pub struct ConduitOpChainSpec {
    /// Inner OP chain spec (handles all standard OP + Ethereum hardforks).
    pub inner: OpChainSpec,
    /// Configuration for StateOverrideFork0 (None if not configured).
    pub state_override_fork0: Option<StateOverrideFork0Config>,
    /// Activation condition for StateOverrideFork0, tracked independently from fork IDs.
    state_override_fork0_activation: ForkCondition,
}

impl EthChainSpec for ConduitOpChainSpec {
    type Header = Header;

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> alloy_eips::eip1559::BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<alloy_eips::eip7840::BlobParams> {
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
        self.inner.display_hardforks()
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
        match fork {
            ConduitOpHardfork::StateOverrideFork0 => self.state_override_fork0_activation,
        }
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
    updates: HashMap<Address, StateOverrideAccount>,
}

const LEGACY_CANYON_GENESIS_CHAIN_IDS: &[u64] = &[1740, 53302, 888888888, 31929];

// These legacy networks have existing peers that do not include StateOverrideFork0 in their
// EIP-2124 fork ID.
const STATE_OVERRIDE_FORK_ID_EXCLUDED_CHAIN_IDS: &[u64] = &[901, 957];

fn exclude_state_override_from_fork_id(op_chain_spec: &OpChainSpec) -> bool {
    STATE_OVERRIDE_FORK_ID_EXCLUDED_CHAIN_IDS.contains(&op_chain_spec.inner.genesis.config.chain_id)
}

fn use_legacy_genesis_header_for_known_chains(op_chain_spec: &mut OpChainSpec) -> bool {
    if !LEGACY_CANYON_GENESIS_CHAIN_IDS.contains(&op_chain_spec.inner.genesis.config.chain_id) {
        return false;
    }

    // These legacy networks have Canyon active at genesis, but their block 0 was built without
    // Shanghai header fields. Keep the runtime hardfork list unchanged so Canyon still enables
    // post-genesis Shanghai semantics, but reseal their genesis headers without withdrawals root.
    let mut genesis_hardforks = op_chain_spec.inner.hardforks.clone();
    genesis_hardforks.remove(&EthereumHardfork::Shanghai);

    op_chain_spec.inner.genesis_header = SealedHeader::seal_slow(make_op_genesis_header(
        &op_chain_spec.inner.genesis,
        &genesis_hardforks,
    ));

    true
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
                state_override_fork0_activation: ForkCondition::Never,
            }));
        }

        // Parse genesis JSON.
        let genesis: Genesis = parse_genesis(s)?;

        // Extract conduit config from extra_fields before converting to OpChainSpec.
        let extras: GenesisExtraFields = genesis
            .config
            .extra_fields
            .deserialize_as()
            .map_err(|e| eyre::eyre!("failed to deserialize conduit config: {e}"))?;

        let raw_fork0 = extras.conduit.and_then(|c| c.state_override_fork0);

        // Convert genesis to OpChainSpec (handles all OP hardfork parsing).
        let mut op_chain_spec: OpChainSpec = genesis.into();
        if use_legacy_genesis_header_for_known_chains(&mut op_chain_spec) {
            eprintln!(
                "Using legacy Canyon genesis header compatibility mode for chain ID {}",
                op_chain_spec.inner.genesis.config.chain_id
            );
        }

        let state_override_fork0_activation = raw_fork0
            .as_ref()
            .map(|raw| ForkCondition::Timestamp(raw.time))
            .unwrap_or(ForkCondition::Never);

        let state_override_fork0 = raw_fork0.map(|raw| {
            let config = StateOverrideFork0Config { updates: raw.updates };

            if exclude_state_override_from_fork_id(&op_chain_spec) {
                eprintln!(
                    "Excluding StateOverrideFork0 from fork ID calculation for chain ID {}",
                    op_chain_spec.inner.genesis.config.chain_id
                );
            } else {
                op_chain_spec.inner.hardforks.insert(
                    ConduitOpHardfork::StateOverrideFork0,
                    ForkCondition::Timestamp(raw.time),
                );
            }

            config
        });

        Ok(Arc::new(ConduitOpChainSpec {
            inner: op_chain_spec,
            state_override_fork0,
            state_override_fork0_activation,
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
                        "code": "0x00"
                    }
                }
            }
        });
        serde_json::to_string(&genesis).unwrap()
    }

    fn with_conduit_fork_for_chain(chain_id: u64, time: u64) -> String {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_conduit_fork(time)).unwrap();
        genesis["config"]["chainId"] = serde_json::json!(chain_id);
        serde_json::to_string(&genesis).unwrap()
    }

    fn legacy_canyon_genesis(chain_id: u64, include_canyon: bool) -> String {
        let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
        let config = genesis["config"].as_object_mut().unwrap();
        config.insert("chainId".to_string(), serde_json::json!(chain_id));
        config.remove("shanghaiTime");
        config.remove("cancunTime");
        config.remove("ecotoneTime");
        config.remove("fjordTime");
        config.remove("graniteTime");
        config.remove("holocene_time");
        if !include_canyon {
            config.remove("canyonTime");
        }
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
                        "code": "0x6080604052"
                    },
                    "0x4200000000000000000000000000000000000099": {
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
            "0x0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        let slot_val: alloy_primitives::B256 =
            "0x00000000000000000000000000000000000000000000000000000000000000ff".parse().unwrap();
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
    fn legacy_chain_ids_use_pre_shanghai_genesis_header() {
        for &chain_id in LEGACY_CANYON_GENESIS_CHAIN_IDS {
            let canyon_spec = parse_spec(&legacy_canyon_genesis(chain_id, true));
            let pre_canyon_spec = parse_spec(&legacy_canyon_genesis(chain_id, false));

            assert!(canyon_spec.op_fork_activation(OpHardfork::Canyon).active_at_timestamp(0));
            assert_eq!(
                canyon_spec.ethereum_fork_activation(EthereumHardfork::Shanghai),
                ForkCondition::Timestamp(0),
            );
            assert_eq!(canyon_spec.genesis_header().withdrawals_root, None);
            assert_eq!(canyon_spec.genesis_hash(), pre_canyon_spec.genesis_hash());
        }
    }

    #[test]
    fn unlisted_chain_id_keeps_upstream_canyon_genesis_header() {
        let spec = parse_spec(&legacy_canyon_genesis(99999, true));

        assert_eq!(
            spec.ethereum_fork_activation(EthereumHardfork::Shanghai),
            ForkCondition::Timestamp(0),
        );
        assert!(spec.genesis_header().withdrawals_root.is_some());
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

    #[test]
    fn excluded_chain_ids_keep_custom_fork_out_of_fork_ids() {
        for &chain_id in STATE_OVERRIDE_FORK_ID_EXCLUDED_CHAIN_IDS {
            let json = with_conduit_fork_for_chain(chain_id, 5000);
            let spec = parse_spec(&json);
            let op_spec: OpChainSpec = {
                let mut genesis: serde_json::Value = serde_json::from_str(&json).unwrap();
                genesis["config"].as_object_mut().unwrap().remove("conduit");
                let genesis: Genesis = serde_json::from_value(genesis).unwrap();
                genesis.into()
            };

            assert_eq!(
                spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0),
                ForkCondition::Timestamp(5000),
            );
            assert!(spec.is_state_override_fork0_active_at_timestamp(5000));

            let names: Vec<&str> = spec.forks_iter().map(|(f, _)| f.name()).collect();
            assert!(
                !names.contains(&"StateOverrideFork0"),
                "forks_iter should not include custom fork for chain {chain_id}, got: {names:?}",
            );

            assert_eq!(spec.fork_id(&head_at(0)), op_spec.fork_id(&head_at(0)));
            assert_eq!(spec.fork_id(&head_at(5000)), op_spec.fork_id(&head_at(5000)));
            assert_eq!(spec.latest_fork_id(), op_spec.latest_fork_id());
        }
    }

    /// Regression test: parse the saigon genesis fixture (used by e2e tests)
    /// with a conduit section injected, exactly as `build_genesis_with_override` does.
    #[test]
    fn parse_saigon_genesis_with_conduit_config() {
        const SAIGON_GENESIS: &str = include_str!(concat!(
            env!("CARGO_WORKSPACE_DIR"),
            "/tests/fixtures/saigon-genesis.json"
        ));

        let mut genesis: serde_json::Value = serde_json::from_str(SAIGON_GENESIS).unwrap();
        genesis["config"]["conduit"] = serde_json::json!({
            "stateOverrideFork0": {
                "time": 1710338137,
                "updates": {
                    "0x4200000000000000000000000000000000000099": {
                        "storage": {
                            "0x0000000000000000000000000000000000000000000000000000000000000001":
                                "0x00000000000000000000000000000000000000000000000000000000000000ff"
                        }
                    }
                }
            }
        });
        let json = serde_json::to_string(&genesis).unwrap();
        let spec = parse_spec(&json);

        assert!(
            spec.state_override_fork0.is_some(),
            "state_override_fork0 should be Some when conduit section is present in saigon genesis"
        );
        let config = spec.state_override_fork0.as_ref().unwrap();
        assert_eq!(config.updates.len(), 1);
    }
}
