use crate::hardforks::{ConduitOpHardfork, ConduitOpHardforks, STATE_OVERRIDE_FORKS};
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

/// Configuration for one state override hardfork.
#[derive(Debug, Clone)]
pub struct StateOverrideForkConfig {
    /// Account state updates to apply at activation, keyed by address.
    pub updates: HashMap<Address, StateOverrideAccount>,
    /// Block spacing around this round's activation, used to detect the transition block.
    ///
    /// Only has to match the block time in force when the round activates; a chain that changed
    /// its block time elsewhere in its history is unaffected.
    pub block_time_at_fork: u64,
}

/// EVM limits to apply when EvmLimitsFork0 activates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmLimitsFork0Config {
    /// Optional maximum deployed contract bytecode size.
    pub max_code_size: Option<usize>,
    /// Optional maximum transaction initcode size.
    pub max_initcode_size: Option<usize>,
    /// Optional maximum gas allowed per transaction.
    pub tx_gas_limit_cap: Option<u64>,
}

/// Custom chain spec wrapping [`OpChainSpec`] with ConduitOp-specific fork configuration.
///
/// Custom hardforks are registered in the inner [`OpChainSpec`] hardfork list by default so they
/// participate in fork IDs, fork filters, and `forks_iter()`. Dedicated configuration fields carry
/// the transition data consumed when each custom fork activates. The state override rounds'
/// activation conditions are tracked separately because some legacy networks exclude the earliest
/// of them from their fork IDs for compatibility.
#[derive(Debug, Clone)]
pub struct ConduitOpChainSpec {
    /// Inner OP chain spec (handles all standard OP + Ethereum hardforks).
    pub inner: OpChainSpec,
    /// Exclusive historical RPC cutoff from genesis; not a consensus hardfork.
    pub migration_block: Option<u64>,
    /// Configuration per state override round, indexed as in [`STATE_OVERRIDE_FORKS`]
    /// (`None` where that round is not configured).
    state_override_forks: [Option<StateOverrideForkConfig>; STATE_OVERRIDE_FORKS.len()],
    /// Activation condition per state override round, tracked independently from fork IDs.
    state_override_fork_activations: [ForkCondition; STATE_OVERRIDE_FORKS.len()],
    /// EVM limits applied when EvmLimitsFork0 is active (None if not configured).
    pub evm_limits_fork0: Option<EvmLimitsFork0Config>,
}

impl ConduitOpChainSpec {
    /// Returns the configuration for `fork`, or `None` if it is not a state override fork or is
    /// not configured for this chain.
    pub fn state_override_fork(&self, fork: ConduitOpHardfork) -> Option<&StateOverrideForkConfig> {
        fork.state_override_index().and_then(|idx| self.state_override_forks[idx].as_ref())
    }

    /// Returns every configured state override round with its configuration, in activation order.
    pub fn state_override_forks(
        &self,
    ) -> impl Iterator<Item = (ConduitOpHardfork, &StateOverrideForkConfig)> {
        STATE_OVERRIDE_FORKS
            .into_iter()
            .zip(&self.state_override_forks)
            .filter_map(|(fork, config)| config.as_ref().map(|config| (fork, config)))
    }
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
        match fork.state_override_index() {
            Some(idx) => self.state_override_fork_activations[idx],
            None => self.inner.fork(fork),
        }
    }
}

/// Top-level extra fields in genesis `config` containing the `"conduit"` key.
#[derive(Debug, Deserialize, Default)]
struct GenesisExtraFields {
    conduit: Option<ConduitOpGenesisConfig>,
}

/// Raw JSON structure for the `"conduit"` section in genesis `config`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConduitOpGenesisConfig {
    migration_block: Option<u64>,
    state_override_fork0: Option<StateOverrideForkRaw>,
    state_override_fork1: Option<StateOverrideForkRaw>,
    state_override_fork2: Option<StateOverrideForkRaw>,
    state_override_fork3: Option<StateOverrideForkRaw>,
    state_override_fork4: Option<StateOverrideForkRaw>,
    state_override_fork5: Option<StateOverrideForkRaw>,
    state_override_fork6: Option<StateOverrideForkRaw>,
    state_override_fork7: Option<StateOverrideForkRaw>,
    state_override_fork8: Option<StateOverrideForkRaw>,
    state_override_fork9: Option<StateOverrideForkRaw>,
    evm_limits_fork0: Option<EvmLimitsFork0Raw>,
}

impl ConduitOpGenesisConfig {
    /// The raw state override sections in [`STATE_OVERRIDE_FORKS`] order.
    fn state_override_forks(self) -> [Option<StateOverrideForkRaw>; STATE_OVERRIDE_FORKS.len()] {
        [
            self.state_override_fork0,
            self.state_override_fork1,
            self.state_override_fork2,
            self.state_override_fork3,
            self.state_override_fork4,
            self.state_override_fork5,
            self.state_override_fork6,
            self.state_override_fork7,
            self.state_override_fork8,
            self.state_override_fork9,
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateOverrideForkRaw {
    time: u64,
    /// Defaults to [`DEFAULT_BLOCK_TIME_AT_FORK`] so existing genesis files are unchanged.
    block_time_at_fork: Option<u64>,
    updates: HashMap<Address, StateOverrideAccount>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvmLimitsFork0Raw {
    time: u64,
    max_code_size: Option<usize>,
    max_initcode_size: Option<usize>,
    tx_gas_limit_cap: Option<u64>,
}

// OP Stack block time, and the transition-detection assumption every existing genesis was
// written under. A round on a chain with different spacing sets `blockTimeAtFork` explicitly.
const DEFAULT_BLOCK_TIME_AT_FORK: u64 = 2;

const LEGACY_CANYON_GENESIS_CHAIN_IDS: &[u64] = &[1740, 53302, 888888888, 31929];

// These legacy networks have existing peers that do not carry the earliest state override rounds
// in their EIP-2124 fork ID, so introducing one there would split peering rather than protect it.
const STATE_OVERRIDE_FORK_ID_EXCLUDED_CHAIN_IDS: &[u64] = &[901, 957];

// How many leading rounds the above networks omit. The exclusion covers only the rounds their
// peers predate; by the time a later round is scheduled the peer set has upgraded, so those get
// the usual fork ID protection on every chain.
const STATE_OVERRIDE_FORK_ID_EXCLUDED_ROUNDS: usize = 2;

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

impl From<OpChainSpec> for ConduitOpChainSpec {
    /// Wraps a plain [`OpChainSpec`] without any Conduit custom-fork configuration.
    fn from(inner: OpChainSpec) -> Self {
        Self {
            inner,
            migration_block: None,
            state_override_forks: [const { None }; STATE_OVERRIDE_FORKS.len()],
            state_override_fork_activations: [ForkCondition::Never; STATE_OVERRIDE_FORKS.len()],
            evm_limits_fork0: None,
        }
    }
}

impl ChainSpecParser for ConduitOpChainSpecParser {
    type ChainSpec = ConduitOpChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        // Try known OP chain names first.
        if let Some(op_chain_spec) = generated_chain_value_parser(s) {
            return Ok(Arc::new(ConduitOpChainSpec::from((*op_chain_spec).clone())));
        }

        // Parse genesis JSON.
        let genesis: Genesis = parse_genesis(s)?;

        // Extract conduit config from extra_fields before converting to OpChainSpec.
        let extras: GenesisExtraFields = genesis
            .config
            .extra_fields
            .deserialize_as()
            .map_err(|e| eyre::eyre!("failed to deserialize conduit config: {e}"))?;

        let mut conduit_config = extras.conduit.unwrap_or_default();
        let migration_block = conduit_config.migration_block;
        let raw_evm_limits_fork0 = conduit_config.evm_limits_fork0.take();
        let raw_state_override_forks = conduit_config.state_override_forks();

        // Convert genesis to OpChainSpec (handles all OP hardfork parsing).
        let mut op_chain_spec: OpChainSpec = genesis.into();
        if use_legacy_genesis_header_for_known_chains(&mut op_chain_spec) {
            eprintln!(
                "Using legacy Canyon genesis header compatibility mode for chain ID {}",
                op_chain_spec.inner.genesis.config.chain_id
            );
        }

        let chain_id = op_chain_spec.inner.genesis.config.chain_id;
        let excludes_early_rounds = exclude_state_override_from_fork_id(&op_chain_spec);
        let mut state_override_forks = [const { None }; STATE_OVERRIDE_FORKS.len()];
        let mut state_override_fork_activations =
            [ForkCondition::Never; STATE_OVERRIDE_FORKS.len()];
        let mut previous_round: Option<(usize, ConduitOpHardfork, u64)> = None;

        for (idx, raw) in raw_state_override_forks.into_iter().enumerate() {
            let fork = STATE_OVERRIDE_FORKS[idx];
            let Some(raw) = raw else { continue };

            // Each round rewrites state left by the previous one, so the rounds must be
            // configured contiguously from 0 and activate strictly in sequence. Checking against
            // the immediately preceding index rather than "any earlier round" also rejects an
            // interior gap, which would otherwise silently drop an intended prerequisite.
            if idx != previous_round.map_or(0, |(previous_idx, _, _)| previous_idx + 1) {
                // Unreachable for idx 0: with no previous round the expected index is 0.
                return Err(eyre::eyre!(
                    "{fork} requires {} to be configured",
                    STATE_OVERRIDE_FORKS[idx - 1]
                ));
            }
            if let Some((_, previous_fork, previous_time)) = previous_round &&
                raw.time <= previous_time
            {
                return Err(eyre::eyre!(
                    "{fork} timestamp {} must be after {previous_fork} timestamp {previous_time}",
                    raw.time
                ));
            }
            previous_round = Some((idx, fork, raw.time));

            // A zero block time would make the transition check compare the timestamp against
            // itself, so the round could never fire.
            let block_time_at_fork = raw.block_time_at_fork.unwrap_or(DEFAULT_BLOCK_TIME_AT_FORK);
            if block_time_at_fork == 0 {
                return Err(eyre::eyre!("{fork} blockTimeAtFork must be greater than zero"));
            }

            state_override_fork_activations[idx] = ForkCondition::Timestamp(raw.time);
            state_override_forks[idx] =
                Some(StateOverrideForkConfig { updates: raw.updates, block_time_at_fork });

            let excluded = excludes_early_rounds && idx < STATE_OVERRIDE_FORK_ID_EXCLUDED_ROUNDS;
            if !excluded {
                op_chain_spec.inner.hardforks.insert(fork, ForkCondition::Timestamp(raw.time));
            }

            // Log every scheduled round: an excluded one is absent from the hardfork table reth
            // prints at startup, so this is the only confirmation the operator gets.
            eprintln!(
                "{fork} scheduled at timestamp {} for chain ID {chain_id}{}",
                raw.time,
                if excluded { " (excluded from fork ID calculation)" } else { "" }
            );
        }

        let evm_limits_fork0 = if let Some(raw) = raw_evm_limits_fork0 {
            match op_chain_spec.op_fork_activation(OpHardfork::Karst) {
                ForkCondition::Timestamp(_) => {}
                condition => {
                    return Err(eyre::eyre!(
                        "EvmLimitsFork0 requires Karst to be timestamp-scheduled, got {condition:?}"
                    ));
                }
            }

            let genesis_timestamp = op_chain_spec.genesis_header().timestamp;
            if raw.time <= genesis_timestamp {
                return Err(eyre::eyre!(
                    "EvmLimitsFork0 timestamp {} must be after genesis timestamp {}",
                    raw.time,
                    genesis_timestamp
                ));
            }

            if raw.max_code_size.is_none() &&
                raw.max_initcode_size.is_none() &&
                raw.tx_gas_limit_cap.is_none()
            {
                return Err(eyre::eyre!("EvmLimitsFork0 must configure at least one EVM limit"));
            }

            // REVM enforces a zero limit literally rather than as "no limit": a zero
            // `txGasLimitCap` rejects every non-deposit transaction, while the txpool treats a
            // zero cap as disabled and keeps admitting them.
            for (name, is_zero) in [
                ("maxCodeSize", raw.max_code_size == Some(0)),
                ("maxInitcodeSize", raw.max_initcode_size == Some(0)),
                ("txGasLimitCap", raw.tx_gas_limit_cap == Some(0)),
            ] {
                if is_zero {
                    return Err(eyre::eyre!("EvmLimitsFork0 {name} must be greater than zero"));
                }
            }

            if let Some(conflicting_fork) =
                op_chain_spec.inner.hardforks.forks_iter().find_map(|(fork, condition)| {
                    (condition == ForkCondition::Timestamp(raw.time)).then(|| fork.name())
                })
            {
                return Err(eyre::eyre!(
                    "EvmLimitsFork0 timestamp {} conflicts with {conflicting_fork}; a distinct timestamp is required for a new fork ID",
                    raw.time
                ));
            }

            op_chain_spec
                .inner
                .hardforks
                .insert(ConduitOpHardfork::EvmLimitsFork0, ForkCondition::Timestamp(raw.time));

            Some(EvmLimitsFork0Config {
                max_code_size: raw.max_code_size,
                max_initcode_size: raw.max_initcode_size,
                tx_gas_limit_cap: raw.tx_gas_limit_cap,
            })
        } else {
            None
        };

        Ok(Arc::new(ConduitOpChainSpec {
            inner: op_chain_spec,
            migration_block,
            state_override_forks,
            state_override_fork_activations,
            evm_limits_fork0,
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

    fn try_parse_spec(json: &str) -> eyre::Result<Arc<ConduitOpChainSpec>> {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("conduit-op-reth-test-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.json");
        std::fs::write(&path, json).unwrap();
        let spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap());
        std::fs::remove_dir_all(&dir).ok();
        spec
    }

    fn parse_spec(json: &str) -> Arc<ConduitOpChainSpec> {
        try_parse_spec(json).expect("failed to parse genesis")
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

    /// Genesis scheduling the leading state override rounds at `times`, each overriding the same
    /// address with a distinguishable byte so the rounds can be told apart.
    fn with_conduit_forks(times: &[u64]) -> String {
        let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
        let mut conduit = serde_json::Map::new();
        for (idx, time) in times.iter().enumerate() {
            conduit.insert(
                format!("stateOverrideFork{idx}"),
                serde_json::json!({
                    "time": time,
                    "updates": {
                        "0x4200000000000000000000000000000000000042": {
                            "code": format!("0x{:02x}", idx)
                        }
                    }
                }),
            );
        }
        genesis["config"]["conduit"] = serde_json::Value::Object(conduit);
        serde_json::to_string(&genesis).unwrap()
    }

    /// As [`with_conduit_forks`], for a specific chain ID.
    fn with_conduit_forks_for_chain(chain_id: u64, times: &[u64]) -> String {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_conduit_forks(times)).unwrap();
        genesis["config"]["chainId"] = serde_json::json!(chain_id);
        serde_json::to_string(&genesis).unwrap()
    }

    fn with_conduit_fork_for_chain(chain_id: u64, time: u64) -> String {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_conduit_fork(time)).unwrap();
        genesis["config"]["chainId"] = serde_json::json!(chain_id);
        serde_json::to_string(&genesis).unwrap()
    }

    fn with_evm_limits_fork(karst_time: Option<u64>, fork_time: u64) -> String {
        let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
        if let Some(karst_time) = karst_time {
            genesis["config"]["karstTime"] = serde_json::json!(karst_time);
        }
        genesis["config"]["conduit"] = serde_json::json!({
            "evmLimitsFork0": {
                "time": fork_time,
                "maxCodeSize": 1_000_000,
                "maxInitcodeSize": 2_000_000,
                "txGasLimitCap": u64::MAX
            }
        });
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
            assert!(spec.state_override_forks().next().is_none());
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

        let config = spec
            .state_override_fork(ConduitOpHardfork::StateOverrideFork0)
            .expect("should have conduit config");
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
    fn parse_genesis_with_both_state_override_forks() {
        let spec = parse_spec(&with_conduit_forks(&[5000, 6000]));

        let addr: Address = "0x4200000000000000000000000000000000000042".parse().unwrap();
        let fork0 = spec
            .state_override_fork(ConduitOpHardfork::StateOverrideFork0)
            .expect("fork0 should be configured");
        let fork1 = spec
            .state_override_fork(ConduitOpHardfork::StateOverrideFork1)
            .expect("fork1 should be configured");
        assert_eq!(fork0.updates[&addr].code.as_ref().unwrap(), &Bytes::from_static(&[0x00]));
        assert_eq!(fork1.updates[&addr].code.as_ref().unwrap(), &Bytes::from_static(&[0x01]));

        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0),
            ForkCondition::Timestamp(5000),
        );
        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork1),
            ForkCondition::Timestamp(6000),
        );
    }

    /// Existing genesis files omit `blockTimeAtFork`, so the default has to stay at the 2s
    /// spacing they were written under — changing it would alter their transition block.
    #[test]
    fn block_time_at_fork_defaults_to_two() {
        let spec = parse_spec(&with_conduit_forks(&[5000]));
        let config = spec.state_override_fork(ConduitOpHardfork::StateOverrideFork0).unwrap();
        assert_eq!(config.block_time_at_fork, DEFAULT_BLOCK_TIME_AT_FORK);
        assert_eq!(config.block_time_at_fork, 2);
    }

    #[test]
    fn block_time_at_fork_is_configurable_per_round() {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_conduit_forks(&[5000, 6000])).unwrap();
        genesis["config"]["conduit"]["stateOverrideFork0"]["blockTimeAtFork"] =
            serde_json::json!(1);
        let spec = parse_spec(&serde_json::to_string(&genesis).unwrap());

        // Set on the first round only; the second keeps the default.
        assert_eq!(
            spec.state_override_fork(ConduitOpHardfork::StateOverrideFork0)
                .unwrap()
                .block_time_at_fork,
            1,
        );
        assert_eq!(
            spec.state_override_fork(ConduitOpHardfork::StateOverrideFork1)
                .unwrap()
                .block_time_at_fork,
            DEFAULT_BLOCK_TIME_AT_FORK,
        );
    }

    /// A misspelled round-level key used to be ignored, which is worst for `blockTimeAtFork`:
    /// the round would silently fall back to the 2s default, and on a 1s chain that re-applies
    /// the override at `ts + 1` over the transition block's own writes.
    #[test]
    fn state_override_round_rejects_unknown_keys() {
        for typo in ["block_time_at_fork", "blocktimeatfork", "blockTime"] {
            let mut genesis: serde_json::Value =
                serde_json::from_str(&with_conduit_forks(&[5000])).unwrap();
            let round = genesis["config"]["conduit"]["stateOverrideFork0"].as_object_mut().unwrap();
            round.remove("blockTimeAtFork");
            round.insert(typo.to_string(), serde_json::json!(1));

            let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap())
                .map(|_| ())
                .expect_err(&format!("{typo} should be rejected"));
            let message = err.to_string();
            assert!(
                message.contains("unknown field") && message.contains(typo),
                "{typo}: unexpected error: {message}",
            );
            // The error names the accepted spelling, so the fix is obvious from the message.
            assert!(message.contains("blockTimeAtFork"), "{typo}: error should name the real key");
        }
    }

    /// Zero would compare the block's timestamp against itself, so the round could never fire.
    #[test]
    fn block_time_at_fork_rejects_zero() {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_conduit_forks(&[5000])).unwrap();
        genesis["config"]["conduit"]["stateOverrideFork0"]["blockTimeAtFork"] =
            serde_json::json!(0);

        let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("StateOverrideFork0 blockTimeAtFork must be greater than zero"),
            "unexpected error: {err}",
        );
    }

    /// Rounds must be contiguous from 0. A gap after the first round is the easy case to miss:
    /// checking only "is any earlier round configured" would accept fork0 + fork2 and silently
    /// drop the prerequisite the genesis meant to schedule.
    #[test]
    fn state_override_rounds_reject_gaps() {
        // Leading gap: fork1 without fork0.
        let mut leading: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
        leading["config"]["conduit"] = serde_json::json!({
            "stateOverrideFork1": { "time": 5000, "updates": {} }
        });

        // Interior gap: fork0 and fork2, no fork1.
        let mut interior: serde_json::Value =
            serde_json::from_str(&with_conduit_forks(&[5000])).unwrap();
        interior["config"]["conduit"]["stateOverrideFork2"] =
            serde_json::json!({ "time": 6000, "updates": {} });

        for (label, genesis, expected) in [
            ("leading", leading, "StateOverrideFork1 requires StateOverrideFork0"),
            ("interior", interior, "StateOverrideFork2 requires StateOverrideFork1"),
        ] {
            let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap())
                .map(|_| ())
                .expect_err(&format!("{label} gap should be rejected"));
            assert!(err.to_string().contains(expected), "{label}: unexpected error: {err}");
        }
    }

    /// The second round rewrites state left by the first, so an earlier or equal activation is a
    /// misconfiguration rather than something to resolve at runtime.
    #[test]
    fn state_override_fork1_must_activate_after_fork0() {
        for fork1_time in [4999, 5000] {
            let err = try_parse_spec(&with_conduit_forks(&[5000, fork1_time])).unwrap_err();
            assert!(
                err.to_string().contains(&format!(
                    "StateOverrideFork1 timestamp {fork1_time} must be after StateOverrideFork0 \
                     timestamp 5000"
                )),
                "unexpected error: {err}",
            );
        }
    }

    /// Two rounds must produce three distinct fork ID stages, each announcing the next.
    #[test]
    fn fork_ids_with_both_custom_forks() {
        let spec = parse_spec(&with_conduit_forks(&[5000, 6000]));

        let base = spec.fork_id(&head_at(4999));
        let after_fork0 = spec.fork_id(&head_at(5000));
        let after_fork1 = spec.fork_id(&head_at(6000));

        assert_eq!(base.next, 5000);
        assert_eq!(after_fork0.next, 6000);
        assert_eq!(after_fork1.next, 0);
        assert_ne!(base.hash, after_fork0.hash);
        assert_ne!(after_fork0.hash, after_fork1.hash);
    }

    /// On the legacy networks the exclusion covers only the rounds their peers predate: the
    /// first `STATE_OVERRIDE_FORK_ID_EXCLUDED_ROUNDS` stay out of the fork ID, and every later
    /// round contributes as it would anywhere else.
    #[test]
    fn excluded_chain_ids_exclude_only_the_earliest_rounds() {
        let times: Vec<u64> =
            (0..STATE_OVERRIDE_FORKS.len()).map(|i| 5000 + i as u64 * 1000).collect();

        for &chain_id in STATE_OVERRIDE_FORK_ID_EXCLUDED_CHAIN_IDS {
            let spec = parse_spec(&with_conduit_forks_for_chain(chain_id, &times));
            let names: Vec<&str> = spec.forks_iter().map(|(f, _)| f.name()).collect();

            for (idx, fork) in STATE_OVERRIDE_FORKS.into_iter().enumerate() {
                let excluded = idx < STATE_OVERRIDE_FORK_ID_EXCLUDED_ROUNDS;
                assert_eq!(
                    !names.contains(&fork.name()),
                    excluded,
                    "{fork} fork ID membership wrong for chain {chain_id}, got: {names:?}",
                );
                // Every round activates either way; only the fork ID contribution is suppressed.
                assert!(spec.is_conduit_op_fork_active_at_timestamp(fork, times[idx]));
            }

            // The excluded rounds leave the fork ID untouched, so it only starts moving at the
            // first round that does participate.
            let excluded_tip = times[STATE_OVERRIDE_FORK_ID_EXCLUDED_ROUNDS - 1];
            let first_included = times[STATE_OVERRIDE_FORK_ID_EXCLUDED_ROUNDS];
            assert_eq!(spec.fork_id(&head_at(0)).hash, spec.fork_id(&head_at(excluded_tip)).hash);
            assert_eq!(spec.fork_id(&head_at(0)).next, first_included);
            assert_ne!(
                spec.fork_id(&head_at(excluded_tip)).hash,
                spec.fork_id(&head_at(first_included)).hash,
            );
        }
    }

    /// A chain that is not on the legacy list carries every round in its fork ID.
    #[test]
    fn unlisted_chain_ids_include_every_round_in_fork_ids() {
        let times: Vec<u64> =
            (0..STATE_OVERRIDE_FORKS.len()).map(|i| 5000 + i as u64 * 1000).collect();
        let spec = parse_spec(&with_conduit_forks(&times));

        let names: Vec<&str> = spec.forks_iter().map(|(f, _)| f.name()).collect();
        for fork in STATE_OVERRIDE_FORKS {
            assert!(names.contains(&fork.name()), "{fork} missing from fork ID, got: {names:?}");
        }

        // Each round is its own fork ID stage, announcing the next.
        for (idx, time) in times.iter().enumerate() {
            let id = spec.fork_id(&head_at(*time));
            let expected_next = times.get(idx + 1).copied().unwrap_or(0);
            assert_eq!(id.next, expected_next, "wrong next at round {idx}");
            if idx > 0 {
                assert_ne!(id.hash, spec.fork_id(&head_at(times[idx - 1])).hash);
            }
        }
    }

    #[test]
    fn parse_genesis_without_conduit_config() {
        let spec = parse_spec(BASE_GENESIS);
        assert_eq!(spec.migration_block, None);
        assert!(spec.state_override_forks().next().is_none());
        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork0),
            ForkCondition::Never,
        );
        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::StateOverrideFork1),
            ForkCondition::Never,
        );
        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::EvmLimitsFork0),
            ForkCondition::Never,
        );
        assert!(spec.evm_limits_fork0.is_none());
    }

    #[test]
    fn migration_block_is_rpc_only() {
        let base_genesis = with_conduit_forks(&[5000, 6000]);
        let baseline = parse_spec(&base_genesis);
        assert_eq!(baseline.migration_block, None);
        for block in [None, Some(0), Some(32956469), Some(u64::MAX)] {
            let mut genesis: serde_json::Value = serde_json::from_str(&base_genesis).unwrap();
            genesis["config"]["conduit"]["migrationBlock"] = serde_json::json!(block);
            let spec = parse_spec(&genesis.to_string());
            assert_eq!(spec.migration_block, block);
            assert_eq!(spec.genesis_hash(), baseline.genesis_hash());
            assert_eq!(spec.genesis_header(), baseline.genesis_header());
            assert_eq!(spec.inner.hardforks, baseline.inner.hardforks);
            assert_eq!(spec.latest_fork_id(), baseline.latest_fork_id());
        }
        for invalid in ["-1", "18446744073709551616", "1.5", "\"42\"", "true", "{}"] {
            let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();
            genesis["config"]["conduit"]["migrationBlock"] = serde_json::from_str(invalid).unwrap();
            assert!(try_parse_spec(&genesis.to_string()).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn parse_evm_limits_fork() {
        let spec = parse_spec(&with_evm_limits_fork(Some(1000), 2000));

        assert_eq!(
            spec.conduit_op_fork_activation(ConduitOpHardfork::EvmLimitsFork0),
            ForkCondition::Timestamp(2000),
        );
        assert!(!spec.is_evm_limits_fork0_active_at_timestamp(1999));
        assert!(spec.is_evm_limits_fork0_active_at_timestamp(2000));
        assert_eq!(
            spec.evm_limits_fork0,
            Some(EvmLimitsFork0Config {
                max_code_size: Some(1_000_000),
                max_initcode_size: Some(2_000_000),
                tx_gas_limit_cap: Some(u64::MAX),
            })
        );

        let names: Vec<&str> = spec.forks_iter().map(|(fork, _)| fork.name()).collect();
        assert!(names.contains(&"EvmLimitsFork0"));

        let before = spec.fork_id(&head_at(1999));
        let active = spec.fork_id(&head_at(2000));
        assert_eq!(before.next, 2000);
        assert_ne!(before.hash, active.hash);
        assert_eq!(active.next, 0);
        assert_eq!(spec.fork_filter(head_at(1999)).current(), before);
        assert_eq!(spec.fork_filter(head_at(2000)).current(), active);
    }

    #[test]
    fn evm_limits_fork_requires_karst() {
        let err = try_parse_spec(&with_evm_limits_fork(None, 2000)).unwrap_err();
        assert!(err.to_string().contains("requires Karst to be timestamp-scheduled"));
    }

    #[test]
    fn evm_limits_fork_can_activate_before_karst() {
        let spec = parse_spec(&with_evm_limits_fork(Some(1000), 500));

        assert!(spec.is_evm_limits_fork0_active_at_timestamp(500));
        assert!(!spec.is_karst_active_at_timestamp(999));
        assert!(spec.is_evm_limits_fork0_active_at_timestamp(1000));
        assert!(spec.is_karst_active_at_timestamp(1000));

        let before = spec.fork_id(&head_at(499));
        let custom_fork = spec.fork_id(&head_at(500));
        let karst = spec.fork_id(&head_at(1000));
        assert_eq!(before.next, 500);
        assert_eq!(custom_fork.next, 1000);
        assert_eq!(karst.next, 0);
        assert_ne!(before.hash, custom_fork.hash);
        assert_ne!(custom_fork.hash, karst.hash);
    }

    #[test]
    fn evm_limits_fork_must_be_after_genesis() {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_evm_limits_fork(Some(1000), 1500)).unwrap();
        genesis["timestamp"] = serde_json::json!("0x5dc");

        let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap()).unwrap_err();
        assert!(err.to_string().contains("must be after genesis timestamp 1500"));
    }

    #[test]
    fn evm_limits_fork_requires_distinct_fork_id_timestamp() {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_evm_limits_fork(Some(1000), 2000)).unwrap();
        genesis["config"]["conduit"]["stateOverrideFork0"] = serde_json::json!({
            "time": 2000,
            "updates": {}
        });

        let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap()).unwrap_err();
        assert!(err.to_string().contains("conflicts with StateOverrideFork0"));
        assert!(err.to_string().contains("distinct timestamp is required for a new fork ID"));
    }

    #[test]
    fn evm_limits_fork_accepts_omitted_and_null_limits() {
        let genesis = with_evm_limits_fork(Some(1000), 2000);

        let mut omitted_tx_cap: serde_json::Value = serde_json::from_str(&genesis).unwrap();
        omitted_tx_cap["config"]["conduit"]["evmLimitsFork0"]
            .as_object_mut()
            .unwrap()
            .remove("txGasLimitCap");
        let spec = parse_spec(&serde_json::to_string(&omitted_tx_cap).unwrap());
        assert_eq!(spec.evm_limits_fork0.unwrap().tx_gas_limit_cap, None);

        for field in ["maxCodeSize", "maxInitcodeSize", "txGasLimitCap"] {
            let mut null: serde_json::Value = serde_json::from_str(&genesis).unwrap();
            null["config"]["conduit"]["evmLimitsFork0"][field] = serde_json::Value::Null;
            assert!(try_parse_spec(&serde_json::to_string(&null).unwrap()).is_ok());
        }
    }

    #[test]
    fn evm_limits_fork_requires_at_least_one_limit() {
        for limits in [
            serde_json::json!({ "time": 2000 }),
            serde_json::json!({
                "time": 2000,
                "maxCodeSize": null,
                "maxInitcodeSize": null,
                "txGasLimitCap": null,
            }),
        ] {
            let mut genesis: serde_json::Value =
                serde_json::from_str(&with_evm_limits_fork(Some(1000), 2000)).unwrap();
            genesis["config"]["conduit"]["evmLimitsFork0"] = limits;

            let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap()).unwrap_err();
            assert!(err.to_string().contains("must configure at least one EVM limit"));
        }
    }

    #[test]
    fn evm_limits_fork_rejects_zero_limits() {
        for field in ["maxCodeSize", "maxInitcodeSize", "txGasLimitCap"] {
            let mut genesis: serde_json::Value =
                serde_json::from_str(&with_evm_limits_fork(Some(1000), 2000)).unwrap();
            genesis["config"]["conduit"]["evmLimitsFork0"][field] = serde_json::json!(0);

            let err = try_parse_spec(&serde_json::to_string(&genesis).unwrap()).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("EvmLimitsFork0 {field} must be greater than zero")),
                "unexpected error: {err}",
            );
        }
    }

    #[test]
    fn evm_limits_fork_accepts_arbitrary_code_size_limits() {
        let mut genesis: serde_json::Value =
            serde_json::from_str(&with_evm_limits_fork(Some(1000), 2000)).unwrap();
        genesis["config"]["conduit"]["evmLimitsFork0"]["maxCodeSize"] =
            serde_json::json!(usize::MAX);
        genesis["config"]["conduit"]["evmLimitsFork0"]["maxInitcodeSize"] =
            serde_json::json!(usize::MAX);

        let spec = parse_spec(&serde_json::to_string(&genesis).unwrap());
        let limits = spec.evm_limits_fork0.unwrap();
        assert_eq!(limits.max_code_size, Some(usize::MAX));
        assert_eq!(limits.max_initcode_size, Some(usize::MAX));
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
            assert!(spec.is_conduit_op_fork_active_at_timestamp(
                ConduitOpHardfork::StateOverrideFork0,
                5000
            ));

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

        let config = spec.state_override_fork(ConduitOpHardfork::StateOverrideFork0).expect(
            "StateOverrideFork0 should be configured from the saigon genesis conduit section",
        );
        assert_eq!(config.updates.len(), 1);
    }
}
