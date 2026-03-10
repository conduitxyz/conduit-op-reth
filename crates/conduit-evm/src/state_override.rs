//! StateOverrideFork0 hardfork state transition.
//!
//! Applies account state overrides (bytecode and/or storage) at the fork activation
//! block, following the same pattern as the Canyon create2 deployer injection in
//! `alloy_op_evm::block::canyon`.

use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes, U256};
use revm::{DatabaseCommit, bytecode::Bytecode, primitives::HashMap, state::EvmStorageSlot};
use serde::Deserialize;
use std::collections::BTreeMap;
use tracing::info;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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
    pub storage: Option<BTreeMap<B256, B256>>,
}

/// Configuration for the StateOverrideFork0 hardfork.
///
/// Contains only the state updates to apply — activation timing is managed by the
/// caller's chainspec, consistent with how other forks are configured.
#[derive(Debug, Clone)]
pub struct StateOverrideFork0Config {
    /// Account state updates to apply at activation, keyed by address.
    pub updates: HashMap<Address, StateOverrideAccount>,
}

// ---------------------------------------------------------------------------
// Genesis parsing
// ---------------------------------------------------------------------------

/// Top-level extra fields in genesis `config` containing the `"conduit"` key.
#[derive(Debug, Deserialize, Default)]
struct GenesisExtraFields {
    conduit: Option<ConduitGenesisConfig>,
}

/// Raw JSON structure for the `"conduit"` section in genesis `config`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConduitGenesisConfig {
    state_override_fork0: Option<StateOverrideFork0Raw>,
}

#[derive(Debug, Deserialize)]
struct StateOverrideFork0Raw {
    time: u64,
    updates: HashMap<Address, StateOverrideAccount>,
}

/// Parsed result from genesis containing both the activation time and the config.
///
/// The activation time should be registered in the caller's chainspec (e.g. as a
/// `ForkCondition::Timestamp`), while the config is passed to
/// [`ensure_state_override_fork0`] at execution time.
#[derive(Debug, Clone)]
pub struct ParsedStateOverrideFork0 {
    /// Timestamp at which the fork activates (for chainspec registration).
    pub activation_time: u64,
    /// State override configuration.
    pub config: StateOverrideFork0Config,
}

/// Parses the `StateOverrideFork0` section from a genesis's extra fields.
///
/// Returns `Ok(None)` if the genesis JSON does not contain a `conduit.stateOverrideFork0`
/// section. Returns `Err` if the section exists but is malformed — callers should treat
/// this as fatal since misconfigured state overrides can cause consensus failures.
pub fn parse_state_override_config(
    genesis: &Genesis,
) -> Result<Option<ParsedStateOverrideFork0>, serde_json::Error> {
    let extras: GenesisExtraFields = genesis.config.extra_fields.deserialize_as()?;

    let Some(raw) = extras.conduit.and_then(|c| c.state_override_fork0) else {
        return Ok(None);
    };

    info!(
        time = raw.time,
        num_updates = raw.updates.len(),
        "Parsed StateOverrideFork0 config from genesis"
    );

    Ok(Some(ParsedStateOverrideFork0 {
        activation_time: raw.time,
        config: StateOverrideFork0Config { updates: raw.updates },
    }))
}

// ---------------------------------------------------------------------------
// State transition
// ---------------------------------------------------------------------------

/// Applies state updates configured for `StateOverrideFork0` at the transition block.
///
/// Each update entry can set `code` (bytecode) and/or `storage` slots on a target address.
/// Existing account balance and nonce are preserved.
///
/// **Important**: Storage overrides on an address that has no code (and no balance/nonce) will
/// be silently discarded by EIP-161 state clear when committed to `State<DB>`. Always pair
/// storage overrides with a `code` field, or target an address that already has a non-empty
/// account (balance, nonce, or code).
///
/// Uses the OP Stack 2-second block time heuristic (matching Canyon's `ensure_create2_deployer`)
/// to detect the transition block without requiring the parent block's timestamp.
pub fn ensure_state_override_fork0<DB>(
    timestamp: u64,
    activation_time: u64,
    config: &StateOverrideFork0Config,
    db: &mut DB,
) -> Result<(), DB::Error>
where
    DB: revm::Database + DatabaseCommit,
{
    // If the fork is active at the current timestamp but was not active at the previous block
    // timestamp (heuristically, OP Stack block time is 2s), then we are at the transition block.
    let end = activation_time.saturating_add(2);
    if timestamp < activation_time || timestamp >= end {
        return Ok(());
    }

    info!("Executing state override fork0 at {}", timestamp);

    let mut changes = HashMap::default();

    for (&address, account) in &config.updates {
        let mut acc_info = db.basic(address)?.unwrap_or_default();

        if let Some(ref code) = account.code {
            acc_info.code_hash = alloy_primitives::keccak256(code);
            acc_info.code = Some(Bytecode::new_raw(code.clone()));
        }

        let mut revm_acc: revm::state::Account = acc_info.into();
        revm_acc.mark_touch();

        if let Some(ref storage) = account.storage {
            for (&key, &value) in storage {
                let key = U256::from_be_bytes(key.0);
                let value = U256::from_be_bytes(value.0);
                let old = db.storage(address, key)?;
                revm_acc.storage.insert(key, EvmStorageSlot::new_changed(old, value, 0));
            }
        }

        changes.insert(address, revm_acc);
    }

    db.commit(changes);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use revm::{database::InMemoryDB, database_interface::DatabaseRef, state::AccountInfo};

    fn bytecode_config() -> StateOverrideFork0Config {
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x42),
            StateOverrideAccount {
                code: Some(Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52])),
                storage: None,
            },
        );
        StateOverrideFork0Config { updates }
    }

    fn storage_only_config() -> StateOverrideFork0Config {
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0xff));
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x99),
            StateOverrideAccount { code: None, storage: Some(storage) },
        );
        StateOverrideFork0Config { updates }
    }

    fn mixed_config() -> StateOverrideFork0Config {
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0xaa));
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x42),
            StateOverrideAccount {
                code: Some(Bytes::from_static(&[0x60, 0x80])),
                storage: Some(storage),
            },
        );
        StateOverrideFork0Config { updates }
    }

    const FORK_TIME: u64 = 1000;

    /// Core happy-path: bytecode injected at exact transition timestamp.
    #[test]
    fn injects_bytecode_at_transition_block() {
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(FORK_TIME, FORK_TIME, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        let bytecode = config.updates[&addr].code.as_ref().unwrap();
        assert_eq!(info.code_hash, alloy_primitives::keccak256(bytecode));
        assert_eq!(info.code.unwrap().original_bytes(), *bytecode);
    }

    /// Mixed config: both code and storage slots applied in a single override entry.
    #[test]
    fn applies_bytecode_and_storage_together() {
        let config = mixed_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(FORK_TIME, FORK_TIME, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        let bytecode = config.updates[&addr].code.as_ref().unwrap();
        assert_eq!(info.code_hash, alloy_primitives::keccak256(bytecode));

        let slot = db.storage_ref(addr, U256::from(0x01)).unwrap();
        assert_eq!(slot, U256::from(0xaa));
    }

    /// Timestamp before fork activation → no state changes.
    #[test]
    fn no_op_before_activation() {
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(998, FORK_TIME, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply before fork activates");
    }

    /// Timestamp past the transition window → complete no-op.
    #[test]
    fn no_op_after_transition() {
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(1002, FORK_TIME, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply after transition block");
    }

    #[test]
    fn preserves_existing_balance_and_nonce() {
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        db.insert_account_info(
            Address::with_last_byte(0x42),
            AccountInfo {
                balance: alloy_primitives::U256::from(100),
                nonce: 5,
                ..Default::default()
            },
        );

        ensure_state_override_fork0(FORK_TIME, FORK_TIME, &config, &mut db).unwrap();

        let info =
            db.basic_ref(Address::with_last_byte(0x42)).unwrap().expect("account should exist");
        assert_eq!(info.balance, alloy_primitives::U256::from(100));
        assert_eq!(info.nonce, 5);
    }

    /// Storage overrides on an empty account (no code, balance, or nonce) are silently
    /// discarded by EIP-161 state clear when committed to `State<DB>`.
    #[test]
    fn storage_only_on_empty_account_is_discarded_by_eip161() {
        use revm::{Database as _, database::State};

        let config = storage_only_config();
        let inner = InMemoryDB::default();
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override_fork0(FORK_TIME, FORK_TIME, &config, &mut db).unwrap();

        db.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);

        let addr = Address::with_last_byte(0x99);
        let slot = db.storage(addr, U256::from(0x01)).unwrap();
        assert_eq!(
            slot,
            U256::ZERO,
            "storage-only override on empty account should be discarded by EIP-161 state clear"
        );
    }

    #[test]
    fn storage_only_on_non_empty_account_persists() {
        use revm::{Database as _, database::State};

        let config = storage_only_config();
        let mut inner = InMemoryDB::default();
        inner.insert_account_info(
            Address::with_last_byte(0x99),
            AccountInfo { balance: alloy_primitives::U256::from(1), ..Default::default() },
        );
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override_fork0(FORK_TIME, FORK_TIME, &config, &mut db).unwrap();

        db.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);

        let addr = Address::with_last_byte(0x99);
        let slot = db.storage(addr, U256::from(0x01)).unwrap();
        assert_eq!(
            slot,
            U256::from(0xff),
            "storage-only override should persist on non-empty account"
        );
    }

    /// Override applied at transition, then code changed externally — a later block
    /// must not revert it.
    #[test]
    fn does_not_reapply_after_transition() {
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(FORK_TIME, FORK_TIME, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let new_code = Bytes::from_static(&[0x01, 0x02]);
        db.insert_account_info(
            addr,
            AccountInfo {
                code_hash: alloy_primitives::keccak256(new_code.as_ref()),
                code: Some(Bytecode::new_raw(new_code.clone())),
                ..Default::default()
            },
        );

        ensure_state_override_fork0(1002, FORK_TIME, &config, &mut db).unwrap();

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(
            info.code.unwrap().original_bytes(),
            new_code,
            "override should not be re-applied after transition"
        );
    }

    /// Fork time far in the future → no-op.
    #[test]
    fn no_op_when_fork_not_active() {
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(1000, u64::MAX, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply when fork is not active");
    }

    /// Genesis parsing: valid conduit config.
    #[test]
    fn parse_genesis_with_conduit_config() {
        let genesis_json = r#"{
            "config": {
                "chainId": 99999,
                "homesteadBlock": 0,
                "conduit": {
                    "stateOverrideFork0": {
                        "time": 1234567890,
                        "updates": {
                            "0x4200000000000000000000000000000000000042": {
                                "code": "0x6080604052"
                            }
                        }
                    }
                }
            },
            "difficulty": "0x0",
            "gasLimit": "0x1c9c380",
            "alloc": {}
        }"#;

        let genesis: Genesis = serde_json::from_str(genesis_json).unwrap();
        let parsed = parse_state_override_config(&genesis)
            .expect("should parse without error")
            .expect("should have conduit config");

        assert_eq!(parsed.activation_time, 1234567890);
        assert_eq!(parsed.config.updates.len(), 1);

        let addr: Address = "0x4200000000000000000000000000000000000042".parse().unwrap();
        assert_eq!(
            parsed.config.updates[&addr].code.as_ref().unwrap(),
            &Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52]),
        );
    }

    /// Genesis parsing: no conduit section → Ok(None).
    #[test]
    fn parse_genesis_without_conduit_config() {
        let genesis_json = r#"{
            "config": { "chainId": 99999 },
            "difficulty": "0x0",
            "gasLimit": "0x1c9c380",
            "alloc": {}
        }"#;

        let genesis: Genesis = serde_json::from_str(genesis_json).unwrap();
        let result = parse_state_override_config(&genesis).unwrap();
        assert!(result.is_none());
    }
}
