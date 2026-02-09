//! StateOverrideFork0 hardfork state transition.
//!
//! Applies account state overrides (bytecode and/or storage) at the fork activation
//! block, following the same pattern as the Canyon create2 deployer injection in
//! `alloy_op_evm::block::canyon`.

use crate::{chainspec::StateOverrideFork0Config, hardforks::ConduitOpHardforks};
use alloy_evm::Database;
use alloy_primitives::U256;
use revm::{DatabaseCommit, bytecode::Bytecode, primitives::HashMap, state::EvmStorageSlot};

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
pub(crate) fn ensure_state_override_fork0<DB>(
    chain_spec: &impl ConduitOpHardforks,
    timestamp: u64,
    config: &StateOverrideFork0Config,
    db: &mut DB,
) -> Result<(), DB::Error>
where
    DB: Database + DatabaseCommit,
{
    // If the fork is active at the current timestamp but was not active at the previous block
    // timestamp (heuristically, OP Stack block time is 2s), then we are at the transition block.
    // TODO(rezmah): review whether 2s heuristic is appropriate for all target chains
    if !chain_spec.is_state_override_fork0_active_at_timestamp(timestamp) ||
        chain_spec.is_state_override_fork0_active_at_timestamp(timestamp.saturating_sub(2))
    {
        return Ok(());
    }

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
                // TODO(rezmah): review whether original_value=ZERO and transaction_id=0
                // are correct for pre-execution storage overrides
                revm_acc.storage.insert(key, EvmStorageSlot::new_changed(U256::ZERO, value, 0));
            }
        }

        db.commit(HashMap::from_iter([(address, revm_acc)]));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chainspec::StateOverrideAccount, hardforks::ConduitOpHardfork};
    use alloy_primitives::{Address, B256, Bytes};
    use reth_chainspec::{EthereumHardfork, EthereumHardforks, ForkCondition};
    use reth_optimism_forks::{OpHardfork, OpHardforks};
    use revm::{database::InMemoryDB, database_interface::DatabaseRef, state::AccountInfo};
    use std::collections::BTreeMap;

    struct MockSpec {
        fork_time: Option<u64>,
    }

    impl EthereumHardforks for MockSpec {
        fn ethereum_fork_activation(&self, _fork: EthereumHardfork) -> ForkCondition {
            ForkCondition::Never
        }
    }

    impl OpHardforks for MockSpec {
        fn op_fork_activation(&self, _fork: OpHardfork) -> ForkCondition {
            ForkCondition::Never
        }
    }

    impl ConduitOpHardforks for MockSpec {
        fn conduit_op_fork_activation(&self, fork: ConduitOpHardfork) -> ForkCondition {
            match fork {
                ConduitOpHardfork::StateOverrideFork0 => match self.fork_time {
                    Some(t) => ForkCondition::Timestamp(t),
                    None => ForkCondition::Never,
                },
            }
        }
    }

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

    /// Core happy-path: bytecode injected at exact transition timestamp.
    #[test]
    fn injects_bytecode_at_transition_block() {
        let spec = MockSpec { fork_time: Some(1000) };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        let bytecode = config.updates[&addr].code.as_ref().unwrap();
        assert_eq!(info.code_hash, alloy_primitives::keccak256(bytecode));
        assert_eq!(info.code.unwrap().original_bytes(), *bytecode);
    }

    /// Mixed config: both code and storage slots applied in a single override entry.
    #[test]
    fn applies_bytecode_and_storage_together() {
        let spec = MockSpec { fork_time: Some(1000) };
        let config = mixed_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

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
        let spec = MockSpec { fork_time: Some(1000) };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 998, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply before fork activates");
    }

    /// Timestamp past the transition window → complete no-op (no account created).
    /// Differs from `does_not_reapply_after_transition` which verifies existing state
    /// isn't clobbered; this test verifies no state is touched at all.
    #[test]
    fn no_op_after_transition() {
        let spec = MockSpec { fork_time: Some(1000) };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1002, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply after transition block");
    }

    #[test]
    fn preserves_existing_balance_and_nonce() {
        let spec = MockSpec { fork_time: Some(1000) };
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

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        let info =
            db.basic_ref(Address::with_last_byte(0x42)).unwrap().expect("account should exist");
        assert_eq!(info.balance, alloy_primitives::U256::from(100));
        assert_eq!(info.nonce, 5);
    }

    /// Storage overrides on an empty account (no code, balance, or nonce) are silently
    /// discarded by EIP-161 state clear when committed to `State<DB>`. Always pair
    /// storage overrides with code.
    #[test]
    fn storage_only_on_empty_account_is_discarded_by_eip161() {
        use revm::{Database as _, database::State};

        let spec = MockSpec { fork_time: Some(1000) };
        let config = storage_only_config();
        let inner = InMemoryDB::default();
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

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

        let spec = MockSpec { fork_time: Some(1000) };
        let config = storage_only_config();
        let mut inner = InMemoryDB::default();
        inner.insert_account_info(
            Address::with_last_byte(0x99),
            AccountInfo { balance: alloy_primitives::U256::from(1), ..Default::default() },
        );
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

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
    /// must not revert it. Differs from `no_op_after_transition` which verifies the
    /// guard on a clean DB; this verifies post-transition state isn't clobbered.
    #[test]
    fn does_not_reapply_after_transition() {
        let spec = MockSpec { fork_time: Some(1000) };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

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

        ensure_state_override_fork0(&spec, 1002, &config, &mut db).unwrap();

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(
            info.code.unwrap().original_bytes(),
            new_code,
            "override should not be re-applied after transition"
        );
    }

    /// Fork time = None → no-op regardless of timestamp.
    #[test]
    fn no_op_when_fork_not_configured() {
        let spec = MockSpec { fork_time: None };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply when fork is not configured");
    }
}
