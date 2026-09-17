//! State override hardfork state transitions.
//!
//! Applies account state overrides (bytecode and/or storage) at a fork's activation block,
//! following the same pattern as the Canyon create2 deployer injection in
//! `alloy_op_evm::block::canyon`.
//!
//! One implementation serves every round in
//! [`STATE_OVERRIDE_FORKS`](crate::hardforks::STATE_OVERRIDE_FORKS): the rounds differ only in
//! which activation condition they read and which updates they carry, both of which arrive as
//! arguments.

use crate::{
    chainspec::StateOverrideForkConfig,
    hardforks::{ConduitOpHardfork, ConduitOpHardforks},
};
use alloy_evm::Database;
use alloy_primitives::U256;
use revm::{
    DatabaseCommit,
    bytecode::Bytecode,
    primitives::HashMap,
    state::{EvmStorageSlot, TransactionId},
};
use tracing::info;

/// Applies the state updates configured for `fork` at its transition block.
///
/// Each update entry can set `code` (bytecode) and/or `storage` slots on a target address.
/// Existing account balance and nonce are preserved.
///
/// **Important**: Storage overrides on an address that has no code (and no balance/nonce) will
/// be silently discarded by EIP-161 state clear when committed to `State<DB>`. Always pair
/// storage overrides with a `code` field, or target an address that already has a non-empty
/// account (balance, nonce, or code).
///
/// Detects the transition block by looking back one block time, the same trick Canyon's
/// `ensure_create2_deployer` uses to avoid needing the parent block's timestamp. The look-back
/// is `config.block_time_at_fork` rather than a fixed 2s: on a 1s chain a hardcoded 2 would fire
/// again at `ts + 1` and clobber whatever the transition block's transactions wrote.
pub fn ensure_state_override<DB>(
    chain_spec: &impl ConduitOpHardforks,
    fork: ConduitOpHardfork,
    timestamp: u64,
    config: &StateOverrideForkConfig,
    db: &mut DB,
) -> Result<(), DB::Error>
where
    DB: Database + DatabaseCommit,
{
    // If the fork is active at the current timestamp but was not active at the previous block's
    // timestamp, we are at the transition block.
    let previous_block = timestamp.saturating_sub(config.block_time_at_fork);
    if !chain_spec.is_conduit_op_fork_active_at_timestamp(fork, timestamp) ||
        chain_spec.is_conduit_op_fork_active_at_timestamp(fork, previous_block)
    {
        return Ok(());
    }

    info!("Executing {fork} state override at {timestamp}");

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
                // Seed the slot's original value from the database. revm's `is_changed()` is
                // `original_value != present_value`, and it gates both the commit filter
                // (`CacheAccount::change`) and the revert recorded for the block
                // (`TransitionAccount::update` -> `RevertToSlot`). A placeholder here would drop
                // any override that sets a slot to zero, and would make the revert reth writes
                // to `StorageChangeSets` claim the slot was zero before the fork — which is what
                // historical queries and rewinds read back.
                //
                // `transaction_id` only drives journal warm/cold tracking, which this
                // pre-execution commit never reaches, so ZERO is correct.
                let original = db.storage(address, key)?;
                revm_acc
                    .storage
                    .insert(key, EvmStorageSlot::new_changed(original, value, TransactionId::ZERO));
            }
        }

        db.commit(HashMap::from_iter([(address, revm_acc)]));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chainspec::StateOverrideAccount, hardforks::STATE_OVERRIDE_FORKS};
    use alloy_primitives::{Address, B256, Bytes};
    use reth_chainspec::{EthereumHardfork, EthereumHardforks, ForkCondition};
    use reth_optimism_forks::{OpHardfork, OpHardforks};
    use revm::{database::InMemoryDB, database_interface::DatabaseRef, state::AccountInfo};
    use std::collections::BTreeMap;

    const FORK0: ConduitOpHardfork = ConduitOpHardfork::StateOverrideFork0;

    /// Activation time per entry of [`STATE_OVERRIDE_FORKS`]; `None` means unconfigured.
    struct MockSpec {
        fork_times: [Option<u64>; STATE_OVERRIDE_FORKS.len()],
    }

    impl MockSpec {
        /// Only the first round is scheduled, at `time`.
        fn fork0_at(time: u64) -> Self {
            let mut fork_times = [None; STATE_OVERRIDE_FORKS.len()];
            fork_times[0] = Some(time);
            Self { fork_times }
        }

        /// No round is scheduled.
        fn unconfigured() -> Self {
            Self { fork_times: [None; STATE_OVERRIDE_FORKS.len()] }
        }

        /// Schedules the leading rounds at the given times, in order.
        fn rounds_at(times: &[u64]) -> Self {
            let mut fork_times = [None; STATE_OVERRIDE_FORKS.len()];
            for (slot, time) in fork_times.iter_mut().zip(times) {
                *slot = Some(*time);
            }
            Self { fork_times }
        }
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
            match fork.state_override_index().and_then(|idx| self.fork_times[idx]) {
                Some(time) => ForkCondition::Timestamp(time),
                None => ForkCondition::Never,
            }
        }
    }

    /// Default OP Stack block spacing, as a genesis omitting `blockTimeAtFork` would get.
    const BLOCK_TIME: u64 = 2;

    fn config_with(code: Option<&'static [u8]>, slot_value: Option<u8>) -> StateOverrideForkConfig {
        config_with_block_time(code, slot_value, BLOCK_TIME)
    }

    fn config_with_block_time(
        code: Option<&'static [u8]>,
        slot_value: Option<u8>,
        block_time_at_fork: u64,
    ) -> StateOverrideForkConfig {
        let storage = slot_value.map(|value| {
            let mut storage = BTreeMap::new();
            storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(value));
            storage
        });
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x42),
            StateOverrideAccount { code: code.map(Bytes::from_static), storage },
        );
        StateOverrideForkConfig { updates, block_time_at_fork }
    }

    fn bytecode_config() -> StateOverrideForkConfig {
        config_with(Some(&[0x60, 0x80, 0x60, 0x40, 0x52]), None)
    }

    fn mixed_config() -> StateOverrideForkConfig {
        config_with(Some(&[0x60, 0x80]), Some(0xaa))
    }

    fn storage_only_config() -> StateOverrideForkConfig {
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0xff));
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x99),
            StateOverrideAccount { code: None, storage: Some(storage) },
        );
        StateOverrideForkConfig { updates, block_time_at_fork: BLOCK_TIME }
    }

    /// Core happy-path: bytecode injected at exact transition timestamp.
    #[test]
    fn injects_bytecode_at_transition_block() {
        let spec = MockSpec::fork0_at(1000);
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        let bytecode = config.updates[&addr].code.as_ref().unwrap();
        assert_eq!(info.code_hash, alloy_primitives::keccak256(bytecode));
        assert_eq!(info.code.unwrap().original_bytes(), *bytecode);
    }

    /// Mixed config: both code and storage slots applied in a single override entry.
    #[test]
    fn applies_bytecode_and_storage_together() {
        let spec = MockSpec::fork0_at(1000);
        let config = mixed_config();
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

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
        let spec = MockSpec::fork0_at(1000);
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 998, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply before fork activates");
    }

    /// Timestamp past the transition window → complete no-op (no account created).
    /// Differs from `does_not_reapply_after_transition` which verifies existing state
    /// isn't clobbered; this test verifies no state is touched at all.
    #[test]
    fn no_op_after_transition() {
        let spec = MockSpec::fork0_at(1000);
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 1002, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply after transition block");
    }

    #[test]
    fn preserves_existing_balance_and_nonce() {
        let spec = MockSpec::fork0_at(1000);
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

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

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

        let spec = MockSpec::fork0_at(1000);
        let config = storage_only_config();
        let inner = InMemoryDB::default();
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

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

        let spec = MockSpec::fork0_at(1000);
        let config = storage_only_config();
        let mut inner = InMemoryDB::default();
        inner.insert_account_info(
            Address::with_last_byte(0x99),
            AccountInfo { balance: alloy_primitives::U256::from(1), ..Default::default() },
        );
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

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
        let spec = MockSpec::fork0_at(1000);
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

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

        ensure_state_override(&spec, FORK0, 1002, &config, &mut db).unwrap();

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
        let spec = MockSpec::unconfigured();
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply when fork is not configured");
    }

    /// An override that sets a slot to zero must clear it. `is_changed()` is
    /// `original_value != present_value`, so seeding the original from the database is what
    /// keeps a zero-valued override from being filtered out of the commit.
    #[test]
    fn overriding_a_slot_to_zero_clears_it() {
        use revm::{Database as _, database::State};

        let spec = MockSpec::fork0_at(1000);
        let config = config_with(Some(&[0x60, 0x80]), Some(0x00));
        let addr = Address::with_last_byte(0x42);

        let existing_code = Bytes::from_static(&[0xfe, 0xfe]);
        let mut inner = InMemoryDB::default();
        inner.insert_account_info(
            addr,
            AccountInfo {
                balance: alloy_primitives::U256::from(1),
                nonce: 1,
                code_hash: alloy_primitives::keccak256(existing_code.as_ref()),
                code: Some(Bytecode::new_raw(existing_code)),
                ..Default::default()
            },
        );
        inner.insert_account_storage(addr, U256::from(0x01), U256::from(0xaa)).unwrap();
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();
        db.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);

        assert_eq!(
            db.storage(addr, U256::from(0x01)).unwrap(),
            U256::ZERO,
            "override to zero should clear the slot",
        );
    }

    /// Unwinding the transition block must restore the slot's pre-fork value. reth writes this
    /// revert to `StorageChangeSets` and serves it from `HistoricalStateProvider`, so it is also
    /// what archive reads return for pre-fork blocks.
    #[test]
    fn revert_records_the_pre_fork_slot_value() {
        use revm::database::{State, states::reverts::RevertToSlot};

        let spec = MockSpec::fork0_at(1000);
        let config = config_with(Some(&[0x60, 0x80]), Some(0xff));
        let addr = Address::with_last_byte(0x42);

        let mut inner = InMemoryDB::default();
        inner.insert_account_info(
            addr,
            AccountInfo { balance: alloy_primitives::U256::from(1), ..Default::default() },
        );
        inner.insert_account_storage(addr, U256::from(0x01), U256::from(0xaa)).unwrap();
        let mut db = State::builder().with_database(inner).with_bundle_update().build();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();
        db.merge_transitions(revm::database::states::bundle_state::BundleRetention::Reverts);
        let bundle = db.take_bundle();

        let slot_revert = bundle
            .reverts
            .to_plain_state_reverts()
            .storage
            .into_iter()
            .flatten()
            .find(|revert| revert.address == addr)
            .expect("transition block should revert the overridden account")
            .storage_revert
            .into_iter()
            .find(|(key, _)| *key == U256::from(0x01))
            .expect("overridden slot should have a revert")
            .1;

        assert_eq!(
            slot_revert,
            RevertToSlot::Some(U256::from(0xaa)),
            "unwinding must restore the value the slot held before the fork",
        );
    }

    /// On a 1s chain a hardcoded 2s look-back would fire again at `ts + 1`, clobbering whatever
    /// the transition block's transactions wrote. `block_time_at_fork` is what prevents that.
    #[test]
    fn respects_configured_block_time_at_fork() {
        let spec = MockSpec::fork0_at(1000);
        let config = config_with_block_time(Some(&[0x60, 0x80]), None, 1);
        let addr = Address::with_last_byte(0x42);
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, FORK0, 1000, &config, &mut db).unwrap();
        assert!(db.basic_ref(addr).unwrap().is_some(), "should apply at the transition block");

        // Simulate the transition block's transactions replacing the code, then step one second.
        let written = Bytes::from_static(&[0x01, 0x02]);
        db.insert_account_info(
            addr,
            AccountInfo {
                code_hash: alloy_primitives::keccak256(written.as_ref()),
                code: Some(Bytecode::new_raw(written.clone())),
                ..Default::default()
            },
        );
        ensure_state_override(&spec, FORK0, 1001, &config, &mut db).unwrap();

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(
            info.code.unwrap().original_bytes(),
            written,
            "a 1s chain must not re-apply the override at ts + 1",
        );
    }

    /// The default 2s look-back would miss the transition entirely on a chain whose blocks are
    /// further apart, so a longer spacing has to be configurable too.
    #[test]
    fn longer_block_time_still_detects_the_transition() {
        let spec = MockSpec::fork0_at(1000);
        let config = config_with_block_time(Some(&[0x60, 0x80]), None, 12);
        let addr = Address::with_last_byte(0x42);

        // Block lands at 1008: active now, and 12s earlier the fork had not activated.
        let mut db = InMemoryDB::default();
        ensure_state_override(&spec, FORK0, 1008, &config, &mut db).unwrap();
        assert!(db.basic_ref(addr).unwrap().is_some(), "should apply at the transition block");

        // The following block at 1020 looks back to 1008, which is already past activation.
        let mut db = InMemoryDB::default();
        ensure_state_override(&spec, FORK0, 1020, &config, &mut db).unwrap();
        assert!(db.basic_ref(addr).unwrap().is_none(), "should not re-apply on the next block");
    }

    /// Every round reads its own activation: walking all six rounds scheduled 1000s apart, each
    /// one and only one fires at its own transition block, and the last write wins.
    #[test]
    fn each_round_applies_only_at_its_own_transition() {
        let times: Vec<u64> =
            (0..STATE_OVERRIDE_FORKS.len()).map(|i| 1000 + i as u64 * 1000).collect();
        let spec = MockSpec::rounds_at(&times);
        // Each round writes a distinguishable byte into the same slot on the same address.
        let configs: Vec<_> = (0..STATE_OVERRIDE_FORKS.len())
            .map(|i| config_with(Some(&[0xfe]), Some(i as u8)))
            .collect();
        let addr = Address::with_last_byte(0x42);
        let mut db = InMemoryDB::default();

        for (round, expected_time) in times.iter().enumerate() {
            // Replaying every round at this timestamp: only `round` is at its transition.
            for (fork, config) in STATE_OVERRIDE_FORKS.into_iter().zip(&configs) {
                ensure_state_override(&spec, fork, *expected_time, config, &mut db).unwrap();
            }
            assert_eq!(
                db.storage_ref(addr, U256::from(0x01)).unwrap(),
                U256::from(round as u8),
                "round {round} should own the slot at timestamp {expected_time}",
            );
        }
    }

    /// Both activation guards accept the same transition window, and the last call wins.
    /// The e2e overlap test separately checks the actual executor's round ordering.
    #[test]
    fn later_round_wins_when_transition_windows_overlap() {
        let spec = MockSpec::rounds_at(&[1000, 1001]);
        let (first, second) = (config_with(Some(&[0x60]), None), config_with(Some(&[0xfe]), None));
        let addr = Address::with_last_byte(0x42);
        let mut db = InMemoryDB::default();

        ensure_state_override(&spec, STATE_OVERRIDE_FORKS[0], 1001, &first, &mut db).unwrap();
        ensure_state_override(&spec, STATE_OVERRIDE_FORKS[1], 1001, &second, &mut db).unwrap();

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(info.code.unwrap().original_bytes(), Bytes::from_static(&[0xfe]));
    }
}
