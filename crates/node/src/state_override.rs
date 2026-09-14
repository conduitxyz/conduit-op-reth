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
/// Uses the OP Stack 2-second block time heuristic (matching Canyon's `ensure_create2_deployer`)
/// to detect the transition block without requiring the parent block's timestamp.
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
    // If the fork is active at the current timestamp but was not active at the previous block
    // timestamp (heuristically, OP Stack block time is 2s), then we are at the transition block.
    // TODO(rezmah): review whether 2s heuristic is appropriate for all target chains
    if !chain_spec.is_conduit_op_fork_active_at_timestamp(fork, timestamp) ||
        chain_spec.is_conduit_op_fork_active_at_timestamp(fork, timestamp.saturating_sub(2))
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
                // `transaction_id` only drives journal warm/cold tracking, which this
                // pre-execution commit never reaches, so ZERO is correct here.
                //
                // KNOWN ISSUE: `original_value` of ZERO leaves known issues around historical
                // queries and rewinds. Forward execution and the state root are unaffected.
                revm_acc.storage.insert(
                    key,
                    EvmStorageSlot::new_changed(U256::ZERO, value, TransactionId::ZERO),
                );
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

    fn config_with(code: Option<&'static [u8]>, slot_value: Option<u8>) -> StateOverrideForkConfig {
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
        StateOverrideForkConfig { updates }
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
        StateOverrideForkConfig { updates }
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

    /// Rounds landing in the same transition window apply in fork order, so the later round
    /// wins. Guards the ordering of the loop in
    /// [`ConduitOpBlockExecutor`](crate::evm::ConduitOpBlockExecutor).
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
