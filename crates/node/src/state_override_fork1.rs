//! StateOverrideFork1 hardfork state transition.
//!
//! The second round of account state overrides, for networks that need to rewrite state twice.
//! Only the activation guard is fork-specific: the updates themselves are applied by
//! [`apply_state_overrides`], shared with
//! [`state_override_fork0`](crate::state_override_fork0).

use crate::{
    chainspec::StateOverrideFork1Config, hardforks::ConduitOpHardforks,
    state_override_fork0::apply_state_overrides,
};
use alloy_evm::Database;
use revm::DatabaseCommit;
use tracing::info;

/// Applies state updates configured for `StateOverrideFork1` at the transition block.
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
pub fn ensure_state_override_fork1<DB>(
    chain_spec: &impl ConduitOpHardforks,
    timestamp: u64,
    config: &StateOverrideFork1Config,
    db: &mut DB,
) -> Result<(), DB::Error>
where
    DB: Database + DatabaseCommit,
{
    // If the fork is active at the current timestamp but was not active at the previous block
    // timestamp (heuristically, OP Stack block time is 2s), then we are at the transition block.
    // TODO(rezmah): review whether 2s heuristic is appropriate for all target chains
    if !chain_spec.is_state_override_fork1_active_at_timestamp(timestamp) ||
        chain_spec.is_state_override_fork1_active_at_timestamp(timestamp.saturating_sub(2))
    {
        return Ok(());
    }

    info!("Executing state override fork1 at {}", timestamp);

    apply_state_overrides(&config.updates, db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chainspec::StateOverrideAccount, hardforks::ConduitOpHardfork};
    use alloy_primitives::{Address, B256, Bytes, U256};
    use reth_chainspec::{EthereumHardfork, EthereumHardforks, ForkCondition};
    use reth_optimism_forks::{OpHardfork, OpHardforks};
    use revm::{database::InMemoryDB, database_interface::DatabaseRef, primitives::HashMap};
    use std::collections::BTreeMap;

    /// Schedules fork0 at 1000 and fork1 at `fork1_time`, so the tests can tell the two rounds
    /// apart. `None` leaves fork1 unconfigured.
    struct MockSpec {
        fork1_time: Option<u64>,
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
                ConduitOpHardfork::StateOverrideFork0 => ForkCondition::Timestamp(1000),
                ConduitOpHardfork::StateOverrideFork1 => match self.fork1_time {
                    Some(t) => ForkCondition::Timestamp(t),
                    None => ForkCondition::Never,
                },
                ConduitOpHardfork::EvmLimitsFork0 => ForkCondition::Never,
            }
        }
    }

    fn fork1_config() -> StateOverrideFork1Config {
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0x11));
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x42),
            StateOverrideAccount {
                code: Some(Bytes::from_static(&[0xfe, 0xfe])),
                storage: Some(storage),
            },
        );
        StateOverrideFork1Config { updates }
    }

    /// Happy path through the shared apply helper: code and storage land at the fork1 transition.
    #[test]
    fn applies_at_transition_block() {
        let spec = MockSpec { fork1_time: Some(2000) };
        let config = fork1_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork1(&spec, 2000, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(info.code.unwrap().original_bytes(), Bytes::from_static(&[0xfe, 0xfe]));
        assert_eq!(db.storage_ref(addr, U256::from(0x01)).unwrap(), U256::from(0x11));
    }

    /// The guard reads fork1's own activation, not fork0's: at fork0's transition block (1000)
    /// fork1 must stay dormant.
    #[test]
    fn no_op_at_fork0_transition() {
        let spec = MockSpec { fork1_time: Some(2000) };
        let config = fork1_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork1(&spec, 1000, &config, &mut db).unwrap();

        assert!(db.basic_ref(Address::with_last_byte(0x42)).unwrap().is_none());
    }

    #[test]
    fn no_op_before_activation() {
        let spec = MockSpec { fork1_time: Some(2000) };
        let config = fork1_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork1(&spec, 1998, &config, &mut db).unwrap();

        assert!(db.basic_ref(Address::with_last_byte(0x42)).unwrap().is_none());
    }

    #[test]
    fn no_op_after_transition() {
        let spec = MockSpec { fork1_time: Some(2000) };
        let config = fork1_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork1(&spec, 2002, &config, &mut db).unwrap();

        assert!(db.basic_ref(Address::with_last_byte(0x42)).unwrap().is_none());
    }

    #[test]
    fn no_op_when_fork_not_configured() {
        let spec = MockSpec { fork1_time: None };
        let config = fork1_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork1(&spec, 2000, &config, &mut db).unwrap();

        assert!(db.basic_ref(Address::with_last_byte(0x42)).unwrap().is_none());
    }
}
