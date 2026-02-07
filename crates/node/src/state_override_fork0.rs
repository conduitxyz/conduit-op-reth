//! StateOverrideFork0 hardfork state transition.
//!
//! Applies account state overrides (bytecode and/or storage) at the fork activation
//! block, following the same pattern as the Canyon create2 deployer injection in
//! [`alloy_op_evm::block::canyon`].

use crate::chainspec::StateOverrideFork0Config;
use crate::hardforks::ConduitOpHardforks;
use alloy_evm::Database;
use alloy_primitives::U256;
use revm::DatabaseCommit;
use revm::bytecode::Bytecode;
use revm::primitives::HashMap;
use revm::state::EvmStorageSlot;

/// Applies state updates configured for [`StateOverrideFork0`] at the transition block.
///
/// Each update entry uses [`GenesisAccount`](alloy_genesis::GenesisAccount) from alloy-genesis,
/// and can optionally set `code` (bytecode) and/or `storage` slots on a target address.
/// Existing account balance and nonce are preserved.
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
    if !chain_spec.is_state_override_fork0_active_at_timestamp(timestamp)
        || chain_spec.is_state_override_fork0_active_at_timestamp(timestamp.saturating_sub(2))
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
                revm_acc
                    .storage
                    .insert(key, EvmStorageSlot::new_changed(U256::ZERO, value, 0));
            }
        }

        db.commit(HashMap::from_iter([(address, revm_acc)]));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardforks::ConduitOpHardfork;
    use alloy_genesis::GenesisAccount;
    use alloy_primitives::{Address, B256, Bytes};
    use reth_chainspec::{EthereumHardfork, EthereumHardforks, ForkCondition};
    use reth_optimism_forks::{OpHardfork, OpHardforks};
    use revm::database::InMemoryDB;
    use revm::database_interface::DatabaseRef;
    use revm::state::AccountInfo;
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
            GenesisAccount {
                code: Some(Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52])),
                ..Default::default()
            },
        );
        StateOverrideFork0Config { updates }
    }

    fn storage_config() -> StateOverrideFork0Config {
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0xff));
        storage.insert(B256::with_last_byte(0x02), B256::with_last_byte(0x42));
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x99),
            GenesisAccount {
                storage: Some(storage),
                ..Default::default()
            },
        );
        StateOverrideFork0Config { updates }
    }

    fn mixed_config() -> StateOverrideFork0Config {
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0xaa));
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x42),
            GenesisAccount {
                code: Some(Bytes::from_static(&[0x60, 0x80])),
                storage: Some(storage),
                ..Default::default()
            },
        );
        StateOverrideFork0Config { updates }
    }

    fn multi_config() -> StateOverrideFork0Config {
        let mut updates = HashMap::default();
        updates.insert(
            Address::with_last_byte(0x42),
            GenesisAccount {
                code: Some(Bytes::from_static(&[0x60, 0x80])),
                ..Default::default()
            },
        );
        let mut storage = BTreeMap::new();
        storage.insert(B256::with_last_byte(0x01), B256::with_last_byte(0xff));
        updates.insert(
            Address::with_last_byte(0x99),
            GenesisAccount {
                storage: Some(storage),
                ..Default::default()
            },
        );
        StateOverrideFork0Config { updates }
    }

    #[test]
    fn injects_bytecode_at_transition_block() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x42);
        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        let bytecode = config.updates[&addr].code.as_ref().unwrap();
        assert_eq!(info.code_hash, alloy_primitives::keccak256(bytecode));
        assert_eq!(info.code.unwrap().original_bytes(), *bytecode);
    }

    #[test]
    fn sets_storage_at_transition_block() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
        let config = storage_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        let addr = Address::with_last_byte(0x99);
        let slot1 = db.storage_ref(addr, U256::from(0x01)).unwrap();
        assert_eq!(slot1, U256::from(0xff));
        let slot2 = db.storage_ref(addr, U256::from(0x02)).unwrap();
        assert_eq!(slot2, U256::from(0x42));
    }

    #[test]
    fn applies_bytecode_and_storage_together() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
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

    #[test]
    fn applies_multiple_updates() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
        let config = multi_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        // Bytecode on 0x42.
        let info = db
            .basic_ref(Address::with_last_byte(0x42))
            .unwrap()
            .expect("account should exist");
        assert!(info.code.is_some());

        // Storage on 0x99.
        let slot = db
            .storage_ref(Address::with_last_byte(0x99), U256::from(0x01))
            .unwrap();
        assert_eq!(slot, U256::from(0xff));
    }

    #[test]
    fn no_op_before_activation() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 998, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply before fork activates");
    }

    #[test]
    fn no_op_after_transition() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1002, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(info.is_none(), "should not apply after transition block");
    }

    #[test]
    fn preserves_existing_balance_and_nonce() {
        let spec = MockSpec {
            fork_time: Some(1000),
        };
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

        let info = db
            .basic_ref(Address::with_last_byte(0x42))
            .unwrap()
            .expect("account should exist");
        assert_eq!(info.balance, alloy_primitives::U256::from(100));
        assert_eq!(info.nonce, 5);
    }

    #[test]
    fn no_op_when_fork_not_configured() {
        let spec = MockSpec { fork_time: None };
        let config = bytecode_config();
        let mut db = InMemoryDB::default();

        ensure_state_override_fork0(&spec, 1000, &config, &mut db).unwrap();

        let info = db.basic_ref(Address::with_last_byte(0x42)).unwrap();
        assert!(
            info.is_none(),
            "should not apply when fork is not configured"
        );
    }
}
