//! Allowlist precompiles: role-based permissions held in precompile storage and changed by
//! ordinary calls, so policy changes need no fork.
//!
//! Each [`AllowList`] lives at its own address in [`CONDUIT_SYSTEM_NAMESPACE`] and keeps its own
//! storage. All implement [`IConduitAllowList`]: Avalanche's `IAllowList` role interface (same
//! role values and storage layout), extended with a [mode](AllowListMode) and a per-account
//! blocked flag for denylist mode. What an allowlist governs is up to its enforcement hook, see
//! [`crate::deployer_allowlist`] and [`crate::tx_allowlist`].

use crate::chainspec::{AllowListConfig, AllowListMode};
use alloy_evm::{
    Database,
    precompiles::{DynPrecompile, PrecompileInput},
};
use alloy_op_evm::OpTx;
use alloy_primitives::{Address, B256, Bytes, Log, U256, address, b256, bytes, keccak256};
use alloy_sol_types::{SolCall, SolError, SolEvent, SolInterface, sol};
use op_revm::transaction::deposit::DEPOSIT_TRANSACTION_TYPE;
use revm::{
    DatabaseCommit,
    bytecode::Bytecode,
    context_interface::Transaction,
    precompile::{
        PrecompileError, PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult,
    },
    primitives::{HashMap, KECCAK_EMPTY},
    state::{EvmStorageSlot, TransactionId},
};
use std::sync::Arc;

sol! {
    /// Avalanche's `IAllowList`, extended with modes and a denylist.
    interface IConduitAllowList {
        event RoleSet(uint256 indexed role, address indexed account, address indexed sender, uint256 oldRole);
        event ModeSet(uint256 oldMode, uint256 newMode, address indexed sender);
        event BlockedSet(address indexed account, bool blocked, address indexed sender);

        error Unauthorized(address sender);
        error InvalidMode(uint256 mode);
        error StaticCallNotAllowed();
        error DelegateCallNotAllowed();
        error ValueNotAllowed();
        error ProtectedAccount(address account);
        error SelfDemotion();
        error PolicyViolation();

        function setAdmin(address addr) external;
        function setManager(address addr) external;
        function setEnabled(address addr) external;
        function setNone(address addr) external;
        function readAllowList(address addr) external view returns (uint256 role);

        function setMode(uint256 mode) external;
        function mode() external view returns (uint256);
        function setBlocked(address addr, bool blocked) external;
        function isBlocked(address addr) external view returns (bool);
        function isAllowed(address addr) external view returns (bool);
    }
}

use IConduitAllowList::IConduitAllowListCalls as Call;

/// Base of the Conduit system contract namespace: system contracts live at this address plus a
/// small index, mirroring OP's `0x4200…` predeploy namespace.
///
/// Chosen to stay clear of every OP Stack range, present and future: the `0x4200…` predeploys,
/// the `0xc0d3c0d3…` predeploy implementations, the `0x4210…` upgrade deployers, the
/// `0xdeaddead…` system senders, and the low precompile range. No key exists for any address in
/// it, and nobody can control the L1 account whose alias it is.
pub const CONDUIT_SYSTEM_NAMESPACE: Address = address!("c0d0000000000000000000000000000000000000");

/// Code stored at every allowlist precompile address. Never executed, since the precompile takes
/// the call; it keeps the account non-empty so EIP-161 never clears the policy storage.
pub const PRECOMPILE_MARKER_CODE: Bytes = bytes!("01");

/// Tracing target for policy rejection events, consumed by the audit indexer.
pub const POLICY_REJECTION_TARGET: &str = "conduit::policy";

/// Initcode a denied operation runs instead: `REVERT` with `PolicyViolation()` (`0xfdff9a96`).
///
/// `PUSH4 0xfdff9a96 PUSH1 0xe0 SHL PUSH1 0 MSTORE PUSH1 4 PUSH1 0 REVERT`.
pub const POLICY_VIOLATION_INITCODE: Bytes = bytes!("63fdff9a9660e01b60005260046000fd");

/// Initcode a denied create runs: [`POLICY_VIOLATION_INITCODE`] followed by `original`.
///
/// The stub reverts before reaching the appended bytes, so the create still fails, but every
/// size limit and gas charge that depends on the initcode applies to the full original input.
pub fn denied_initcode(original: &[u8]) -> Bytes {
    [POLICY_VIOLATION_INITCODE.as_ref(), original].concat().into()
}

/// Revert data of a denied operation.
pub const POLICY_VIOLATION_REVERT_DATA: Bytes = bytes!("fdff9a96");

/// Storage key of the mode: `keccak256("conduit.allowList.mode")`.
pub const MODE_KEY: B256 =
    b256!("a787e85ba13a852c7f3a82799dfb32a479abe4e382b3bc20697f2aeda7c17fc7");

/// Namespace of the blocked flags: `keccak256("conduit.allowList.blocked")`.
pub const BLOCKED_NAMESPACE: B256 =
    b256!("4dd7da0365ecea7845add48115dd336e35bbc383b894af19ab164a509c42412c");

/// Gas charged by each precompile read.
pub const READ_GAS: u64 = 2_600;
/// Gas charged by each precompile write, before its event.
pub const WRITE_GAS: u64 = 20_000;

/// Protocol senders every allowlist exempts: the depositor account, the keyless OP
/// network-upgrade deployers, and address zero, which sends the proxy-admin upgrade deposits.
/// Without this exemption an allowlist would break L1 attributes deposits and OP network
/// upgrades. A user transaction can be sent from none of these: they have no known keys, and
/// nobody can control the L1 accounts whose aliases they are.
///
/// Any future OP fork that sends upgrade deposits from a new sender must add it here in the same
/// release, or that fork's upgrade will fail.
pub const SYSTEM_SENDERS: [Address; 12] = [
    // Depositor account: L1 attributes, Karst and later NUT bundle upgrade transactions.
    address!("deaddeaddeaddeaddeaddeaddeaddeaddead0001"),
    // Proxy-admin upgrade calls in every OP network upgrade.
    Address::ZERO,
    // Ecotone L1Block and GasPriceOracle deployers.
    address!("4210000000000000000000000000000000000000"),
    address!("4210000000000000000000000000000000000001"),
    // Fjord GasPriceOracle deployer.
    address!("4210000000000000000000000000000000000002"),
    // Isthmus L1Block, GasPriceOracle and OperatorFeeVault deployers.
    address!("4210000000000000000000000000000000000003"),
    address!("4210000000000000000000000000000000000004"),
    address!("4210000000000000000000000000000000000005"),
    // Jovian L1Block and GasPriceOracle deployers.
    address!("4210000000000000000000000000000000000006"),
    address!("4210000000000000000000000000000000000007"),
    // Ecotone EIP-4788 beacon roots contract sender.
    address!("0b799c86a49deeb90402691f1041aa3af2d3c875"),
    // Isthmus EIP-2935 history storage contract sender.
    address!("3462413af4609098e1e27a490f554f260213d685"),
];

/// Returns whether `sender` is a protocol system sender, exempt from every allowlist.
pub fn is_system_sender(sender: Address) -> bool {
    SYSTEM_SENDERS.contains(&sender)
}

/// Returns whether `tx` is a deposit.
pub(crate) fn is_deposit(tx: &OpTx) -> bool {
    tx.tx_type() == DEPOSIT_TRANSACTION_TYPE
}

/// Role an account holds in an allowlist. Values match Avalanche's `IAllowList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// No role.
    None = 0,
    /// Allowed in allowlist mode.
    Enabled = 1,
    /// Allowed, and manages every role and the mode.
    Admin = 2,
    /// Allowed, and manages the Enabled role and blocked flags of non-privileged accounts.
    Manager = 3,
}

impl Role {
    fn from_word(value: U256) -> Self {
        match value.saturating_to::<u8>() {
            1 => Self::Enabled,
            2 => Self::Admin,
            3 => Self::Manager,
            // Only the precompile writes roles, and it only writes the values above.
            _ => Self::None,
        }
    }

    /// Whether the role is Admin or Manager.
    const fn is_privileged(self) -> bool {
        matches!(self, Self::Admin | Self::Manager)
    }
}

/// Storage key of `account`'s role: the address left-padded to a word, as in Avalanche.
pub fn role_key(account: Address) -> U256 {
    U256::from_be_bytes(account.into_word().0)
}

/// Storage key of `account`'s blocked flag: `keccak256(abi.encode(account, BLOCKED_NAMESPACE))`.
pub fn blocked_key(account: Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(account.into_word().as_slice());
    preimage[32..].copy_from_slice(BLOCKED_NAMESPACE.as_slice());
    U256::from_be_bytes(keccak256(preimage).0)
}

/// An allowlist precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowList {
    /// Precompile address, in [`CONDUIT_SYSTEM_NAMESPACE`].
    pub address: Address,
    /// Precompile name, used as its precompile ID and in logs.
    pub name: &'static str,
    /// Whether Admins and Managers stay allowed even when blocked, so that a denylist can never
    /// lock out the accounts that manage it.
    pub privileged_always_allowed: bool,
}

impl AllowList {
    /// Returns whether this allowlist allows `account`, reading precompile storage through
    /// `read`.
    ///
    /// This is the one rule both the precompile's `isAllowed` and the enforcement hooks apply.
    pub fn is_allowed<E>(
        &self,
        account: Address,
        mut read: impl FnMut(U256) -> Result<U256, E>,
    ) -> Result<bool, E> {
        if is_system_sender(account) {
            return Ok(true);
        }
        let mode = read(U256::from_be_bytes(MODE_KEY.0))?;
        Ok(match AllowListMode::from_u8(mode.saturating_to()) {
            Some(AllowListMode::Off) => true,
            Some(AllowListMode::Allowlist) => {
                Role::from_word(read(role_key(account))?) != Role::None
            }
            Some(AllowListMode::Denylist) => {
                (self.privileged_always_allowed &&
                    Role::from_word(read(role_key(account))?).is_privileged()) ||
                    read(blocked_key(account))?.is_zero()
            }
            // Unreachable: `setMode` and the genesis config only store known modes. Fail closed.
            None => false,
        })
    }

    /// The precompile, for EVMs whose block has this allowlist's fork active.
    ///
    /// `protected` accounts can never lose their role or be blocked, see
    /// [`AllowListConfig::protected_addresses`].
    pub fn precompile(self, protected: Arc<[Address]>) -> DynPrecompile {
        DynPrecompile::new_stateful(PrecompileId::Custom(self.name.into()), move |input| {
            run_precompile(self, &protected, input)
        })
    }

    /// Seeds the precompile account with its marker code and `config`, unless already seeded.
    ///
    /// Call this at every block where the allowlist's fork is active. Once seeded the account has
    /// code, which nothing can remove (the code never runs, so it can never self-destruct), so
    /// later blocks are a single cached account lookup.
    pub fn ensure_seeded<DB>(&self, config: &AllowListConfig, db: &mut DB) -> Result<(), DB::Error>
    where
        DB: Database + DatabaseCommit,
    {
        let mut info = db.basic(self.address)?.unwrap_or_default();
        if info.code_hash != KECCAK_EMPTY {
            return Ok(());
        }

        tracing::info!(name = self.name, ?config, "Seeding allowlist precompile");

        // Any balance sent to the address before activation is preserved.
        info.nonce = info.nonce.max(1);
        info.code_hash = keccak256(&PRECOMPILE_MARKER_CODE);
        info.code = Some(Bytecode::new_raw(PRECOMPILE_MARKER_CODE));
        let mut account: revm::state::Account = info.into();
        account.mark_touch();

        let roles = [
            (&config.admin_addresses, Role::Admin),
            (&config.manager_addresses, Role::Manager),
            (&config.enabled_addresses, Role::Enabled),
        ];
        let slots = roles
            .into_iter()
            .flat_map(|(accounts, role)| {
                accounts.iter().map(move |account| (role_key(*account), U256::from(role as u8)))
            })
            .chain(
                config
                    .blocked_addresses
                    .iter()
                    .map(|account| (blocked_key(*account), U256::from(1))),
            )
            .chain([(U256::from_be_bytes(MODE_KEY.0), U256::from(config.mode as u8))]);
        for (key, value) in slots {
            // Seed the original value from the database so the change and its revert are
            // recorded correctly, as `ensure_state_override` does.
            let original = db.storage(self.address, key)?;
            account
                .storage
                .insert(key, EvmStorageSlot::new_changed(original, value, TransactionId::ZERO));
        }

        db.commit(HashMap::from_iter([(self.address, account)]));
        Ok(())
    }
}

/// Gas for emitting an event, priced as a `LOG` with its topics and data words.
const fn event_gas(topics: u64, data_words: u64) -> u64 {
    375 + 375 * topics + 8 * 32 * data_words
}

/// Gas charged up front for `call`; reverts keep it.
const fn call_gas(call: &Call) -> u64 {
    match call {
        Call::setAdmin(_) | Call::setManager(_) | Call::setEnabled(_) | Call::setNone(_) => {
            WRITE_GAS + event_gas(4, 1)
        }
        Call::setMode(_) => WRITE_GAS + event_gas(2, 2),
        Call::setBlocked(_) => WRITE_GAS + event_gas(3, 1),
        Call::readAllowList(_) | Call::mode(_) | Call::isBlocked(_) => READ_GAS,
        // Mode, then role and blocked flag at most.
        Call::isAllowed(_) => 3 * READ_GAS,
    }
}

const fn is_write(call: &Call) -> bool {
    matches!(
        call,
        Call::setAdmin(_) |
            Call::setManager(_) |
            Call::setEnabled(_) |
            Call::setNone(_) |
            Call::setMode(_) |
            Call::setBlocked(_)
    )
}

/// Precompile storage accessed through the EVM journal, so writes revert with the call frame.
struct PrecompileStorage<'a, 'b> {
    address: Address,
    input: &'a mut PrecompileInput<'b>,
}

impl PrecompileStorage<'_, '_> {
    fn read(&mut self, key: U256) -> Result<U256, PrecompileError> {
        self.input
            .internals
            .sload(self.address, key)
            .map(|load| load.data)
            .map_err(|err| PrecompileError::Fatal(err.to_string()))
    }

    fn write(&mut self, key: U256, value: U256) -> Result<(), PrecompileError> {
        self.input
            .internals
            .sstore(self.address, key, value)
            .map(|_| ())
            .map_err(|err| PrecompileError::Fatal(err.to_string()))
    }

    fn role(&mut self, account: Address) -> Result<Role, PrecompileError> {
        self.read(role_key(account)).map(Role::from_word)
    }

    fn emit(&mut self, event: impl SolEvent) {
        self.input.internals.log(Log { address: self.address, data: event.encode_log_data() });
    }
}

fn run_precompile(
    list: AllowList,
    protected: &[Address],
    mut input: PrecompileInput<'_>,
) -> PrecompileResult {
    let reservoir = input.reservoir;
    let revert =
        |gas: u64, error: &dyn Fn() -> Bytes| Ok(PrecompileOutput::revert(gas, error(), reservoir));

    // Strict decoding rejects non-canonical input, such as dirty high bits in an address. Failed
    // decoding is charged a read, so malformed calls are not free.
    let Ok(call) = Call::abi_decode_validate(input.data) else {
        if READ_GAS > input.gas {
            return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, reservoir));
        }
        return revert(READ_GAS, &Bytes::new);
    };
    let gas = call_gas(&call);
    if gas > input.gas {
        return Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, reservoir));
    }

    // A DELEGATECALL or CALLCODE would run with another account's context; only direct calls
    // may read or change the policy.
    if input.target_address != list.address {
        return revert(gas, &|| IConduitAllowList::DelegateCallNotAllowed {}.abi_encode().into());
    }
    if !input.value.is_zero() {
        return revert(gas, &|| IConduitAllowList::ValueNotAllowed {}.abi_encode().into());
    }
    if is_write(&call) && input.is_static {
        return revert(gas, &|| IConduitAllowList::StaticCallNotAllowed {}.abi_encode().into());
    }

    let sender = input.caller;
    let mut storage = PrecompileStorage { address: list.address, input: &mut input };
    let unauthorized =
        || -> Bytes { IConduitAllowList::Unauthorized { sender }.abi_encode().into() };

    let output: Bytes = match call {
        Call::readAllowList(call) => IConduitAllowList::readAllowListCall::abi_encode_returns(
            &U256::from(storage.role(call.addr)? as u8),
        )
        .into(),
        Call::mode(_) => IConduitAllowList::modeCall::abi_encode_returns(
            &storage.read(U256::from_be_bytes(MODE_KEY.0))?,
        )
        .into(),
        Call::isBlocked(call) => IConduitAllowList::isBlockedCall::abi_encode_returns(
            &!storage.read(blocked_key(call.addr))?.is_zero(),
        )
        .into(),
        Call::isAllowed(call) => IConduitAllowList::isAllowedCall::abi_encode_returns(
            &list.is_allowed(call.addr, |key| storage.read(key))?,
        )
        .into(),
        Call::setAdmin(IConduitAllowList::setAdminCall { addr }) |
        Call::setManager(IConduitAllowList::setManagerCall { addr }) |
        Call::setEnabled(IConduitAllowList::setEnabledCall { addr }) |
        Call::setNone(IConduitAllowList::setNoneCall { addr }) => {
            let role = match call {
                Call::setAdmin(_) => Role::Admin,
                Call::setManager(_) => Role::Manager,
                Call::setEnabled(_) => Role::Enabled,
                _ => Role::None,
            };
            let sender_role = storage.role(sender)?;
            let old_role = storage.role(addr)?;
            // Admins manage every role. Managers grant or revoke only Enabled, and only on
            // accounts that are not Admins or Managers.
            let authorized = match sender_role {
                Role::Admin => true,
                Role::Manager => !role.is_privileged() && !old_role.is_privileged(),
                Role::Enabled | Role::None => false,
            };
            if !authorized {
                return revert(gas, &unauthorized);
            }
            // Admins can only be removed by another admin, so the last admin always remains.
            if addr == sender && sender_role == Role::Admin && role != Role::Admin {
                return revert(gas, &|| IConduitAllowList::SelfDemotion {}.abi_encode().into());
            }
            if role == Role::None && protected.contains(&addr) {
                return revert(gas, &|| {
                    IConduitAllowList::ProtectedAccount { account: addr }.abi_encode().into()
                });
            }
            storage.write(role_key(addr), U256::from(role as u8))?;
            storage.emit(IConduitAllowList::RoleSet {
                role: U256::from(role as u8),
                account: addr,
                sender,
                oldRole: U256::from(old_role as u8),
            });
            Bytes::new()
        }
        Call::setMode(IConduitAllowList::setModeCall { mode }) => {
            if storage.role(sender)? != Role::Admin {
                return revert(gas, &unauthorized);
            }
            if mode > U256::from(u8::MAX) || AllowListMode::from_u8(mode.to()).is_none() {
                return revert(gas, &|| IConduitAllowList::InvalidMode { mode }.abi_encode().into());
            }
            let key = U256::from_be_bytes(MODE_KEY.0);
            let old_mode = storage.read(key)?;
            storage.write(key, mode)?;
            storage.emit(IConduitAllowList::ModeSet { oldMode: old_mode, newMode: mode, sender });
            Bytes::new()
        }
        Call::setBlocked(IConduitAllowList::setBlockedCall { addr, blocked }) => {
            let authorized = match storage.role(sender)? {
                Role::Admin => true,
                Role::Manager => !storage.role(addr)?.is_privileged(),
                Role::Enabled | Role::None => false,
            };
            if !authorized {
                return revert(gas, &unauthorized);
            }
            if blocked && protected.contains(&addr) {
                return revert(gas, &|| {
                    IConduitAllowList::ProtectedAccount { account: addr }.abi_encode().into()
                });
            }
            storage.write(blocked_key(addr), U256::from(blocked))?;
            storage.emit(IConduitAllowList::BlockedSet { account: addr, blocked, sender });
            Bytes::new()
        }
    };

    Ok(PrecompileOutput::new(gas, output, reservoir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deployer_allowlist::DEPLOYER_ALLOWLIST, tx_allowlist::TX_ALLOWLIST};

    #[test]
    fn constants_match_their_preimages() {
        assert_eq!(MODE_KEY, keccak256("conduit.allowList.mode"));
        assert_eq!(BLOCKED_NAMESPACE, keccak256("conduit.allowList.blocked"));
        assert_eq!(
            POLICY_VIOLATION_REVERT_DATA,
            Bytes::from(IConduitAllowList::PolicyViolation {}.abi_encode())
        );
        assert_eq!(&POLICY_VIOLATION_INITCODE[1..5], POLICY_VIOLATION_REVERT_DATA.as_ref());
    }

    #[test]
    fn allowlists_are_in_the_conduit_namespace() {
        let base = U256::from_be_slice(CONDUIT_SYSTEM_NAMESPACE.as_slice());
        for (list, index) in [(DEPLOYER_ALLOWLIST, 1), (TX_ALLOWLIST, 2)] {
            let address = U256::from_be_slice(list.address.as_slice());
            assert_eq!(address - base, U256::from(index), "{}", list.name);
            // Clear of OP's predeploy, implementation and upgrade-deployer prefixes.
            for op_prefix in [&[0x42, 0x00][..], &[0xc0, 0xd3], &[0x42, 0x10]] {
                assert!(!list.address.starts_with(op_prefix), "{}", list.name);
            }
            assert!(!is_system_sender(list.address), "{}", list.name);
        }
    }

    #[test]
    fn role_key_matches_avalanche_layout() {
        let account = address!("00000000000000000000000000000000000a11ce");
        assert_eq!(role_key(account), U256::from(0x0a11ce));
    }

    #[test]
    fn system_senders_are_exempt() {
        for sender in SYSTEM_SENDERS {
            assert!(is_system_sender(sender));
            // Exempt even when the policy would deny everyone.
            let deny_all = |_| Ok::<_, ()>(U256::from(1));
            assert_eq!(DEPLOYER_ALLOWLIST.is_allowed(sender, deny_all), Ok(true));
            assert_eq!(TX_ALLOWLIST.is_allowed(sender, deny_all), Ok(true));
        }
    }

    #[test]
    fn is_allowed_follows_the_mode() {
        let account = address!("00000000000000000000000000000000000a11ce");
        let read = |mode: AllowListMode, role: Role, blocked: bool| {
            move |key: U256| {
                Ok::<_, ()>(if key == U256::from_be_bytes(MODE_KEY.0) {
                    U256::from(mode as u8)
                } else if key == role_key(account) {
                    U256::from(role as u8)
                } else if key == blocked_key(account) {
                    U256::from(blocked)
                } else {
                    U256::ZERO
                })
            }
        };

        for list in [DEPLOYER_ALLOWLIST, TX_ALLOWLIST] {
            assert_eq!(
                list.is_allowed(account, read(AllowListMode::Off, Role::None, true)),
                Ok(true)
            );
            assert_eq!(
                list.is_allowed(account, read(AllowListMode::Allowlist, Role::None, false)),
                Ok(false)
            );
            for role in [Role::Enabled, Role::Manager, Role::Admin] {
                assert_eq!(
                    list.is_allowed(account, read(AllowListMode::Allowlist, role, false)),
                    Ok(true)
                );
            }
            assert_eq!(
                list.is_allowed(account, read(AllowListMode::Denylist, Role::None, false)),
                Ok(true)
            );
            assert_eq!(
                list.is_allowed(account, read(AllowListMode::Denylist, Role::Enabled, true)),
                Ok(false)
            );
            // An unknown stored mode fails closed.
            assert_eq!(list.is_allowed(account, |_| Ok::<_, ()>(U256::from(9))), Ok(false));
        }

        // Blocking an Admin stops it deploying, but never stops it transacting.
        let blocked_admin = read(AllowListMode::Denylist, Role::Admin, true);
        assert_eq!(DEPLOYER_ALLOWLIST.is_allowed(account, blocked_admin), Ok(false));
        assert_eq!(TX_ALLOWLIST.is_allowed(account, blocked_admin), Ok(true));
    }
}
