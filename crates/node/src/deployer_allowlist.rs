//! `DeployerAllowListFork0`: the [`DEPLOYER_ALLOWLIST`] precompile, enforced on every contract
//! creation.
//!
//! Enforcement keys on `tx.origin`, which for deposits is the already-aliased L2 sender. A
//! denied create behaves exactly as if its initcode were [`denied_initcode`]: the
//! [`POLICY_VIOLATION_INITCODE`](crate::allowlist::POLICY_VIOLATION_INITCODE) stub, which reverts
//! with `PolicyViolation()`, followed by the original initcode. Upstream revm therefore does all of
//! the accounting: the creator's nonce is bumped, no account is created, no value moves, the
//! frame's unused gas is returned and the caller sees address zero with the revert data in
//! `RETURNDATA`. Because the original initcode is kept, a denied create pays every
//! initcode-dependent charge and meets every limit a genuine one would; one within 16 bytes of the
//! initcode size limit therefore exceeds it, which makes a top-level L2 create invalid and a
//! top-level create deposit a failed deposit. For `CREATE2` the created address is derived from the
//! combined initcode, consistent with that rule. The same rule applies to L2 transactions and
//! deposits, so a denied deposit is still included.
//!
//! Rejections are logged only from consensus execution, not from RPC simulations.
//!
//! Nested creates are rewritten by the CREATE/CREATE2 instruction overrides installed by
//! [`install_create_guards`]; a top-level create is rewritten before execution by the EVM
//! wrapper in [`crate::policy_evm`].

use crate::{
    allowlist::{AllowList, POLICY_REJECTION_TARGET, denied_initcode, is_deposit},
    chainspec::ConduitOpChainSpec,
    hardforks::ConduitOpHardforks,
};
use alloy_evm::Database;
use alloy_op_evm::{OpEvmContext, OpTx};
use alloy_primitives::{U256, address, keccak256};
use op_revm::transaction::OpTxTr;
use revm::{
    DatabaseCommit,
    bytecode::opcode,
    context_interface::{Block, Transaction},
    handler::instructions::EthInstructions,
    interpreter::{
        FrameInput, Host, InstructionContext, InstructionExecResult, InstructionResult,
        InterpreterAction,
        instructions::{Instruction, contract},
        interpreter::EthInterpreter,
        interpreter_types::LoopControl,
    },
};

/// The contract deployer allowlist: index 1 of
/// [`CONDUIT_SYSTEM_NAMESPACE`](crate::allowlist::CONDUIT_SYSTEM_NAMESPACE).
pub const DEPLOYER_ALLOWLIST: AllowList = AllowList {
    address: address!("c0d0000000000000000000000000000000000001"),
    name: "DeployerAllowList",
    privileged_always_allowed: false,
};

/// Replaces the CREATE and CREATE2 instructions with versions that enforce the policy.
///
/// Only call this for EVMs whose block has `DeployerAllowListFork0` active.
pub fn install_create_guards<DB: Database>(
    instructions: &mut EthInstructions<EthInterpreter, OpEvmContext<DB>>,
) {
    let table = instructions.instruction_table_mut();
    table[opcode::CREATE as usize] = Instruction::new(guarded_create::<false, DB>);
    table[opcode::CREATE2 as usize] = Instruction::new(guarded_create::<true, DB>);
}

/// Runs the stock create instruction, then swaps in the policy-violation initcode if the policy
/// denies `tx.origin`.
///
/// The stock instruction has already applied every pre-frame check and charge (static context,
/// initcode limits, gas) against the original initcode, so a denied create costs the caller what
/// it would have cost anyway. The policy is read through the journal, so a change made earlier in
/// the same transaction applies; the precompile charges a fixed gas price, so the slots this
/// warms have no visible gas effect.
fn guarded_create<const IS_CREATE2: bool, DB: Database>(
    ctx: InstructionContext<'_, OpEvmContext<DB>, EthInterpreter>,
) -> InstructionExecResult {
    let InstructionContext { interpreter, host } = ctx;
    let result =
        contract::create::<IS_CREATE2, EthInterpreter, OpEvmContext<DB>>(InstructionContext {
            interpreter: &mut *interpreter,
            host: &mut *host,
        });
    if result != Err(InstructionResult::Suspend) {
        return result;
    }

    let origin = host.tx.caller();
    let address = DEPLOYER_ALLOWLIST.address;
    host.load_account_info_skip_cold_load(address, false, false)?;
    let allowed = DEPLOYER_ALLOWLIST.is_allowed(origin, |key| {
        host.sload_skip_cold_load(address, key, false).map(|load| load.data)
    })?;

    if !allowed &&
        let Some(InterpreterAction::NewFrame(FrameInput::Create(inputs))) =
            interpreter.bytecode.action()
    {
        // RPC simulations are the only callers that disable EIP-3607; see `ConduitOpEvm`.
        if !host.cfg.disable_eip3607 {
            tracing::info!(
                target: POLICY_REJECTION_TARGET,
                rule = DEPLOYER_ALLOWLIST.name,
                deposit = is_deposit(&host.tx),
                tx_hash = ?host.tx.enveloped_tx().map(keccak256),
                %origin,
                creator = %inputs.caller(),
                scheme = ?inputs.scheme(),
                block_number = %host.block.number(),
                "denied contract creation"
            );
        }
        let initcode = denied_initcode(inputs.init_code());
        inputs.set_init_code(initcode);
    }

    result
}

/// Applies the policy to a top-level create transaction by replacing its initcode with
/// [`denied_initcode`] before execution, so it runs as an ordinary reverted create.
///
/// `read` reads precompile storage as committed before the transaction. Rejections are logged
/// only if `log` is set.
pub fn deny_top_level_create<E>(
    tx: &mut OpTx,
    block_number: u64,
    log: bool,
    read: impl FnMut(U256) -> Result<U256, E>,
) -> Result<(), E> {
    if !tx.0.base.kind.is_create() || DEPLOYER_ALLOWLIST.is_allowed(tx.caller(), read)? {
        return Ok(());
    }

    if log {
        tracing::info!(
            target: POLICY_REJECTION_TARGET,
            rule = DEPLOYER_ALLOWLIST.name,
            deposit = is_deposit(tx),
            tx_hash = ?tx.enveloped_tx().map(keccak256),
            origin = %tx.caller(),
            creator = %tx.caller(),
            scheme = "Create",
            block_number,
            "denied contract creation"
        );
    }
    tx.0.base.data = denied_initcode(&tx.0.base.data);
    Ok(())
}

/// Seeds the deployer allowlist at every block where `DeployerAllowListFork0` is active; a no-op
/// once seeded.
pub fn ensure_deployer_allowlist<DB>(
    chain_spec: &ConduitOpChainSpec,
    timestamp: u64,
    db: &mut DB,
) -> Result<(), DB::Error>
where
    DB: Database + DatabaseCommit,
{
    match &chain_spec.deployer_allowlist_fork0 {
        Some(config) if chain_spec.is_deployer_allowlist_fork0_active_at_timestamp(timestamp) => {
            DEPLOYER_ALLOWLIST.ensure_seeded(config, db)
        }
        _ => Ok(()),
    }
}
