//! `TxAllowListFork0`: the [`TX_ALLOWLIST`] precompile, enforced on every transaction sender.
//!
//! The checked sender is `tx.origin`: the L2 transaction's signer, or a deposit's already-aliased
//! L2 sender. A sponsored transaction is checked against its sponsor, not against EIP-7702
//! authorization signers.
//!
//! - A denied L2 transaction is invalid: builders skip it and a block containing it fails
//!   validation, so it is never included, pays no fee and keeps its nonce.
//! - A deposit cannot be invalid without stalling derivation, so a denied deposit runs as if it
//!   were a create with [`POLICY_VIOLATION_INITCODE`]: it is included with status 0, its mint is
//!   kept, its nonce is bumped and it has no other effect. A denied deposit whose gas limit cannot
//!   cover a create's intrinsic gas (such as a 21,000-gas transfer) fails that check instead and
//!   becomes a failed deposit: still included with status 0, mint kept and nonce bumped, but using
//!   its whole gas limit.
//!
//! Admins and Managers are always allowed to transact, so a denylist can never lock out the
//! accounts that manage either allowlist.

use crate::{
    allowlist::{AllowList, POLICY_REJECTION_TARGET, POLICY_VIOLATION_INITCODE, is_deposit},
    chainspec::ConduitOpChainSpec,
    hardforks::ConduitOpHardforks,
};
use alloy_evm::Database;
use alloy_op_evm::OpTx;
use alloy_primitives::{TxKind, U256, address, keccak256};
use op_revm::transaction::OpTxTr;
use revm::{DatabaseCommit, context_interface::Transaction};

/// The transaction allowlist: index 2 of
/// [`CONDUIT_SYSTEM_NAMESPACE`](crate::allowlist::CONDUIT_SYSTEM_NAMESPACE).
pub const TX_ALLOWLIST: AllowList = AllowList {
    address: address!("c0d0000000000000000000000000000000000002"),
    name: "TxAllowList",
    privileged_always_allowed: true,
};

/// Outcome of applying the transaction allowlist to a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxSenderCheck {
    /// The sender is allowed; the transaction is unchanged.
    Allowed,
    /// The sender of a deposit is denied; the deposit was rewritten into a reverted no-op.
    DepositDenied,
    /// The sender of an L2 transaction is denied; the transaction must be rejected as invalid.
    Rejected,
}

/// Applies the transaction allowlist to `tx` before execution.
///
/// `read` reads precompile storage as committed before the transaction.
pub fn allow_tx_sender<E>(
    tx: &mut OpTx,
    block_number: u64,
    read: impl FnMut(U256) -> Result<U256, E>,
) -> Result<TxSenderCheck, E> {
    if TX_ALLOWLIST.is_allowed(tx.caller(), read)? {
        return Ok(TxSenderCheck::Allowed);
    }

    let deposit = is_deposit(tx);
    tracing::info!(
        target: POLICY_REJECTION_TARGET,
        rule = TX_ALLOWLIST.name,
        deposit,
        tx_hash = ?tx.enveloped_tx().map(keccak256),
        origin = %tx.caller(),
        block_number,
        "denied transaction sender"
    );
    if !deposit {
        return Ok(TxSenderCheck::Rejected);
    }
    tx.0.base.kind = TxKind::Create;
    tx.0.base.data = POLICY_VIOLATION_INITCODE;
    Ok(TxSenderCheck::DepositDenied)
}

/// Seeds the transaction allowlist at every block where `TxAllowListFork0` is active; a no-op
/// once seeded.
pub fn ensure_tx_allowlist<DB>(
    chain_spec: &ConduitOpChainSpec,
    timestamp: u64,
    db: &mut DB,
) -> Result<(), DB::Error>
where
    DB: Database + DatabaseCommit,
{
    match &chain_spec.tx_allowlist_fork0 {
        Some(config) if chain_spec.is_tx_allowlist_fork0_active_at_timestamp(timestamp) => {
            TX_ALLOWLIST.ensure_seeded(config, db)
        }
        _ => Ok(()),
    }
}
