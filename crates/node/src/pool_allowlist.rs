//! Transaction pool admission for the allowlist forks.
//!
//! Block execution already enforces both allowlists, but on its own it leaves the pool holding
//! transactions the sequencer never includes: builders skip a transaction from a denied sender
//! once per build without evicting it, so it stays pending until its sender is allowed again.
//! The pool therefore applies the same rules:
//!
//! - [`PolicyValidator`] rejects transactions whose sender the transaction allowlist denies, and
//!   top-level contract creations whose sender the deployer allowlist denies. Such a creation would
//!   only ever be included as a revert (see
//!   [`deny_top_level_create`](crate::deployer_allowlist::deny_top_level_create)), so rejecting it
//!   spares the sender its fee. A creation nested in a call cannot be detected before execution and
//!   is still reverted by the EVM.
//! - [`maintain_pool_policies`] re-applies the rules to every pooled transaction whenever a
//!   committed block changes either allowlist, including the block that seeds it at activation.
//!
//! Both read the allowlists at the latest block. Before a fork activates its precompile holds no
//! storage, which reads as mode `Off`, so nothing is rejected early.

use crate::{
    allowlist::AllowList, chainspec::ConduitOpChainSpec, deployer_allowlist::DEPLOYER_ALLOWLIST,
    tx_allowlist::TX_ALLOWLIST,
};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use futures_util::{Stream, StreamExt};
use reth_chainspec::ChainSpecProvider;
use reth_optimism_node::{OpValidatorWrapper, txpool::OpTransactionValidator};
use reth_primitives_traits::NodePrimitives;
use reth_provider::CanonStateNotification;
use reth_revm::db::BundleState;
use reth_storage_api::{StateProvider, StateProviderFactory, errors::provider::ProviderResult};
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionPool, TransactionValidationOutcome,
    TransactionValidator,
    error::{InvalidPoolTransactionError, PoolTransactionError},
};
use std::{any::Any, fmt};
use tracing::{info, warn};

/// Why the pool rejects a transaction under the allowlist forks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPoolError {
    /// The transaction allowlist denies the sender.
    SenderNotAllowlisted,
    /// The deployer allowlist denies the sender of a contract creation.
    DeployerNotAllowlisted,
}

impl fmt::Display for PolicyPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SenderNotAllowlisted => crate::tx_allowlist::TX_SENDER_NOT_ALLOWLISTED,
            Self::DeployerNotAllowlisted => "contract deployer is not allowlisted",
        })
    }
}

impl core::error::Error for PolicyPoolError {}

impl PoolTransactionError for PolicyPoolError {
    /// The transaction is well-formed, and the policy may allow it later, so peers relaying it
    /// are not penalized.
    fn is_bad_transaction(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The allowlists a chain configures, which the pool enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolPolicies {
    tx_allowlist: bool,
    deployer_allowlist: bool,
}

impl PoolPolicies {
    /// The allowlist forks `chain_spec` configures.
    pub fn new(chain_spec: &ConduitOpChainSpec) -> Self {
        Self {
            tx_allowlist: chain_spec.tx_allowlist_fork0.is_some(),
            deployer_allowlist: chain_spec.deployer_allowlist_fork0.is_some(),
        }
    }

    /// Whether the pool enforces any allowlist.
    pub const fn any(&self) -> bool {
        self.tx_allowlist || self.deployer_allowlist
    }

    fn lists(&self) -> impl Iterator<Item = AllowList> {
        [
            self.tx_allowlist.then_some(TX_ALLOWLIST),
            self.deployer_allowlist.then_some(DEPLOYER_ALLOWLIST),
        ]
        .into_iter()
        .flatten()
    }

    /// Returns why `state` denies a transaction from `sender`, a contract creation if
    /// `is_create`, if it does.
    pub fn rejection(
        &self,
        state: &dyn StateProvider,
        sender: Address,
        is_create: bool,
    ) -> ProviderResult<Option<PolicyPoolError>> {
        if self.tx_allowlist && !is_allowed(TX_ALLOWLIST, state, sender)? {
            return Ok(Some(PolicyPoolError::SenderNotAllowlisted));
        }
        if self.deployer_allowlist && is_create && !is_allowed(DEPLOYER_ALLOWLIST, state, sender)? {
            return Ok(Some(PolicyPoolError::DeployerNotAllowlisted));
        }
        Ok(None)
    }

    /// Whether `bundle` changes the storage, or the account, of an enforced allowlist.
    pub fn changed_in(&self, bundle: &BundleState) -> bool {
        self.lists().any(|list| {
            bundle.account(&list.address).is_some_and(|account| {
                account.is_info_changed() || account.storage.values().any(|slot| slot.is_changed())
            })
        })
    }
}

fn is_allowed(
    list: AllowList,
    state: &dyn StateProvider,
    account: Address,
) -> ProviderResult<bool> {
    list.is_allowed(account, |key| {
        state.storage(list.address, B256::from(key)).map(|value| value.unwrap_or(U256::ZERO))
    })
}

/// Pool validator that applies [`PoolPolicies`] to the transactions `inner` accepts.
#[derive(Debug)]
pub struct PolicyValidator<V, Provider> {
    inner: V,
    provider: Provider,
    policies: PoolPolicies,
}

impl<V, Provider> PolicyValidator<V, Provider>
where
    Provider: ChainSpecProvider<ChainSpec = ConduitOpChainSpec>,
{
    /// Wraps `inner`, enforcing the allowlists `provider`'s chain configures.
    pub fn new(inner: V, provider: Provider) -> Self {
        let policies = PoolPolicies::new(&provider.chain_spec());
        Self { inner, provider, policies }
    }
}

impl<V, Provider> TransactionValidator for PolicyValidator<V, Provider>
where
    V: TransactionValidator,
    Provider: StateProviderFactory + fmt::Debug + Send + Sync,
{
    type Transaction = V::Transaction;
    type Block = V::Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let outcome = self.inner.validate_transaction(origin, transaction).await;
        if !self.policies.any() {
            return outcome;
        }
        let TransactionValidationOutcome::Valid { transaction: valid, .. } = &outcome else {
            return outcome;
        };

        let tx = valid.transaction();
        let rejection = self
            .provider
            .latest()
            .and_then(|state| self.policies.rejection(state.as_ref(), tx.sender(), tx.is_create()));
        match rejection {
            Ok(None) => outcome,
            Ok(Some(error)) => {
                let TransactionValidationOutcome::Valid { transaction, .. } = outcome else {
                    unreachable!("checked above")
                };
                TransactionValidationOutcome::Invalid(
                    transaction.into_transaction(),
                    InvalidPoolTransactionError::other(error),
                )
            }
            Err(error) => TransactionValidationOutcome::Error(*tx.hash(), Box::new(error)),
        }
    }

    fn on_new_head_block(&self, new_tip_block: &reth_primitives_traits::SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_tip_block);
    }
}

/// [`OpValidatorWrapper`] that wraps op-reth's validator in a [`PolicyValidator`].
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyValidatorWrapper;

impl<Provider, T, Evm> OpValidatorWrapper<Provider, T, Evm> for PolicyValidatorWrapper
where
    OpTransactionValidator<Provider, T, Evm>: TransactionValidator,
    Provider: ChainSpecProvider<ChainSpec = ConduitOpChainSpec>
        + StateProviderFactory
        + fmt::Debug
        + Send
        + Sync,
{
    type Validator = PolicyValidator<OpTransactionValidator<Provider, T, Evm>, Provider>;

    fn wrap(
        self,
        validator: OpTransactionValidator<Provider, T, Evm>,
        provider: Provider,
    ) -> Self::Validator {
        PolicyValidator::new(validator, provider)
    }
}

/// Evicts pooled transactions the allowlists deny, whenever a canonical block changes them.
pub async fn maintain_pool_policies<Pool, Client, N, St>(
    pool: Pool,
    client: Client,
    policies: PoolPolicies,
    mut events: St,
) where
    Pool: TransactionPool,
    Client: StateProviderFactory,
    N: NodePrimitives,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin,
{
    while let Some(event) = events.next().await {
        // A reorg that drops a policy change is handled like one that makes it: both can deny
        // pooled transactions that were allowed before.
        let changed = policies.changed_in(event.committed().execution_outcome().state()) ||
            event
                .reverted()
                .is_some_and(|chain| policies.changed_in(chain.execution_outcome().state()));
        if !changed {
            continue
        }
        if let Err(error) = evict_denied(&pool, &client, policies) {
            warn!(target: "txpool", %error, "Failed to apply allowlist changes to the pool");
        }
    }
}

/// Removes every pooled transaction that the latest allowlists deny.
fn evict_denied<Pool, Client>(
    pool: &Pool,
    client: &Client,
    policies: PoolPolicies,
) -> ProviderResult<()>
where
    Pool: TransactionPool,
    Client: StateProviderFactory,
{
    let state = client.latest()?;
    let mut denied = Vec::new();
    for tx in pool.all_transactions().iter() {
        if policies.rejection(state.as_ref(), tx.sender(), tx.transaction.is_create())?.is_some() {
            denied.push(*tx.hash());
        }
    }
    if !denied.is_empty() {
        let evicted = pool.remove_transactions(denied).len();
        info!(target: "txpool", evicted, "Evicted transactions the allowlists now deny");
    }
    Ok(())
}
