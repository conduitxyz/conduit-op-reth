//! `eth_call`, `eth_estimateGas` and `eth_simulateV1` overrides that serve flashblock
//! pending state.
//!
//! The stock reth implementations of these methods resolve the `pending` block tag via
//! `evm_env_at`, which falls back to the latest canonical block when the provider has no
//! pending block (always the case for flashblocks, which only populate an RPC-level
//! overlay). As a result, `eth_call(..., "pending")` executes against canonical state and
//! does not observe preconfirmed transactions, unlike `eth_getBalance`,
//! `eth_getStorageAt`, `eth_getTransactionReceipt` and `eth_sendRawTransactionSync`,
//! which all consult the flashblock overlay.
//!
//! This module follows the approach used by Base's node (base/base `flashblocks` crate):
//! when the request targets the `pending` tag and a pending flashblock exists, the
//! flashblock's accumulated [`BundleState`] is converted into a [`StateOverride`] and the
//! request is delegated to the inner eth API pinned to the flashblock's canonical anchor
//! block, with user-supplied overrides applied on top.

use alloy_consensus::BlockHeader;
use alloy_eips::BlockId;
use alloy_json_rpc::RpcObject;
use alloy_primitives::{B256, Bytes, U256};
use alloy_rpc_types_eth::{
    BlockOverrides,
    simulate::{SimBlock, SimulatePayload, SimulatedBlock},
    state::{EvmOverrides, StateOverride, StateOverridesBuilder},
};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use reth_optimism_rpc::{OpEthApi, OpEthApiError};
use reth_revm::{db::BundleState, primitives::KECCAK_EMPTY};
use reth_rpc_eth_api::{
    FromEvmError, RpcBlock, RpcConvert, RpcNodeCore, RpcTxReq,
    helpers::{EthCall, FullEthApi},
};
use tracing::trace;

/// Provides the state of the current pending flashblock as a [`StateOverride`] anchored
/// on a canonical block.
pub trait PendingFlashblockState: Send + Sync {
    /// Returns the canonical anchor block and the accumulated state overrides of the
    /// current pending flashblock, or `None` when no flashblock is available.
    fn pending_flashblock_overrides(
        &self,
    ) -> impl Future<Output = Option<(BlockId, StateOverride)>> + Send;
}

impl<N, Rpc> PendingFlashblockState for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError>,
{
    async fn pending_flashblock_overrides(&self) -> Option<(BlockId, StateOverride)> {
        let flashblock = self.pending_flashblock().await.ok().flatten()?;
        let overrides =
            bundle_state_overrides(&flashblock.pending.executed_block.execution_output.state);
        // Anchor on the canonical block number, matching Base's implementation.
        //
        // Possible future improvement: anchor on the exact block hash
        // (`flashblock.canonical_anchor_hash`) instead, which pins the overrides to the
        // block the flashblock was actually built on and fails closed during reorg
        // races where two parents can share the same height.
        let anchor_number =
            flashblock.pending.executed_block.recovered_block.header().number().saturating_sub(1);
        Some((BlockId::number(anchor_number), overrides))
    }
}

/// Converts a flashblock's accumulated [`BundleState`] into a [`StateOverride`] that can
/// be applied on top of the flashblock's canonical anchor block.
///
/// Accounts override balance, nonce, changed storage slots and (for newly deployed
/// contracts) code, mirroring how Base's node builds its pending state overrides.
pub fn bundle_state_overrides(bundle: &BundleState) -> StateOverride {
    let mut overrides = StateOverride::default();
    for (address, account) in &bundle.state {
        let account_override = overrides.entry(*address).or_default();
        let Some(info) = account.info.as_ref() else {
            // Account was destroyed or cleared in the pending block. Zero the account
            // like Base does (post-selfdestruct execution state).
            //
            // Possible future improvement: also set `state = Some(empty map)` to fully
            // wipe the destroyed account's canonical storage, which Base leaves
            // visible. Only reachable for same-tx creation+selfdestruct post-Cancun.
            account_override.balance = Some(U256::ZERO);
            account_override.nonce = Some(0);
            account_override.code = Some(Bytes::new());
            continue;
        };

        account_override.balance = Some(info.balance);
        account_override.nonce = Some(info.nonce);
        if info.code_hash != KECCAK_EMPTY {
            if let Some(code) = info.code.as_ref().or_else(|| bundle.contracts.get(&info.code_hash))
            {
                // `bytes()` returns the analysis-padded bytecode, matching Base.
                //
                // Possible future improvement: use `code.original_bytes()` instead,
                // which strips the trailing analysis padding so EXTCODESIZE /
                // EXTCODEHASH / CODECOPY on pending-deployed contracts return the
                // actual deployed code.
                account_override.code = Some(code.bytes());
            }
        } else if account.original_info.as_ref().is_some_and(|orig| orig.code_hash != KECCAK_EMPTY)
        {
            // The account's code was cleared in the pending block (e.g. an EIP-7702
            // delegation removal); explicitly override with empty code so the canonical
            // code does not leak through.
            account_override.code = Some(Bytes::new());
        }

        if !account.storage.is_empty() {
            let state_diff = account_override.state_diff.get_or_insert_with(Default::default);
            state_diff.extend(
                account
                    .storage
                    .iter()
                    .map(|(slot, value)| (B256::from(*slot), B256::from(value.present_value))),
            );
        }
    }
    overrides
}

// Namespace overrides serving flashblock pending state for call-like methods.
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait FlashblocksCallApi<TxReq: RpcObject, B: RpcObject> {
    #[method(name = "call")]
    async fn call(
        &self,
        request: TxReq,
        block_number: Option<BlockId>,
        state_overrides: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes>;

    #[method(name = "estimateGas")]
    async fn estimate_gas(
        &self,
        request: TxReq,
        block_number: Option<BlockId>,
        state_override: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<U256>;

    #[method(name = "simulateV1")]
    async fn simulate_v1(
        &self,
        opts: SimulatePayload<TxReq>,
        block_number: Option<BlockId>,
    ) -> RpcResult<Vec<SimulatedBlock<B>>>;
}

/// RPC extension that overrides `eth_call`, `eth_estimateGas` and `eth_simulateV1` so
/// the `pending` block tag observes flashblock state.
#[derive(Debug, Clone)]
pub struct FlashblocksCallExt<Eth> {
    eth_api: Eth,
}

impl<Eth> FlashblocksCallExt<Eth> {
    pub const fn new(eth_api: Eth) -> Self {
        Self { eth_api }
    }

    /// Resolves the effective block id and flashblock state overrides for a request.
    ///
    /// For the `pending` tag with an available flashblock this returns the canonical
    /// anchor block id and the flashblock overrides; otherwise the request passes
    /// through unchanged.
    async fn resolve_pending(
        &self,
        block_number: Option<BlockId>,
    ) -> (Option<BlockId>, Option<StateOverride>)
    where
        Eth: PendingFlashblockState,
    {
        let block_id = block_number.unwrap_or_default();
        if !block_id.is_pending() {
            return (block_number, None);
        }
        match self.eth_api.pending_flashblock_overrides().await {
            Some((anchor, overrides)) => {
                trace!(target: "rpc::flashblocks", ?anchor, "serving pending call from flashblock state");
                (Some(anchor), Some(overrides))
            }
            None => (block_number, None),
        }
    }
}

/// Merges flashblock state overrides with user-supplied overrides.
///
/// User overrides win per account, mirroring the behavior of Base's flashblocks RPC.
fn merge_overrides(
    flashblock: Option<StateOverride>,
    user: Option<StateOverride>,
) -> Option<StateOverride> {
    match (flashblock, user) {
        (None, user) => user,
        (Some(flashblock), user) => {
            Some(StateOverridesBuilder::new(flashblock).extend(user.unwrap_or_default()).build())
        }
    }
}

#[async_trait]
impl<Eth> FlashblocksCallApiServer<RpcTxReq<Eth::NetworkTypes>, RpcBlock<Eth::NetworkTypes>>
    for FlashblocksCallExt<Eth>
where
    Eth: FullEthApi + PendingFlashblockState + Clone + 'static,
{
    async fn call(
        &self,
        request: RpcTxReq<Eth::NetworkTypes>,
        block_number: Option<BlockId>,
        state_overrides: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes> {
        let (block_id, flashblock_overrides) = self.resolve_pending(block_number).await;
        let state_overrides = merge_overrides(flashblock_overrides, state_overrides);

        EthCall::call(
            &self.eth_api,
            request,
            block_id,
            EvmOverrides::new(state_overrides, block_overrides),
        )
        .await
        .map_err(Into::into)
    }

    async fn estimate_gas(
        &self,
        request: RpcTxReq<Eth::NetworkTypes>,
        block_number: Option<BlockId>,
        state_override: Option<StateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<U256> {
        let (block_id, flashblock_overrides) = self.resolve_pending(block_number).await;
        let state_override = merge_overrides(flashblock_overrides, state_override);

        EthCall::estimate_gas_at(
            &self.eth_api,
            request,
            block_id.unwrap_or_default(),
            EvmOverrides::new(state_override, block_overrides),
        )
        .await
        .map_err(Into::into)
    }

    async fn simulate_v1(
        &self,
        opts: SimulatePayload<RpcTxReq<Eth::NetworkTypes>>,
        block_number: Option<BlockId>,
    ) -> RpcResult<Vec<SimulatedBlock<RpcBlock<Eth::NetworkTypes>>>> {
        let (block_id, flashblock_overrides) = self.resolve_pending(block_number).await;

        // Prepend the flashblock overrides to each simulated block's state overrides.
        let opts = match flashblock_overrides {
            Some(overrides) => {
                let block_state_calls = opts
                    .block_state_calls
                    .into_iter()
                    .map(|sim_block| SimBlock {
                        state_overrides: merge_overrides(
                            Some(overrides.clone()),
                            sim_block.state_overrides,
                        ),
                        ..sim_block
                    })
                    .collect();
                SimulatePayload { block_state_calls, ..opts }
            }
            None => opts,
        };

        EthCall::simulate_v1(&self.eth_api, opts, block_id).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, address};
    use reth_revm::{
        db::{AccountStatus, BundleAccount, states::StorageSlot},
        state::{AccountInfo, Bytecode},
    };

    const ADDR: Address = address!("00000000000000000000000000000000000000aa");

    fn bundle_with_account(account: BundleAccount) -> BundleState {
        let mut bundle = BundleState::default();
        bundle.state.insert(ADDR, account);
        bundle
    }

    #[test]
    fn changed_account_overrides_balance_nonce_and_storage() {
        let account = BundleAccount {
            info: Some(AccountInfo { balance: U256::from(42), nonce: 7, ..Default::default() }),
            original_info: None,
            storage: [(
                U256::from(0),
                StorageSlot {
                    previous_or_original_value: U256::from(4),
                    present_value: U256::from(5),
                },
            )]
            .into_iter()
            .collect(),
            status: AccountStatus::Changed,
        };

        let overrides = bundle_state_overrides(&bundle_with_account(account));
        let acc = overrides.get(&ADDR).unwrap();
        assert_eq!(acc.balance, Some(U256::from(42)));
        assert_eq!(acc.nonce, Some(7));
        assert_eq!(acc.code, None);
        assert_eq!(acc.state, None);
        let diff = acc.state_diff.as_ref().unwrap();
        assert_eq!(diff.get(&B256::from(U256::from(0))), Some(&B256::from(U256::from(5))));
    }

    #[test]
    fn deployed_contract_overrides_code() {
        let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00]));
        let account = BundleAccount {
            info: Some(AccountInfo {
                balance: U256::ZERO,
                nonce: 1,
                code_hash: code.hash_slow(),
                code: Some(code.clone()),
                ..Default::default()
            }),
            original_info: None,
            storage: Default::default(),
            status: AccountStatus::Changed,
        };

        let overrides = bundle_state_overrides(&bundle_with_account(account));
        let acc = overrides.get(&ADDR).unwrap();
        assert_eq!(acc.code, Some(code.bytes()));
        assert_eq!(acc.state_diff, None);
    }

    #[test]
    fn cleared_code_emits_empty_code_override() {
        let original_code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00]));
        let account = BundleAccount {
            // Post-state: code removed (e.g. EIP-7702 delegation cleared).
            info: Some(AccountInfo { nonce: 2, ..Default::default() }),
            original_info: Some(AccountInfo {
                nonce: 1,
                code_hash: original_code.hash_slow(),
                code: Some(original_code),
                ..Default::default()
            }),
            storage: Default::default(),
            status: AccountStatus::Changed,
        };

        let overrides = bundle_state_overrides(&bundle_with_account(account));
        let acc = overrides.get(&ADDR).unwrap();
        assert_eq!(acc.code, Some(Bytes::new()));
    }

    #[test]
    fn destroyed_account_is_zeroed() {
        let account = BundleAccount {
            info: None,
            original_info: Some(AccountInfo {
                balance: U256::from(1),
                nonce: 3,
                ..Default::default()
            }),
            storage: Default::default(),
            status: AccountStatus::Destroyed,
        };

        let overrides = bundle_state_overrides(&bundle_with_account(account));
        let acc = overrides.get(&ADDR).unwrap();
        assert_eq!(acc.balance, Some(U256::ZERO));
        assert_eq!(acc.nonce, Some(0));
        assert_eq!(acc.code, Some(Bytes::new()));
        // Canonical storage is left visible, matching Base (see comment in
        // `bundle_state_overrides`).
        assert_eq!(acc.state, None);
        assert_eq!(acc.state_diff, None);
    }

    #[test]
    fn user_overrides_win_per_account() {
        let mut flashblock = StateOverride::default();
        flashblock.entry(ADDR).or_default().balance = Some(U256::from(1));

        let mut user = StateOverride::default();
        user.entry(ADDR).or_default().balance = Some(U256::from(2));

        let merged = merge_overrides(Some(flashblock), Some(user)).unwrap();
        assert_eq!(merged.get(&ADDR).unwrap().balance, Some(U256::from(2)));
    }
}
