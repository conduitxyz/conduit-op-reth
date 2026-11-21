//! `eth_getProof` with the storage key count capped at [`MAX_PROOF_SLOTS`].
//!
//! UPSTREAM-MIRROR: paradigmxyz/reth#27716, which is not in the pinned `ethereum-optimism/reth`
//! (`op-v2.6.0-2`) tag and has no counterpart in op-reth's proofs-history `eth_getProof` override
//! (`op-reth/v2.8.0`). Delete this module once a dependency bump caps both handlers.
//!
//! #27716 also caps `eth_getMultiProof`; op-reth does not serve that method, which
//! `crates/bin/tests/rpc_bounds.rs` pins.

use alloy_eips::BlockId;
use alloy_primitives::Address;
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use alloy_serde::JsonStorageKey;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::ErrorObject,
};
use reth_optimism_rpc::eth::proofs::{EthApiExt, EthApiOverrideServer};
use reth_optimism_trie::OpProofsStore;
use reth_rpc_eth_api::{
    FromEthApiError,
    helpers::{EthState, FullEthApi},
};
use reth_rpc_eth_types::EthApiError;
use tracing::trace;

/// The maximum number of storage keys accepted by a single `eth_getProof` request.
///
/// UPSTREAM-MIRROR(copy): `reth_rpc_server_types::constants::DEFAULT_MAX_PROOF_SLOTS`.
pub const MAX_PROOF_SLOTS: usize = 1024;

/// Rejects an `eth_getProof` request asking for more than [`MAX_PROOF_SLOTS`] storage keys.
fn ensure_proof_key_count(keys: &[JsonStorageKey]) -> Result<(), EthApiError> {
    if keys.len() > MAX_PROOF_SLOTS {
        return Err(EthApiError::InvalidParams(format!(
            "storage key count {} exceeds limit {MAX_PROOF_SLOTS}",
            keys.len(),
        )));
    }
    Ok(())
}

/// `eth_getProof`, with the storage key count capped at [`MAX_PROOF_SLOTS`].
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait CappedGetProofApi {
    /// Returns the account and storage values of the given account, with Merkle proofs.
    #[method(name = "getProof")]
    async fn get_proof(
        &self,
        address: Address,
        keys: Vec<JsonStorageKey>,
        block_number: Option<BlockId>,
    ) -> RpcResult<EIP1186AccountProofResponse>;
}

/// Caps the key count, then serves the proof from live state.
#[derive(Debug)]
pub struct CappedGetProof<Eth>(pub Eth);

#[async_trait]
impl<Eth> CappedGetProofApiServer for CappedGetProof<Eth>
where
    Eth: FullEthApi + Send + Sync + 'static,
    ErrorObject<'static>: From<Eth::Error>,
{
    async fn get_proof(
        &self,
        address: Address,
        keys: Vec<JsonStorageKey>,
        block_number: Option<BlockId>,
    ) -> RpcResult<EIP1186AccountProofResponse> {
        trace!(target: "rpc::eth", ?address, ?keys, ?block_number, "Serving eth_getProof");
        ensure_proof_key_count(&keys).map_err(Eth::Error::from_eth_err)?;
        Ok(EthState::get_proof(&self.0, address, keys, block_number)?.await?)
    }
}

/// Caps the key count, then serves the proof from the proofs-history storage.
#[derive(Debug)]
pub struct CappedHistoricalGetProof<Eth, P>(pub EthApiExt<Eth, P>);

#[async_trait]
impl<Eth, P> CappedGetProofApiServer for CappedHistoricalGetProof<Eth, P>
where
    Eth: FullEthApi + Send + Sync + 'static,
    ErrorObject<'static>: From<Eth::Error>,
    P: OpProofsStore + Clone + 'static,
{
    async fn get_proof(
        &self,
        address: Address,
        keys: Vec<JsonStorageKey>,
        block_number: Option<BlockId>,
    ) -> RpcResult<EIP1186AccountProofResponse> {
        ensure_proof_key_count(&keys).map_err(Eth::Error::from_eth_err)?;
        EthApiOverrideServer::get_proof(&self.0, address, keys, block_number).await
    }
}
