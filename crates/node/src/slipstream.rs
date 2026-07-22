//! RPC-node ingress for Conduit Slipstream.
//!
//! The RPC node forwards each batch to the active sequencer. It can attach best-effort EIP-2930
//! access-list hints computed against its local state; the sequencer remains responsible for
//! admission, execution, and synchronous per-transaction verdicts.

use std::{sync::Arc, time::Duration};

use alloy_consensus::Transaction;
use alloy_eips::{
    BlockId,
    eip2930::{AccessList, AccessListItem},
};
use alloy_json_rpc::RpcError;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rpc_types_eth::state::{StateOverride, StateOverridesBuilder};
use futures_util::{StreamExt, stream};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::ErrorObjectOwned,
};
use op_alloy_consensus::OpPooledTransaction;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::OpTransactionRequest;
use reth_metrics::{
    Metrics,
    metrics::{Counter, Histogram},
};
use reth_optimism_rpc::{SequencerClient, SequencerClientError};
use reth_rpc_eth_api::helpers::{EthCall, FullEthApi};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, warn};

const SEND_RAW_TRANSACTION_BATCH_METHOD: &str = "slipstream_sendRawTransactionBatch";
const SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD: &str =
    "slipstream_sendRawTransactionBatchWithHints";

#[derive(Debug, Clone, Copy)]
pub struct SlipstreamConfig {
    pub forward_concurrency: usize,
    pub forward_timeout: Duration,
    pub build_concurrency: usize,
    pub build_timeout: Duration,
    pub max_batch_bytes: usize,
}

/// A transaction executed into a published flashblock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlipstreamIncludedTx {
    pub index: usize,
    pub hash: B256,
    pub sender: Address,
    pub nonce: u64,
    pub block_number: u64,
    pub flashblock_index: u64,
}

/// A transaction that is invalid as submitted and must not be resent unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlipstreamRejectedTx {
    pub index: usize,
    pub error: String,
}

/// A transaction that was not executed for a transient reason and can be resent unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlipstreamRetryTx {
    pub index: usize,
    pub reason: String,
}

/// Synchronous per-transaction verdicts returned by the active sequencer.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SlipstreamBatchAck {
    pub included: Vec<SlipstreamIncludedTx>,
    pub rejected: Vec<SlipstreamRejectedTx>,
    pub retry: Vec<SlipstreamRetryTx>,
}

/// A raw transaction paired with an advisory state-access hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlipstreamHintedTx {
    pub tx: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<AccessList>,
}

#[rpc(server, namespace = "slipstream")]
pub trait SlipstreamApi {
    #[method(name = "sendRawTransactionBatch")]
    async fn send_raw_transaction_batch(&self, txs: Vec<Bytes>) -> RpcResult<SlipstreamBatchAck>;
}

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder")]
struct SlipstreamMetrics {
    /// Slipstream batches forwarded to the active sequencer.
    slipstream_forwarded_batches: Counter,
    /// Slipstream transactions forwarded to the active sequencer.
    slipstream_forwarded_txs: Counter,
    /// Slipstream forwards that failed.
    slipstream_forward_error_count: Counter,
    /// Access-list hint generation attempts.
    slipstream_hint_build_attempt_count: Counter,
    /// Successful access-list hint generations.
    slipstream_hint_build_success_count: Counter,
    /// Access-list hint generation duration.
    slipstream_hint_build_duration: Histogram,
    /// Time spent waiting for access-list simulation capacity.
    slipstream_hint_permit_wait_duration: Histogram,
    /// Failed or timed-out access-list hint generations.
    slipstream_hint_build_error_count: Counter,
    /// Access-list simulations that exceeded the per-hint execution timeout.
    slipstream_hint_simulation_timeout_count: Counter,
    /// Access-list simulations that failed after acquiring capacity.
    slipstream_hint_simulation_error_count: Counter,
    /// Transactions that could not be decoded or prepared for access-list simulation.
    slipstream_hint_preparation_error_count: Counter,
}

#[derive(Clone)]
pub struct SlipstreamRpcExt<Eth> {
    sequencer_client: SequencerClient,
    eth_api: Eth,
    compute_hints: bool,
    config: SlipstreamConfig,
    forward_permits: Arc<Semaphore>,
    hint_permits: Arc<Semaphore>,
    metrics: SlipstreamMetrics,
}

impl<Eth> SlipstreamRpcExt<Eth> {
    pub fn new(
        sequencer_client: SequencerClient,
        eth_api: Eth,
        compute_hints: bool,
        config: SlipstreamConfig,
    ) -> Self {
        Self {
            sequencer_client,
            eth_api,
            compute_hints,
            config,
            forward_permits: Arc::new(Semaphore::new(config.forward_concurrency)),
            hint_permits: Arc::new(Semaphore::new(config.build_concurrency)),
            metrics: SlipstreamMetrics::default(),
        }
    }
}

#[async_trait]
impl<Eth> SlipstreamApiServer for SlipstreamRpcExt<Eth>
where
    Eth: FullEthApi<NetworkTypes = Optimism> + 'static,
{
    async fn send_raw_transaction_batch(&self, txs: Vec<Bytes>) -> RpcResult<SlipstreamBatchAck> {
        self.forward_batch(txs).await
    }
}

impl<Eth> SlipstreamRpcExt<Eth>
where
    Eth: FullEthApi<NetworkTypes = Optimism> + 'static,
{
    async fn forward_batch(&self, txs: Vec<Bytes>) -> RpcResult<SlipstreamBatchAck> {
        self.metrics.slipstream_forwarded_batches.increment(1);
        self.metrics.slipstream_forwarded_txs.increment(txs.len() as u64);
        debug!(
            target: "slipstream",
            txs = txs.len(),
            endpoint = self.sequencer_client.endpoint(),
            "forwarding Slipstream batch to configured sequencer"
        );

        if self.compute_hints {
            let minimum_hinted_size = unhinted_txs_json_size(&txs);
            if minimum_hinted_size > self.config.max_batch_bytes {
                warn!(
                    target: "slipstream",
                    minimum_hinted_size,
                    "Slipstream batch cannot fit the hinted forwarding size limit; forwarding without hints"
                );
            } else {
                let hinted_txs = self.build_hints(txs.clone()).await;
                let hinted_size = hinted_txs_json_size(&hinted_txs);
                if hinted_size <= self.config.max_batch_bytes {
                    let _permit = self.acquire_forward_permit().await?;
                    let request = self
                        .sequencer_client
                        .request(SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD, (hinted_txs,));
                    let response = tokio::time::timeout(self.config.forward_timeout, request)
                        .await
                        .map_err(|_| {
                            self.metrics.slipstream_forward_error_count.increment(1);
                            forwarding_timeout_error()
                        })?;
                    match response {
                        Ok(ack) => return Ok(ack),
                        Err(err) if is_method_not_found(&err) => warn!(
                            target: "slipstream",
                            endpoint = self.sequencer_client.endpoint(),
                            "active sequencer does not support Slipstream hints; forwarding without hints"
                        ),
                        Err(err) => {
                            self.record_forward_error(&err);
                            return Err(ErrorObjectOwned::from(err));
                        }
                    }
                } else {
                    warn!(
                        target: "slipstream",
                        hinted_size,
                        "computed Slipstream hints exceed the forwarding size limit; forwarding without hints"
                    );
                }
            }
        }

        let _permit = self.acquire_forward_permit().await?;
        let request = self.sequencer_client.request(SEND_RAW_TRANSACTION_BATCH_METHOD, (txs,));
        tokio::time::timeout(self.config.forward_timeout, request)
            .await
            .map_err(|_| {
                self.metrics.slipstream_forward_error_count.increment(1);
                forwarding_timeout_error()
            })?
            .inspect_err(|err| self.record_forward_error(err))
            .map_err(ErrorObjectOwned::from)
    }

    async fn acquire_forward_permit(&self) -> Result<OwnedSemaphorePermit, ErrorObjectOwned> {
        tokio::time::timeout(
            self.config.forward_timeout,
            Arc::clone(&self.forward_permits).acquire_owned(),
        )
        .await
        .map_err(|_| {
            self.metrics.slipstream_forward_error_count.increment(1);
            forwarding_timeout_error()
        })
        .map(|permit| permit.expect("Slipstream forwarding semaphore is never closed"))
    }

    fn record_forward_error(&self, err: &impl std::fmt::Display) {
        self.metrics.slipstream_forward_error_count.increment(1);
        warn!(
            target: "slipstream",
            error = %err,
            endpoint = self.sequencer_client.endpoint(),
            "failed to forward Slipstream batch to sequencer"
        );
    }

    async fn build_hints(&self, txs: Vec<Bytes>) -> Vec<SlipstreamHintedTx> {
        let permits = Arc::clone(&self.hint_permits);
        let mut hinted = stream::iter(txs.into_iter().enumerate())
            .map(|(index, tx)| {
                let permits = Arc::clone(&permits);
                async move {
                    self.metrics.slipstream_hint_build_attempt_count.increment(1);
                    let permit_wait_started = std::time::Instant::now();
                    let permit = permits
                        .acquire_owned()
                        .await
                        .expect("Slipstream hint semaphore is never closed");
                    self.metrics
                        .slipstream_hint_permit_wait_duration
                        .record(permit_wait_started.elapsed());
                    let started = std::time::Instant::now();
                    let result = match prepare_hint(&tx) {
                        Ok((request, state_override, sender, destination)) => {
                            let eth_api = self.eth_api.clone();
                            // State reads are not cancellable. The detached task retains its permit after
                            // timeout so replacement work cannot exceed the node-wide concurrency cap.
                            let mut task = tokio::spawn(async move {
                                let _permit = permit;
                                EthCall::create_access_list_at(
                                    &eth_api,
                                    request,
                                    Some(BlockId::latest()),
                                    Some(state_override),
                                )
                                .await
                                .map_err(|err| err.to_string())
                                .and_then(|result| match result.error {
                                    Some(err) => Err(err),
                                    None => {
                                        let mut access_list = result.access_list;
                                        add_hint_accounts(
                                            &mut access_list,
                                            [Some(sender), destination],
                                        );
                                        Ok(access_list)
                                    }
                                })
                            });
                            // Start the simulation timeout only after the permit is acquired and
                            // the transaction is prepared.
                            match tokio::time::timeout(self.config.build_timeout, &mut task).await {
                                Ok(Ok(Ok(hint))) => Ok(hint),
                                Ok(Ok(Err(err))) => Err(HintBuildFailure::Simulation(err)),
                                Ok(Err(err)) => Err(HintBuildFailure::Simulation(format!(
                                    "hint task failed: {err}"
                                ))),
                                Err(_) => Err(HintBuildFailure::SimulationTimeout),
                            }
                        }
                        Err(err) => {
                            drop(permit);
                            Err(HintBuildFailure::Preparation(err))
                        }
                    };
                    let hint = match result {
                        Ok(hint) => {
                            self.metrics.slipstream_hint_build_success_count.increment(1);
                            Some(hint)
                        }
                        Err(failure) => {
                        self.metrics.slipstream_hint_build_error_count.increment(1);
                            match &failure {
                                HintBuildFailure::SimulationTimeout => self
                                    .metrics
                                    .slipstream_hint_simulation_timeout_count
                                    .increment(1),
                                HintBuildFailure::Simulation(_) => self
                                    .metrics
                                    .slipstream_hint_simulation_error_count
                                    .increment(1),
                                HintBuildFailure::Preparation(_) => self
                                    .metrics
                                    .slipstream_hint_preparation_error_count
                                    .increment(1),
                            }
                            debug!(target: "slipstream", index, error = %failure, "failed to build Slipstream access-list hint");
                            None
                        }
                    };
                    self.metrics.slipstream_hint_build_duration.record(started.elapsed());
                    (index, SlipstreamHintedTx { tx, hint })
                }
            })
            .buffer_unordered(self.config.build_concurrency)
            .collect::<Vec<_>>()
            .await;
        hinted.sort_unstable_by_key(|(index, _)| *index);
        hinted.into_iter().map(|(_, tx)| tx).collect()
    }
}

enum HintBuildFailure {
    SimulationTimeout,
    Simulation(String),
    Preparation(String),
}

impl std::fmt::Display for HintBuildFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimulationTimeout => f.write_str("hint simulation timed out"),
            Self::Simulation(err) | Self::Preparation(err) => f.write_str(err),
        }
    }
}

fn prepare_hint(
    raw: &Bytes,
) -> Result<(OpTransactionRequest, StateOverride, Address, Option<Address>), String> {
    let recovered =
        recover_raw_transaction::<OpPooledTransaction>(raw).map_err(|err| err.to_string())?;
    let signer = recovered.signer();
    let nonce = recovered.nonce();
    let destination = recovered.to();
    let mut request: OpTransactionRequest = match recovered.into_inner() {
        OpPooledTransaction::Legacy(tx) => tx.into(),
        OpPooledTransaction::Eip2930(tx) => tx.into(),
        OpPooledTransaction::Eip1559(tx) => tx.into(),
        OpPooledTransaction::Eip7702(tx) => tx.into(),
    };
    // Access-list entries add intrinsic gas. Reusing a tightly estimated signed gas limit can
    // therefore make discovery report out-of-gas solely because of the list it just discovered.
    // Let the simulation estimate its own gas; the forwarded signed transaction is unchanged.
    request.as_mut().gas = None;
    let state_override = StateOverridesBuilder::default()
        .with_nonce(signer, nonce)
        .with_balance(signer, U256::MAX)
        .build();
    Ok((request.from(signer), state_override, signer, destination))
}

fn add_hint_accounts(
    access_list: &mut AccessList,
    accounts: impl IntoIterator<Item = Option<Address>>,
) {
    for address in accounts.into_iter().flatten() {
        if !access_list.0.iter().any(|item| item.address == address) {
            access_list.0.push(AccessListItem { address, storage_keys: Vec::new() });
        }
    }
}

fn hinted_txs_json_size(txs: &[SlipstreamHintedTx]) -> usize {
    let mut size = 2usize.saturating_add(txs.len().saturating_sub(1));
    for tx in txs {
        size = size.saturating_add(11usize.saturating_add(tx.tx.len().saturating_mul(2)));
        if let Some(hint) = &tx.hint {
            size = size.saturating_add(10);
            size = size.saturating_add(hint.0.len().saturating_sub(1));
            for item in &hint.0 {
                size = size.saturating_add(73);
                size = size.saturating_add(item.storage_keys.len().saturating_sub(1));
                size = size.saturating_add(item.storage_keys.len().saturating_mul(68));
            }
        }
    }
    size
}

fn unhinted_txs_json_size(txs: &[Bytes]) -> usize {
    let mut size = 2usize.saturating_add(txs.len().saturating_sub(1));
    for tx in txs {
        size = size.saturating_add(11usize.saturating_add(tx.len().saturating_mul(2)));
    }
    size
}

fn is_method_not_found(err: &SequencerClientError) -> bool {
    matches!(
        err,
        SequencerClientError::HttpError(RpcError::ErrorResp(payload)) if payload.code == -32601
    )
}

fn forwarding_timeout_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, "Slipstream forwarding timed out", None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, hex};

    #[test]
    fn hint_simulation_does_not_inherit_signed_gas_limit() {
        let raw = Bytes::from(hex!(
            "02f86a82038502018206a9826e129442000000000000000000000000000000000000060484d0e30db0c080a0b321803fa4187e8e965aad318bc38ba58a630c7954eb98adb99db6a565cacd29a0688328cbec3b0ba0ac1f7097767c5a5e552ee7b7bdab32ccc0cef07bf56a1eda"
        ));

        let (request, _, _, _) = prepare_hint(&raw).unwrap();
        let request: alloy_rpc_types_eth::TransactionRequest = request.into();

        assert_eq!(request.gas, None);
        assert_eq!(request.nonce, Some(2));
    }

    #[test]
    fn hint_includes_sender_and_destination_without_losing_existing_storage_keys() {
        let sender = address!("1000000000000000000000000000000000000000");
        let destination = address!("2000000000000000000000000000000000000000");
        let other = address!("3000000000000000000000000000000000000000");
        let keys = vec![B256::ZERO, B256::repeat_byte(1)];
        let mut hint = AccessList(vec![
            AccessListItem { address: destination, storage_keys: keys.clone() },
            AccessListItem { address: other, storage_keys: vec![B256::repeat_byte(2)] },
        ]);

        add_hint_accounts(&mut hint, [Some(sender), Some(destination)]);

        assert_eq!(hint.0.len(), 3);
        assert_eq!(hint.0[0].address, destination);
        assert_eq!(hint.0[0].storage_keys, keys);
        assert_eq!(hint.0[2], AccessListItem { address: sender, storage_keys: Vec::new() });
    }

    #[test]
    fn hint_accounts_handle_self_transfer_and_contract_creation() {
        let sender = address!("1000000000000000000000000000000000000000");
        let mut hint = AccessList::default();

        add_hint_accounts(&mut hint, [Some(sender), Some(sender)]);
        add_hint_accounts(&mut hint, [Some(sender), None]);

        assert_eq!(
            hint,
            AccessList(vec![AccessListItem { address: sender, storage_keys: Vec::new() }])
        );
    }

    #[test]
    fn hinted_wire_format_and_size_match_builder() {
        let txs = vec![
            SlipstreamHintedTx { tx: Bytes::from_static(&[1, 2]), hint: None },
            SlipstreamHintedTx {
                tx: Bytes::from_static(&[3]),
                hint: Some(AccessList(vec![AccessListItem {
                    address: Address::ZERO,
                    storage_keys: vec![B256::ZERO, B256::repeat_byte(1)],
                }])),
            },
        ];

        assert_eq!(hinted_txs_json_size(&txs), serde_json::to_vec(&txs).unwrap().len());
        assert_eq!(
            unhinted_txs_json_size(&txs.iter().map(|tx| tx.tx.clone()).collect::<Vec<_>>()),
            serde_json::to_vec(
                &txs.iter()
                    .map(|tx| SlipstreamHintedTx { tx: tx.tx.clone(), hint: None })
                    .collect::<Vec<_>>()
            )
            .unwrap()
            .len()
        );

        let value = serde_json::to_value(&txs[1]).unwrap();
        assert_eq!(value["tx"], "0x03");
        assert!(value["hint"].is_array());
    }
}
