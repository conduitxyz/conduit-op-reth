//! Optional G3 Slipstream RPC extensions for OP-Reth replicas.
//!
//! Public RPC requests reach OP-Reth replicas, while the active op-rbuilder
//! sequencer owns the Slipstream mailbox. The public batch method is proxied
//! directly to the configured sequencer. The sync override submits immutable
//! signed bytes through the same forwarding helper, then obtains the normal
//! RPC receipt from this replica's pending-flashblock overlay. The ordinary
//! txpool is never used by the sync path.
//!
//! Client cancellation drops the retry/receipt-wait future. An attempt already
//! accepted by the sequencer may still be included, matching the stock sync
//! method's timeout and cancellation semantics.

use std::{future::Future, time::Duration};

use alloy_json_rpc::{ErrorPayload, RpcObject};
use alloy_primitives::{B256, Bytes, keccak256};
use alloy_rpc_types_eth::error::EthRpcErrorCode;
use alloy_transport::RpcError;
use conduit_op_reth_rpc_api::{
    SEND_RAW_TRANSACTION_BATCH_METHOD, SlipstreamApiServer, SlipstreamBatchAck,
    SlipstreamSyncApiServer,
};
#[cfg(test)]
use conduit_op_reth_rpc_api::{
    SEND_RAW_TRANSACTION_SYNC_METHOD, SlipstreamIncludedTx, SlipstreamRejectedTx, SlipstreamRetryTx,
};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    types::ErrorObjectOwned,
};
use reth_optimism_rpc::{SequencerClient, SequencerClientError};
use reth_rpc_eth_api::{
    RpcReceipt,
    helpers::{EthTransactions, FullEthApi},
};
use reth_rpc_eth_types::EthApiError;
use tracing::warn;

const RETRY_BACKOFF: Duration = Duration::from_millis(10);

const INVALID_REQUEST_CODE: i32 = -32600;
const METHOD_NOT_FOUND_CODE: i32 = -32601;
const INVALID_PARAMS_CODE: i32 = -32602;
const INTERNAL_ERROR_CODE: i32 = -32603;

/// Replica-side implementation of the optional synchronous Slipstream path.
#[derive(Clone)]
pub struct SlipstreamSyncExt<Eth> {
    eth_api: Eth,
    sequencer_client: SequencerClient,
}

impl<Eth> SlipstreamSyncExt<Eth> {
    /// Creates the extension with the replica's registered eth API and its
    /// existing configured sequencer client.
    pub const fn new(eth_api: Eth, sequencer_client: SequencerClient) -> Self {
        Self { eth_api, sequencer_client }
    }
}

enum SingleTxVerdict {
    Included,
    Rejected(String),
    Retry { ambiguous: bool },
}

fn classify_single_ack(ack: SlipstreamBatchAck) -> SingleTxVerdict {
    if ack.included.into_iter().any(|tx| tx.index == 0) {
        SingleTxVerdict::Included
    } else if let Some(rejected) = ack.rejected.into_iter().find(|tx| tx.index == 0) {
        SingleTxVerdict::Rejected(rejected.error)
    } else if let Some(retry) = ack.retry.into_iter().find(|tx| tx.index == 0) {
        SingleTxVerdict::Retry { ambiguous: retry.reason == "verdict-unavailable" }
    } else {
        SingleTxVerdict::Retry { ambiguous: true }
    }
}

#[derive(Debug)]
enum SubmitFailure {
    Retry(String),
    Fatal(ErrorObjectOwned),
}

fn classify_submit_error(error: SequencerClientError) -> SubmitFailure {
    match error {
        SequencerClientError::HttpError(RpcError::ErrorResp(ErrorPayload {
            code,
            message,
            ..
        })) if matches!(
            code as i32,
            INVALID_REQUEST_CODE | METHOD_NOT_FOUND_CODE | INVALID_PARAMS_CODE
        ) =>
        {
            SubmitFailure::Fatal(ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                format!("configured sequencer does not support the Slipstream RPC: {message}"),
                None::<()>,
            ))
        }
        error => SubmitFailure::Retry(error.to_string()),
    }
}

async fn forward_batch_to_slipstream(
    sequencer_client: &SequencerClient,
    raw_txs: Vec<Bytes>,
) -> Result<SlipstreamBatchAck, SequencerClientError> {
    sequencer_client.request(SEND_RAW_TRANSACTION_BATCH_METHOD, (raw_txs,)).await
}

async fn submit_to_slipstream(
    sequencer_client: &SequencerClient,
    raw_tx: Bytes,
) -> Result<SlipstreamBatchAck, SubmitFailure> {
    forward_batch_to_slipstream(sequencer_client, vec![raw_tx]).await.map_err(classify_submit_error)
}

fn transaction_rejected(reason: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        EthRpcErrorCode::TransactionRejected.code(),
        format!("Slipstream rejected transaction: {reason}"),
        None::<()>,
    )
}

fn confirmation_timeout(hash: B256, duration: Duration) -> ErrorObjectOwned {
    EthApiError::TransactionConfirmationTimeout { hash, duration }.into()
}

async fn with_confirmation_timeout<R, F>(
    hash: B256,
    duration: Duration,
    operation: F,
) -> RpcResult<R>
where
    F: Future<Output = RpcResult<R>>,
{
    match tokio::time::timeout(duration, operation).await {
        Ok(result) => result,
        Err(_) => Err(confirmation_timeout(hash, duration)),
    }
}

/// Retries one immutable signed transaction until Slipstream includes or
/// rejects it. Once included, only the local authoritative receipt is polled;
/// the transaction is never submitted again.
async fn submit_single_with_retry<R, Submit, SubmitFuture, Receipt, ReceiptFuture>(
    raw_tx: Bytes,
    mut submit: Submit,
    mut receipt: Receipt,
) -> RpcResult<R>
where
    Submit: FnMut(Bytes) -> SubmitFuture,
    SubmitFuture: Future<Output = Result<SlipstreamBatchAck, SubmitFailure>>,
    Receipt: FnMut(B256) -> ReceiptFuture,
    ReceiptFuture: Future<Output = RpcResult<Option<R>>>,
{
    let hash = keccak256(&raw_tx);
    let mut included = false;
    let mut ambiguous_attempt = false;

    loop {
        // If a prior network attempt reached the builder but lost its response,
        // prefer the resulting receipt over submitting a duplicate.
        if let Some(receipt) = receipt(hash).await? {
            return Ok(receipt);
        }

        if included {
            tokio::time::sleep(RETRY_BACKOFF).await;
            continue;
        }

        match submit(raw_tx.clone()).await {
            Ok(ack) => match classify_single_ack(ack) {
                SingleTxVerdict::Included => included = true,
                SingleTxVerdict::Rejected(reason) => {
                    if ambiguous_attempt {
                        // A previous attempt may have reached the mailbox and
                        // lost its response. A later duplicate can then be
                        // rejected even though the original will be included.
                        // Stop resubmitting and let the authoritative receipt
                        // or outer confirmation timeout resolve the ambiguity.
                        included = true;
                    } else {
                        return Err(transaction_rejected(reason));
                    }
                }
                SingleTxVerdict::Retry { ambiguous } => ambiguous_attempt |= ambiguous,
            },
            Err(SubmitFailure::Fatal(error)) => return Err(error),
            Err(SubmitFailure::Retry(error)) => {
                ambiguous_attempt = true;
                warn!(target: "rpc::slipstream", %error, "transient Slipstream submission failure");
            }
        }

        tokio::time::sleep(RETRY_BACKOFF).await;
    }
}

#[async_trait]
impl<Eth> SlipstreamApiServer for SlipstreamSyncExt<Eth>
where
    Eth: Send + Sync + 'static,
{
    async fn send_raw_transaction_batch(
        &self,
        raw_txs: Vec<Bytes>,
    ) -> RpcResult<SlipstreamBatchAck> {
        forward_batch_to_slipstream(&self.sequencer_client, raw_txs).await.map_err(Into::into)
    }
}

#[async_trait]
impl<Eth> SlipstreamSyncApiServer<RpcReceipt<Eth::NetworkTypes>> for SlipstreamSyncExt<Eth>
where
    Eth: FullEthApi + Clone + 'static,
    RpcReceipt<Eth::NetworkTypes>: RpcObject,
{
    async fn send_raw_transaction_sync(
        &self,
        raw_tx: Bytes,
    ) -> RpcResult<RpcReceipt<Eth::NetworkTypes>> {
        let hash = keccak256(&raw_tx);
        let timeout_duration = EthTransactions::send_raw_transaction_sync_timeout(&self.eth_api);
        let sequencer_client = self.sequencer_client.clone();
        let submit = move |raw_tx| {
            let sequencer_client = sequencer_client.clone();
            async move { submit_to_slipstream(&sequencer_client, raw_tx).await }
        };
        let eth_api = self.eth_api.clone();
        let receipt = move |hash| {
            let eth_api = eth_api.clone();
            async move { EthTransactions::transaction_receipt(&eth_api, hash).await.map_err(Into::into) }
        };

        with_confirmation_timeout(
            hash,
            timeout_duration,
            submit_single_with_retry(raw_tx, submit, receipt),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{RpcModule, server::ServerBuilder};
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    fn included_ack() -> SlipstreamBatchAck {
        SlipstreamBatchAck {
            included: vec![SlipstreamIncludedTx {
                index: 0,
                hash: B256::ZERO,
                sender: Default::default(),
                nonce: 0,
                block_number: 1,
                flashblock_index: 0,
            }],
            ..Default::default()
        }
    }

    fn rejected_ack(reason: &str) -> SlipstreamBatchAck {
        SlipstreamBatchAck {
            rejected: vec![SlipstreamRejectedTx { index: 0, error: reason.to_string() }],
            ..Default::default()
        }
    }

    fn retry_ack(reason: &str) -> SlipstreamBatchAck {
        SlipstreamBatchAck {
            retry: vec![SlipstreamRetryTx { index: 0, reason: reason.to_string() }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn included_transaction_returns_authoritative_receipt() {
        let included = Arc::new(AtomicBool::new(false));
        let submit_included = included.clone();
        let submit = move |_| {
            submit_included.store(true, Ordering::SeqCst);
            async { Ok(included_ack()) }
        };
        let receipt_included = included.clone();
        let receipt = move |_| {
            let value = receipt_included.load(Ordering::SeqCst).then_some(42u64);
            async move { Ok(value) }
        };

        assert_eq!(
            submit_single_with_retry(Bytes::from_static(b"signed tx"), submit, receipt)
                .await
                .unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn rejection_returns_transaction_error_with_reason() {
        let submit = |_| async { Ok(rejected_ack("nonce-too-low")) };
        let receipt = |_| async { Ok(None::<u64>) };

        let error =
            submit_single_with_retry(Bytes::from_static(b"tx"), submit, receipt).await.unwrap_err();

        assert_eq!(error.code(), EthRpcErrorCode::TransactionRejected.code());
        assert!(error.message().contains("nonce-too-low"));
    }

    #[tokio::test]
    async fn retry_then_inclusion_preserves_signed_bytes() {
        let raw_tx = Bytes::from_static(b"immutable signed bytes");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let outcomes =
            Arc::new(Mutex::new(VecDeque::from([retry_ack("mailbox-full"), included_ack()])));
        let included = Arc::new(AtomicBool::new(false));
        let submit_seen = seen.clone();
        let submit_outcomes = outcomes.clone();
        let submit_included = included.clone();
        let submit = move |submitted: Bytes| {
            submit_seen.lock().unwrap().push(submitted);
            let ack = submit_outcomes.lock().unwrap().pop_front().unwrap();
            if !ack.included.is_empty() {
                submit_included.store(true, Ordering::SeqCst);
            }
            async move { Ok(ack) }
        };
        let receipt_included = included.clone();
        let receipt = move |_| {
            let value = receipt_included.load(Ordering::SeqCst).then_some(7u64);
            async move { Ok(value) }
        };

        assert_eq!(submit_single_with_retry(raw_tx.clone(), submit, receipt).await.unwrap(), 7);
        assert_eq!(seen.lock().unwrap().as_slice(), &[raw_tx.clone(), raw_tx]);
    }

    #[tokio::test]
    async fn missing_verdict_is_retried() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let submit_attempts = attempts.clone();
        let included = Arc::new(AtomicBool::new(false));
        let submit_included = included.clone();
        let submit = move |_| {
            let attempt = submit_attempts.fetch_add(1, Ordering::SeqCst);
            let ack = if attempt == 0 {
                SlipstreamBatchAck::default()
            } else {
                submit_included.store(true, Ordering::SeqCst);
                included_ack()
            };
            async move { Ok(ack) }
        };
        let receipt_included = included.clone();
        let receipt = move |_| {
            let value = receipt_included.load(Ordering::SeqCst).then_some(1u64);
            async move { Ok(value) }
        };

        assert_eq!(
            submit_single_with_retry(Bytes::from_static(b"tx"), submit, receipt).await.unwrap(),
            1
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ambiguous_retry_prefers_late_receipt_over_duplicate_rejection() {
        let outcomes = Arc::new(Mutex::new(VecDeque::from([
            SlipstreamBatchAck::default(),
            rejected_ack("nonce-too-low"),
        ])));
        let submit_outcomes = outcomes.clone();
        let submit = move |_| {
            let ack = submit_outcomes.lock().unwrap().pop_front().unwrap();
            async move { Ok(ack) }
        };
        let receipt_checks = Arc::new(AtomicUsize::new(0));
        let checks = receipt_checks.clone();
        let receipt = move |_| {
            let value = (checks.fetch_add(1, Ordering::SeqCst) >= 3).then_some(5u64);
            async move { Ok(value) }
        };

        assert_eq!(
            submit_single_with_retry(Bytes::from_static(b"tx"), submit, receipt).await.unwrap(),
            5
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ambiguous_duplicate_rejection_waits_for_outer_deadline() {
        let raw_tx = Bytes::from_static(b"tx");
        let hash = keccak256(&raw_tx);
        let outcomes = Arc::new(Mutex::new(VecDeque::from([
            SlipstreamBatchAck::default(),
            rejected_ack("nonce-too-low"),
        ])));
        let submit_outcomes = outcomes.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let submit_attempts = attempts.clone();
        let submit = move |_| {
            submit_attempts.fetch_add(1, Ordering::SeqCst);
            let ack = submit_outcomes.lock().unwrap().pop_front().unwrap();
            async move { Ok(ack) }
        };
        let receipt = |_| async { Ok(None::<u64>) };
        let timeout_duration = Duration::from_millis(25);

        let error = with_confirmation_timeout(
            hash,
            timeout_duration,
            submit_single_with_retry(raw_tx, submit, receipt),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), EthRpcErrorCode::TransactionConfirmationTimeout.code());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_retries_stop_at_configured_sync_deadline() {
        let raw_tx = Bytes::from_static(b"tx");
        let hash = keccak256(&raw_tx);
        let attempts = Arc::new(AtomicUsize::new(0));
        let submit_attempts = attempts.clone();
        let submit = move |_| {
            submit_attempts.fetch_add(1, Ordering::SeqCst);
            async { Ok(retry_ack("job-cancelled")) }
        };
        let receipt = |_| async { Ok(None::<u64>) };
        let timeout_duration = Duration::from_millis(25);

        let error = with_confirmation_timeout(
            hash,
            timeout_duration,
            submit_single_with_retry(raw_tx, submit, receipt),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), EthRpcErrorCode::TransactionConfirmationTimeout.code());
        assert!(error.message().contains(&hash.to_string()));
        assert!(attempts.load(Ordering::SeqCst) > 1);
    }

    #[tokio::test]
    async fn public_batch_api_directly_forwards_and_returns_sequencer_ack() {
        let raw_txs = vec![
            Bytes::from_static(b"signed transaction 1"),
            Bytes::from_static(b"signed transaction 2"),
        ];
        let expected = raw_txs.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let server_calls = calls.clone();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut module = RpcModule::new(());
        module
            .register_async_method(SEND_RAW_TRANSACTION_BATCH_METHOD, move |params, _, _| {
                let expected = expected.clone();
                let server_calls = server_calls.clone();
                async move {
                    let (received,): (Vec<Bytes>,) = params.parse()?;
                    assert_eq!(received, expected);
                    server_calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ErrorObjectOwned>(included_ack())
                }
            })
            .unwrap();
        let handle = server.start(module);
        let client = SequencerClient::new(format!("http://{address}")).await.unwrap();
        let ext = SlipstreamSyncExt::new((), client);

        let ack = SlipstreamApiServer::send_raw_transaction_batch(&ext, raw_txs).await.unwrap();

        assert!(matches!(classify_single_ack(ack), SingleTxVerdict::Included));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn missing_slipstream_method_fails_immediately() {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut module = RpcModule::new(());
        module.register_method("rpc_other", |_, _, _| "ok").unwrap();
        let handle = server.start(module);
        let client = SequencerClient::new(format!("http://{address}")).await.unwrap();

        let error = submit_to_slipstream(&client, Bytes::from_static(b"tx")).await.unwrap_err();

        let SubmitFailure::Fatal(error) = error else { panic!("method-not-found must be fatal") };
        assert_eq!(error.code(), INTERNAL_ERROR_CODE);
        assert!(error.message().contains("does not support"));
        handle.stop().unwrap();
    }

    #[derive(Clone)]
    struct TestRpc;

    #[async_trait]
    impl SlipstreamApiServer for TestRpc {
        async fn send_raw_transaction_batch(
            &self,
            _txs: Vec<Bytes>,
        ) -> RpcResult<SlipstreamBatchAck> {
            Ok(SlipstreamBatchAck::default())
        }
    }

    #[async_trait]
    impl SlipstreamSyncApiServer<u64> for TestRpc {
        async fn send_raw_transaction_sync(&self, _tx: Bytes) -> RpcResult<u64> {
            Ok(1)
        }
    }

    #[test]
    fn rpc_extensions_expose_batch_and_replace_only_send_raw_transaction_sync() {
        let mut module = SlipstreamApiServer::into_rpc(TestRpc);
        module.merge(SlipstreamSyncApiServer::into_rpc(TestRpc)).unwrap();

        let method_names = module.method_names().collect::<Vec<_>>();
        assert_eq!(
            method_names,
            [SEND_RAW_TRANSACTION_BATCH_METHOD, SEND_RAW_TRANSACTION_SYNC_METHOD]
        );
        assert!(!module.method_names().any(|name| name == "eth_sendRawTransaction"));
        assert_eq!(
            module.method_names().filter(|name| *name == SEND_RAW_TRANSACTION_SYNC_METHOD).count(),
            1
        );
    }
}
