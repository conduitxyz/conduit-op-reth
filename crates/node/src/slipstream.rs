//! Optional public Slipstream batch proxy for OP-Reth replicas.
//!
//! Public RPC requests reach OP-Reth replicas, while the active op-rbuilder
//! owns the Slipstream mailbox. This module rejects transactions that are
//! statically invalid, forwards the rest unchanged to the configured
//! leader-aware sequencer endpoint and returns its response with the original
//! request indexes.
//!
//! The replica only mirrors checks that cannot drift from the sequencer: empty
//! bytes, decoding and signature recovery, and the chain ID. Batch size, fee cap
//! and gas limit depend on sequencer configuration or state and stay with the
//! sequencer, which still runs every check and remains authoritative.

use alloy_consensus::{Transaction, transaction::SignerRecoverable};
use alloy_eips::{eip2718::Decodable2718, eip2930::AccessList};
use alloy_primitives::Bytes;
use conduit_op_reth_rpc_api::{
    SEND_RAW_TRANSACTION_BATCH_METHOD, SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD,
    SlipstreamApiServer, SlipstreamBatchAck, SlipstreamHintedTx, SlipstreamRejectedTx,
    SlipstreamWarmAck, WARM_HINTS_METHOD,
};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    types::ErrorObjectOwned,
};
use op_alloy_consensus::OpTxEnvelope;
use reth_optimism_rpc::SequencerClient;

/// Replica-side proxy for the public Slipstream batch API.
#[derive(Clone)]
pub struct SlipstreamProxy {
    sequencer_client: SequencerClient,
    chain_id: u64,
}

impl SlipstreamProxy {
    /// Creates a proxy using the replica's configured sequencer client.
    pub const fn new(sequencer_client: SequencerClient, chain_id: u64) -> Self {
        Self { sequencer_client, chain_id }
    }

    /// Splits a batch into local rejections and the original indexes of the
    /// transactions that should be forwarded.
    fn precheck<'a>(
        &self,
        raw_txs: impl Iterator<Item = &'a Bytes>,
    ) -> (Vec<SlipstreamRejectedTx>, Vec<usize>) {
        let mut rejected = Vec::new();
        let mut forwarded = Vec::new();
        for (index, raw) in raw_txs.enumerate() {
            match precheck_raw_tx(raw, self.chain_id) {
                Ok(()) => forwarded.push(index),
                Err(error) => rejected.push(SlipstreamRejectedTx { index, error }),
            }
        }
        (rejected, forwarded)
    }
}

/// Rejects a raw transaction that the sequencer would reject regardless of its
/// state or configuration.
fn precheck_raw_tx(raw: &Bytes, chain_id: u64) -> Result<(), String> {
    if raw.is_empty() {
        return Err("empty transaction".to_string());
    }
    let tx = OpTxEnvelope::decode_2718_exact(raw)
        .map_err(|err| format!("failed to decode transaction: {err}"))?;
    tx.recover_signer().map_err(|_| "invalid transaction signature".to_string())?;
    // Pre-EIP-155 legacy transactions carry no chain ID and are left to the sequencer.
    if let Some(tx_chain_id) = tx.chain_id() &&
        tx_chain_id != chain_id
    {
        return Err(format!("invalid chain id: expected {chain_id}, got {tx_chain_id}"));
    }
    Ok(())
}

/// Maps the indexes of a sequencer response for the forwarded subset back to
/// the original request and merges in the local rejections.
fn merge_acks(
    mut ack: SlipstreamBatchAck,
    forwarded: &[usize],
    mut rejected: Vec<SlipstreamRejectedTx>,
) -> RpcResult<SlipstreamBatchAck> {
    let remap = |index: usize| {
        forwarded.get(index).copied().ok_or_else(|| {
            ErrorObjectOwned::owned(
                jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                format!("sequencer returned out-of-range batch index {index}"),
                None::<()>,
            )
        })
    };
    for tx in &mut ack.included {
        tx.index = remap(tx.index)?;
    }
    for tx in &mut ack.rejected {
        tx.index = remap(tx.index)?;
    }
    for tx in &mut ack.retry {
        tx.index = remap(tx.index)?;
    }
    rejected.append(&mut ack.rejected);
    rejected.sort_by_key(|tx| tx.index);
    ack.rejected = rejected;
    Ok(ack)
}

#[async_trait]
impl SlipstreamApiServer for SlipstreamProxy {
    async fn send_raw_transaction_batch(
        &self,
        raw_txs: Vec<Bytes>,
    ) -> RpcResult<SlipstreamBatchAck> {
        let (rejected, forwarded) = self.precheck(raw_txs.iter());
        if forwarded.is_empty() {
            return Ok(SlipstreamBatchAck { rejected, ..Default::default() });
        }
        let raw_txs = if rejected.is_empty() {
            raw_txs
        } else {
            forwarded.iter().map(|&index| raw_txs[index].clone()).collect()
        };
        let ack = self
            .sequencer_client
            .request(SEND_RAW_TRANSACTION_BATCH_METHOD, (raw_txs,))
            .await
            .map_err(Into::<ErrorObjectOwned>::into)?;
        merge_acks(ack, &forwarded, rejected)
    }

    async fn send_raw_transaction_batch_with_hints(
        &self,
        txs: Vec<SlipstreamHintedTx>,
    ) -> RpcResult<SlipstreamBatchAck> {
        let (rejected, forwarded) = self.precheck(txs.iter().map(|tx| &tx.tx));
        if forwarded.is_empty() {
            return Ok(SlipstreamBatchAck { rejected, ..Default::default() });
        }
        let txs = if rejected.is_empty() {
            txs
        } else {
            forwarded.iter().map(|&index| txs[index].clone()).collect()
        };
        let ack = self
            .sequencer_client
            .request(SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD, (txs,))
            .await
            .map_err(Into::<ErrorObjectOwned>::into)?;
        merge_acks(ack, &forwarded, rejected)
    }

    async fn warm_hints(&self, hints: Vec<AccessList>) -> RpcResult<SlipstreamWarmAck> {
        // Forwarded like the other two: the replica owns no mailbox and no prewarm pool, so the
        // hints have to reach whichever node is building.
        self.sequencer_client.request(WARM_HINTS_METHOD, (hints,)).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{B256, Signature, TxKind, U256};
    use conduit_op_reth_rpc_api::{SlipstreamIncludedTx, SlipstreamRetryTx};
    use jsonrpsee::{
        RpcModule,
        server::{ServerBuilder, ServerHandle},
    };
    use std::sync::{Arc, Mutex};

    const CHAIN_ID: u64 = 8453;

    fn eip1559_tx(chain_id: u64, nonce: u64, signature: Signature) -> Bytes {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Default::default()),
            ..Default::default()
        };
        OpTxEnvelope::Eip1559(tx.into_signed(signature)).encoded_2718().into()
    }

    fn valid_tx(nonce: u64) -> Bytes {
        eip1559_tx(CHAIN_ID, nonce, Signature::test_signature())
    }

    fn unrecoverable_signature() -> Signature {
        Signature::new(U256::ZERO, U256::ZERO, false)
    }

    fn included(index: usize) -> SlipstreamIncludedTx {
        SlipstreamIncludedTx {
            index,
            hash: B256::ZERO,
            sender: Default::default(),
            nonce: 0,
            block_number: 1,
            flashblock_index: 0,
        }
    }

    fn included_ack() -> SlipstreamBatchAck {
        SlipstreamBatchAck { included: vec![included(0)], ..Default::default() }
    }

    /// Mock sequencer that records every batch it receives and answers with `ack`.
    async fn mock_sequencer<T>(
        method: &'static str,
        ack: SlipstreamBatchAck,
    ) -> (SlipstreamProxy, ServerHandle, Arc<Mutex<Vec<Vec<T>>>>)
    where
        T: jsonrpsee::core::DeserializeOwned + Send + Sync + Clone + 'static,
    {
        let received = Arc::new(Mutex::new(Vec::new()));
        let server_received = received.clone();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut module = RpcModule::new(());
        module
            .register_async_method(method, move |params, _, _| {
                let server_received = server_received.clone();
                let ack = ack.clone();
                async move {
                    let (batch,): (Vec<T>,) = params.parse()?;
                    server_received.lock().unwrap().push(batch);
                    Ok::<_, ErrorObjectOwned>(ack)
                }
            })
            .unwrap();
        let handle = server.start(module);
        let client = SequencerClient::new(format!("http://{address}")).await.unwrap();
        (SlipstreamProxy::new(client, CHAIN_ID), handle, received)
    }

    #[test]
    fn precheck_rejects_statically_invalid_transactions() {
        assert_eq!(precheck_raw_tx(&Bytes::new(), CHAIN_ID).unwrap_err(), "empty transaction");
        assert!(
            precheck_raw_tx(&Bytes::from_static(b"not a transaction"), CHAIN_ID)
                .unwrap_err()
                .starts_with("failed to decode transaction")
        );
        assert_eq!(
            precheck_raw_tx(&eip1559_tx(CHAIN_ID, 0, unrecoverable_signature()), CHAIN_ID)
                .unwrap_err(),
            "invalid transaction signature"
        );
        assert_eq!(
            precheck_raw_tx(&eip1559_tx(1, 0, Signature::test_signature()), CHAIN_ID).unwrap_err(),
            "invalid chain id: expected 8453, got 1"
        );
        precheck_raw_tx(&valid_tx(0), CHAIN_ID).unwrap();
    }

    #[test]
    fn precheck_leaves_pre_eip155_transactions_to_the_sequencer() {
        let tx = TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Default::default()),
            ..Default::default()
        };
        let raw: Bytes =
            OpTxEnvelope::Legacy(tx.into_signed(Signature::test_signature())).encoded_2718().into();
        precheck_raw_tx(&raw, CHAIN_ID).unwrap();
    }

    #[tokio::test]
    async fn public_batch_api_directly_forwards_and_returns_sequencer_ack() {
        let raw_txs = vec![valid_tx(0), valid_tx(1)];
        let (proxy, handle, received) =
            mock_sequencer::<Bytes>(SEND_RAW_TRANSACTION_BATCH_METHOD, included_ack()).await;

        let ack =
            SlipstreamApiServer::send_raw_transaction_batch(&proxy, raw_txs.clone()).await.unwrap();

        assert_eq!(ack.included.len(), 1);
        assert_eq!(ack.included[0].index, 0);
        assert_eq!(*received.lock().unwrap(), vec![raw_txs]);
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn fully_invalid_batch_is_answered_without_forwarding() {
        let raw_txs = vec![Bytes::new(), eip1559_tx(1, 0, Signature::test_signature())];
        let (proxy, handle, received) =
            mock_sequencer::<Bytes>(SEND_RAW_TRANSACTION_BATCH_METHOD, included_ack()).await;

        let ack = SlipstreamApiServer::send_raw_transaction_batch(&proxy, raw_txs).await.unwrap();

        assert!(ack.included.is_empty());
        assert!(ack.retry.is_empty());
        assert_eq!(ack.rejected.iter().map(|tx| tx.index).collect::<Vec<_>>(), [0, 1]);
        assert!(received.lock().unwrap().is_empty());
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn mixed_batch_forwards_valid_bytes_and_restores_original_indexes() {
        // Original indexes: 0 invalid, 1 valid, 2 invalid, 3 valid, 4 valid.
        let raw_txs = vec![
            Bytes::new(),
            valid_tx(1),
            Bytes::from_static(b"garbage"),
            valid_tx(3),
            valid_tx(4),
        ];
        // The sequencer sees only [1, 3, 4] and answers with indexes into that subset.
        let sequencer_ack = SlipstreamBatchAck {
            included: vec![included(0)],
            rejected: vec![SlipstreamRejectedTx { index: 2, error: "nonce too low".into() }],
            retry: vec![SlipstreamRetryTx { index: 1, reason: "mailbox-full".into() }],
        };
        let (proxy, handle, received) =
            mock_sequencer::<Bytes>(SEND_RAW_TRANSACTION_BATCH_METHOD, sequencer_ack).await;

        let ack =
            SlipstreamApiServer::send_raw_transaction_batch(&proxy, raw_txs.clone()).await.unwrap();

        assert_eq!(
            *received.lock().unwrap(),
            vec![vec![raw_txs[1].clone(), raw_txs[3].clone(), raw_txs[4].clone()]]
        );
        assert_eq!(ack.included.iter().map(|tx| tx.index).collect::<Vec<_>>(), [1]);
        assert_eq!(ack.retry.iter().map(|tx| tx.index).collect::<Vec<_>>(), [3]);
        assert_eq!(ack.rejected.iter().map(|tx| tx.index).collect::<Vec<_>>(), [0, 2, 4]);
        assert_eq!(ack.rejected[2].error, "nonce too low");
        handle.stop().unwrap();
    }

    #[tokio::test]
    async fn hinted_batch_forwards_valid_entries_with_their_hints() {
        let hint = Some(AccessList::default());
        let txs = vec![
            SlipstreamHintedTx { tx: Bytes::new(), hint: None },
            SlipstreamHintedTx { tx: valid_tx(1), hint: hint.clone() },
        ];
        let (proxy, handle, received) = mock_sequencer::<SlipstreamHintedTx>(
            SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD,
            included_ack(),
        )
        .await;

        let ack = SlipstreamApiServer::send_raw_transaction_batch_with_hints(&proxy, txs.clone())
            .await
            .unwrap();

        assert_eq!(*received.lock().unwrap(), vec![vec![txs[1].clone()]]);
        assert_eq!(ack.included[0].index, 1);
        assert_eq!(ack.rejected.iter().map(|tx| tx.index).collect::<Vec<_>>(), [0]);
        handle.stop().unwrap();
    }

    #[test]
    fn out_of_range_sequencer_index_is_an_error() {
        let ack = SlipstreamBatchAck { included: vec![included(5)], ..Default::default() };
        assert!(merge_acks(ack, &[0, 1], Vec::new()).is_err());
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

        async fn send_raw_transaction_batch_with_hints(
            &self,
            _txs: Vec<SlipstreamHintedTx>,
        ) -> RpcResult<SlipstreamBatchAck> {
            Ok(SlipstreamBatchAck::default())
        }

        async fn warm_hints(&self, hints: Vec<AccessList>) -> RpcResult<SlipstreamWarmAck> {
            Ok(SlipstreamWarmAck { accepted: hints.len() })
        }
    }

    #[test]
    fn rpc_extension_only_exposes_slipstream_batch_methods() {
        let module = SlipstreamApiServer::into_rpc(TestRpc);
        let mut method_names = module.method_names().collect::<Vec<_>>();
        method_names.sort_unstable();

        let mut expected = [
            SEND_RAW_TRANSACTION_BATCH_METHOD,
            SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD,
            WARM_HINTS_METHOD,
        ];
        expected.sort_unstable();
        assert_eq!(method_names, expected);
        assert!(!module.method_names().any(|name| name == "eth_sendRawTransaction"));
        assert!(!module.method_names().any(|name| name == "eth_sendRawTransactionSync"));
    }
}
