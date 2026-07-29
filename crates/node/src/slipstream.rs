//! Optional public Slipstream batch proxy for OP-Reth replicas.
//!
//! Public RPC requests reach OP-Reth replicas, while the active op-rbuilder
//! owns the Slipstream mailbox. This module forwards the batch unchanged to
//! the configured leader-aware sequencer endpoint and returns its response.

use alloy_primitives::Bytes;
use conduit_op_reth_rpc_api::{
    SEND_RAW_TRANSACTION_BATCH_METHOD, SlipstreamApiServer, SlipstreamBatchAck,
};
use jsonrpsee::core::{RpcResult, async_trait};
use reth_optimism_rpc::SequencerClient;

/// Replica-side proxy for the public Slipstream batch API.
#[derive(Clone)]
pub struct SlipstreamProxy {
    sequencer_client: SequencerClient,
}

impl SlipstreamProxy {
    /// Creates a proxy using the replica's configured sequencer client.
    pub const fn new(sequencer_client: SequencerClient) -> Self {
        Self { sequencer_client }
    }
}

#[async_trait]
impl SlipstreamApiServer for SlipstreamProxy {
    async fn send_raw_transaction_batch(
        &self,
        raw_txs: Vec<Bytes>,
    ) -> RpcResult<SlipstreamBatchAck> {
        self.sequencer_client
            .request(SEND_RAW_TRANSACTION_BATCH_METHOD, (raw_txs,))
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use conduit_op_reth_rpc_api::SlipstreamIncludedTx;
    use jsonrpsee::{RpcModule, server::ServerBuilder, types::ErrorObjectOwned};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
        let proxy = SlipstreamProxy::new(client);

        let ack = SlipstreamApiServer::send_raw_transaction_batch(&proxy, raw_txs).await.unwrap();

        assert_eq!(ack.included.len(), 1);
        assert_eq!(ack.included[0].index, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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

    #[test]
    fn rpc_extension_only_exposes_slipstream_batch_method() {
        let module = SlipstreamApiServer::into_rpc(TestRpc);
        let method_names = module.method_names().collect::<Vec<_>>();

        assert_eq!(method_names, [SEND_RAW_TRANSACTION_BATCH_METHOD]);
        assert!(!module.method_names().any(|name| name == "eth_sendRawTransaction"));
        assert!(!module.method_names().any(|name| name == "eth_sendRawTransactionSync"));
    }
}
