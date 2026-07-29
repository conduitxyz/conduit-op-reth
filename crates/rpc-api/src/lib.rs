//! Shared JSON-RPC contract for Conduit Slipstream clients and servers.
//!
//! This crate intentionally contains only wire types and generated RPC traits.
//! The G3 builder owns mailbox execution, while OP-Reth replicas may use the
//! same contract as clients when serving `eth_sendRawTransactionSync`.

use alloy_json_rpc::RpcObject;
use alloy_primitives::{Address, B256, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

/// Fully-qualified JSON-RPC name of the Slipstream batch method.
pub const SEND_RAW_TRANSACTION_BATCH_METHOD: &str = "slipstream_sendRawTransactionBatch";
/// Fully-qualified JSON-RPC name of the standard synchronous transaction method.
pub const SEND_RAW_TRANSACTION_SYNC_METHOD: &str = "eth_sendRawTransactionSync";

/// A transaction executed into a published flashblock.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlipstreamIncludedTx {
    pub index: usize,
    pub hash: B256,
    pub sender: Address,
    pub nonce: u64,
    pub block_number: u64,
    pub flashblock_index: u64,
}

/// A transaction that is invalid as submitted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlipstreamRejectedTx {
    pub index: usize,
    pub error: String,
}

/// A transaction that was not executed for a transient reason.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlipstreamRetryTx {
    pub index: usize,
    pub reason: String,
}

/// Per-batch response of `slipstream_sendRawTransactionBatch`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SlipstreamBatchAck {
    #[serde(default)]
    pub included: Vec<SlipstreamIncludedTx>,
    #[serde(default)]
    pub rejected: Vec<SlipstreamRejectedTx>,
    #[serde(default)]
    pub retry: Vec<SlipstreamRetryTx>,
}

/// Public Slipstream batch-submission API implemented by G3 rbuilder nodes.
#[rpc(server, namespace = "slipstream")]
pub trait SlipstreamApi {
    /// Submits signed transactions for the next flashblock and returns one
    /// execution verdict per input transaction.
    #[method(name = "sendRawTransactionBatch")]
    async fn send_raw_transaction_batch(&self, txs: Vec<Bytes>) -> RpcResult<SlipstreamBatchAck>;
}

/// One-method adapter used to replace the standard synchronous transaction
/// implementation without replacing any other `eth` method.
#[rpc(server, namespace = "eth")]
pub trait SlipstreamSyncApi<R: RpcObject> {
    /// Submits one signed transaction through Slipstream and returns its
    /// authoritative pending or canonical receipt.
    #[method(name = "sendRawTransactionSync")]
    async fn send_raw_transaction_sync(&self, tx: Bytes) -> RpcResult<R>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_ack_ignores_future_wire_fields() {
        let ack: SlipstreamBatchAck = serde_json::from_str(
            r#"{
                "included": [{
                    "index": 0,
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "sender": "0x0000000000000000000000000000000000000002",
                    "nonce": 3,
                    "block_number": 4,
                    "flashblock_index": 5,
                    "future_field": true
                }],
                "rejected": [{"index": 1, "error": "invalid"}],
                "retry": [{"index": 2, "reason": "mailbox-full"}],
                "future_top_level_field": true
            }"#,
        )
        .unwrap();

        assert_eq!(ack.included[0].index, 0);
        assert_eq!(ack.rejected[0].error, "invalid");
        assert_eq!(ack.retry[0].reason, "mailbox-full");
    }
}
