//! Shared JSON-RPC contract for Conduit Slipstream clients and servers.
//!
//! This crate intentionally contains only wire types and generated RPC traits.
//! The G3 builder owns mailbox execution, while OP-Reth replicas use the same
//! contract to proxy public batch requests to the active builder.

use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

/// Fully-qualified JSON-RPC name of the Slipstream batch method.
pub const SEND_RAW_TRANSACTION_BATCH_METHOD: &str = "slipstream_sendRawTransactionBatch";

/// Fully-qualified JSON-RPC name of the hint-carrying Slipstream batch method.
pub const SEND_RAW_TRANSACTION_BATCH_WITH_HINTS_METHOD: &str =
    "slipstream_sendRawTransactionBatchWithHints";

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

/// A raw transaction paired with an advisory state-access hint computed by a
/// forwarding node.
///
/// An absent hint means generation failed or ran past its best-effort budget; an
/// empty hint is a successful result that touched nothing. Hints are advisory:
/// they let the builder prewarm state, and cannot change execution outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SlipstreamHintedTx {
    pub tx: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<AccessList>,
}

/// Public Slipstream batch-submission API implemented by G3 rbuilder nodes.
#[rpc(server, namespace = "slipstream")]
pub trait SlipstreamApi {
    /// Submits signed transactions for the next flashblock and returns one
    /// execution verdict per input transaction.
    #[method(name = "sendRawTransactionBatch")]
    async fn send_raw_transaction_batch(&self, txs: Vec<Bytes>) -> RpcResult<SlipstreamBatchAck>;

    /// Same as [`Self::send_raw_transaction_batch`], with an advisory
    /// state-access hint per transaction for prewarming.
    #[method(name = "sendRawTransactionBatchWithHints")]
    async fn send_raw_transaction_batch_with_hints(
        &self,
        txs: Vec<SlipstreamHintedTx>,
    ) -> RpcResult<SlipstreamBatchAck>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip2930::AccessListItem;

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

    #[test]
    fn hinted_tx_hint_is_optional_on_the_wire() {
        // Senders that predate hints omit the field entirely.
        let unhinted: SlipstreamHintedTx = serde_json::from_str(r#"{"tx":"0x01"}"#).unwrap();
        assert_eq!(unhinted.hint, None);
        // And a missing hint is not serialized back, so the payload stays compact.
        assert_eq!(serde_json::to_string(&unhinted).unwrap(), r#"{"tx":"0x01"}"#);
    }

    #[test]
    fn hinted_tx_round_trips_an_access_list() {
        let tx = SlipstreamHintedTx {
            tx: Bytes::from_static(&[0x02]),
            hint: Some(AccessList(vec![AccessListItem {
                address: Address::with_last_byte(7),
                storage_keys: vec![B256::with_last_byte(9)],
            }])),
        };
        let encoded = serde_json::to_string(&tx).unwrap();
        assert_eq!(serde_json::from_str::<SlipstreamHintedTx>(&encoded).unwrap(), tx);
    }
}
