//! Bounded historical forwarding for an explicit migration cutoff.
//!
//! Wrap registered methods, not the dispatcher: transport-specific method access and jsonrpsee's
//! batch/response limits must still apply. The upstream middleware bypasses those checks.

use alloy_eips::BlockId;
use alloy_primitives::B256;
use jsonrpsee::{
    core::{
        client::ClientT,
        server::{MethodCallback, MethodResponse, Methods},
        traits::ToRpcParams,
    },
    http_client::{HttpClient, HttpClientBuilder},
    types::{ErrorObjectOwned, Params, ResponsePayload},
};
use reth_node_builder::{FullNodeComponents, rpc::RpcContext};
use reth_optimism_node::args::RollupArgs;
use reth_rpc_eth_api::EthApiTypes;
use reth_storage_api::{BlockReaderIdExt, TransactionsProvider};
use serde_json::{Value, value::RawValue};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 16;

/// Explicit historical endpoint and exclusive cutoff, separate from consensus configuration.
pub struct HistoricalRpcOverride {
    endpoint: String,
    cutoff: u64,
}

impl HistoricalRpcOverride {
    /// Remove the upstream endpoint only when overriding, preventing duplicate forwarding.
    pub fn take(args: &mut RollupArgs, cutoff: Option<u64>) -> eyre::Result<Option<Self>> {
        cutoff
            .map(|cutoff| {
                let endpoint = args.historical_rpc.take().ok_or_else(|| {
                    eyre::eyre!("--rollup.historicalrpc.block requires --rollup.historicalrpc")
                })?;
                Ok(Self { endpoint, cutoff })
            })
            .transpose()
    }

    /// Install after other RPC overrides so local fallback retains their behavior.
    pub fn install<N, EthApi>(self, ctx: &mut RpcContext<'_, N, EthApi>) -> eyre::Result<()>
    where
        N: FullNodeComponents,
        EthApi: EthApiTypes,
    {
        let rpc = &ctx.config().rpc;
        let client = HttpClientBuilder::default()
            .request_timeout(REQUEST_TIMEOUT)
            .max_request_size(rpc.rpc_max_request_size.get().saturating_mul(1024 * 1024))
            .max_response_size(rpc.rpc_max_response_size.get().saturating_mul(1024 * 1024))
            .build(&self.endpoint)?;
        let forwarder = Arc::new(Forwarder {
            provider: ctx.provider().clone(),
            client,
            cutoff: self.cutoff,
            permits: Semaphore::new(MAX_IN_FLIGHT),
        });
        // Never merge one transport's method set into another (e.g. WS-only debug into HTTP).
        if let Some(methods) = ctx.modules.http_methods(|_| true) {
            ctx.modules.replace_http(forwarder.wrap(methods)?)?;
        }
        if let Some(methods) = ctx.modules.ws_methods(|_| true) {
            ctx.modules.replace_ws(forwarder.wrap(methods)?)?;
        }
        if let Some(methods) = ctx.modules.ipc_methods(|_| true) {
            ctx.modules.replace_ipc(forwarder.wrap(methods)?)?;
        }
        tracing::info!(target: "reth::cli", cutoff = self.cutoff, "Installed bounded historical RPC forwarding");
        Ok(())
    }
}

struct Forwarder<P> {
    provider: P,
    client: HttpClient,
    cutoff: u64,
    permits: Semaphore,
}

impl<P: BlockReaderIdExt + TransactionsProvider + Send + Sync + 'static> Forwarder<P> {
    fn wrap(self: &Arc<Self>, methods: Methods) -> eyre::Result<Methods> {
        let mut wrapped = Methods::new();
        for name in methods.method_names().filter(|name| parameter_index(name).is_some()) {
            let original = methods.method(name).unwrap().clone();
            if !matches!(original, MethodCallback::Sync(_) | MethodCallback::Async(_)) {
                continue;
            }
            let this = self.clone();
            wrapped.verify_and_insert(
                name,
                MethodCallback::Async(Arc::new(move |id, params, conn, max_size, extensions| {
                    let this = this.clone();
                    let original = original.clone();
                    Box::pin(async move {
                        if this.should_forward(name, &params) {
                            // Fail fast rather than queueing unbounded work behind a slow endpoint.
                            let Ok(_permit) = this.permits.try_acquire() else {
                                return MethodResponse::error(
                                    id,
                                    ErrorObjectOwned::owned(
                                        -32005,
                                        "Historical RPC busy",
                                        None::<()>,
                                    ),
                                )
                                .with_extensions(extensions);
                            };
                            let raw_params = RawParams(params.as_str().map(str::to_owned));
                            if let Ok(result) =
                                this.client.request::<Box<RawValue>, _>(name, raw_params).await
                            {
                                return MethodResponse::response(
                                    id,
                                    ResponsePayload::success(result).into(),
                                    max_size,
                                )
                                .with_extensions(extensions);
                            }
                            // As upstream, backend failures fall back to the original local
                            // handler.
                            tracing::debug!(target: "rpc::historical", method = name, "Historical RPC request failed; falling back locally");
                        }
                        match original {
                            MethodCallback::Sync(callback) => {
                                callback(id, params, max_size, extensions)
                            }
                            MethodCallback::Async(callback) => {
                                callback(id, params, conn, max_size, extensions).await
                            }
                            _ => unreachable!("only ordinary calls are wrapped"),
                        }
                    })
                })),
            )?;
        }
        Ok(wrapped)
    }

    fn should_forward(&self, method: &str, params: &Params<'_>) -> bool {
        let Some(index) = parameter_index(method) else { return false };
        let Ok(values) = params.parse::<Vec<Value>>() else { return false };
        let Some(value) = values.into_iter().nth(index) else { return false };
        if matches!(
            method,
            "debug_traceTransaction" |
                "eth_getTransactionByHash" |
                "eth_getTransactionReceipt" |
                "eth_getRawTransactionByHash"
        ) {
            let Ok(hash) = serde_json::from_value::<B256>(value) else { return false };
            return match self.provider.transaction_by_hash_with_meta(hash) {
                Ok(Some((_, meta))) => meta.block_number < self.cutoff,
                Ok(None) => true,
                Err(_) => false,
            };
        }
        let Ok(block) = serde_json::from_value::<BlockId>(value) else { return false };
        match self.provider.block_number_for_id(block) {
            Ok(Some(number)) => number < self.cutoff,
            Ok(None) => block.is_hash(),
            Err(_) => false,
        }
    }
}

// Keep aligned with op-reth/v2.4.3 historical.rs. No writes, subscriptions, arbitrary methods,
// or multi-block scans. Each forwarded call makes at most one historical RPC request.
fn parameter_index(method: &str) -> Option<usize> {
    match method {
        "eth_getBlockByNumber" |
        "eth_getBlockByHash" |
        "eth_getBlockReceipts" |
        "eth_getHeaderByNumber" |
        "eth_getHeaderByHash" |
        "eth_getBlockTransactionCountByNumber" |
        "eth_getBlockTransactionCountByHash" |
        "eth_getUncleCountByBlockNumber" |
        "eth_getUncleCountByBlockHash" |
        "eth_getUncleByBlockNumberAndIndex" |
        "eth_getUncleByBlockHashAndIndex" |
        "eth_getTransactionByBlockNumberAndIndex" |
        "eth_getTransactionByBlockHashAndIndex" |
        "eth_getRawTransactionByBlockNumberAndIndex" |
        "eth_getRawTransactionByBlockHashAndIndex" |
        "debug_traceBlockByNumber" |
        "debug_traceBlockByHash" |
        "debug_traceTransaction" |
        "eth_getTransactionByHash" |
        "eth_getTransactionReceipt" |
        "eth_getRawTransactionByHash" => Some(0),
        "eth_getBalance" |
        "eth_getCode" |
        "eth_getTransactionCount" |
        "eth_call" |
        "eth_estimateGas" |
        "eth_createAccessList" |
        "debug_traceCall" => Some(1),
        "eth_getStorageAt" | "eth_getProof" => Some(2),
        _ => None,
    }
}

struct RawParams(Option<String>);

impl ToRpcParams for RawParams {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        self.0.map(RawValue::from_string).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn https_client_builds_with_workspace_tls_features() {
        // No network I/O: exercises TLS provider selection with both rustls providers enabled.
        HttpClientBuilder::default().build("https://127.0.0.1:1").unwrap();
    }
}
