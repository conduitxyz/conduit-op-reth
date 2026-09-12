use super::{BASE_GENESIS, parse_chain_spec, test_node_config};
use conduit_op_reth_node::{historical_rpc::HistoricalRpcOverride, node::ConduitOpNode};
use jsonrpsee::{RpcModule, core::client::ClientT, rpc_params, server::ServerBuilder};
use reth_node_builder::NodeBuilder;
use reth_optimism_node::args::RollupArgs;
use reth_tasks::Runtime;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Exercise real HTTP forwarding, including replacing a nonzero Bedrock cutoff.
#[tokio::test]
async fn historical_rpc_cutoff() -> eyre::Result<()> {
    let server = ServerBuilder::default().build("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", server.local_addr()?);
    let mut module = RpcModule::new(());
    module.register_method("eth_getBlockByNumber", |params, _, _| {
        let (block, _): (String, bool) = params.parse()?;
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(json!({"historical": block}))
    })?;
    module.register_method("eth_getTransactionReceipt", |params, _, _| {
        let (hash,): (alloy_primitives::B256,) = params.parse()?;
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(json!({"historical": hash}))
    })?;
    let server_handle = server.start(module);

    // (Bedrock, override, block, should forward). A smaller override catches accidentally
    // retaining the upstream layer; Bedrock=0 catches its upstream "disabled" special case.
    for (bedrock, cutoff, queries) in [
        (0, Some(10), vec![(9, true), (10, false), (11, false)]),
        (10, Some(5), vec![(4, true), (5, false), (9, false)]),
        (10, None, vec![(9, true), (10, false)]),
        (0, None, vec![(9, false)]),
        (10, Some(0), vec![(0, false), (9, false)]),
    ] {
        let mut genesis: Value = serde_json::from_str(BASE_GENESIS)?;
        genesis["config"]["bedrockBlock"] = json!(bedrock);
        let chain = parse_chain_spec(&genesis.to_string());
        let genesis_hash = reth_chainspec::EthChainSpec::genesis_hash(chain.as_ref());
        let mut args = RollupArgs { historical_rpc: Some(endpoint.clone()), ..Default::default() };
        let historical_rpc = HistoricalRpcOverride::take(&mut args, cutoff)?;
        let tasks = Runtime::test();
        let handle = NodeBuilder::new(test_node_config(chain))
            .testing_node(tasks.clone())
            .node(ConduitOpNode::new(args))
            .extend_rpc_modules(move |mut ctx| {
                if let Some(historical_rpc) = historical_rpc {
                    historical_rpc.install(&mut ctx)?;
                }
                Ok(())
            })
            .launch()
            .await?;
        let client = handle.node.rpc_server_handle().http_client().unwrap();

        for (block, forwarded) in queries {
            let block_id = format!("0x{block:x}");
            let response: Value =
                client.request("eth_getBlockByNumber", rpc_params![&block_id, false]).await?;
            let expected = if forwarded {
                json!({"historical": block_id})
            } else if block == 0 {
                // Genesis remains local when the explicit cutoff is zero.
                assert_eq!(response["hash"], json!(genesis_hash));
                continue;
            } else {
                Value::Null // These blocks do not exist locally.
            };
            assert_eq!(response, expected, "bedrock={bedrock}, cutoff={cutoff:?}, block={block}");
        }
        if cutoff.is_some() {
            let hash = alloy_primitives::B256::repeat_byte(0x42);
            let receipt: Value =
                client.request("eth_getTransactionReceipt", rpc_params![hash]).await?;
            assert_eq!(receipt, json!({"historical": hash}));
        }
        drop(handle);
        drop(tasks);
    }
    server_handle.stop()?;
    Ok(())
}

#[tokio::test]
async fn historical_rpc_security_limits() -> eyre::Result<()> {
    use jsonrpsee::core::{client::Error as ClientError, params::BatchRequestBuilder};
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let debug_calls = Arc::new(AtomicUsize::new(0));
    let server = ServerBuilder::default().build("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", server.local_addr()?);
    let mut module = RpcModule::new(slow_calls.clone());
    module.register_async_method("eth_getBlockByNumber", |params, slow_calls, _| async move {
        let (block, _): (String, bool) = params.parse()?;
        let result = match block.as_str() {
            "0x2" => json!("x".repeat(2 * 1024 * 1024)),
            "0x3" => json!("x".repeat(600 * 1024)),
            "0x4" => {
                slow_calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Value>().await
            }
            _ => json!({"historical": block}),
        };
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(result)
    })?;
    let debug_hits = debug_calls.clone();
    module.register_method("debug_traceBlockByNumber", move |_, _, _| {
        debug_hits.fetch_add(1, Ordering::SeqCst);
        "historical-debug"
    })?;
    let upstream = server.start(module);
    let mut args = RollupArgs { historical_rpc: Some(endpoint), ..Default::default() };
    let historical_rpc = HistoricalRpcOverride::take(&mut args, Some(10))?.unwrap();
    let mut config = test_node_config(parse_chain_spec(BASE_GENESIS));
    config.rpc =
        config.rpc.with_http_api("eth".parse()?).with_ws().with_ws_api("eth,debug".parse()?);
    // Distinct bind addresses keep port-zero HTTP/WS listeners separate.
    config.rpc.ws_addr = "::1".parse()?;
    config.rpc.rpc_max_response_size = 1u32.into();
    let tasks = Runtime::test();
    let handle = NodeBuilder::new(config)
        .testing_node(tasks.clone())
        .node(ConduitOpNode::new(args))
        .extend_rpc_modules(move |mut ctx| historical_rpc.install(&mut ctx))
        .launch()
        .await?;
    let rpc = handle.node.rpc_server_handle();
    let http = rpc.http_client().unwrap();
    let ws = jsonrpsee::ws_client::WsClientBuilder::default().build(rpc.ws_url().unwrap()).await?;

    let error = http
        .request::<Value, _>("debug_traceBlockByNumber", rpc_params!["0x1", json!({})])
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Call(ref e) if e.code() == -32601), "{error:?}");
    assert_eq!(debug_calls.load(Ordering::SeqCst), 0);
    let result: Value =
        ws.request("debug_traceBlockByNumber", rpc_params!["0x1", json!({})]).await?;
    assert_eq!(result, json!("historical-debug"));
    assert_eq!(debug_calls.load(Ordering::SeqCst), 1);

    // The historical client rejects a body larger than the configured server limit and falls
    // back locally. Two individually legal responses must still obey the aggregate batch cap.
    let oversized: Value = http.request("eth_getBlockByNumber", rpc_params!["0x2", false]).await?;
    assert_eq!(oversized, Value::Null);
    let within_limit: String =
        http.request("eth_getBlockByNumber", rpc_params!["0x3", false]).await?;
    assert_eq!(within_limit.len(), 600 * 1024);
    let mut batch = BatchRequestBuilder::new();
    for _ in 0..2 {
        batch.insert("eth_getBlockByNumber", rpc_params!["0x3", false])?;
    }
    let error = http.batch_request::<Value>(batch).await.unwrap_err();
    // The server returns a single -32011 error object, which the client cannot parse as a batch.
    assert!(matches!(error, ClientError::ParseError(_)), "{error:?}");

    // Saturate the shared HTTP/WS budget with a stalled backend. Additional work is rejected,
    // not queued; every admitted call times out and releases its permit.
    let pending = (0..16)
        .map(|_| {
            let http = http.clone();
            tokio::spawn(async move {
                http.request::<Value, _>("eth_getBlockByNumber", rpc_params!["0x4", false]).await
            })
        })
        .collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_secs(5), async {
        while slow_calls.load(Ordering::SeqCst) < 16 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        ws.request::<Value, _>("eth_getBlockByNumber", rpc_params!["0x4", false]),
    )
    .await?
    .unwrap_err();
    assert!(matches!(error, ClientError::Call(ref e) if e.code() == -32005), "{error:?}");
    assert_eq!(slow_calls.load(Ordering::SeqCst), 16);
    let results =
        tokio::time::timeout(Duration::from_secs(35), futures_util::future::join_all(pending))
            .await?;
    for result in results {
        assert_eq!(result??, Value::Null);
    }
    let recovered: Value = http.request("eth_getBlockByNumber", rpc_params!["0x1", false]).await?;
    assert_eq!(recovered, json!({"historical": "0x1"}));
    upstream.stop()?;
    Ok(())
}
