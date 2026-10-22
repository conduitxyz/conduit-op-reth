use super::{BASE_GENESIS, parse_chain_spec, test_node_config};
use conduit_op_reth_node::node::ConduitOpNode;
use jsonrpsee::{RpcModule, core::client::ClientT, rpc_params, server::ServerBuilder};
use reth_node_builder::NodeBuilder;
use reth_optimism_node::args::RollupArgs;
use reth_tasks::Runtime;
use serde_json::{Value, json};

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

    // (Bedrock, migration, CLI override, queries). A smaller override catches accidentally
    // retaining the upstream layer; Bedrock=0 catches its upstream "disabled" special case.
    for (bedrock, migration, cutoff, queries) in [
        (0, None, Some(10), vec![(9, true), (10, false), (11, false)]),
        (10, None, Some(5), vec![(4, true), (5, false), (9, false)]),
        (10, None, None, vec![(9, true), (10, false)]),
        (0, None, None, vec![(9, false)]),
        (10, None, Some(0), vec![(0, false), (9, false)]),
        (0, Some(10), None, vec![(9, true), (10, false), (11, false)]),
        (10, Some(5), None, vec![(4, true), (5, false), (9, false)]),
        (10, Some(8), Some(5), vec![(4, true), (5, false), (7, false)]),
        (0, Some(5), Some(8), vec![(5, true), (7, true), (8, false)]),
        (10, Some(8), Some(0), vec![(0, false), (7, false)]),
        (10, Some(0), None, vec![(0, false), (9, false)]),
    ] {
        let mut genesis: Value = serde_json::from_str(BASE_GENESIS)?;
        genesis["config"]["bedrockBlock"] = json!(bedrock);
        if let Some(migration) = migration {
            genesis["config"]["conduit"]["migrationBlock"] = json!(migration);
        }
        let chain = parse_chain_spec(&genesis.to_string());
        let genesis_hash = reth_chainspec::EthChainSpec::genesis_hash(chain.as_ref());
        let args = RollupArgs { historical_rpc: Some(endpoint.clone()), ..Default::default() };
        let mut node = ConduitOpNode::new(args);
        node.historical_rpc_block = cutoff;
        let tasks = Runtime::test();
        let handle = NodeBuilder::new(test_node_config(chain))
            .testing_node(tasks.clone())
            .node(node)
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
            assert_eq!(
                response, expected,
                "bedrock={bedrock}, migration={migration:?}, cutoff={cutoff:?}, block={block}"
            );
        }
        if cutoff.is_some() || migration.is_some() {
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
async fn migration_block_without_historical_endpoint() -> eyre::Result<()> {
    let mut genesis: Value = serde_json::from_str(BASE_GENESIS)?;
    genesis["config"]["conduit"]["migrationBlock"] = json!(10);
    let chain = parse_chain_spec(&genesis.to_string());
    let genesis_hash = reth_chainspec::EthChainSpec::genesis_hash(chain.as_ref());
    let tasks = Runtime::test();
    let handle = NodeBuilder::new(test_node_config(chain))
        .testing_node(tasks.clone())
        .node(ConduitOpNode::new(RollupArgs::default()))
        .launch()
        .await?;
    let client = handle.node.rpc_server_handle().http_client().unwrap();
    let local: Value = client.request("eth_getBlockByNumber", rpc_params!["0x0", false]).await?;
    assert_eq!(local["hash"], json!(genesis_hash));
    let absent: Value = client.request("eth_getBlockByNumber", rpc_params!["0x9", false]).await?;
    assert_eq!(absent, Value::Null);
    Ok(())
}
