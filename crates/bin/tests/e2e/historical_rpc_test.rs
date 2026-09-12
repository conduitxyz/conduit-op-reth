use super::{BASE_GENESIS, parse_chain_spec, test_node_config};
use conduit_op_reth_node::node::ConduitOpNode;
use jsonrpsee::{RpcModule, core::client::ClientT, rpc_params, server::ServerBuilder};
use reth_node_builder::NodeBuilder;
use reth_optimism_node::args::RollupArgs;
use reth_tasks::Runtime;
use serde_json::{Value, json};

/// Exercise the real add-ons and HTTP middleware, including replacing a nonzero Bedrock cutoff.
#[tokio::test]
async fn historical_rpc_cutoff() -> eyre::Result<()> {
    let server = ServerBuilder::default().build("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", server.local_addr()?);
    let mut module = RpcModule::new(());
    module.register_method("eth_getBlockByNumber", |params, _, _| {
        let (block, _): (String, bool) = params.parse()?;
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(json!({"historical": block}))
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
        let mut node = ConduitOpNode::new(RollupArgs {
            historical_rpc: Some(endpoint.clone()),
            ..Default::default()
        });
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
            assert_eq!(response, expected, "bedrock={bedrock}, cutoff={cutoff:?}, block={block}");
        }
        drop(handle);
        drop(tasks);
    }
    server_handle.stop()?;
    Ok(())
}
