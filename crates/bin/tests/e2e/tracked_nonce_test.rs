use super::{
    FORK_ACTIVATION_TIMESTAMP, PREFUND_BALANCE, PREFUND_BALANCE_U256, advance,
    build_genesis_with_override, op_payload_attributes, parse_chain_spec, test_node_config,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{B256, Bytes, TxKind};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use conduit_op_reth_node::node::ConduitOpNode;
use jsonrpsee::{core::client::ClientT, rpc_params};
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::{node::NodeTestContext, transaction::TransactionTestContext};
use reth_node_builder::{Node, NodeBuilder};
use reth_provider::ChangedAccount;
use reth_tasks::Runtime;
use reth_transaction_pool::{TransactionPool, TransactionPoolExt};
use serde_json::json;

/// Reproduce upstream's stale-validation ordering through Conduit's built pool and RPC.
/// The provider deliberately stays at nonce 0 while the pool receives a newer account
/// update, modelling a validation snapshot that predates that update without timing sleeps.
#[tokio::test]
async fn tracked_nonce_opt_in_reaches_pool_and_changes_admission() -> eyre::Result<()> {
    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    for enforce in [false, true] {
        let chain = parse_chain_spec(&build_genesis_with_override(
            FORK_ACTIVATION_TIMESTAMP,
            json!({}),
            Some(json!({format!("{}", signer.address()): {"balance": PREFUND_BALANCE}})),
        ));
        let chain_id = chain.chain_id();
        let tasks = Runtime::test();
        let mut node = ConduitOpNode::default();
        node.enforce_tracked_nonce = enforce;
        node.args.enable_tx_conditional = true;
        let handle = NodeBuilder::new(test_node_config(chain))
            .testing_node(tasks.clone())
            .with_types::<ConduitOpNode>()
            .with_components(node.components_builder().map_pool(|mut builder| {
                builder.inner.pool_config_overrides.max_account_slots = Some(23);
                builder
            }))
            .with_add_ons(node.add_ons())
            .launch()
            .await?;
        let mut ctx = NodeTestContext::new(handle.node, op_payload_attributes).await?;
        advance!(ctx);
        let pool = &ctx.inner.pool;
        assert_eq!(pool.config().enforce_tracked_nonce, enforce);
        assert_eq!(pool.config().max_account_slots, 23, "upstream overrides must survive");
        let client = ctx.inner.rpc_server_handle().http_client().unwrap();

        let mut raw = Vec::new();
        for (nonce, tip) in [(0, 1), (0, 2), (2, 1), (1, 1)] {
            let signed = TransactionTestContext::sign_tx(
                signer.clone(),
                TransactionRequest {
                    chain_id: Some(chain_id),
                    nonce: Some(nonce),
                    gas: Some(100_000),
                    max_fee_per_gas: Some(1_000_000_000_000),
                    max_priority_fee_per_gas: Some(tip),
                    to: Some(TxKind::Call(signer.address())),
                    ..Default::default()
                },
            )
            .await;
            raw.push(Bytes::from(signed.encoded_2718()));
        }
        client.request::<B256, _>("eth_sendRawTransaction", rpc_params![&raw[0]]).await?;
        pool.update_accounts(vec![ChangedAccount {
            address: signer.address(),
            nonce: 2,
            balance: PREFUND_BALANCE_U256,
        }]);
        assert!(pool.pending_transactions().is_empty());

        let stale = client.request::<B256, _>("eth_sendRawTransaction", rpc_params![&raw[1]]).await;
        if enforce {
            let error = stale.unwrap_err();
            assert!(error.to_string().contains("nonce too low"), "{error}");
        } else {
            stale?;
        }
        client.request::<B256, _>("eth_sendRawTransaction", rpc_params![&raw[2]]).await?;
        let best: Vec<_> = pool.best_transactions().map(|tx| tx.nonce()).collect();
        assert_eq!(best, if enforce { vec![2] } else { vec![0] });

        if enforce {
            // A lower canonical account update, as applied during reorg maintenance,
            // replaces the tracked nonce. Before that update, nonce 0 was rejected above.
            pool.update_accounts(vec![ChangedAccount {
                address: signer.address(),
                nonce: 0,
                balance: PREFUND_BALANCE_U256,
            }]);
            client.request::<B256, _>("eth_sendRawTransaction", rpc_params![&raw[1]]).await?;
            client.request::<B256, _>("eth_sendRawTransaction", rpc_params![&raw[3]]).await?;
            let best: Vec<_> = pool.best_transactions().map(|tx| tx.nonce()).collect();
            assert_eq!(best, vec![0, 1, 2]);
        }
    }
    Ok(())
}
