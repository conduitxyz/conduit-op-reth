use super::{
    INITIAL_PAYLOAD_TIMESTAMP, PREFUND_BALANCE, build_genesis_with_override, launch_test_node,
    op_payload_attributes, parse_chain_spec,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{B256, Bytes, TxKind, U256, address};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::{core::client::ClientT, rpc_params};
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_provider::StateProviderFactory;
use reth_storage_api::StateProvider;
use serde_json::{Value, json};

/// Exercise Conduit's actual Engine API, not the stock OpNode or the wrapper in isolation.
/// Invalid derived transactions must fail at FCU, and valid ones must execute Conduit forks.
#[tokio::test]
async fn derived_payload_validation_uses_conduit_evm() -> eyre::Result<()> {
    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let contract = address!("4200000000000000000000000000000000000099");
    let timestamp = INITIAL_PAYLOAD_TIMESTAMP + 1;
    // The override installs code that stores 42 in slot 0. A stock OP EVM would instead
    // execute a transfer to an empty account and produce a different state root.
    let chain = parse_chain_spec(&build_genesis_with_override(
        timestamp,
        json!({format!("{contract}"): {"code": "0x602a60005500"}}),
        Some(json!({format!("{}", signer.address()): {"balance": PREFUND_BALANCE}})),
    ));
    let chain_id = chain.chain_id();
    let (_tasks, ctx) = launch_test_node!(chain);
    let client = ctx.inner.auth_server_handle().http_client();
    let forkchoice = ctx.current_forkchoice_state()?;
    let mut transactions = Vec::new();
    for nonce in [7, 0] {
        let signed = TransactionTestContext::sign_tx(
            signer.clone(),
            TransactionRequest {
                chain_id: Some(chain_id),
                nonce: Some(nonce),
                gas: Some(100_000),
                max_fee_per_gas: Some(1_000_000_000_000),
                max_priority_fee_per_gas: Some(1),
                to: Some(TxKind::Call(contract)),
                ..Default::default()
            },
        )
        .await;
        transactions.push(Bytes::from(signed.encoded_2718()));
    }

    // The nonce gap passes envelope decoding but fails execution. This catches a missing
    // wrapper or missing Reth error propagation, unlike a malformed-envelope-only test.
    for invalid in [&transactions[0], &Bytes::from_static(&[0x7d, 0xc0])] {
        let mut attrs = op_payload_attributes(timestamp).0;
        attrs.no_tx_pool = Some(true);
        attrs.transactions.as_mut().unwrap().push(invalid.clone());
        let error = client
            .request::<Value, _>("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, attrs])
            .await
            .unwrap_err();
        let jsonrpsee::core::ClientError::Call(error) = error else {
            panic!("expected an Engine API error, got {error}");
        };
        assert_eq!(error.code(), -38003, "invalid derived attributes: {error}");
        if invalid == &transactions[0] {
            assert!(error.to_string().contains("nonce"), "expected nonce-gap rejection: {error}");
        }
    }

    // Mempool builds and deposit-only derived builds still return a payload ID.
    for no_tx_pool in [false, true] {
        let mut attrs = op_payload_attributes(timestamp).0;
        attrs.no_tx_pool = Some(no_tx_pool);
        let response: Value =
            client.request("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, attrs]).await?;
        assert_eq!(response["payloadStatus"]["status"], "VALID");
        assert!(response["payloadId"].is_string());
    }

    let mut attrs = op_payload_attributes(timestamp).0;
    attrs.no_tx_pool = Some(true);
    attrs.transactions.as_mut().unwrap().push(transactions[1].clone());
    let response: Value =
        client.request("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, &attrs]).await?;
    assert_eq!(response["payloadStatus"]["status"], "VALID");
    let payload_id = response["payloadId"].as_str().expect("derived payload ID");
    let retry: Value =
        client.request("engine_forkchoiceUpdatedV3", rpc_params![forkchoice, &attrs]).await?;
    assert_eq!(retry["payloadId"], payload_id);
    let built: Value = client.request("engine_getPayloadV4", rpc_params![payload_id]).await?;
    let payload = &built["executionPayload"];
    assert_eq!(payload["transactions"], json!(attrs.transactions));
    let status: Value = client
        .request(
            "engine_newPayloadV4",
            rpc_params![payload, Vec::<B256>::new(), B256::ZERO, Vec::<Bytes>::new()],
        )
        .await?;
    assert_eq!(status["status"], "VALID", "{status}");
    let hash: B256 = serde_json::from_value(payload["blockHash"].clone())?;
    ctx.update_forkchoice(hash, hash).await?;
    ctx.wait_block(1, hash, false).await?;
    assert_eq!(ctx.inner.provider.latest()?.storage(contract, B256::ZERO)?, Some(U256::from(42)));
    Ok(())
}
