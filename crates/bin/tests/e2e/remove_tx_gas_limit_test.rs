use crate::e2e::{
    BASE_GENESIS, FORK_ACTIVATION_TIMESTAMP, advance, launch_test_node, op_payload_attributes,
    parse_chain_spec,
};
use alloy_consensus::{Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, TxKind, U256, address};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::helpers::EthTransactions;
use reth_storage_api::AccountReader;

const TX_GAS_LIMIT: u64 = 500_000_000;
const BLOCK_GAS_LIMIT: u64 = 1_000_000_000;
const GAS_BURNER_MEMORY_BYTES: u64 = 16_000_000;
const GAS_BURNER_RESERVE: u64 = 10_000;
const MIN_EXPECTED_GAS_USED: u64 = TX_GAS_LIMIT - GAS_BURNER_RESERVE;

alloy_sol_macro::sol!("tests/e2e/contracts/GasBurner.sol");

fn high_gas_limit_payload_attributes(
    timestamp: u64,
) -> reth_optimism_node::payload::OpPayloadAttrs {
    let mut attributes = op_payload_attributes(timestamp);
    attributes.0.gas_limit = Some(BLOCK_GAS_LIMIT);
    attributes
}

fn remove_tx_gas_limit_genesis(
    sender: alloy_primitives::Address,
    gas_burner: alloy_primitives::Address,
) -> String {
    let mut genesis: serde_json::Value =
        serde_json::from_str(BASE_GENESIS).expect("failed to parse base genesis");

    // This fixture activates Jovian at genesis, so child blocks require Jovian base-fee params.
    let obj = genesis.as_object_mut().unwrap();
    obj.remove("extradata");
    obj.insert("extraData".to_string(), serde_json::json!("0x01000000fa000000060000000000000000"));

    genesis["gasLimit"] = serde_json::json!(format!("0x{BLOCK_GAS_LIMIT:x}"));
    genesis["baseFeePerGas"] = serde_json::json!("0x1");
    genesis["config"]["karstTime"] = serde_json::json!(0);
    genesis["config"]["conduit"] = serde_json::json!({
        "removeTxGasLimitFork0": { "time": FORK_ACTIVATION_TIMESTAMP }
    });
    let artifact: serde_json::Value =
        serde_json::from_str(include_str!("contracts/GasBurner.json"))
            .expect("failed to parse gas burner artifact");
    let deployed_bytecode: Bytes =
        serde_json::from_value(artifact["deployedBytecode"]["object"].clone())
            .expect("gas burner artifact should contain deployed bytecode");

    genesis["alloc"][format!("{sender}")] = serde_json::json!({
        "balance": "0xde0b6b3a7640000"
    });
    genesis["alloc"][format!("{gas_burner}")] = serde_json::json!({
        "balance": "0x0",
        "code": deployed_bytecode
    });

    serde_json::to_string(&genesis).unwrap()
}

/// Proves the full RPC -> txpool -> payload builder -> execution path rejects a 500M-gas
/// transaction under Karst's EIP-7825 cap, then accepts and executes it after the custom fork.
#[tokio::test]
async fn test_500m_gas_transaction_after_remove_tx_gas_limit_fork() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let gas_burner = address!("5000000000000000000000000000000000000000");
    let chain_spec = parse_chain_spec(&remove_tx_gas_limit_genesis(signer.address(), gas_burner));
    let (_tasks, mut ctx) =
        launch_test_node!(chain_spec.clone(), high_gas_limit_payload_attributes);
    let input = GasBurner::burnCall {
        memoryBytes: U256::from(GAS_BURNER_MEMORY_BYTES),
        gasReserve: U256::from(GAS_BURNER_RESERVE),
    }
    .abi_encode();

    let tx = TransactionRequest {
        chain_id: Some(chain_spec.chain_id()),
        nonce: Some(0),
        to: Some(TxKind::Call(gas_burner)),
        value: Some(U256::from(1)),
        gas: Some(TX_GAS_LIMIT),
        max_fee_per_gas: Some(1_000_000_000),
        max_priority_fee_per_gas: Some(1),
        input: TransactionInput::new(input.into()),
        ..Default::default()
    };
    let signed = TransactionTestContext::sign_tx(signer, tx).await;
    let raw_tx: Bytes = signed.encoded_2718().into();

    // Block 1 is after Karst but before the custom fork. The txpool must enforce EIP-7825.
    advance!(ctx);
    let err = ctx.rpc.inject_tx(raw_tx.clone()).await.unwrap_err();
    assert!(
        err.to_string().contains("gas limit too high"),
        "expected EIP-7825 rejection before custom fork, got: {err}"
    );

    // Block 2 activates the custom fork. Once it is canonical, the txpool must accept the same tx.
    advance!(ctx);
    let tx_hash = ctx.rpc.inject_tx(raw_tx).await?;

    // Block 3 proves the payload builder and block executor both accept the declared 500M limit.
    let payload = advance!(ctx);
    let included = payload
        .block()
        .body()
        .transactions()
        .find(|tx| *tx.tx_hash() == tx_hash)
        .expect("500M-gas transaction should be included after custom fork");
    assert_eq!(included.gas_limit(), TX_GAS_LIMIT);

    let receipt = ctx
        .rpc
        .inner
        .eth_api()
        .transaction_receipt(tx_hash)
        .await?
        .expect("500M-gas transaction should have a receipt");
    assert!(receipt.inner.inner.status(), "gas burner execution should succeed");
    assert!(
        receipt.inner.gas_used >= MIN_EXPECTED_GAS_USED,
        "gas burner should execute inside REVM and consume nearly 500M gas, used {}",
        receipt.inner.gas_used
    );

    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.basic_account(&gas_burner)?.expect("gas burner should exist").balance,
        U256::from(1),
        "value transfer proves the gas-burning call completed successfully"
    );

    Ok(())
}
