use crate::e2e::{
    BASE_GENESIS, FORK_ACTIVATION_TIMESTAMP, advance, launch_test_node, op_payload_attributes,
    parse_chain_spec,
};
use alloy_consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, TxKind, U256, address};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use conduit_op_reth_node::hardforks::ConduitOpHardforks;
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_optimism_chainspec::OpHardforks;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::helpers::EthTransactions;
use reth_storage_api::AccountReader;

const TX_GAS_LIMIT: u64 = 500_000_000;
const BLOCK_GAS_LIMIT: u64 = 1_000_000_000;
const GAS_BURNER_MEMORY_BYTES: u64 = 16_000_000;
const GAS_BURNER_RESERVE: u64 = 10_000;
const MIN_EXPECTED_GAS_USED: u64 = TX_GAS_LIMIT - GAS_BURNER_RESERVE;
// Leave one block to initialize the txpool's tracked block gas limit, then one block to execute
// the pre-Karst transaction.
const KARST_ACTIVATION_TIMESTAMP: u64 = FORK_ACTIVATION_TIMESTAMP + 1;
const EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP: u64 = KARST_ACTIVATION_TIMESTAMP + 1;

alloy_sol_macro::sol!("tests/e2e/contracts/GasBurner.sol");

fn high_gas_limit_payload_attributes(
    timestamp: u64,
) -> reth_optimism_node::payload::OpPayloadAttrs {
    let mut attributes = op_payload_attributes(timestamp);
    attributes.0.gas_limit = Some(BLOCK_GAS_LIMIT);
    attributes
}

fn evm_limits_genesis(
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
    genesis["config"]["karstTime"] = serde_json::json!(KARST_ACTIVATION_TIMESTAMP);
    genesis["config"]["conduit"] = serde_json::json!({
        "evmLimitsFork0": {
            "time": EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP,
            "txGasLimitCap": u64::MAX
        }
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

/// Proves the full RPC -> txpool -> payload builder -> execution path accepts and executes a
/// 500M-gas transaction before Karst, rejects one under Karst's EIP-7825 cap, then accepts and
/// executes it again after the custom fork.
#[tokio::test]
async fn test_500m_gas_transaction_across_evm_limits_fork() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let gas_burner = address!("5000000000000000000000000000000000000000");
    let chain_spec = parse_chain_spec(&evm_limits_genesis(signer.address(), gas_burner));
    let (_tasks, mut ctx) =
        launch_test_node!(chain_spec.clone(), high_gas_limit_payload_attributes);
    let input = GasBurner::burnCall {
        memoryBytes: U256::from(GAS_BURNER_MEMORY_BYTES),
        gasReserve: U256::from(GAS_BURNER_RESERVE),
    }
    .abi_encode();

    let gas_burner_tx = |nonce| TransactionRequest {
        chain_id: Some(chain_spec.chain_id()),
        nonce: Some(nonce),
        to: Some(TxKind::Call(gas_burner)),
        value: Some(U256::from(1)),
        gas: Some(TX_GAS_LIMIT),
        max_fee_per_gas: Some(1_000_000_000),
        max_priority_fee_per_gas: Some(1),
        input: TransactionInput::new(input.clone().into()),
        ..Default::default()
    };

    // The txpool starts with a conservative block gas limit and tracks the actual limit after its
    // first canonical block.
    advance!(ctx);

    // Block 2 is before Karst. The txpool, payload builder, and REVM must all accept and execute a
    // transaction with a 500M declared gas limit.
    let pre_karst = TransactionTestContext::sign_tx(signer.clone(), gas_burner_tx(0)).await;
    let pre_karst_hash = ctx.rpc.inject_tx(Bytes::from(pre_karst.encoded_2718())).await?;
    let pre_karst_payload = advance!(ctx);
    let pre_karst_timestamp = pre_karst_payload.block().timestamp();
    assert!(!chain_spec.is_karst_active_at_timestamp(pre_karst_timestamp));
    assert!(!chain_spec.is_evm_limits_fork0_active_at_timestamp(pre_karst_timestamp));
    let pre_karst_tx = pre_karst_payload
        .block()
        .body()
        .transactions()
        .find(|tx| *tx.tx_hash() == pre_karst_hash)
        .expect("500M-gas transaction should be included before Karst");
    assert_eq!(pre_karst_tx.gas_limit(), TX_GAS_LIMIT);
    let pre_karst_receipt = ctx
        .rpc
        .inner
        .eth_api()
        .transaction_receipt(pre_karst_hash)
        .await?
        .expect("pre-Karst 500M-gas transaction should have a receipt");
    assert!(pre_karst_receipt.inner.inner.status(), "pre-Karst gas burner should succeed");
    assert!(
        pre_karst_receipt.inner.gas_used >= MIN_EXPECTED_GAS_USED,
        "pre-Karst gas burner should consume nearly 500M gas, used {}",
        pre_karst_receipt.inner.gas_used
    );

    let post_karst = TransactionTestContext::sign_tx(signer, gas_burner_tx(1)).await;
    let post_karst_raw: Bytes = post_karst.encoded_2718().into();

    // Block 3 activates Karst. Once it is canonical, the txpool must enforce EIP-7825.
    let karst_payload = advance!(ctx);
    let karst_timestamp = karst_payload.block().timestamp();
    assert!(chain_spec.is_karst_active_at_timestamp(karst_timestamp));
    assert!(!chain_spec.is_evm_limits_fork0_active_at_timestamp(karst_timestamp));
    let err = ctx.rpc.inject_tx(post_karst_raw.clone()).await.unwrap_err();
    assert!(
        err.to_string().contains("gas limit too high"),
        "expected EIP-7825 rejection under Karst, got: {err}"
    );

    // Block 4 activates the custom fork. Once it is canonical, the txpool must accept the same tx.
    let custom_fork_payload = advance!(ctx);
    let custom_fork_timestamp = custom_fork_payload.block().timestamp();
    assert!(chain_spec.is_karst_active_at_timestamp(custom_fork_timestamp));
    assert!(chain_spec.is_evm_limits_fork0_active_at_timestamp(custom_fork_timestamp));
    let post_fork_hash = ctx.rpc.inject_tx(post_karst_raw).await?;

    // Block 5 proves the payload builder and REVM accept and execute it again.
    let post_fork_payload = advance!(ctx);
    let post_fork_tx = post_fork_payload
        .block()
        .body()
        .transactions()
        .find(|tx| *tx.tx_hash() == post_fork_hash)
        .expect("500M-gas transaction should be included after custom fork");
    assert_eq!(post_fork_tx.gas_limit(), TX_GAS_LIMIT);

    let post_fork_receipt = ctx
        .rpc
        .inner
        .eth_api()
        .transaction_receipt(post_fork_hash)
        .await?
        .expect("post-fork 500M-gas transaction should have a receipt");
    assert!(post_fork_receipt.inner.inner.status(), "post-fork gas burner should succeed");
    assert!(
        post_fork_receipt.inner.gas_used >= MIN_EXPECTED_GAS_USED,
        "post-fork gas burner should consume nearly 500M gas, used {}",
        post_fork_receipt.inner.gas_used
    );

    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.basic_account(&gas_burner)?.expect("gas burner should exist").balance,
        U256::from(2),
        "both value transfers prove the pre-Karst and post-fork calls completed successfully"
    );

    Ok(())
}
