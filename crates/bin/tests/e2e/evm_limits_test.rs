use crate::e2e::{
    BASE_GENESIS, FORK_ACTIVATION_TIMESTAMP, advance, launch_test_node, op_payload_attributes,
    parse_chain_spec,
};
use alloy_consensus::{BlockHeader, Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, TxKind, U256, address};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolConstructor};
use conduit_op_reth_node::hardforks::ConduitOpHardforks;
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_optimism_chainspec::OpHardforks;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::helpers::EthTransactions;
use reth_storage_api::{AccountReader, StateProvider};
use revm::primitives::{eip170::MAX_CODE_SIZE, eip3860::MAX_INITCODE_SIZE};

const TX_GAS_LIMIT: u64 = 500_000_000;
const BLOCK_GAS_LIMIT: u64 = 1_000_000_000;
const GAS_BURNER_MEMORY_BYTES: u64 = 16_000_000;
const GAS_BURNER_RESERVE: u64 = 10_000;
const MIN_EXPECTED_GAS_USED: u64 = TX_GAS_LIMIT - GAS_BURNER_RESERVE;
const LARGE_CONTRACT_SIZE: usize = MAX_INITCODE_SIZE + 1_024;
const CUSTOM_CODE_SIZE_LIMIT: usize = LARGE_CONTRACT_SIZE;
const CUSTOM_INITCODE_SIZE_LIMIT: usize = LARGE_CONTRACT_SIZE + 10_000;
const CONTRACT_DEPLOYMENT_GAS_LIMIT: u64 = 15_000_000;
const _: () = assert!(LARGE_CONTRACT_SIZE > MAX_CODE_SIZE);
// Leave one block to initialize the txpool's tracked block gas limit, then one block to execute
// the pre-Karst transaction.
const KARST_ACTIVATION_TIMESTAMP: u64 = FORK_ACTIVATION_TIMESTAMP + 1;
const EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP: u64 = KARST_ACTIVATION_TIMESTAMP + 1;
const PRE_KARST_EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP: u64 = FORK_ACTIVATION_TIMESTAMP - 1;

alloy_sol_macro::sol!("tests/e2e/contracts/GasBurner.sol");
alloy_sol_macro::sol!("tests/e2e/contracts/LargeContract.sol");

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
    evm_limits_fork0_time: u64,
    mut limits: serde_json::Value,
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
    limits["time"] = serde_json::json!(evm_limits_fork0_time);
    genesis["config"]["conduit"] = serde_json::json!({ "evmLimitsFork0": limits });
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

fn gas_burner_transaction(
    chain_id: u64,
    gas_burner: alloy_primitives::Address,
    nonce: u64,
) -> TransactionRequest {
    let input = GasBurner::burnCall {
        memoryBytes: U256::from(GAS_BURNER_MEMORY_BYTES),
        gasReserve: U256::from(GAS_BURNER_RESERVE),
    }
    .abi_encode();

    TransactionRequest {
        chain_id: Some(chain_id),
        nonce: Some(nonce),
        to: Some(TxKind::Call(gas_burner)),
        value: Some(U256::from(1)),
        gas: Some(TX_GAS_LIMIT),
        max_fee_per_gas: Some(1_000_000_000),
        max_priority_fee_per_gas: Some(1),
        input: TransactionInput::new(input.into()),
        ..Default::default()
    }
}

fn large_contract_initcode() -> Bytes {
    let artifact: serde_json::Value =
        serde_json::from_str(include_str!("contracts/LargeContract.json"))
            .expect("failed to parse large contract artifact");
    let creation_code: Bytes = serde_json::from_value(artifact["bytecode"]["object"].clone())
        .expect("large contract artifact should contain creation bytecode");
    let constructor =
        LargeContract::constructorCall { runtimeCode: Bytes::from(vec![0; LARGE_CONTRACT_SIZE]) };

    let mut initcode = creation_code.to_vec();
    initcode.extend(constructor.abi_encode());
    Bytes::from(initcode)
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
    let chain_spec = parse_chain_spec(&evm_limits_genesis(
        signer.address(),
        gas_burner,
        EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP,
        serde_json::json!({ "txGasLimitCap": u64::MAX }),
    ));
    let (_tasks, mut ctx) =
        launch_test_node!(chain_spec.clone(), high_gas_limit_payload_attributes);
    let gas_burner_tx = |nonce| gas_burner_transaction(chain_spec.chain_id(), gas_burner, nonce);

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

/// Proves that activating EvmLimitsFork0 before Karst prevents Karst's EIP-7825 transaction gas
/// cap from taking effect in the txpool, payload builder, and REVM.
#[tokio::test]
async fn test_500m_tx_gas_cap_override_persists_through_karst() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let gas_burner = address!("5000000000000000000000000000000000000000");
    let chain_spec = parse_chain_spec(&evm_limits_genesis(
        signer.address(),
        gas_burner,
        PRE_KARST_EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP,
        serde_json::json!({ "txGasLimitCap": u64::MAX }),
    ));
    let (_tasks, mut ctx) =
        launch_test_node!(chain_spec.clone(), high_gas_limit_payload_attributes);

    // Block 1 activates the custom fork and initializes the txpool's tracked block gas limit.
    let custom_fork_payload = advance!(ctx);
    let custom_fork_timestamp = custom_fork_payload.block().timestamp();
    assert!(chain_spec.is_evm_limits_fork0_active_at_timestamp(custom_fork_timestamp));
    assert!(!chain_spec.is_karst_active_at_timestamp(custom_fork_timestamp));

    // Block 2 proves the custom fork allows the 500M-gas transaction before Karst.
    let pre_karst = TransactionTestContext::sign_tx(
        signer.clone(),
        gas_burner_transaction(chain_spec.chain_id(), gas_burner, 0),
    )
    .await;
    let pre_karst_hash = ctx.rpc.inject_tx(Bytes::from(pre_karst.encoded_2718())).await?;
    let pre_karst_payload = advance!(ctx);
    let pre_karst_timestamp = pre_karst_payload.block().timestamp();
    assert!(chain_spec.is_evm_limits_fork0_active_at_timestamp(pre_karst_timestamp));
    assert!(!chain_spec.is_karst_active_at_timestamp(pre_karst_timestamp));
    let pre_karst_tx = pre_karst_payload
        .block()
        .body()
        .transactions()
        .find(|tx| *tx.tx_hash() == pre_karst_hash)
        .expect("500M-gas transaction should be included after EvmLimitsFork0");
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

    // Block 3 activates Karst. The custom fork must remain active after the standard hardfork
    // changes the underlying EVM spec.
    let karst_payload = advance!(ctx);
    let karst_timestamp = karst_payload.block().timestamp();
    assert!(chain_spec.is_evm_limits_fork0_active_at_timestamp(karst_timestamp));
    assert!(chain_spec.is_karst_active_at_timestamp(karst_timestamp));

    let tx = TransactionTestContext::sign_tx(
        signer,
        gas_burner_transaction(chain_spec.chain_id(), gas_burner, 1),
    )
    .await;

    // Injecting after Karst is canonical proves the txpool still sees the custom u64::MAX cap.
    let tx_hash = ctx.rpc.inject_tx(Bytes::from(tx.encoded_2718())).await?;
    let post_karst_payload = advance!(ctx);
    let included = post_karst_payload
        .block()
        .body()
        .transactions()
        .find(|tx| *tx.tx_hash() == tx_hash)
        .expect("500M-gas transaction should be included after Karst");
    assert_eq!(included.gas_limit(), TX_GAS_LIMIT);

    let receipt = ctx
        .rpc
        .inner
        .eth_api()
        .transaction_receipt(tx_hash)
        .await?
        .expect("post-Karst 500M-gas transaction should have a receipt");
    assert!(receipt.inner.inner.status(), "post-Karst gas burner should succeed");
    assert!(
        receipt.inner.gas_used >= MIN_EXPECTED_GAS_USED,
        "post-Karst gas burner should consume nearly 500M gas, used {}",
        receipt.inner.gas_used
    );

    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.basic_account(&gas_burner)?.expect("gas burner should exist").balance,
        U256::from(2),
        "both value transfers prove the pre-Karst and post-Karst calls completed successfully"
    );

    Ok(())
}

/// Proves EvmLimitsFork0 updates both txpool initcode validation and REVM's deployed contract-size
/// validation by deploying one contract that exceeds both protocol defaults.
#[tokio::test]
async fn test_oversized_initcode_and_contract_after_evm_limits_fork() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let gas_burner = address!("5000000000000000000000000000000000000000");
    let chain_spec = parse_chain_spec(&evm_limits_genesis(
        signer.address(),
        gas_burner,
        PRE_KARST_EVM_LIMITS_FORK0_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "maxCodeSize": CUSTOM_CODE_SIZE_LIMIT,
            "maxInitcodeSize": CUSTOM_INITCODE_SIZE_LIMIT,
        }),
    ));
    let (_tasks, mut ctx) =
        launch_test_node!(chain_spec.clone(), high_gas_limit_payload_attributes);

    let initcode = large_contract_initcode();
    let initcode_len = initcode.len();
    assert!(initcode_len > MAX_INITCODE_SIZE);
    let deployment = TransactionTestContext::sign_tx(
        signer,
        TransactionRequest {
            chain_id: Some(chain_spec.chain_id()),
            nonce: Some(0),
            to: Some(TxKind::Create),
            gas: Some(CONTRACT_DEPLOYMENT_GAS_LIMIT),
            max_fee_per_gas: Some(1_000_000_000),
            max_priority_fee_per_gas: Some(1),
            input: TransactionInput::new(initcode),
            ..Default::default()
        },
    )
    .await;
    let raw_deployment: Bytes = deployment.encoded_2718().into();

    // At genesis, the txpool still enforces EIP-3860's default initcode limit.
    let err = ctx.rpc.inject_tx(raw_deployment.clone()).await.unwrap_err();
    assert!(
        err.to_string().contains("max initcode size exceeded"),
        "expected oversized initcode rejection before EvmLimitsFork0, got: {err}"
    );

    // Block 1 activates EvmLimitsFork0. The same transaction must now pass txpool validation.
    let activation_payload = advance!(ctx);
    let activation_timestamp = activation_payload.block().timestamp();
    assert!(chain_spec.is_evm_limits_fork0_active_at_timestamp(activation_timestamp));
    assert!(!chain_spec.is_karst_active_at_timestamp(activation_timestamp));
    let deployment_hash = ctx.rpc.inject_tx(raw_deployment).await?;

    // Block 2 proves REVM also applies the custom contract-size limit during creation.
    let deployment_payload = advance!(ctx);
    let included = deployment_payload
        .block()
        .body()
        .transactions()
        .find(|tx| *tx.tx_hash() == deployment_hash)
        .expect("oversized contract deployment should be included after EvmLimitsFork0");
    assert_eq!(included.input().len(), initcode_len);

    let receipt = ctx
        .rpc
        .inner
        .eth_api()
        .transaction_receipt(deployment_hash)
        .await?
        .expect("oversized contract deployment should have a receipt");
    assert!(receipt.inner.inner.status(), "oversized contract deployment should succeed");
    let contract_address =
        receipt.inner.contract_address.expect("deployment should create a contract");

    let state = ctx.inner.provider.latest()?;
    let code = state.account_code(&contract_address)?.expect("deployed contract should have code");
    assert_eq!(code.original_bytes().len(), LARGE_CONTRACT_SIZE);

    Ok(())
}
