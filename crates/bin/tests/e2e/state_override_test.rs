use crate::e2e::{
    build_genesis_with_override, launch_test_node, parse_chain_spec, FORK_ACTIVATION_TIMESTAMP,
    PREFUND_BALANCE, STORAGE_ADDRESS, STORAGE_SLOT, STORAGE_SLOT_2, TARGET_ADDRESS, TARGET_BYTECODE,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, TxKind, U256};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_provider::StateProviderFactory;
use reth_storage_api::{AccountReader, StateProvider};

#[tokio::test]
async fn test_state_override_bytecode_applied_at_activation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000042": {
                "code": "0x6080604052"
            }
        }),
        None,
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Block at t=2: fork not yet active.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state.account_code(&TARGET_ADDRESS)?;
    assert!(code.is_none(), "should have no code before activation");

    // Block at t=4: fork activates (transition block).
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code at activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(TARGET_BYTECODE),
        "bytecode should be injected at activation"
    );

    // Block at t=6: post-activation, bytecode persists.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code after activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(TARGET_BYTECODE),
        "bytecode should persist after activation"
    );

    Ok(())
}

#[tokio::test]
async fn test_state_override_storage_applied_at_activation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000099": {
                "code": "0x6080604052",
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000001":
                        "0x00000000000000000000000000000000000000000000000000000000000000ff"
                }
            }
        }),
        None,
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Block at t=2: fork not yet active.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state.account_code(&STORAGE_ADDRESS)?;
    assert!(code.is_none(), "should have no code before activation");
    let value = state.storage(STORAGE_ADDRESS, STORAGE_SLOT.into())?;
    assert_eq!(value, None, "storage should be empty before activation");

    // Block at t=4: fork activates.
ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state.account_code(&STORAGE_ADDRESS)?;
    assert!(code.is_some(), "should have code at activation");
    let value = state.storage(STORAGE_ADDRESS, STORAGE_SLOT.into())?;
    assert_eq!(
        value,
        Some(U256::from(0xff)),
        "storage value should be set at activation"
    );

    // Block at t=6: post-activation, storage persists.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let value = state.storage(STORAGE_ADDRESS, STORAGE_SLOT.into())?;
    assert_eq!(
        value,
        Some(U256::from(0xff)),
        "storage value should persist after activation"
    );

    Ok(())
}

#[tokio::test]
async fn test_state_override_preserves_existing_balance() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000042": {
                "code": "0x6080604052"
            }
        }),
        Some(serde_json::json!({
            "0x4200000000000000000000000000000000000042": {
                "balance": PREFUND_BALANCE
            }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    let expected_balance = U256::from_str_radix("de0b6b3a7640000", 16).unwrap();

    // Pre-activation: balance should be set from genesis alloc.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let account = state
        .basic_account(&TARGET_ADDRESS)?
        .expect("account should exist from genesis alloc");
    assert_eq!(account.balance, expected_balance, "pre-fund balance should exist before activation");

    // Activation: bytecode applied, balance preserved.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let account = state
        .basic_account(&TARGET_ADDRESS)?
        .expect("account should exist after activation");
    assert_eq!(
        account.balance, expected_balance,
        "balance should be preserved after bytecode override"
    );

    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code at activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(TARGET_BYTECODE),
        "bytecode should be applied at activation"
    );

    Ok(())
}

/// Deploys a contract via transaction before the fork, then verifies the override
/// replaces both the code and sets multiple storage slots at activation.
#[tokio::test]
async fn test_state_override_overwrites_deployed_contract() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Deployer: first account from test mnemonic "test test ... junk".
    let deployer_key: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let deployer_addr = deployer_key.address();
    // Precompute the CREATE address (deployer, nonce=0).
    let contract_addr = deployer_addr.create(0);

    // Init code that deploys runtime bytecode 0xfefe:
    //   PUSH2 0xfefe  PUSH1 0x00  MSTORE  PUSH1 0x02  PUSH1 0x1e  RETURN
    let init_code = Bytes::from_static(&[0x61, 0xfe, 0xfe, 0x60, 0x00, 0x52, 0x60, 0x02, 0x60, 0x1e, 0xf3]);

    // Build genesis: fund deployer, configure override targeting the precomputed contract address.
    let contract_hex = format!("{contract_addr}");
    let deployer_hex = format!("{deployer_addr}");
    let mut updates = serde_json::Map::new();
    updates.insert(
        contract_hex,
        serde_json::json!({
            "code": "0x6080604052",
            "storage": {
                "0x0000000000000000000000000000000000000000000000000000000000000001":
                    "0x00000000000000000000000000000000000000000000000000000000000000ff",
                "0x0000000000000000000000000000000000000000000000000000000000000002":
                    "0x0000000000000000000000000000000000000000000000000000000000000042"
            }
        }),
    );
    let mut alloc = serde_json::Map::new();
    alloc.insert(deployer_hex, serde_json::json!({ "balance": "0xde0b6b3a7640000" }));

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::Value::Object(updates),
        Some(serde_json::Value::Object(alloc)),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Deploy the contract in block 1 (before fork activation).
    let tx_request = TransactionRequest {
        nonce: Some(0),
        chain_id: Some(202601),
        gas: Some(100_000),
        max_fee_per_gas: Some(20_000_000_000u128),
        max_priority_fee_per_gas: Some(1_000_000_000u128),
        to: Some(TxKind::Create),
        input: TransactionInput { input: None, data: Some(init_code) },
        ..Default::default()
    };
    let signed = TransactionTestContext::sign_tx(deployer_key, tx_request).await;
    let raw_tx: Bytes = signed.encoded_2718().into();
    ctx.rpc.inject_tx(raw_tx).await?;
    ctx.advance_block().await?;

    // Verify the contract was deployed with original code.
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("contract should be deployed");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe]),
        "should have original deployed bytecode"
    );

    // Block 2: fork activates — code and storage should be overridden.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("contract should still have code after override");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(TARGET_BYTECODE),
        "code should be overwritten by fork override"
    );
    let val1 = state.storage(contract_addr, STORAGE_SLOT.into())?;
    assert_eq!(val1, Some(U256::from(0xff)), "slot 1 should be set by override");
    let val2 = state.storage(contract_addr, STORAGE_SLOT_2.into())?;
    assert_eq!(val2, Some(U256::from(0x42)), "slot 2 should be set by override");

    // Block 3: post-activation, values persist.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("code should persist after activation");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));
    let val1 = state.storage(contract_addr, STORAGE_SLOT.into())?;
    assert_eq!(val1, Some(U256::from(0xff)), "slot 1 should persist");
    let val2 = state.storage(contract_addr, STORAGE_SLOT_2.into())?;
    assert_eq!(val2, Some(U256::from(0x42)), "slot 2 should persist");

    Ok(())
}
