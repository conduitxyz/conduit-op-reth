use crate::e2e::{
    FORK_ACTIVATION_TIMESTAMP, OverrideTestV1, OverrideTestV2, PREFUND_BALANCE, STORAGE_ADDRESS,
    STORAGE_SLOT, STORAGE_SLOT_2, TARGET_ADDRESS, TARGET_BYTECODE, build_genesis_with_override,
    create_deploy_tx, launch_test_node, parse_chain_spec,
};
use alloy_primitives::{Bytes, TxKind, U256, address};
use alloy_rpc_types_eth::{TransactionRequest, state::EvmOverrides};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use reth_chainspec::EthChainSpec;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::helpers::EthCall;
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
    let value = state.storage(STORAGE_ADDRESS, STORAGE_SLOT)?;
    assert_eq!(value, None, "storage should be empty before activation");

    // Block at t=4: fork activates.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state.account_code(&STORAGE_ADDRESS)?;
    assert!(code.is_some(), "should have code at activation");
    let value = state.storage(STORAGE_ADDRESS, STORAGE_SLOT)?;
    assert_eq!(
        value,
        Some(U256::from(0xff)),
        "storage value should be set at activation"
    );

    // Block at t=6: post-activation, storage persists.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let value = state.storage(STORAGE_ADDRESS, STORAGE_SLOT)?;
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
    assert_eq!(
        account.balance, expected_balance,
        "pre-fund balance should exist before activation"
    );

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
    let init_code = Bytes::from_static(&[
        0x61, 0xfe, 0xfe, 0x60, 0x00, 0x52, 0x60, 0x02, 0x60, 0x1e, 0xf3,
    ]);

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
    alloc.insert(
        deployer_hex,
        serde_json::json!({ "balance": "0xde0b6b3a7640000" }),
    );

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::Value::Object(updates),
        Some(serde_json::Value::Object(alloc)),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec.clone());

    // Deploy the contract in block 1 (before fork activation).
    let raw_tx = create_deploy_tx(chain_spec.chain_id(), init_code, deployer_key).await;
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
    let val1 = state.storage(contract_addr, STORAGE_SLOT)?;
    assert_eq!(
        val1,
        Some(U256::from(0xff)),
        "slot 1 should be set by override"
    );
    let val2 = state.storage(contract_addr, STORAGE_SLOT_2)?;
    assert_eq!(
        val2,
        Some(U256::from(0x42)),
        "slot 2 should be set by override"
    );

    // Block 3: post-activation, values persist.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("code should persist after activation");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));
    let val1 = state.storage(contract_addr, STORAGE_SLOT)?;
    assert_eq!(val1, Some(U256::from(0xff)), "slot 1 should persist");
    let val2 = state.storage(contract_addr, STORAGE_SLOT_2)?;
    assert_eq!(val2, Some(U256::from(0x42)), "slot 2 should persist");

    Ok(())
}

/// Proves injected bytecode is actually executable via `eth_call`.
///
/// Places V1 deployed bytecode (getValue() → 42) at a fixed address via genesis alloc,
/// then overrides it with V2 (getValue() → 99) at fork activation. Uses `EthCall::call`
/// to verify the return value changes.
#[tokio::test]
async fn test_state_override_bytecode_executable_via_eth_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let contract_addr = address!("bEEF00000000000000000000000000000000bEEF");

    // V1/V2 deployed bytecodes as hex strings (Display includes 0x prefix).
    let v1_hex = format!("{}", OverrideTestV1::DEPLOYED_BYTECODE);
    let v2_hex = format!("{}", OverrideTestV2::DEPLOYED_BYTECODE);

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            format!("{contract_addr}"): {
                "code": v2_hex
            }
        }),
        // Pre-populate the address with V1 bytecode in genesis alloc.
        Some(serde_json::json!({
            format!("{contract_addr}"): {
                "balance": "0x0",
                "code": v1_hex
            }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Encode getValue() call.
    let calldata: Bytes = OverrideTestV1::getValueCall {}.abi_encode().into();
    let call_request = TransactionRequest {
        to: Some(TxKind::Call(contract_addr)),
        input: alloy_rpc_types_eth::TransactionInput {
            input: None,
            data: Some(calldata.clone()),
        },
        ..Default::default()
    };

    // Block 1: before fork activation — V1 is deployed, getValue() should return 42.
    ctx.advance_block().await?;
    let result = EthCall::call(
        ctx.rpc.inner.eth_api(),
        call_request.clone().into(),
        None,
        EvmOverrides::default(),
    )
    .await?;
    let ret = OverrideTestV1::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(
        ret,
        U256::from(42),
        "V1 getValue() should return 42 before fork"
    );

    // Block 2: fork activates — V2 bytecode is injected, getValue() should return 99.
    ctx.advance_block().await?;
    let result = EthCall::call(
        ctx.rpc.inner.eth_api(),
        call_request.clone().into(),
        None,
        EvmOverrides::default(),
    )
    .await?;
    let ret = OverrideTestV2::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(
        ret,
        U256::from(99),
        "V2 getValue() should return 99 after fork"
    );

    // Block 3: post-activation — still V2.
    ctx.advance_block().await?;
    let result = EthCall::call(
        ctx.rpc.inner.eth_api(),
        call_request.into(),
        None,
        EvmOverrides::default(),
    )
    .await?;
    let ret = OverrideTestV2::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(
        ret,
        U256::from(99),
        "V2 getValue() should persist after fork"
    );

    Ok(())
}

/// Verifies that multiple addresses can be overridden simultaneously at activation.
///
/// Address A: bytecode-only override
/// Address B: bytecode + storage override
#[tokio::test]
async fn test_state_override_multi_account() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let addr_a = address!("aAaA000000000000000000000000000000000001");
    let addr_b = address!("bBbB000000000000000000000000000000000002");

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            format!("{addr_a}"): {
                "code": "0x6080604052"
            },
            format!("{addr_b}"): {
                "code": "0xfefe",
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

    // Block 1: before fork — neither address should have code.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    assert!(
        state.account_code(&addr_a)?.is_none(),
        "addr_a: no code before fork"
    );
    assert!(
        state.account_code(&addr_b)?.is_none(),
        "addr_b: no code before fork"
    );
    assert_eq!(
        state.storage(addr_b, STORAGE_SLOT)?,
        None,
        "addr_b: no storage before fork"
    );

    // Block 2: fork activates — both addresses should be overridden.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;

    let code_a = state
        .account_code(&addr_a)?
        .expect("addr_a should have code at activation");
    assert_eq!(
        code_a.original_bytes(),
        Bytes::from_static(TARGET_BYTECODE),
        "addr_a: bytecode should match"
    );

    let code_b = state
        .account_code(&addr_b)?
        .expect("addr_b should have code at activation");
    assert_eq!(
        code_b.original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe]),
        "addr_b: bytecode should match"
    );
    let val = state.storage(addr_b, STORAGE_SLOT)?;
    assert_eq!(
        val,
        Some(U256::from(0xff)),
        "addr_b: storage slot should be set"
    );

    // Block 3: post-activation — both persist.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;

    let code_a = state
        .account_code(&addr_a)?
        .expect("addr_a: code should persist");
    assert_eq!(code_a.original_bytes(), Bytes::from_static(TARGET_BYTECODE));

    let code_b = state
        .account_code(&addr_b)?
        .expect("addr_b: code should persist");
    assert_eq!(code_b.original_bytes(), Bytes::from_static(&[0xfe, 0xfe]));
    let val = state.storage(addr_b, STORAGE_SLOT)?;
    assert_eq!(
        val,
        Some(U256::from(0xff)),
        "addr_b: storage should persist"
    );

    Ok(())
}
