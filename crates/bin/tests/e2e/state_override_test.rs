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
use reth_rpc_eth_api::{EthApiServer, helpers::EthCall};
use reth_storage_api::{AccountReader, StateProvider};

/// Advance one block and wait for it to be committed.
///
/// `advance_block()` returns before the pipeline finishes. `wait_block()` polls
/// until the block header is available, ensuring `provider.latest()` is up to date.
macro_rules! advance {
    ($ctx:expr) => {{
        let payload = $ctx.advance_block().await?;
        $ctx.wait_block(payload.block().number, payload.block().hash(), false)
            .await?;
        payload
    }};
}

/// Bytecode-only override: absent before fork, injected at activation, persists after.
#[tokio::test]
async fn test_state_override_bytecode_applied_at_activation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000042": { "code": "0x6080604052" }
        }),
        None,
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Block 1: fork not yet active.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert!(
        state.account_code(&TARGET_ADDRESS)?.is_none(),
        "should have no code before activation"
    );

    // Block 2: fork activates (transition block).
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code at activation");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));

    // Block 3: bytecode persists.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code after activation");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));

    Ok(())
}

/// Code + storage override on a fresh address: both absent before fork, applied at
/// activation, persist after.
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

    // Block 1: fork not yet active.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert!(state.account_code(&STORAGE_ADDRESS)?.is_none());
    assert_eq!(state.storage(STORAGE_ADDRESS, STORAGE_SLOT)?, None);

    // Block 2: fork activates.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert!(state.account_code(&STORAGE_ADDRESS)?.is_some());
    assert_eq!(
        state.storage(STORAGE_ADDRESS, STORAGE_SLOT)?,
        Some(U256::from(0xff))
    );

    // Block 3: storage persists.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.storage(STORAGE_ADDRESS, STORAGE_SLOT)?,
        Some(U256::from(0xff))
    );

    Ok(())
}

/// Override applies bytecode without clobbering a pre-existing genesis balance.
#[tokio::test]
async fn test_state_override_preserves_existing_balance() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000042": { "code": "0x6080604052" }
        }),
        Some(serde_json::json!({
            "0x4200000000000000000000000000000000000042": { "balance": PREFUND_BALANCE }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    let expected_balance = U256::from_str_radix("de0b6b3a7640000", 16).unwrap();

    // Block 1: balance from genesis alloc.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let account = state
        .basic_account(&TARGET_ADDRESS)?
        .expect("account should exist from genesis alloc");
    assert_eq!(account.balance, expected_balance);

    // Block 2: fork activates — balance preserved, bytecode applied.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let account = state
        .basic_account(&TARGET_ADDRESS)?
        .expect("account should exist after activation");
    assert_eq!(account.balance, expected_balance);
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code at activation");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));

    Ok(())
}

/// Deploys a contract via transaction before the fork, then verifies the override
/// replaces both the code and sets multiple storage slots at activation.
#[tokio::test]
async fn test_state_override_overwrites_deployed_contract() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let deployer_key: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let deployer_addr = deployer_key.address();
    let contract_addr = deployer_addr.create(0);

    // Init code: deploys runtime bytecode 0xfefe.
    let init_code = Bytes::from_static(&[
        0x61, 0xfe, 0xfe, 0x60, 0x00, 0x52, 0x60, 0x02, 0x60, 0x1e, 0xf3,
    ]);

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

    // Block 1: deploy the contract before fork activation.
    let raw_tx = create_deploy_tx(chain_spec.chain_id(), init_code, deployer_key).await;
    let tx_hash = ctx.rpc.inject_tx(raw_tx).await?;

    // Wait for the tx to appear in the pool before building a block.
    let start = std::time::Instant::now();
    loop {
        if ctx
            .rpc
            .inner
            .eth_api()
            .transaction_by_hash(tx_hash)
            .await?
            .is_some()
        {
            break;
        }
        if start.elapsed() > std::time::Duration::from_secs(2) {
            eyre::bail!("tx {tx_hash} did not appear in txpool");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let payload = advance!(ctx);
    let included = payload
        .block()
        .body()
        .transactions()
        .any(|tx| *tx.tx_hash() == tx_hash);
    assert!(included, "deploy tx should be included in block");

    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("contract should be deployed");
    assert_eq!(code.original_bytes(), Bytes::from_static(&[0xfe, 0xfe]));

    // Block 2: fork activates — code and storage overridden.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("should have code after override");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));
    assert_eq!(
        state.storage(contract_addr, STORAGE_SLOT)?,
        Some(U256::from(0xff))
    );
    assert_eq!(
        state.storage(contract_addr, STORAGE_SLOT_2)?,
        Some(U256::from(0x42))
    );

    // Block 3: values persist.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&contract_addr)?
        .expect("code should persist");
    assert_eq!(code.original_bytes(), Bytes::from_static(TARGET_BYTECODE));
    assert_eq!(
        state.storage(contract_addr, STORAGE_SLOT)?,
        Some(U256::from(0xff))
    );
    assert_eq!(
        state.storage(contract_addr, STORAGE_SLOT_2)?,
        Some(U256::from(0x42))
    );

    Ok(())
}

/// Places V1 bytecode (getValue() -> 42) via genesis alloc, overrides with V2
/// (getValue() -> 99) at fork activation, and verifies via `eth_call`.
#[tokio::test]
async fn test_state_override_bytecode_executable_via_eth_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let contract_addr = address!("bEEF00000000000000000000000000000000bEEF");
    let v1_hex = format!("{}", OverrideTestV1::DEPLOYED_BYTECODE);
    let v2_hex = format!("{}", OverrideTestV2::DEPLOYED_BYTECODE);

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({ format!("{contract_addr}"): { "code": v2_hex } }),
        Some(serde_json::json!({
            format!("{contract_addr}"): { "balance": "0x0", "code": v1_hex }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    let calldata: Bytes = OverrideTestV1::getValueCall {}.abi_encode().into();
    let call_request = TransactionRequest {
        to: Some(TxKind::Call(contract_addr)),
        input: alloy_rpc_types_eth::TransactionInput {
            input: None,
            data: Some(calldata),
        },
        ..Default::default()
    };

    macro_rules! eth_call {
        ($ctx:expr, $req:expr) => {
            EthCall::call(
                $ctx.rpc.inner.eth_api(),
                $req.into(),
                None,
                EvmOverrides::default(),
            )
            .await
        };
    }

    // Block 1: V1 deployed, getValue() -> 42.
    advance!(ctx);
    let result = eth_call!(ctx, call_request.clone())?;
    let ret = OverrideTestV1::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(ret, U256::from(42));

    // Block 2: fork activates, V2 injected, getValue() -> 99.
    advance!(ctx);
    let result = eth_call!(ctx, call_request.clone())?;
    let ret = OverrideTestV2::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(ret, U256::from(99));

    // Block 3: still V2.
    advance!(ctx);
    let result = eth_call!(ctx, call_request)?;
    let ret = OverrideTestV2::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(ret, U256::from(99));

    Ok(())
}

/// Multiple addresses overridden simultaneously at activation.
#[tokio::test]
async fn test_state_override_multi_account() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let addr_a = address!("aAaA000000000000000000000000000000000001");
    let addr_b = address!("bBbB000000000000000000000000000000000002");

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            format!("{addr_a}"): { "code": "0x6080604052" },
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

    // Block 1: neither address has code.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert!(state.account_code(&addr_a)?.is_none());
    assert!(state.account_code(&addr_b)?.is_none());
    assert_eq!(state.storage(addr_b, STORAGE_SLOT)?, None);

    // Block 2: fork activates — both overridden.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.account_code(&addr_a)?.unwrap().original_bytes(),
        Bytes::from_static(TARGET_BYTECODE)
    );
    assert_eq!(
        state.account_code(&addr_b)?.unwrap().original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe])
    );
    assert_eq!(state.storage(addr_b, STORAGE_SLOT)?, Some(U256::from(0xff)));

    // Block 3: both persist.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.account_code(&addr_a)?.unwrap().original_bytes(),
        Bytes::from_static(TARGET_BYTECODE)
    );
    assert_eq!(
        state.account_code(&addr_b)?.unwrap().original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe])
    );
    assert_eq!(state.storage(addr_b, STORAGE_SLOT)?, Some(U256::from(0xff)));

    Ok(())
}
