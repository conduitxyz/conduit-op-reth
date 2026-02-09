use crate::e2e::{
    FORK_ACTIVATION_TIMESTAMP, PREFUND_BALANCE, PREFUND_BALANCE_U256, STORAGE_SLOT_1,
    STORAGE_SLOT_2, TARGET_BYTECODE, advance, build_genesis_with_override, launch_test_node,
    parse_chain_spec,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, TxKind, U256, address};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest, state::EvmOverrides};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::{EthApiServer, helpers::EthCall};
use reth_storage_api::{AccountReader, StateProvider};

// Deployed bytecodes for OverrideTestV1 (getValue() -> 42) and OverrideTestV2 (getValue() -> 99).
alloy_sol_macro::sol! {
    #[sol(deployed_bytecode = "0x6080604052348015600e575f5ffd5b50600436106030575f3560e01c806320965255146034578063509d8c7214604e575b5f5ffd5b603a6068565b60405160459190608b565b60405180910390f35b60546070565b604051605f9190608b565b60405180910390f35b5f602a905090565b602a81565b5f819050919050565b6085816075565b82525050565b5f602082019050609c5f830184607e565b9291505056fea2646970667358221220a878e13f3fe81d198d4cc2c8716b34cd19d74f6fa7f34366a55ae658dc08bd3c64736f6c63430008210033")]
    contract OverrideTestV1 {
        uint256 public constant VALUE = 42;
        function getValue() external pure returns (uint256) { return VALUE; }
    }
}

alloy_sol_macro::sol! {
    #[sol(deployed_bytecode = "0x6080604052348015600e575f5ffd5b50600436106030575f3560e01c806320965255146034578063509d8c7214604e575b5f5ffd5b603a6068565b60405160459190608b565b60405180910390f35b60546070565b604051605f9190608b565b60405180910390f35b5f6063905090565b606381565b5f819050919050565b6085816075565b82525050565b5f602082019050609c5f830184607e565b9291505056fea2646970667358221220572d53ef774c53414dd4f8118dde0e1f3f5a02736b33f5b85bf890fed04a9c2364736f6c63430008210033")]
    contract OverrideTestV2 {
        uint256 public constant VALUE = 99;
        function getValue() external pure returns (uint256) { return VALUE; }
    }
}

async fn create_deploy_tx(chain_id: u64, init_code: Bytes, wallet: PrivateKeySigner) -> Bytes {
    let tx = TransactionRequest {
        nonce: Some(0),
        chain_id: Some(chain_id),
        gas: Some(100_000),
        max_fee_per_gas: Some(1_000_000_000_000u128),
        max_priority_fee_per_gas: Some(1_000_000_000u128),
        to: Some(TxKind::Create),
        input: TransactionInput::new(init_code),
        ..Default::default()
    };
    let signed = TransactionTestContext::sign_tx(wallet, tx).await;
    signed.encoded_2718().into()
}

/// Consolidates the core override scenarios: multi-account override (code-only vs code+storage),
/// balance preservation on an address with a pre-existing genesis alloc, and 3-block persistence.
#[tokio::test]
async fn test_state_override_applied_at_activation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // addr_a: fresh address, code + storage override.
    // addr_b: has a pre-existing genesis balance, code-only override (tests balance preservation).
    let addr_a = address!("aAaA000000000000000000000000000000000001");
    let addr_b = address!("bBbB000000000000000000000000000000000002");

    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            format!("{addr_a}"): {
                "code": "0x6080604052",
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000001":
                        "0x00000000000000000000000000000000000000000000000000000000000000ff"
                }
            },
            format!("{addr_b}"): { "code": "0xfefe" }
        }),
        Some(serde_json::json!({
            format!("{addr_b}"): { "balance": PREFUND_BALANCE }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Block 1: fork not yet active — no overrides applied.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert!(state.account_code(&addr_a)?.is_none());
    assert_eq!(state.storage(addr_a, STORAGE_SLOT_1)?, None);
    assert!(state.account_code(&addr_b)?.is_none());
    assert_eq!(
        state
            .basic_account(&addr_b)?
            .expect("addr_b from genesis alloc")
            .balance,
        PREFUND_BALANCE_U256
    );

    // Block 2: fork activates — both overrides applied, balance preserved.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.account_code(&addr_a)?.unwrap().original_bytes(),
        Bytes::from_static(TARGET_BYTECODE)
    );
    assert_eq!(
        state.storage(addr_a, STORAGE_SLOT_1)?,
        Some(U256::from(0xff))
    );
    assert_eq!(
        state.account_code(&addr_b)?.unwrap().original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe])
    );
    assert_eq!(
        state.basic_account(&addr_b)?.unwrap().balance,
        PREFUND_BALANCE_U256,
    );

    // Block 3: all values persist.
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.account_code(&addr_a)?.unwrap().original_bytes(),
        Bytes::from_static(TARGET_BYTECODE)
    );
    assert_eq!(
        state.storage(addr_a, STORAGE_SLOT_1)?,
        Some(U256::from(0xff))
    );
    assert_eq!(
        state.account_code(&addr_b)?.unwrap().original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe])
    );
    assert_eq!(
        state.basic_account(&addr_b)?.unwrap().balance,
        PREFUND_BALANCE_U256,
    );

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
        serde_json::json!({ "balance": PREFUND_BALANCE }),
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
        state.storage(contract_addr, STORAGE_SLOT_1)?,
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
        state.storage(contract_addr, STORAGE_SLOT_1)?,
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
        input: TransactionInput::new(calldata),
        ..Default::default()
    };

    // Block 1: V1 deployed, getValue() -> 42.
    advance!(ctx);
    let result = EthCall::call(
        ctx.rpc.inner.eth_api(),
        call_request.clone().into(),
        None,
        EvmOverrides::default(),
    )
    .await?;
    let ret = OverrideTestV1::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(ret, U256::from(42));

    // Block 2: fork activates, V2 injected, getValue() -> 99.
    advance!(ctx);
    let result = EthCall::call(
        ctx.rpc.inner.eth_api(),
        call_request.clone().into(),
        None,
        EvmOverrides::default(),
    )
    .await?;
    let ret = OverrideTestV2::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(ret, U256::from(99));

    // Block 3: still V2.
    advance!(ctx);
    let result = EthCall::call(
        ctx.rpc.inner.eth_api(),
        call_request.into(),
        None,
        EvmOverrides::default(),
    )
    .await?;
    let ret = OverrideTestV2::getValueCall::abi_decode_returns(&result)?;
    assert_eq!(ret, U256::from(99));

    Ok(())
}
