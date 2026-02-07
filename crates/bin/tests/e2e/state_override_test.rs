use crate::e2e::{
    build_genesis_with_override, launch_test_node, parse_chain_spec, FORK_ACTIVATION_TIMESTAMP,
    PREFUND_BALANCE, STORAGE_ADDRESS, STORAGE_SLOT, STORAGE_SLOT_2, TARGET_ADDRESS, TARGET_BYTECODE,
};
use alloy_primitives::{Bytes, U256};
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

#[tokio::test]
async fn test_state_override_overwrites_existing_code() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    // Genesis alloc deploys old code on TARGET_ADDRESS; override replaces it.
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000042": {
                "code": "0x6080604052"
            }
        }),
        Some(serde_json::json!({
            "0x4200000000000000000000000000000000000042": {
                "balance": "0x0",
                "code": "0xfefe"
            }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Block at t=2: fork not yet active, should have genesis code.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have genesis code before activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe]),
        "should have old code from genesis alloc"
    );

    // Block at t=4: fork activates, code should be overwritten.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&TARGET_ADDRESS)?
        .expect("should have code at activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(TARGET_BYTECODE),
        "bytecode should be overwritten by fork override"
    );

    Ok(())
}

#[tokio::test]
async fn test_state_override_overwrites_existing_storage_multiple_slots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    // Genesis alloc deploys code + storage on STORAGE_ADDRESS; override replaces both
    // with new code and two storage slots.
    let genesis_json = build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            "0x4200000000000000000000000000000000000099": {
                "code": "0x6080604052",
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000001":
                        "0x00000000000000000000000000000000000000000000000000000000000000ff",
                    "0x0000000000000000000000000000000000000000000000000000000000000002":
                        "0x0000000000000000000000000000000000000000000000000000000000000042"
                }
            }
        }),
        Some(serde_json::json!({
            "0x4200000000000000000000000000000000000099": {
                "balance": "0x0",
                "code": "0xfefe",
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000001": "0xbb",
                    "0x0000000000000000000000000000000000000000000000000000000000000002": "0xcc"
                }
            }
        })),
    );
    let chain_spec = parse_chain_spec(&genesis_json);
    let (_tasks, mut ctx) = launch_test_node!(chain_spec);

    // Block at t=2: fork not yet active, should have genesis values.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&STORAGE_ADDRESS)?
        .expect("should have genesis code before activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(&[0xfe, 0xfe]),
        "should have old code from genesis alloc"
    );
    let val1 = state.storage(STORAGE_ADDRESS, STORAGE_SLOT.into())?;
    assert_eq!(val1, Some(U256::from(0xbb)), "slot 1 should have genesis value");
    let val2 = state.storage(STORAGE_ADDRESS, STORAGE_SLOT_2.into())?;
    assert_eq!(val2, Some(U256::from(0xcc)), "slot 2 should have genesis value");

    // Block at t=4: fork activates, code and both slots should be overwritten.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let code = state
        .account_code(&STORAGE_ADDRESS)?
        .expect("should have code at activation");
    assert_eq!(
        code.original_bytes(),
        Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52]),
        "code should be overwritten by fork override"
    );
    let val1 = state.storage(STORAGE_ADDRESS, STORAGE_SLOT.into())?;
    assert_eq!(val1, Some(U256::from(0xff)), "slot 1 should be overwritten");
    let val2 = state.storage(STORAGE_ADDRESS, STORAGE_SLOT_2.into())?;
    assert_eq!(val2, Some(U256::from(0x42)), "slot 2 should be overwritten");

    // Block at t=6: post-activation, values persist.
    ctx.advance_block().await?;
    let state = ctx.inner.provider.latest()?;
    let val1 = state.storage(STORAGE_ADDRESS, STORAGE_SLOT.into())?;
    assert_eq!(val1, Some(U256::from(0xff)), "slot 1 should persist");
    let val2 = state.storage(STORAGE_ADDRESS, STORAGE_SLOT_2.into())?;
    assert_eq!(val2, Some(U256::from(0x42)), "slot 2 should persist");

    Ok(())
}
