//! End-to-end coverage of the allowlist forks on a running node: each precompile is seeded at
//! activation, its policy is enforced on both submission paths, and an admin grant made through
//! the precompile lifts the restriction for later transactions.
//!
//! Every block is built by the node's payload builder and then imported through the engine API,
//! so builder and validator execution must agree for the test to advance.

use crate::e2e::{
    BASE_GENESIS, FORK_ACTIVATION_TIMESTAMP, advance, launch_test_node, op_payload_attributes,
    parse_chain_spec,
};
use alloy_consensus::TxReceipt;
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address, bytes};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use conduit_op_reth_node::{
    allowlist::{IConduitAllowList, PRECOMPILE_MARKER_CODE, Role, role_key},
    chainspec::l1_to_l2_alias,
    deployer_allowlist::DEPLOYER_ALLOWLIST,
    hardforks::ConduitOpHardforks,
    tx_allowlist::TX_ALLOWLIST,
};
use op_alloy_consensus::{OpTxEnvelope, TxDeposit};
use reth_chainspec::EthChainSpec;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_provider::StateProviderFactory;
use reth_rpc_eth_api::helpers::EthTransactions;
use reth_storage_api::{AccountReader, StateProvider};

const FACTORY: Address = address!("00000000000000000000000000000000000fac70");
/// L1 address of the chain's `L1CrossDomainMessenger`.
const L1_MESSENGER: Address = address!("25ace71c97b33cc4729cf772ae268934f7ab5fa1");
/// L2 sender of the test deposit; on neither allowlist.
const DEPOSITOR: Address = address!("000000000000000000000000000000000000d00d");
/// Block in which the test deposit is included, the first after activation.
const DEPOSIT_TIMESTAMP: u64 = FORK_ACTIVATION_TIMESTAMP + 1;

/// Factory runtime: `CREATE`s a contract with runtime `0x00` and stores its address in slot 0.
const CREATE_FACTORY: Bytes = bytes!("6460016000f3600052" "6005601b6000f0" "600055" "00");
/// Initcode deploying the one-byte runtime `0x00`.
const DEPLOYABLE_INITCODE: Bytes = bytes!("60016000f3");

/// Genesis activating the allowlist fork `fork` (its `conduit` key) at
/// [`FORK_ACTIVATION_TIMESTAMP`], with `admin` as its only admin.
fn genesis(fork: &str, admin: Address, user: Address) -> String {
    let mut genesis: serde_json::Value = serde_json::from_str(BASE_GENESIS).unwrap();

    // This fixture activates Jovian at genesis, so child blocks require Jovian base-fee params.
    let obj = genesis.as_object_mut().unwrap();
    obj.remove("extradata");
    obj.insert("extraData".to_string(), serde_json::json!("0x01000000fa000000060000000000000000"));
    genesis["baseFeePerGas"] = serde_json::json!("0x1");

    let mut section = serde_json::json!({
        "time": FORK_ACTIVATION_TIMESTAMP,
        "mode": "allowlist",
        "adminAddresses": [admin],
    });
    if fork == "txAllowListFork0" {
        // The transaction allowlist must admit the aliased L1 messenger, or bridging would break.
        section["l1CrossDomainMessenger"] = serde_json::json!(L1_MESSENGER);
        section["enabledAddresses"] = serde_json::json!([l1_to_l2_alias(L1_MESSENGER)]);
    }
    genesis["config"]["conduit"] = serde_json::json!({ fork: section });
    for funded in [admin, user] {
        genesis["alloc"][format!("{funded}")] =
            serde_json::json!({ "balance": "0xde0b6b3a7640000" });
    }
    genesis["alloc"][format!("{FACTORY}")] =
        serde_json::json!({ "balance": "0x0", "nonce": "0x1", "code": CREATE_FACTORY });

    serde_json::to_string(&genesis).unwrap()
}

/// Payload attributes that add a deposit from [`DEPOSITOR`] to `to` with `input` in the block at
/// [`DEPOSIT_TIMESTAMP`].
fn attributes_with_deposit(
    timestamp: u64,
    to: TxKind,
    input: Bytes,
) -> reth_optimism_node::payload::OpPayloadAttrs {
    let mut attributes = op_payload_attributes(timestamp);
    if timestamp == DEPOSIT_TIMESTAMP {
        let deposit = TxDeposit {
            source_hash: B256::with_last_byte(0xde),
            from: DEPOSITOR,
            to,
            mint: 1_000,
            value: U256::ZERO,
            gas_limit: 1_000_000,
            is_system_transaction: false,
            input,
        };
        attributes.0.transactions.as_mut().unwrap().push(deposit.encoded_2718().into());
    }
    attributes
}

/// The test deposit among a block's `transactions`.
fn find_deposit(transactions: &[OpTxEnvelope]) -> B256 {
    transactions
        .iter()
        .find_map(|tx| match tx {
            OpTxEnvelope::Deposit(deposit) if deposit.inner().from == DEPOSITOR => {
                Some(deposit.hash())
            }
            _ => None,
        })
        .expect("the deposit is included")
}

fn request(chain_id: u64, nonce: u64, to: TxKind, input: Bytes) -> TransactionRequest {
    TransactionRequest {
        chain_id: Some(chain_id),
        nonce: Some(nonce),
        to: Some(to),
        gas: Some(1_000_000),
        max_fee_per_gas: Some(1_000_000_000),
        max_priority_fee_per_gas: Some(1),
        input: TransactionInput::new(input),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_deployer_allowlist_enforced_on_both_paths() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let admin: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let user: PrivateKeySigner =
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse()?;
    let chain_spec =
        parse_chain_spec(&genesis("deployerAllowListFork0", admin.address(), user.address()));
    let chain_id = chain_spec.chain_id();
    let (_tasks, mut ctx) = launch_test_node!(chain_spec.clone(), |timestamp| {
        attributes_with_deposit(timestamp, TxKind::Create, DEPLOYABLE_INITCODE)
    });

    macro_rules! send {
        ($signer:expr, $request:expr) => {{
            let signed = TransactionTestContext::sign_tx($signer.clone(), $request).await;
            ctx.rpc.inject_tx(Bytes::from(signed.encoded_2718())).await?
        }};
    }
    macro_rules! succeeded {
        ($hash:expr) => {
            ctx.rpc
                .inner
                .eth_api()
                .transaction_receipt($hash)
                .await?
                .expect("included")
                .inner
                .inner
                .status()
        };
    }

    // Block 1 is before activation; block 2 activates the fork and seeds the precompile.
    advance!(ctx);
    let activation = advance!(ctx);
    assert!(
        chain_spec
            .is_deployer_allowlist_fork0_active_at_timestamp(activation.block().header().timestamp)
    );
    let state = ctx.inner.provider.latest()?;
    let precompile = state.basic_account(&DEPLOYER_ALLOWLIST.address)?.expect("seeded");
    assert_eq!(precompile.nonce, 1);
    assert_eq!(
        state.account_code(&DEPLOYER_ALLOWLIST.address)?.unwrap().original_bytes(),
        PRECOMPILE_MARKER_CODE
    );
    assert_eq!(
        state.storage(DEPLOYER_ALLOWLIST.address, role_key(admin.address()).into())?,
        Some(U256::from(Role::Admin as u8))
    );

    // Block 3: the unlisted user deploys through the factory and directly, and the deposit tries
    // a top-level create. All three are included; none deploys anything.
    let via_factory = send!(user, request(chain_id, 0, TxKind::Call(FACTORY), Bytes::new()));
    let direct = send!(user, request(chain_id, 1, TxKind::Create, DEPLOYABLE_INITCODE));
    let denied = advance!(ctx);
    assert!(succeeded!(via_factory), "the factory call itself succeeds");
    assert!(!succeeded!(direct), "the direct create reverts");

    assert!(
        !succeeded!(find_deposit(&denied.block().body().transactions)),
        "the deposit create reverts"
    );

    let state = ctx.inner.provider.latest()?;
    // Storing address zero into the empty slot leaves it unset.
    assert_eq!(
        state.storage(FACTORY, B256::ZERO)?.unwrap_or_default(),
        U256::ZERO,
        "factory saw address zero"
    );
    for created in [FACTORY.create(1), user.address().create(1), DEPOSITOR.create(0)] {
        assert!(state.account_code(&created)?.is_none(), "{created} must not be deployed");
    }
    assert_eq!(
        state.basic_account(&DEPOSITOR)?.expect("minted").balance,
        U256::from(1_000),
        "the deposit's mint is kept"
    );

    // Block 4: the admin enables the user through the precompile.
    let grant = IConduitAllowList::setEnabledCall { addr: user.address() }.abi_encode();
    let grant_hash =
        send!(admin, request(chain_id, 0, TxKind::Call(DEPLOYER_ALLOWLIST.address), grant.into()));
    advance!(ctx);
    assert!(succeeded!(grant_hash));

    // Block 5: the same factory call now deploys.
    send!(user, request(chain_id, 2, TxKind::Call(FACTORY), Bytes::new()));
    advance!(ctx);
    let state = ctx.inner.provider.latest()?;
    let created = FACTORY.create(2);
    assert_eq!(
        state.storage(FACTORY, B256::ZERO)?,
        Some(U256::from_be_bytes(created.into_word().0))
    );
    assert!(state.account_code(&created)?.is_some(), "the enabled user's contract is deployed");

    Ok(())
}

#[tokio::test]
async fn test_tx_allowlist_enforced_on_both_paths() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let admin: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let user: PrivateKeySigner =
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse()?;
    let chain_spec =
        parse_chain_spec(&genesis("txAllowListFork0", admin.address(), user.address()));
    let chain_id = chain_spec.chain_id();
    let (_tasks, mut ctx) = launch_test_node!(chain_spec.clone(), |timestamp| {
        attributes_with_deposit(timestamp, TxKind::Call(FACTORY), Bytes::new())
    });

    macro_rules! send {
        ($signer:expr, $request:expr) => {{
            let signed = TransactionTestContext::sign_tx($signer.clone(), $request).await;
            ctx.rpc.inject_tx(Bytes::from(signed.encoded_2718())).await?
        }};
    }
    macro_rules! receipt {
        ($hash:expr) => {
            ctx.rpc.inner.eth_api().transaction_receipt($hash).await?
        };
    }

    // Block 1 is before activation; block 2 activates the fork and seeds the precompile.
    advance!(ctx);
    let activation = advance!(ctx);
    assert!(
        chain_spec.is_tx_allowlist_fork0_active_at_timestamp(activation.block().header().timestamp)
    );
    let state = ctx.inner.provider.latest()?;
    assert_eq!(
        state.storage(TX_ALLOWLIST.address, role_key(admin.address()).into())?,
        Some(U256::from(Role::Admin as u8))
    );

    // Block 3: the unlisted user's transaction is left out; the unlisted deposit is included but
    // only bumps its nonce and keeps its mint.
    let pending = send!(user, request(chain_id, 0, TxKind::Call(FACTORY), Bytes::new()));
    let denied = advance!(ctx);
    assert!(
        !denied.block().body().transactions.iter().any(|tx| tx.tx_hash() == pending),
        "the unlisted user's transaction is not included"
    );
    assert!(receipt!(pending).is_none());

    let deposit = receipt!(find_deposit(&denied.block().body().transactions)).expect("included");
    assert!(!deposit.inner.inner.status(), "the denied deposit reverts");
    let state = ctx.inner.provider.latest()?;
    let depositor = state.basic_account(&DEPOSITOR)?.expect("minted");
    assert_eq!(depositor.balance, U256::from(1_000), "the deposit's mint is kept");
    assert_eq!(depositor.nonce, 1, "the deposit's nonce is bumped");
    assert_eq!(state.basic_account(&FACTORY)?.unwrap().nonce, 1, "the deposit's call never ran");

    // Block 4: the admin enables the user. Block 5: the still-pending transaction goes through.
    let grant = IConduitAllowList::setEnabledCall { addr: user.address() }.abi_encode();
    let grant_hash =
        send!(admin, request(chain_id, 0, TxKind::Call(TX_ALLOWLIST.address), grant.into()));
    advance!(ctx);
    assert!(receipt!(grant_hash).expect("included").inner.inner.status());
    advance!(ctx);
    let included = receipt!(pending).expect("the user's transaction is included once enabled");
    assert!(included.inner.inner.status());

    Ok(())
}
