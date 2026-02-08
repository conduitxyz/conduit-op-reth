use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B64, B256, Bytes, TxKind, address, b256};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use conduit_op_reth_node::chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser};
use reth_cli::chainspec::ChainSpecParser;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_primitives_traits::WithEncoded;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub mod state_override_test;

// deployed bytecodes for OverrideTestV1 (VALUE = 42) and OverrideTestV2 (VALUE = 99).
alloy_sol_macro::sol! {
    #[sol(deployed_bytecode = "0x6080604052348015600e575f5ffd5b50600436106030575f3560e01c806320965255146034578063509d8c7214604e575b5f5ffd5b603a6068565b60405160459190608b565b60405180910390f35b60546070565b604051605f9190608b565b60405180910390f35b5f602a905090565b602a81565b5f819050919050565b6085816075565b82525050565b5f602082019050609c5f830184607e565b9291505056fea2646970667358221220a878e13f3fe81d198d4cc2c8716b34cd19d74f6fa7f34366a55ae658dc08bd3c64736f6c63430008210033")]
    contract OverrideTestV1 {
        uint256 public constant VALUE = 42;
        function getValue() external pure returns (uint256) {
            return VALUE;
        }
    }
}

alloy_sol_macro::sol! {
    #[sol(deployed_bytecode = "0x6080604052348015600e575f5ffd5b50600436106030575f3560e01c806320965255146034578063509d8c7214604e575b5f5ffd5b603a6068565b60405160459190608b565b60405180910390f35b60546070565b604051605f9190608b565b60405180910390f35b5f6063905090565b606381565b5f819050919050565b6085816075565b82525050565b5f602082019050609c5f830184607e565b9291505056fea2646970667358221220572d53ef774c53414dd4f8118dde0e1f3f5a02736b33f5b85bf890fed04a9c2364736f6c63430008210033")]
    contract OverrideTestV2 {
        uint256 public constant VALUE = 99;
        function getValue() external pure returns (uint256) {
            return VALUE;
        }
    }
}

pub const TARGET_ADDRESS: Address = address!("4200000000000000000000000000000000000042");
pub const TARGET_BYTECODE: &[u8] = &[0x60, 0x80, 0x60, 0x40, 0x52];
pub const STORAGE_ADDRESS: Address = address!("4200000000000000000000000000000000000099");
pub const STORAGE_SLOT: B256 =
    b256!("0000000000000000000000000000000000000000000000000000000000000001");
pub const STORAGE_SLOT_2: B256 =
    b256!("0000000000000000000000000000000000000000000000000000000000000002");
pub const PREFUND_BALANCE: &str = "0xde0b6b3a7640000"; // 1 ETH

/// Initial timestamp used by reth's `PayloadTestContext` (hardcoded).
/// Each `advance_block()` increments by 1.
const INITIAL_PAYLOAD_TIMESTAMP: u64 = 1710338135;

/// Fork activation timestamp.
/// - Block 1: t=INITIAL+1 -> fork not active
/// - Block 2: t=INITIAL+2 -> fork active, NOT active at t-2 -> applies override
/// - Block 3: t=INITIAL+3 -> fork active AND active at t-2 -> no-op
pub const FORK_ACTIVATION_TIMESTAMP: u64 = INITIAL_PAYLOAD_TIMESTAMP + 2;

const BASE_GENESIS: &str = include_str!("../../../../tests/fixtures/saigon-genesis.json");

/// Create OP payload attributes including the required L1 block info deposit tx.
pub fn op_payload_attributes<T: alloy_eips::Decodable2718>(
    timestamp: u64,
) -> OpPayloadBuilderAttributes<T> {
    let attributes = alloy_rpc_types_engine::PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
    };

    let l1_info_raw = Bytes::from_static(
        &reth_optimism_chainspec::constants::TX_SET_L1_BLOCK_OP_MAINNET_BLOCK_124665056,
    );
    let l1_info_tx = T::decode_2718(&mut l1_info_raw.as_ref())
        .expect("failed to decode L1 block info deposit tx");

    OpPayloadBuilderAttributes {
        payload_attributes: EthPayloadBuilderAttributes::new(B256::ZERO, attributes),
        transactions: vec![WithEncoded::new(l1_info_raw, l1_info_tx)],
        no_tx_pool: false,
        gas_limit: Some(30_000_000),
        eip_1559_params: Some(B64::ZERO),
        min_base_fee: Some(0),
    }
}

/// Build genesis JSON with a `conduit.stateOverrideFork0` section injected.
pub fn build_genesis_with_override(
    fork_time: u64,
    updates: serde_json::Value,
    extra_alloc: Option<serde_json::Value>,
) -> String {
    let mut genesis: serde_json::Value =
        serde_json::from_str(BASE_GENESIS).expect("failed to parse base genesis");

    // // Jovian extra data: 17 bytes (version=1, zeros for eip1559 params/min base fee).
    // if let Some(obj) = genesis.as_object_mut() {
    //     obj.remove("extradata");
    //     obj.insert(
    //         "extraData".to_string(),
    //         serde_json::Value::String("0x0100000000000000000000000000000000".to_string()),
    //     );
    // }

    genesis["config"]["conduit"] = serde_json::json!({
        "stateOverrideFork0": {
            "time": fork_time,
            "updates": updates
        }
    });

    if let Some(serde_json::Value::Object(map)) = extra_alloc {
        let alloc_obj = genesis["alloc"]
            .as_object_mut()
            .expect("alloc should be object");
        for (k, v) in map {
            alloc_obj.insert(k, v);
        }
    }

    serde_json::to_string(&genesis).unwrap()
}

/// Parse a genesis JSON string into an `Arc<ConduitOpChainSpec>` via a temp file.
pub fn parse_chain_spec(genesis_json: &str) -> Arc<ConduitOpChainSpec> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "conduit-op-e2e-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        id,
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("genesis.json");
    std::fs::write(&path, genesis_json).unwrap();
    let spec =
        ConduitOpChainSpecParser::parse(path.to_str().unwrap()).expect("failed to parse genesis");
    std::fs::remove_dir_all(&dir).ok();
    spec
}

/// Build a `NodeConfig` tuned for deterministic e2e tests.
fn test_node_config(chain_spec: Arc<ConduitOpChainSpec>) -> NodeConfig<ConduitOpChainSpec> {
    let mut c = NodeConfig::new(chain_spec)
        .with_unused_ports()
        .with_disabled_discovery()
        .with_disabled_rpc_cache()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    c.engine.persistence_threshold = 0;
    c.engine.memory_block_buffer_target = 0;
    c.engine.prewarming_disabled = true;
    c.network.no_persist_peers = true;
    c.network.disable_tx_gossip = true;
    c.network.max_peers = Some(0);
    c
}

/// Launch a test node from a chain spec.
///
/// Must be a macro: `NodeBuilder::launch()` returns an unnameable `impl` type.
/// The returned `TaskManager` must be held alive for the test duration.
macro_rules! launch_test_node {
    ($chain_spec:expr) => {{
        use reth_e2e_test_utils::node::NodeTestContext;
        use reth_node_builder::{NodeBuilder, NodeHandle};
        use reth_tasks::TaskManager;

        let tasks = TaskManager::current();
        let node_config = crate::e2e::test_node_config($chain_spec);
        let NodeHandle {
            node,
            node_exit_future: _,
        } = NodeBuilder::new(node_config)
            .testing_node(tasks.executor())
            .node(conduit_op_reth_node::node::ConduitOpNode::default())
            .launch()
            .await?;

        let ctx = NodeTestContext::new(node, crate::e2e::op_payload_attributes).await?;
        (tasks, ctx)
    }};
}

pub(crate) use launch_test_node;

/// Build a signed CREATE transaction (raw RLP-encoded bytes).
pub async fn create_deploy_tx(chain_id: u64, init_code: Bytes, wallet: PrivateKeySigner) -> Bytes {
    let tx = TransactionRequest {
        nonce: Some(0),
        chain_id: Some(chain_id),
        gas: Some(100_000),
        max_fee_per_gas: Some(1_000_000_000_000u128),
        max_priority_fee_per_gas: Some(1_000_000_000u128),
        to: Some(TxKind::Create),
        input: TransactionInput {
            input: None,
            data: Some(init_code),
        },
        ..Default::default()
    };
    let signed = TransactionTestContext::sign_tx(wallet, tx).await;
    signed.encoded_2718().into()
}
