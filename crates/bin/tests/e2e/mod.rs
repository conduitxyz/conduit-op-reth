use alloy_primitives::{address, b256, Address, Bytes, B256, B64};
use conduit_op_reth_node::chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser};
use reth_cli::chainspec::ChainSpecParser;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_primitives_traits::WithEncoded;
use std::sync::Arc;

pub mod state_override_test;

/// Address to receive bytecode override.
pub const TARGET_ADDRESS: Address = address!("4200000000000000000000000000000000000042");

/// Bytecode to inject at TARGET_ADDRESS (minimal PUSH1 0x80 PUSH1 0x40 MSTORE).
pub const TARGET_BYTECODE: &[u8] = &[0x60, 0x80, 0x60, 0x40, 0x52];

/// Address to receive storage overrides.
pub const STORAGE_ADDRESS: Address = address!("4200000000000000000000000000000000000099");

/// Storage slot key.
pub const STORAGE_SLOT: B256 =
    b256!("0000000000000000000000000000000000000000000000000000000000000001");

/// Initial timestamp used by the PayloadTestContext (hardcoded in reth-e2e-test-utils).
/// Each advance_block() increments by 1.
const INITIAL_PAYLOAD_TIMESTAMP: u64 = 1710338135;

/// Fork activation timestamp. PayloadTestContext starts at INITIAL_PAYLOAD_TIMESTAMP and
/// increments by 1, so:
/// - Block 1: t=INITIAL+1 → fork not active
/// - Block 2: t=INITIAL+2 → fork active now, NOT active at t-2=INITIAL → applies override
/// - Block 3: t=INITIAL+3 → fork active now AND at t-2=INITIAL+1 → no-op
pub const FORK_ACTIVATION_TIMESTAMP: u64 = INITIAL_PAYLOAD_TIMESTAMP + 2;

/// Balance to pre-fund TARGET_ADDRESS with in the balance-preservation test.
pub const PREFUND_BALANCE: &str = "0xde0b6b3a7640000"; // 1 ETH

/// Base genesis JSON with all OP hardforks at genesis.
const BASE_GENESIS: &str = include_str!("../../../../tests/fixtures/saigon-genesis.json");

/// Create OP payload attributes for the test node.
///
/// Includes the L1 block info deposit transaction required by every OP Stack block.
/// Uses the same hardcoded deposit tx from OP mainnet block 124665056 that reth's
/// `LocalPayloadAttributesBuilder` uses.
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

    // Decode the L1 block info deposit tx from the raw constant.
    let l1_info_raw =
        Bytes::from_static(&reth_optimism_chainspec::constants::TX_SET_L1_BLOCK_OP_MAINNET_BLOCK_124665056);
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

/// Build a genesis JSON with the conduit stateOverrideFork0 section injected.
pub fn build_genesis_with_override(
    fork_time: u64,
    updates: serde_json::Value,
    extra_alloc: Option<serde_json::Value>,
) -> String {
    let mut genesis: serde_json::Value =
        serde_json::from_str(BASE_GENESIS).expect("failed to parse base genesis");

    genesis["config"]["conduit"] = serde_json::json!({
        "stateOverrideFork0": {
            "time": fork_time,
            "updates": updates
        }
    });

    if let Some(alloc) = extra_alloc {
        if let serde_json::Value::Object(map) = alloc {
            let alloc_obj = genesis["alloc"].as_object_mut().expect("alloc should be object");
            for (k, v) in map {
                alloc_obj.insert(k, v);
            }
        }
    }

    serde_json::to_string(&genesis).unwrap()
}

/// Parse a genesis JSON string into an Arc<ConduitOpChainSpec> via a temp file.
pub fn parse_chain_spec(genesis_json: &str) -> Arc<ConduitOpChainSpec> {
    let dir = std::env::temp_dir().join(format!(
        "conduit-op-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("genesis.json");
    std::fs::write(&path, genesis_json).unwrap();
    let spec = ConduitOpChainSpecParser::parse(path.to_str().unwrap())
        .expect("failed to parse genesis");
    std::fs::remove_dir_all(&dir).ok();
    spec
}

/// Launch a test node and produce a `(TaskManager, NodeTestContext)`.
///
/// This is a macro because `NodeBuilder::launch()` returns `impl` types that cannot
/// be named in a function signature. Expanding inline lets the compiler infer everything.
///
/// **Important**: The returned `TaskManager` must be held alive for the duration of the test;
/// dropping it shuts down the node's background tasks.
macro_rules! launch_test_node {
    ($chain_spec:expr) => {{
        use reth_e2e_test_utils::node::NodeTestContext;
        use reth_node_builder::{NodeBuilder, NodeHandle};
        use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
        use reth_tasks::TaskManager;

        let tasks = TaskManager::current();
        let node_config = NodeConfig::new($chain_spec)
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

        let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
            .testing_node(tasks.executor())
            .node(conduit_op_reth_node::node::ConduitOpNode::default())
            .launch()
            .await?;

        let ctx = NodeTestContext::new(node, crate::e2e::op_payload_attributes).await?;
        (tasks, ctx)
    }};
}

pub(crate) use launch_test_node;
