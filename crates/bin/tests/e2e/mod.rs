use alloy_primitives::{Address, B64, B256, Bytes, b256};
use conduit_op_reth_node::chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser};
use reth_cli::chainspec::ChainSpecParser;
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_primitives_traits::WithEncoded;
use std::sync::Arc;

pub mod genesis_validation_test;
pub mod state_override_test;

/// Solidity contract preamble: PUSH1 0x80 PUSH1 0x40 MSTORE.
pub const TARGET_BYTECODE: &[u8] = &[0x60, 0x80, 0x60, 0x40, 0x52];
pub const STORAGE_SLOT_1: B256 =
    b256!("0000000000000000000000000000000000000000000000000000000000000001");
pub const STORAGE_SLOT_2: B256 =
    b256!("0000000000000000000000000000000000000000000000000000000000000002");
pub const PREFUND_BALANCE: &str = "0xde0b6b3a7640000"; // 1 ETH
pub const PREFUND_BALANCE_U256: alloy_primitives::U256 =
    alloy_primitives::U256::from_limbs([0xde0b6b3a7640000, 0, 0, 0]);

/// Initial timestamp used by reth's `PayloadTestContext` (hardcoded).
/// Each `advance_block()` increments by 1.
const INITIAL_PAYLOAD_TIMESTAMP: u64 = 1710338135;

/// Fork activation timestamp.
/// - Block 1: t=INITIAL+1 -> fork not active
/// - Block 2: t=INITIAL+2 -> fork active, NOT active at t-2 -> applies override
/// - Block 3: t=INITIAL+3 -> fork active AND active at t-2 -> no-op
pub const FORK_ACTIVATION_TIMESTAMP: u64 = INITIAL_PAYLOAD_TIMESTAMP + 2;

pub(crate) const BASE_GENESIS: &str = include_str!(concat!(
    env!("CARGO_WORKSPACE_DIR"),
    "/tests/fixtures/saigon-genesis.json"
));

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

    // Jovian extra data: 17 bytes (version=1, zeros for eip1559 params/min base fee).
    let obj = genesis.as_object_mut().unwrap();
    obj.remove("extradata");
    obj.insert(
        "extraData".to_string(),
        serde_json::json!("0x0100000000000000000000000000000000"),
    );

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
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let path = dir.path().join("genesis.json");
    std::fs::write(&path, genesis_json).unwrap();
    ConduitOpChainSpecParser::parse(path.to_str().unwrap()).expect("failed to parse genesis")
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

pub(crate) use advance;
