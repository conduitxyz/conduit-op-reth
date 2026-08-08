use alloy_primitives::{Address, B64, B256, Bytes, b256, hex};
use conduit_op_reth_node::chainspec::{ConduitOpChainSpec, ConduitOpChainSpecParser};
use reth_cli::chainspec::ChainSpecParser;
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_optimism_node::{OpPayloadAttributes, payload::OpPayloadAttrs};
use std::sync::Arc;

pub mod genesis_validation_test;
pub mod proofs_history_test;
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

/// Fork activation timestamp. The e2e harness builds blocks 1 second apart, so the
/// injected genesis sets `blockTimeAtFork: 1` and the transition window is:
/// - Block 1: t=INITIAL+1 -> fork not active
/// - Block 2: t=INITIAL+2 -> fork active, NOT active at t-1 -> applies override
/// - Block 3: t=INITIAL+3 -> fork active AND active at t-1 -> no-op
pub const FORK_ACTIVATION_TIMESTAMP: u64 = INITIAL_PAYLOAD_TIMESTAMP + 2;

pub(crate) const BASE_GENESIS: &str =
    include_str!(concat!(env!("CARGO_WORKSPACE_DIR"), "/tests/fixtures/saigon-genesis.json"));

/// Create OP payload attributes including the required L1 block info deposit tx.
pub fn op_payload_attributes(timestamp: u64) -> OpPayloadAttrs {
    let attributes = alloy_rpc_types_engine::PayloadAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Some(vec![]),
        parent_beacon_block_root: Some(B256::ZERO),
        slot_number: None,
    };

    // L1 block info "set L1 block" deposit tx from OP mainnet block 124665056.
    // Inlined here because the constant is no longer pub-exported from
    // `reth-optimism-chainspec` after the op-reth crate split.
    // <https://optimistic.etherscan.io/tx/0x312e290cf36df704a2217b015d6455396830b0ce678b860ebfcc30f41403d7b1>
    const TX_SET_L1_BLOCK_OP_MAINNET_BLOCK_124665056: [u8; 251] = hex!(
        "7ef8f8a0683079df94aa5b9cf86687d739a60a9b4f0835e520ec4d664e2e415dca17a6df94deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b8a4440a5e200000146b000f79c500000000000000040000000066d052e700000000013ad8a3000000000000000000000000000000000000000000000000000000003ef1278700000000000000000000000000000000000000000000000000000000000000012fdf87b89884a61e74b322bbcf60386f543bfae7827725efaaf0ab1de2294a590000000000000000000000006887246668a3b87f54deb3b94ba47a6f63f32985"
    );
    let l1_info_raw = Bytes::from_static(&TX_SET_L1_BLOCK_OP_MAINNET_BLOCK_124665056);

    OpPayloadAttrs(OpPayloadAttributes {
        payload_attributes: attributes,
        transactions: Some(vec![l1_info_raw]),
        no_tx_pool: Some(false),
        gas_limit: Some(30_000_000),
        eip_1559_params: Some(B64::ZERO),
        min_base_fee: Some(0),
    })
}

/// Build genesis JSON with a `conduit.stateOverrideFork0` section injected.
pub fn build_genesis_with_override(
    fork_time: u64,
    updates: serde_json::Value,
    extra_alloc: Option<serde_json::Value>,
) -> String {
    let mut genesis: serde_json::Value =
        serde_json::from_str(BASE_GENESIS).expect("failed to parse base genesis");

    // Jovian extra data: 17 bytes (version=1, denominator=250, elasticity=6, min base fee=0).
    // Because this fixture activates Jovian at genesis, the genesis header must carry valid
    // Jovian base-fee params for the first child block to validate against its parent.
    let obj = genesis.as_object_mut().unwrap();
    obj.remove("extradata");
    obj.insert("extraData".to_string(), serde_json::json!("0x01000000fa000000060000000000000000"));

    genesis["config"]["conduit"] = serde_json::json!({
        "stateOverrideFork0": {
            "time": fork_time,
            // The e2e payload builder advances timestamps by 1s per block.
            "blockTimeAtFork": 1,
            "updates": updates
        }
    });

    if let Some(serde_json::Value::Object(map)) = extra_alloc {
        let alloc_obj = genesis["alloc"].as_object_mut().expect("alloc should be object");
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
/// The returned `Runtime` must be held alive for the test duration.
macro_rules! launch_test_node {
    ($chain_spec:expr) => {{
        use reth_e2e_test_utils::node::NodeTestContext;
        use reth_node_builder::{NodeBuilder, NodeHandle};
        use reth_tasks::Runtime as TaskRuntime;

        let tasks = TaskRuntime::test();
        let node_config = crate::e2e::test_node_config($chain_spec);
        let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
            .testing_node(tasks.clone())
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
        $ctx.wait_block(payload.block().number, payload.block().hash(), false).await?;
        payload
    }};
}

pub(crate) use advance;

/// In-process equivalent of `conduit-op-reth proofs init`: backfill the proofs storage from
/// the current chain state. Mirrors the body of upstream's `InitCommand::run_init`.
pub fn initialize_proofs_storage<F, S>(provider: &F, storage: S) -> eyre::Result<()>
where
    F: reth_provider::DatabaseProviderFactory + reth_provider::BlockNumReader,
    F::Provider: reth_provider::DBProvider + reth_provider::StorageSettingsCache,
    S: reth_optimism_trie::OpProofsStore,
{
    use reth_chainspec::ChainInfo;
    use reth_optimism_trie::{InitializationJob, RethTrieStorageLayout};
    use reth_provider::{DBProvider as _, StorageSettingsCache as _};

    let ChainInfo { best_number, best_hash, .. } = provider.chain_info()?;
    let db_provider = provider.database_provider_ro()?.disable_long_read_transaction_safety();
    let trie_layout = if db_provider.cached_storage_settings().is_v2() {
        RethTrieStorageLayout::Packed
    } else {
        RethTrieStorageLayout::Legacy
    };
    InitializationJob::new(storage, db_provider.into_tx(), trie_layout)
        .run(best_number, best_hash)?;
    Ok(())
}

/// Launch a test node with the proofs-history ExEx and RPC overrides installed,
/// mirroring `conduit_op_reth_node::launcher::launch_with_proof_history`.
///
/// The verification interval is 1: the ExEx replay engine re-executes every block with the
/// node's EVM config. If proof replay ever stops using `ConduitOpEvmConfig`, re-executing a
/// `StateOverrideFork0` transition block diverges and the ExEx (and the test) fails.
macro_rules! launch_test_node_with_proofs {
    ($chain_spec:expr, $proofs_dir:expr, $store_ty:ty) => {{
        use futures_util::FutureExt as _;
        use reth_e2e_test_utils::node::NodeTestContext;
        use reth_node_builder::{FullNodeComponents as _, NodeBuilder, NodeHandle};
        use reth_optimism_exex::OpProofsExEx;
        use reth_optimism_rpc::{
            debug::{DebugApiExt, DebugApiOverrideServer},
            eth::proofs::{EthApiExt, EthApiOverrideServer},
        };
        use reth_optimism_trie::OpProofsStorage;
        use reth_tasks::Runtime as TaskRuntime;
        use std::sync::Arc;

        let tasks = TaskRuntime::test();
        let node_config = crate::e2e::test_node_config($chain_spec);

        let mdbx = Arc::new(<$store_ty>::new($proofs_dir)?);
        let storage: OpProofsStorage<Arc<$store_ty>> = mdbx.clone().into();
        let storage_exex = storage.clone();
        let storage_rpc = storage;

        let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
            .testing_node(tasks.clone())
            .node(conduit_op_reth_node::node::ConduitOpNode::default())
            .install_exex("proofs-history", async move |exex_context| {
                // The CLI requires `proofs init` before boot; in-process we run the same
                // initialization job against the freshly-written genesis state.
                crate::e2e::initialize_proofs_storage(exex_context.provider(), mdbx)?;
                Ok(OpProofsExEx::builder(exex_context, storage_exex)
                    .with_verification_interval(1)
                    .build()
                    .run()
                    .boxed())
            })
            .extend_rpc_modules(move |ctx| {
                let api_ext = EthApiExt::new(ctx.registry.eth_api().clone(), storage_rpc.clone());
                let debug_ext = DebugApiExt::new(
                    ctx.node().provider().clone(),
                    ctx.registry.eth_api().clone(),
                    storage_rpc,
                    ctx.node().task_executor().clone(),
                    ctx.node().evm_config().clone(),
                );
                let eth_replaced = ctx.modules.replace_configured(api_ext.into_rpc())?;
                let debug_replaced = ctx.modules.replace_configured(debug_ext.into_rpc())?;
                assert!(eth_replaced && debug_replaced, "proofs RPC overrides must install");
                Ok(())
            })
            .launch()
            .await?;

        let ctx = NodeTestContext::new(node, crate::e2e::op_payload_attributes).await?;
        (tasks, ctx)
    }};
}

pub(crate) use launch_test_node_with_proofs;
