//! In-process e2e tests for the proofs-history ExEx across a `StateOverrideFork0`
//! activation, using the same deterministic engine-driven harness as the other e2e tests.
//! Both proofs storage schemas (v1 and v2) are covered, mirroring upstream's `live.rs`
//! test matrix.
//!
//! Upgrade tripwires encoded here:
//! - the ExEx must ingest the fork-transition block, and with verification interval 1 it
//!   re-executes every block via the node's EVM config — if proof replay ever stops using
//!   `ConduitOpEvmConfig`, the transition block diverges and proofs are never served,
//! - `eth_getProof` (served from the proofs storage through the RPC override module) must reflect
//!   the override after the fork and the account's absence before it, identically on both storage
//!   schemas.

use crate::e2e::{
    FORK_ACTIVATION_TIMESTAMP, STORAGE_SLOT_1, TARGET_BYTECODE, advance,
    build_genesis_with_override, launch_test_node_with_proofs, parse_chain_spec,
};
use alloy_primitives::{Address, B256, U256, address, keccak256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
use std::time::Duration;

/// keccak256 of empty code, expected for accounts that do not exist yet.
const KECCAK_EMPTY: B256 =
    alloy_primitives::b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

const OVERRIDE_ADDR: Address = address!("4200000000000000000000000000000000000099");

fn override_genesis() -> String {
    build_genesis_with_override(
        FORK_ACTIVATION_TIMESTAMP,
        serde_json::json!({
            format!("{OVERRIDE_ADDR}"): {
                "code": "0x6080604052",
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000001":
                        "0x00000000000000000000000000000000000000000000000000000000000000ff"
                }
            }
        }),
        None,
    )
}

/// Polls `eth_getProof` until the ExEx has ingested the target block (ingestion is async
/// with respect to block commits).
async fn get_proof_with_retry(
    client: &HttpClient,
    block: &str,
) -> eyre::Result<EIP1186AccountProofResponse> {
    let mut last_err = None;
    for _ in 0..100 {
        match client
            .request::<EIP1186AccountProofResponse, _>(
                "eth_getProof",
                rpc_params![OVERRIDE_ADDR, [STORAGE_SLOT_1], block],
            )
            .await
        {
            Ok(proof) => return Ok(proof),
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(eyre::eyre!(
        "proofs storage never served block {block}; ExEx ingestion or replay verification \
         failed: {last_err:?}"
    ))
}

/// Shared assertions: blocks 1 (pre-fork), 2 (transition) and 4 (post-fork) must be
/// served from the proofs storage with the correct override state.
async fn assert_proofs_track_fork(client: &HttpClient) -> eyre::Result<()> {
    // Post-fork: the proof served from the proofs storage must reflect the override.
    let proof = get_proof_with_retry(client, "0x4").await?;
    assert_eq!(proof.code_hash, keccak256(TARGET_BYTECODE), "override code not in proofs");
    assert!(!proof.account_proof.is_empty(), "missing account proof nodes");
    let slot_proof = &proof.storage_proof[0];
    assert_eq!(slot_proof.value, U256::from(0xff), "overridden slot not in proofs storage");
    assert!(!slot_proof.proof.is_empty(), "missing storage proof nodes");

    // The transition block itself must also be served (the replay engine re-executed it).
    let proof = get_proof_with_retry(client, "0x2").await?;
    assert_eq!(proof.code_hash, keccak256(TARGET_BYTECODE));
    assert_eq!(proof.storage_proof[0].value, U256::from(0xff));

    // Pre-fork: the account must not exist.
    let proof = get_proof_with_retry(client, "0x1").await?;
    assert_eq!(proof.code_hash, KECCAK_EMPTY, "account must not exist before the fork");
    assert_eq!(proof.storage_proof[0].value, U256::ZERO);

    Ok(())
}

macro_rules! proofs_history_scenario {
    ($store_ty:ty) => {{
        reth_tracing::init_test_tracing();

        let chain_spec = parse_chain_spec(&override_genesis());
        let proofs_dir = tempfile::tempdir()?;
        let (_tasks, mut ctx) =
            launch_test_node_with_proofs!(chain_spec, proofs_dir.path(), $store_ty);

        // Block 1: pre-fork. Block 2: fork transition (override applies). Blocks 3-4: post.
        for _ in 0..4 {
            advance!(ctx);
        }

        let client = ctx
            .inner
            .rpc_server_handle()
            .http_client()
            .ok_or_else(|| eyre::eyre!("test node must expose an http server"))?;
        assert_proofs_track_fork(&client).await
    }};
}

#[tokio::test]
async fn test_proofs_history_tracks_state_override_fork_v1() -> eyre::Result<()> {
    proofs_history_scenario!(reth_optimism_trie::db::MdbxProofsStorage)
}

#[tokio::test]
async fn test_proofs_history_tracks_state_override_fork_v2() -> eyre::Result<()> {
    proofs_history_scenario!(reth_optimism_trie::db::MdbxProofsStorageV2)
}
