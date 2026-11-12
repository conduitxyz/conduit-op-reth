//! `eth_callBundle` and `eth_getProof` request bounds (paradigmxyz/reth#28253, #27716), pinned
//! against the real binary so the launcher's RPC wiring is what's under test, on both the plain
//! and the proofs-history launch paths.

use alloy_eips::{BlockNumberOrTag, Encodable2718};
use alloy_primitives::{Address, B256, TxKind, U256, hex};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_rpc_types_mev::{EthCallBundle, EthCallBundleResponse};
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::{
    core::client::{ClientT, Error as RpcError},
    http_client::{HeaderMap, HttpClient, HttpClientBuilder},
    rpc_params,
};
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_rpc_layer::{JwtSecret, secret_to_bearer_header};
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_conduit-op-reth");
const SAIGON_GENESIS: &str =
    include_str!(concat!(env!("CARGO_WORKSPACE_DIR"), "/tests/fixtures/saigon-genesis.json"));

/// Kills the node when the test ends, pass or fail.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn run_cli(args: &[&str]) {
    let output = Command::new(BIN).args(args).output().expect("failed to run binary");
    assert!(
        output.status.success(),
        "command {args:?} failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Writes the Saigon genesis with `funded` prefunded, returning its path and chain id.
fn write_genesis(dir: &Path, funded: Address) -> (String, u64) {
    let mut genesis: Value = serde_json::from_str(SAIGON_GENESIS).unwrap();
    genesis["alloc"][funded.to_string()] = json!({ "balance": "0xd3c21bcecceda1000000" });
    let chain_id = genesis["config"]["chainId"].as_u64().unwrap();
    let path = dir.join("genesis.json");
    std::fs::write(&path, serde_json::to_string(&genesis).unwrap()).unwrap();
    (path.to_str().unwrap().to_owned(), chain_id)
}

/// A running node with clients for its public HTTP and its JWT-authenticated engine port.
struct RunningNode {
    _node: Node,
    http: HttpClient,
    auth: HttpClient,
}

/// Starts the node; with `proofs_history`, initializes and serves the proofs-history storage.
async fn start_node(dir: &Path, genesis: &str, proofs_history: bool) -> RunningNode {
    let datadir = dir.join("datadir");
    let datadir = datadir.to_str().unwrap();
    let proofs = dir.join("proofs");
    let proofs = proofs.to_str().unwrap();
    let mut extra: Vec<&str> = Vec::new();
    if proofs_history {
        run_cli(&["init", "--chain", genesis, "--datadir", datadir]);
        run_cli(&[
            "proofs",
            "init",
            "--chain",
            genesis,
            "--datadir",
            datadir,
            "--proofs-history.storage-path",
            proofs,
            "--proofs-history.skip-backfill",
        ]);
        extra.extend(["--proofs-history", "--proofs-history.storage-path", proofs]);
    }

    let jwt = JwtSecret::random();
    let jwt_path = dir.join("jwt.hex");
    std::fs::write(&jwt_path, hex::encode(jwt.as_bytes())).unwrap();

    let http_port = free_port();
    let auth_port = free_port();
    let mut node = Node(
        Command::new(BIN)
            .args(["node", "--chain", genesis, "--datadir", datadir])
            .args(["--http", "--http.addr", "127.0.0.1", "--http.api", "eth"])
            .args(["--http.port", &http_port.to_string()])
            .args(["--authrpc.port", &auth_port.to_string()])
            .arg("--authrpc.jwtsecret")
            .arg(&jwt_path)
            .args(["--port", &free_port().to_string()])
            .args(["--disable-discovery", "--ipcdisable"])
            .args(&extra)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(60))
        .build(format!("http://127.0.0.1:{http_port}"))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            panic!("node exited ({status}) during startup");
        }
        if client.request::<Value, _>("eth_chainId", rpc_params![]).await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "node RPC did not come up");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let mut headers = HeaderMap::new();
    headers.insert("authorization", secret_to_bearer_header(&jwt));
    let auth = HttpClientBuilder::default()
        .set_headers(headers)
        .request_timeout(Duration::from_secs(60))
        .build(format!("http://127.0.0.1:{auth_port}"))
        .unwrap();
    RunningNode { _node: node, http: client, auth }
}

fn rpc_error(err: RpcError, code: i32) -> String {
    let RpcError::Call(err) = err else { panic!("expected a JSON-RPC error, got {err}") };
    assert_eq!(err.code(), code, "unexpected error: {err:?}");
    err.message().to_owned()
}

fn invalid_params(err: RpcError) -> String {
    rpc_error(err, -32602)
}

async fn assert_get_proof_is_capped(client: &HttpClient) {
    let address = Address::with_last_byte(1);
    let keys = |len| vec![B256::ZERO; len];

    let proof: Value = client
        .request("eth_getProof", rpc_params![address, keys(1024), "latest"])
        .await
        .expect("1024 keys are within the cap");
    assert_eq!(proof["storageProof"].as_array().unwrap().len(), 1024);

    let err = client
        .request::<Value, _>("eth_getProof", rpc_params![address, keys(1025), "latest"])
        .await
        .unwrap_err();
    assert_eq!(invalid_params(err), "storage key count 1025 exceeds limit 1024");
}

/// `eth_getMultiProof` is uncapped at this pin; it must stay unserved (op-reth withholds it).
async fn assert_get_multi_proof_is_unserved(client: &HttpClient) {
    let targets = vec![(Address::with_last_byte(1), vec![B256::ZERO])];
    let err = client
        .request::<Value, _>("eth_getMultiProof", rpc_params![targets, "latest"])
        .await
        .unwrap_err();
    rpc_error(err, -32601);
}

async fn assert_call_bundle_shares_gas_limit(
    client: &HttpClient,
    signer: PrivateKeySigner,
    chain_id: u64,
) {
    let mut txs = Vec::new();
    for nonce in 0..2 {
        let tx = TransactionRequest {
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            gas: Some(30_000),
            max_fee_per_gas: Some(1_000_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            to: Some(TxKind::Call(Address::with_last_byte(0xbb))),
            value: Some(U256::from(1)),
            ..Default::default()
        };
        txs.push(TransactionTestContext::sign_tx(signer.clone(), tx).await.encoded_2718().into());
    }
    let bundle = EthCallBundle {
        txs,
        block_number: 1,
        state_block_number: BlockNumberOrTag::Latest,
        ..Default::default()
    };

    let call = |gas_limit| {
        let bundle = EthCallBundle { gas_limit: Some(gas_limit), ..bundle.clone() };
        async move {
            client.request::<EthCallBundleResponse, _>("eth_callBundle", rpc_params![bundle]).await
        }
    };

    // Two transactions can't pay 2 * 21,000 intrinsic gas: rejected before simulating.
    let err = call(41_999).await.unwrap_err();
    assert_eq!(
        invalid_params(err),
        "bundle of 2 transactions exceeds the block gas limit of 41999"
    );

    // Each transfer uses 21,000 of its 30,000 gas limit, leaving 29,999 for the second.
    let err = call(50_999).await.unwrap_err();
    assert_eq!(invalid_params(err), "bundle gas exceeds the block gas limit of 50999");

    let response = call(51_000).await.expect("bundle fits the gas limit");
    assert_eq!(response.total_gas_used, 42_000);
}

async fn run(proofs_history: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let signer = PrivateKeySigner::random();
    let (genesis, chain_id) = write_genesis(tmp.path(), signer.address());
    let node = start_node(tmp.path(), &genesis, proofs_history).await;

    assert_get_proof_is_capped(&node.http).await;
    assert_get_proof_is_capped(&node.auth).await;
    assert_get_multi_proof_is_unserved(&node.http).await;
    assert_get_multi_proof_is_unserved(&node.auth).await;
    assert_call_bundle_shares_gas_limit(&node.http, signer, chain_id).await;
}

#[tokio::test]
async fn rpc_bounds_without_proofs_history() {
    run(false).await;
}

#[tokio::test]
async fn rpc_bounds_with_proofs_history() {
    run(true).await;
}
