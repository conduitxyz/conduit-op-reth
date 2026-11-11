//! RPC request bounds backported from upstream reth (paradigmxyz/reth#27716), pinned against the
//! real binary so the launcher's RPC wiring is what's under test, on both the plain and the
//! proofs-history launch paths.

use alloy_primitives::{Address, B256, hex};
use jsonrpsee::{
    core::client::{ClientT, Error as RpcError},
    http_client::{HeaderMap, HttpClient, HttpClientBuilder},
    rpc_params,
};
use reth_rpc_layer::{JwtSecret, secret_to_bearer_header};
use serde_json::Value;
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

/// Writes the Saigon genesis, returning its path.
fn write_genesis(dir: &Path) -> String {
    let path = dir.join("genesis.json");
    std::fs::write(&path, SAIGON_GENESIS).unwrap();
    path.to_str().unwrap().to_owned()
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

async fn run(proofs_history: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let genesis = write_genesis(tmp.path());
    let node = start_node(tmp.path(), &genesis, proofs_history).await;

    assert_get_proof_is_capped(&node.http).await;
    assert_get_proof_is_capped(&node.auth).await;
    assert_get_multi_proof_is_unserved(&node.http).await;
    assert_get_multi_proof_is_unserved(&node.auth).await;
}

#[tokio::test]
async fn rpc_bounds_without_proofs_history() {
    run(false).await;
}

#[tokio::test]
async fn rpc_bounds_with_proofs_history() {
    run(true).await;
}
