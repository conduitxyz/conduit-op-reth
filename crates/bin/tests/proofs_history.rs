//! CLI smoke test for the `proofs` subcommands against a Conduit datadir.
//!
//! The behavioral proofs-history coverage (ExEx, RPC overrides, `StateOverrideFork0`
//! interplay) lives in the in-process e2e suite (`e2e/proofs_history_test.rs`). This test
//! only pins what the in-process harness cannot: the upstream `proofs init` command —
//! running with `N = OpNode` and the `InnerOpChainSpecParser` adapter — must open a datadir
//! created by the Conduit binary (genesis identity match) and must be idempotent.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_conduit-op-reth");
const SAIGON_GENESIS: &str =
    include_str!(concat!(env!("CARGO_WORKSPACE_DIR"), "/tests/fixtures/saigon-genesis.json"));

fn run_cli(args: &[&str]) -> String {
    let output = Command::new(BIN).args(args).output().expect("failed to run binary");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "command {args:?} failed:\n{combined}");
    combined
}

#[test]
fn proofs_init_works_against_conduit_datadir() {
    let tmp = tempfile::tempdir().unwrap();

    // A genesis carrying a `conduit` section: upstream commands must tolerate it.
    let mut genesis: serde_json::Value = serde_json::from_str(SAIGON_GENESIS).unwrap();
    genesis["config"]["conduit"] =
        serde_json::json!({ "stateOverrideFork0": { "time": 1781055382u64, "updates": {} } });
    let genesis_path = tmp.path().join("genesis.json");
    std::fs::write(&genesis_path, serde_json::to_string(&genesis).unwrap()).unwrap();
    let genesis = genesis_path.to_str().unwrap();

    let datadir = tmp.path().join("datadir");
    let datadir = datadir.to_str().unwrap();

    // Datadir written by the Conduit node types...
    run_cli(&["init", "--chain", genesis, "--datadir", datadir]);

    // ...must be readable by the upstream `proofs init` (via InnerOpChainSpecParser/OpNode),
    // for both storage schemas, idempotently.
    for version in ["v1", "v2"] {
        let proofs = tmp.path().join(format!("proofs-{version}"));
        let proofs = proofs.to_str().unwrap();
        let args = [
            "proofs",
            "init",
            "--chain",
            genesis,
            "--datadir",
            datadir,
            "--proofs-history.storage-path",
            proofs,
            "--proofs-history.storage-version",
            version,
            "--proofs-history.skip-backfill",
        ];

        let out = run_cli(&args);
        assert!(
            out.contains("initialized successfully"),
            "proofs init ({version}) did not succeed:\n{out}"
        );

        let out = run_cli(&args);
        assert!(
            out.contains("already initialized"),
            "proofs init ({version}) not idempotent:\n{out}"
        );
    }
}
