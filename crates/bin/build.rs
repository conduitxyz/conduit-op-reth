use std::{env, error::Error};
use vergen::{BuildBuilder, CargoBuilder, Emitter};
use vergen_git2::Git2Builder;

fn main() -> Result<(), Box<dyn Error>> {
    let mut emitter = Emitter::default();

    let build_builder = BuildBuilder::default().build_timestamp(true).build()?;
    emitter.add_instructions(&build_builder)?;

    let cargo_builder = CargoBuilder::default().features(true).target_triple(true).build()?;
    emitter.add_instructions(&cargo_builder)?;

    let git_builder =
        Git2Builder::default().describe(false, true, None).dirty(true).sha(false).build()?;
    emitter.add_instructions(&git_builder)?;

    emitter.emit_and_set()?;

    let sha = env::var("VERGEN_GIT_SHA")?;
    let sha_short = &sha[0..7];

    let is_dirty = env::var("VERGEN_GIT_DIRTY")? == "true";
    let not_on_tag = env::var("VERGEN_GIT_DESCRIBE")?.ends_with(&format!("-g{sha_short}"));
    let version_suffix = if is_dirty || not_on_tag { "-dev" } else { "" };
    println!("cargo:rustc-env=CONDUIT_OP_RETH_VERSION_SUFFIX={version_suffix}");

    // Set short SHA
    println!("cargo:rustc-env=VERGEN_GIT_SHA_SHORT={}", &sha[..8]);

    // Set the build profile
    let out_dir = env::var("OUT_DIR").unwrap();
    let profile = out_dir.rsplit(std::path::MAIN_SEPARATOR).nth(3).unwrap();
    println!("cargo:rustc-env=CONDUIT_OP_RETH_BUILD_PROFILE={profile}");

    // Set formatted version strings
    let pkg_version = env!("CARGO_PKG_VERSION");

    // Short version: 1.0.0 (abc1234)
    println!(
        "cargo:rustc-env=CONDUIT_OP_RETH_SHORT_VERSION={pkg_version}{version_suffix} ({sha_short})"
    );

    // Long version lines
    println!(
        "cargo:rustc-env=CONDUIT_OP_RETH_LONG_VERSION_0=Version: {pkg_version}{version_suffix}"
    );
    println!("cargo:rustc-env=CONDUIT_OP_RETH_LONG_VERSION_1=Commit SHA: {sha}");
    println!(
        "cargo:rustc-env=CONDUIT_OP_RETH_LONG_VERSION_2=Build Timestamp: {}",
        env::var("VERGEN_BUILD_TIMESTAMP")?
    );
    println!(
        "cargo:rustc-env=CONDUIT_OP_RETH_LONG_VERSION_3=Build Features: {}",
        env::var("VERGEN_CARGO_FEATURES")?
    );
    println!("cargo:rustc-env=CONDUIT_OP_RETH_LONG_VERSION_4=Build Profile: {profile}");

    // P2P client version: conduit-op-reth/v1.0.0-abc1234/aarch64-apple-darwin
    println!(
        "cargo:rustc-env=CONDUIT_OP_RETH_P2P_CLIENT_VERSION=conduit-op-reth/v{pkg_version}-{sha_short}/{}",
        env::var("VERGEN_CARGO_TARGET_TRIPLE")?
    );

    Ok(())
}
