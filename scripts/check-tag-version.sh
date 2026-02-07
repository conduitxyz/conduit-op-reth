#!/usr/bin/env bash
# Pre-push hook helper: verifies that a version tag matches Cargo.toml.
# Install: ln -sf ../../scripts/pre-push .git/hooks/pre-push
set -euo pipefail

cargo_ver=$(cargo metadata --no-deps --format-version 1 2>/dev/null \
  | jq -r '.packages[] | select(.name == "conduit-op-reth") | .version')

if [ -z "$cargo_ver" ]; then
  echo "error: could not read conduit-op-reth version from Cargo.toml"
  exit 1
fi

while read -r local_ref local_sha remote_ref remote_sha; do
  # Only check version tags
  if [[ "$local_ref" =~ ^refs/tags/v ]]; then
    tag="${local_ref#refs/tags/v}"
    if [[ "$tag" != "$cargo_ver"* ]]; then
      echo "error: tag v${tag} doesn't match Cargo.toml version ${cargo_ver}"
      echo "hint: update the version in Cargo.toml or use the correct tag"
      exit 1
    fi
    echo "tag v${tag} matches Cargo.toml version ${cargo_ver}"
  fi
done
