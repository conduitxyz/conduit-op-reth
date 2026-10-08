#!/usr/bin/env bash
# Verifies the cargo git checkout of ethereum-optimism/optimism before building
# with OP_RETH_SYNC_SUPERCHAIN=0:
#   - the checkout is at the exact commit locked in Cargo.lock
#   - its superchain-registry submodule is at the commit optimism records for it
# Both revisions are derived from Cargo.lock and the checkout, so bumping the
# op-reth tag in Cargo.toml needs no change here. Run after `cargo fetch --locked`.
set -euo pipefail

lockfile="${1:-Cargo.lock}"
checkouts="${CARGO_HOME:-$HOME/.cargo}/git/checkouts"

revs=$(sed -n 's|^source = "git+https://github.com/ethereum-optimism/optimism?[^#]*#\([0-9a-f]\{40\}\)"$|\1|p' "$lockfile" | sort -u)
if [ -z "$revs" ]; then
  echo "error: no ethereum-optimism/optimism git source found in $lockfile"
  exit 1
fi
if [ "$(wc -l <<<"$revs")" -ne 1 ]; then
  echo "error: multiple ethereum-optimism/optimism revisions locked in $lockfile:"
  echo "$revs"
  exit 1
fi
rev="$revs"

checkout=""
for dir in "$checkouts"/optimism-*/"${rev:0:7}"*; do
  if [ -d "$dir" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$rev" ]; then
    checkout="$dir"
    break
  fi
done
if [ -z "$checkout" ]; then
  echo "error: no optimism checkout at $rev under $checkouts (did cargo fetch --locked run?)"
  exit 1
fi

expected_registry=$(git -C "$checkout" ls-tree HEAD superchain-registry | awk '$2 == "commit" { print $3 }')
if [ -z "$expected_registry" ]; then
  echo "error: optimism $rev has no superchain-registry submodule"
  exit 1
fi
actual_registry=$(git -C "$checkout/superchain-registry" rev-parse HEAD)
if [ "$actual_registry" != "$expected_registry" ]; then
  echo "error: superchain-registry is at $actual_registry, optimism $rev expects $expected_registry"
  exit 1
fi

echo "optimism checkout verified: $rev (superchain-registry $expected_registry)"
