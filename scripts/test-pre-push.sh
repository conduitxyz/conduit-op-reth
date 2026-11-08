#!/usr/bin/env bash
# Exercise the documented hook installation against a local remote.
set -euo pipefail

source_root=$(git rev-parse --show-toplevel)
tmp_root=$(cd "${TMPDIR:-/tmp}" && pwd -P)
tmp_dir=$(mktemp -d "$tmp_root/conduit-pre-push-test.XXXXXXXX")
cleanup() {
  # Only remove the fixture directory created above.
  if [[ "$(dirname "$tmp_dir")" == "$tmp_root" &&
        "$(basename "$tmp_dir")" == conduit-pre-push-test.* ]]; then
    rm -rf -- "$tmp_dir"
  fi
}
trap cleanup EXIT

repo="$tmp_dir/repository with spaces"
remote="$tmp_dir/remote.git"
git init --quiet --bare "$remote"
git init --quiet --initial-branch=main "$repo"
cd "$repo"
git config user.name 'Hook test'
git config user.email 'hook-test@example.invalid'
git config commit.gpgsign false
git config core.hooksPath .git/hooks
mkdir -p scripts src
cp "$source_root/scripts/pre-push" "$source_root/scripts/check-tag-version.sh" scripts/
cat > Cargo.toml <<'EOF'
[package]
name = "conduit-op-reth"
version = "1.2.3"
edition = "2021"
EOF
touch src/lib.rs
git add Cargo.toml src scripts
git commit --quiet -m 'Create hook test fixture'
git remote add origin "$remote"
ln -s ../../scripts/pre-push .git/hooks/pre-push

git push --quiet origin main
git --git-dir="$remote" show-ref --verify --quiet refs/heads/main
echo 'PASS: branch push through the symlinked hook'

for tag in v1.2.3 v1.2.3-rc.1; do
  git tag "$tag"
  git push --quiet origin "$tag"
  git --git-dir="$remote" show-ref --verify --quiet "refs/tags/$tag"
done
echo 'PASS: matching release and prerelease tags'

git tag v1.2.30
if git push origin v1.2.30 >"$tmp_dir/rejected-push.log" 2>&1; then
  echo 'FAIL: mismatched version tag was accepted' >&2
  exit 1
fi
grep -F "doesn't match Cargo.toml version 1.2.3" "$tmp_dir/rejected-push.log"
if git --git-dir="$remote" show-ref --verify --quiet refs/tags/v1.2.30; then
  echo 'FAIL: rejected tag reached the remote' >&2
  exit 1
fi
echo 'PASS: mismatched version tag is rejected by the helper'

# Linked worktrees share the installed hook but must read their own Cargo.toml.
linked_repo="$tmp_dir/linked worktree"
git worktree add --quiet -b topic "$linked_repo"
cd "$linked_repo"
sed -i 's/version = "1.2.3"/version = "1.3.0"/' Cargo.toml
git add Cargo.toml
git commit --quiet -m 'Change the linked worktree version'
git tag v1.3.0
hooks_dir=$(git rev-parse --git-common-dir)/hooks
git -c core.hooksPath="$hooks_dir" push --quiet origin v1.3.0
git --git-dir="$remote" show-ref --verify --quiet refs/tags/v1.3.0
echo 'PASS: linked worktree uses its own version'
