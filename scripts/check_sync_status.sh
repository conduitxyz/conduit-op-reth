#!/bin/bash

NODE_URL="${NODE_URL:-http://localhost:80}"
ALLOWED_LAG="${ALLOWED_LAG:-0}"

RESULT=$(curl -s -X POST "$NODE_URL" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}')

SYNCING=$(echo "$RESULT" | jq -r '.result')

if [ "$SYNCING" = "false" ]; then
  echo "Node is fully synced."
  exit 0
fi

# reth reports highestBlock equal to currentBlock while it syncs, so the sync target is
# taken as the furthest of highestBlock and the stage checkpoints (Headers runs ahead).
CURRENT=$(echo "$RESULT" | jq -r '.result.currentBlock')
TARGETS=$(echo "$RESULT" | jq -r '.result.highestBlock, (.result.stages[]?.block)')
if [[ ! "$CURRENT" =~ ^0x[0-9a-fA-F]+$ ]]; then
  echo "Unexpected eth_syncing response: $RESULT"
  exit 1
fi
CURRENT=$(( 16#${CURRENT#0x} ))
HIGHEST=$CURRENT
for TARGET in $TARGETS; do
  [[ "$TARGET" =~ ^0x[0-9a-fA-F]+$ ]] || continue
  TARGET=$(( 16#${TARGET#0x} ))
  [ "$TARGET" -gt "$HIGHEST" ] && HIGHEST=$TARGET
done

if [ "$HIGHEST" -le "$CURRENT" ]; then
  echo "Node is syncing, but reports no target ahead of block ${CURRENT}; lag is unknown."
  exit 1
fi
LAG=$(( HIGHEST - CURRENT ))

if [ "$LAG" -lt "$ALLOWED_LAG" ]; then
  echo "Node is syncing, but within allowed lag of ${ALLOWED_LAG} blocks."
  exit 0
else
  echo "Node is syncing, lag of ${LAG} blocks exceeds allowed lag."
  exit 1
fi
