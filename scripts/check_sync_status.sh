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

CURRENT=$(echo "$RESULT" | jq -r '.result.currentBlock')
HIGHEST=$(echo "$RESULT" | jq -r '.result.highestBlock')
LAG=$(( 16#${HIGHEST#0x} - 16#${CURRENT#0x} ))

if [ "$LAG" -lt "$ALLOWED_LAG" ]; then
  echo "Node is syncing, but within allowed lag of ${ALLOWED_LAG} blocks."
  exit 0
else
  echo "Node is syncing, lag of ${LAG} blocks exceeds allowed lag."
  exit 1
fi
