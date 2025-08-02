#!/bin/bash
# Simple test for POC31 Diffie-Hellman HMAC knocking.
set -e
cd "$(dirname "$0")"

CONFIG=../config/poc31_dh.yaml
LOG=logs/server_dh.log

python3 server_dh.py --config "$CONFIG" &
SERVER_PID=$!
sleep 1

python3 client_dh.py --config "$CONFIG"
sleep 1

kill $SERVER_PID
sleep 1

if grep -q "Valid knock" "$LOG"; then
  echo "Test succeeded"
else
  echo "Test failed" >&2
  exit 1
fi
