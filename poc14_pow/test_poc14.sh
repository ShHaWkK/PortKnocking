#!/bin/bash
# Simple test for POC14 proof-of-work knocking.
set -e

CONFIG=../config/poc14_pow.yaml
LOG=logs/server_pow.log

python3 server_pow.py --config "$CONFIG" &
SERVER_PID=$!
sleep 1

python3 client_pow.py --config "$CONFIG"
sleep 1

kill $SERVER_PID
sleep 1

if grep -q "Valid knock" "$LOG"; then
  echo "Test succeeded"
else
  echo "Test failed" >&2
  exit 1
fi
