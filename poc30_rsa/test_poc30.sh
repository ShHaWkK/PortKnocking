#!/bin/bash
# Simple test for POC30 RSA challenge-response knocking.
set -e
cd "$(dirname "$0")"

CONFIG=../config/poc30_rsa.yaml
LOG=logs/server_rsa.log

python3 server_rsa.py --config "$CONFIG" &
SERVER_PID=$!
sleep 1

python3 client_rsa.py --config "$CONFIG"
sleep 1

kill $SERVER_PID
sleep 1

if grep -q "Valid signature" "$LOG"; then
  echo "Test succeeded"
else
  echo "Test failed" >&2
  exit 1
fi
