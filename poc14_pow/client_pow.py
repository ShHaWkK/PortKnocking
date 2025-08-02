#!/usr/bin/env python3
"""Client for POC14 proof-of-work port knocking."""

import argparse
import hashlib
import os
import socket
import time
import yaml


def load_conf(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def solve_pow(challenge: str, difficulty: int) -> str:
    nonce = 0
    prefix = "0" * difficulty
    while True:
        candidate = f"{nonce}".encode()
        h = hashlib.sha256(challenge.encode() + candidate).hexdigest()
        if h.startswith(prefix):
            return str(nonce)
        nonce += 1


def main() -> None:
    parser = argparse.ArgumentParser(description="POW-based port-knocking client")
    parser.add_argument("--config", required=True, help="Path to poc14_pow.yaml")
    args = parser.parse_args()

    conf = load_conf(args.config)
    challenge = conf["challenge"]
    difficulty = int(conf["difficulty"])
    knock_port = int(conf["knock_port"])

    print(f"Solving proof of work: difficulty {difficulty} ...")
    start = time.time()
    nonce = solve_pow(challenge, difficulty)
    duration = time.time() - start
    print(f"Found nonce {nonce} in {duration:.2f}s")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(nonce.encode(), ("127.0.0.1", knock_port))
    sock.close()
    print("Knock sent")


if __name__ == "__main__":
    main()
