#!/usr/bin/env python3
"""Client for POC30 RSA challenge-response port knocking."""

import argparse
import socket
import yaml

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_conf(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def main() -> None:
    parser = argparse.ArgumentParser(description="RSA challenge-response knocking client")
    parser.add_argument("--config", required=True, help="Path to poc30_rsa.yaml")
    args = parser.parse_args()

    conf = load_conf(args.config)
    knock_port = int(conf["knock_port"])
    priv_key_path = conf["private_key"]

    private_key = load_private_key(priv_key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"HELLO", ("127.0.0.1", knock_port))
    challenge, _ = sock.recvfrom(1024)
    signature = private_key.sign(
        challenge,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sock.sendto(signature, ("127.0.0.1", knock_port))
    sock.close()
    print("Knock sent")


if __name__ == "__main__":
    main()
