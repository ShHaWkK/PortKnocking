#!/usr/bin/env python3
"""Client for POC31 Diffie-Hellman HMAC port knocking."""

import argparse
import hashlib
import hmac
import socket
import yaml

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


def load_conf(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="Diffie-Hellman HMAC knocking client")
    parser.add_argument("--config", required=True, help="Path to poc31_dh.yaml")
    args = parser.parse_args()

    conf = load_conf(args.config)
    challenge = conf["challenge"].encode()
    knock_port = int(conf["knock_port"])

    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(pub_bytes, ("127.0.0.1", knock_port))
    server_pub, _ = sock.recvfrom(64)
    server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
    shared = priv.exchange(server_public)
    mac = hmac.new(shared, challenge, hashlib.sha256).hexdigest().encode()
    sock.sendto(mac, ("127.0.0.1", knock_port))
    sock.close()
    print("Knock sent")


if __name__ == "__main__":
    main()
