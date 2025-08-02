#!/usr/bin/env python3
"""POC31: Port-knocking with X25519 Diffie-Hellman and HMAC.
The server exchanges a DH key with the client and expects an HMAC
of a shared challenge using the derived secret."""

import argparse
import hashlib
import hmac
import logging
import os
import socket
import threading
import time
import yaml

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


def setup_logger(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    logging.basicConfig(
        filename=path,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger().addHandler(logging.StreamHandler())


def load_conf(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def open_port(ip: str, port: int, duration: int) -> None:
    logging.info(f"[+] Valid DH knock from {ip}; would open port {port} for {duration}s")

    def close_later():
        time.sleep(duration)
        logging.info(f"[-] Port {port} for {ip} would now be closed")

    threading.Thread(target=close_later, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Diffie-Hellman HMAC knocking server")
    parser.add_argument("--config", required=True, help="Path to poc31_dh.yaml")
    args = parser.parse_args()

    conf = load_conf(args.config)
    challenge = conf["challenge"].encode()
    knock_port = int(conf["knock_port"])
    service_port = int(conf["service_port"])
    open_duration = int(conf["open_duration"])
    log_file = conf["log_file"]

    setup_logger(log_file)
    logging.info(f"Server DH listening on UDP {knock_port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", knock_port))
    sock.settimeout(5)

    try:
        while True:
            try:
                client_pub_bytes, addr = sock.recvfrom(64)
            except socket.timeout:
                continue
            src_ip = addr[0]
            try:
                client_public = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
            except Exception:
                logging.info(f"Invalid public key from {src_ip}")
                continue
            server_private = x25519.X25519PrivateKey.generate()
            server_pub_bytes = server_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            sock.sendto(server_pub_bytes, addr)
            shared = server_private.exchange(client_public)
            expected = hmac.new(shared, challenge, hashlib.sha256).hexdigest().encode()
            try:
                hmac_msg, addr2 = sock.recvfrom(128)
            except socket.timeout:
                logging.info(f"No HMAC from {src_ip}")
                continue
            if addr2[0] != src_ip:
                logging.info("HMAC from different IP")
                continue
            if hmac.compare_digest(hmac_msg.strip(), expected):
                logging.info(f"Valid knock from {src_ip}")
                open_port(src_ip, service_port, open_duration)
            else:
                logging.info(f"Invalid HMAC from {src_ip}")
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
