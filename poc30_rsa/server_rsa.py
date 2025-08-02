#!/usr/bin/env python3
"""POC30: Port-knocking using RSA challenge-response.
The server issues a random challenge and expects a valid RSA signature
before opening the service port for a short duration.
"""

import argparse
import logging
import os
import secrets
import socket
import threading
import time
import yaml

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


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


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def open_port(ip: str, port: int, duration: int) -> None:
    logging.info(f"[+] Valid RSA knock from {ip}; would open port {port} for {duration}s")

    def close_later():
        time.sleep(duration)
        logging.info(f"[-] Port {port} for {ip} would now be closed")

    threading.Thread(target=close_later, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="RSA challenge-response knocking server")
    parser.add_argument("--config", required=True, help="Path to poc30_rsa.yaml")
    args = parser.parse_args()

    conf = load_conf(args.config)
    knock_port = int(conf["knock_port"])
    service_port = int(conf["service_port"])
    open_duration = int(conf["open_duration"])
    log_file = conf["log_file"]
    pub_key_path = conf["public_key"]
    challenge_size = int(conf.get("challenge_size", 16))

    setup_logger(log_file)
    public_key = load_public_key(pub_key_path)
    logging.info(f"Server RSA listening on UDP {knock_port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", knock_port))
    sock.settimeout(5)

    try:
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            src_ip = addr[0]
            if data.strip() != b"HELLO":
                logging.info(f"Unexpected message from {src_ip}")
                continue
            challenge = secrets.token_hex(challenge_size)
            sock.sendto(challenge.encode(), addr)
            try:
                sig, addr2 = sock.recvfrom(4096)
            except socket.timeout:
                logging.info(f"No signature from {src_ip}")
                continue
            if addr2[0] != src_ip:
                logging.info("Signature from different IP")
                continue
            try:
                public_key.verify(
                    sig,
                    challenge.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                logging.info(f"Valid signature from {src_ip}")
                open_port(src_ip, service_port, open_duration)
            except Exception:
                logging.info(f"Invalid signature from {src_ip}")
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
