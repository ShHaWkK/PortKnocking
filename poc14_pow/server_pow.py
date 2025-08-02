#!/usr/bin/env python3
"""POC14: Port-knocking with proof-of-work requirement.
The server listens for a UDP packet containing a nonce. It verifies
that SHA256(challenge + nonce) has the required number of leading zeros
(hex digits). If valid, the server logs that the service port is opened
for the source IP for a limited duration.
"""

import argparse
import hashlib
import logging
import os
import socket
import threading
import time
import yaml


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


def hash_has_leading_zeros(h: str, difficulty: int) -> bool:
    prefix = "0" * difficulty
    return h.startswith(prefix)


def check_pow(challenge: str, nonce: str, difficulty: int) -> bool:
    h = hashlib.sha256(f"{challenge}{nonce}".encode()).hexdigest()
    return hash_has_leading_zeros(h, difficulty)


def open_port(ip: str, port: int, duration: int) -> None:
    logging.info(f"[+] Proof valid from {ip}; would open port {port} for {duration}s")
    # Real iptables manipulation omitted in this environment.
    def close_later():
        time.sleep(duration)
        logging.info(f"[-] Port {port} for {ip} would now be closed")

    threading.Thread(target=close_later, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="POW-based port-knocking server")
    parser.add_argument("--config", required=True, help="Path to poc14_pow.yaml")
    args = parser.parse_args()

    conf = load_conf(args.config)
    challenge = conf["challenge"]
    difficulty = int(conf["difficulty"])
    knock_port = int(conf["knock_port"])
    service_port = int(conf["service_port"])
    open_duration = int(conf["open_duration"])
    log_file = conf["log_file"]

    setup_logger(log_file)
    logging.info(
        f"Server POW listening on UDP {knock_port} with challenge '{challenge}'"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", knock_port))

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            nonce = data.decode(errors="ignore").strip()
            src_ip = addr[0]
            if check_pow(challenge, nonce, difficulty):
                logging.info(f"Valid knock from {src_ip} (nonce={nonce})")
                open_port(src_ip, service_port, open_duration)
            else:
                logging.info(f"Invalid knock from {src_ip} (nonce={nonce})")
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
