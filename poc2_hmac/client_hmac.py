#!/usr/bin/env python3
"""
client_hmac_knock.py

Envoie un knock sécurisé (HMAC+timestamp) au serveur pour déclencher l'ouverture d'un port.

Usage :
  python3 client_hmac_knock.py --config ../config/poc2_hmac.yaml --server 10.0.0.5
"""

import yaml
import argparse
import time
import socket
import sys

def load_yaml(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def compute_hmac(secret: bytes, src_ip: str, timestamp: int) -> str:
    import hmac, hashlib
    msg = f"{src_ip}|{timestamp}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def get_local_ip():
    # tentative pour obtenir IP locale sortante
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(description="Client knock HMAC")
    parser.add_argument("--config", required=True, help="Chemin vers poc2_hmac.yaml")
    parser.add_argument("--server", required=True, help="Adresse IP du serveur")
    args = parser.parse_args()

    conf = load_yaml(args.config)
    secret = conf["secret"].encode()
    knock_port = conf["knock_port"]

    # On choisit l'IP source qu'on envoie dans la signature : 
    src_ip = get_local_ip()
    timestamp = int(time.time())
    hmac_val = compute_hmac(secret, src_ip, timestamp)
    payload = f"{timestamp}|{hmac_val}".encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (args.server, knock_port))
        print(f"[+] Knock HMAC envoyé à {args.server}:{knock_port} (src_ip={src_ip}, ts={timestamp})")
    except Exception as e:
        print(f"[!] Échec envoi knock : {e}", file=sys.stderr)
    finally:
        sock.close()

if __name__ == "__main__":
    main()