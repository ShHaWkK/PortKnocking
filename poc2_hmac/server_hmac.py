#!/usr/bin/env python3
"""
server_hmac_knock.py

POC2 : Port-knocking avec knock authentifié (HMAC + timestamp).
Le port cible est fermé par défaut. Après réception d'un knock valide
(fraîcheur + signature + anti-replay), on ouvre temporairement le port pour l'IP source.

Usage :
  sudo python3 server_hmac_knock.py --config ../config/poc2_hmac.yaml
"""

import yaml
import argparse
import os
import time
import subprocess
import threading
import logging
from collections import deque
from socket import socket, AF_INET, SOCK_DGRAM

# === anti-replay storage ===
used_nonces = {}  # ip -> deque of timestamps

def setup_logger(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    logging.basicConfig(
        filename=path,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.getLogger().addHandler(logging.StreamHandler())  # aussi console

def load_yaml(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def compute_hmac(secret: bytes, src_ip: str, timestamp: int) -> str:
    import hmac, hashlib
    msg = f"{src_ip}|{timestamp}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def verify_hmac(secret: bytes, src_ip: str, timestamp: int, received: str) -> bool:
    expected = compute_hmac(secret, src_ip, timestamp)
    import hmac
    return hmac.compare_digest(expected, received)

def is_fresh(timestamp: int, tolerance: int) -> bool:
    return abs(time.time() - timestamp) <= tolerance

def cleanup_nonces(ip, tolerance):
    if ip not in used_nonces:
        return
    now = time.time()
    dq = used_nonces[ip]
    while dq and now - dq[0] > tolerance:
        dq.popleft()
    if not dq:
        used_nonces.pop(ip, None)

def open_port(ip, service_port, open_duration):
    logging.info(f"[+] Autorisation temporaire du port {service_port} pour {ip}")
    try:
        subprocess.run([
            "iptables", "-I", "INPUT", "-p", "tcp", "-s", ip,
            "--dport", str(service_port), "-j", "ACCEPT"
        ], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Échec ajout règle iptables pour {ip}: {e}")
        return

    def close_later():
        time.sleep(open_duration)
        logging.info(f"[-] Révocation du port {service_port} pour {ip}")
        try:
            subprocess.run([
                "iptables", "-D", "INPUT", "-p", "tcp", "-s", ip,
                "--dport", str(service_port), "-j", "ACCEPT"
            ], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Échec suppression règle iptables pour {ip}: {e}")

    threading.Thread(target=close_later, daemon=True).start()

def ensure_port_closed(service_port):
    # On peut ajouter une règle DROP par défaut pour le port cible (si pas déjà)
    subprocess.run([
        "iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(service_port),
        "-j", "DROP"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # si la règle DROP n'existe pas, on l'ajoute
    result = subprocess.run([
        "iptables", "-S", "INPUT"
    ], capture_output=True, text=True)
    rule = f"-p tcp -m tcp --dport {service_port} -j DROP"
    if rule not in result.stdout:
        logging.info(f"Ajout d'une règle par défaut DROP sur {service_port}")
        subprocess.run([
            "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(service_port), "-j", "DROP"
        ])

def main():
    parser = argparse.ArgumentParser(description="Serveur port-knocking HMAC+timestamp")
    parser.add_argument("--config", required=True, help="Chemin vers poc2_hmac.yaml")
    args = parser.parse_args()

    conf = load_yaml(args.config)
    secret = conf["secret"].encode()
    knock_port = conf["knock_port"]
    service_port = conf["service_port"]
    time_tolerance = conf["time_tolerance"]
    open_duration = conf["open_duration"]
    log_file = conf["log_file"]

    setup_logger(log_file)
    logging.info("Démarrage du serveur HMAC port-knocking")
    logging.info(f"Knock attendu sur UDP {knock_port}, service cible: {service_port}")

    ensure_port_closed(service_port)

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(("", knock_port))

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            src_ip = addr[0]
            payload = data.decode(errors="ignore").strip()
            parts = payload.split("|")
            if len(parts) != 2:
                logging.warning(f"Format invalide de {src_ip}: {payload}")
                continue
            ts_str, received_hmac = parts
            try:
                ts = int(ts_str)
            except ValueError:
                logging.warning(f"Timestamp invalide de {src_ip}: {ts_str}")
                continue

            cleanup_nonces(src_ip, time_tolerance)

            if not is_fresh(ts, time_tolerance):
                logging.info(f"Rejet {src_ip} : timestamp hors tolérance ({ts})")
                continue

            if src_ip in used_nonces and ts in used_nonces[src_ip]:
                logging.info(f"Rejet replay de {src_ip} pour timestamp {ts}")
                continue

            if not verify_hmac(secret, src_ip, ts, received_hmac):
                logging.info(f"Rejet signature invalide de {src_ip}")
                continue

            # Knock validé
            used_nonces.setdefault(src_ip, deque()).append(ts)
            logging.info(f"Knock valide reçu de {src_ip}, ouverture du port")
            open_port(src_ip, service_port, open_duration)
    except KeyboardInterrupt:
        logging.info("Arrêt demandé par utilisateur")
    except Exception as e:
        logging.exception(f"Erreur critique: {e}")
    finally:
        logging.info("Fin du serveur")
        sock.close()

if __name__ == "__main__":
    main()
