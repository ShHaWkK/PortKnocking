#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client de démonstration pour le mécanisme de port‑knocking UDP.
Ce script envoie une série de paquets UDP vers les ports définis
par la séquence du serveur. Une fois la séquence envoyée, il tente
d'établir une connexion TCP au port de service ouvert par le serveur.
"""
import socket
import sys
import time
from typing import List

def send_udp_knock(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b'Knock', (host, port))
    print(f"[DEBUG] Knock UDP envoyé sur le port {port}")

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage : python3 udp_knock_client.py <adresse_du_serveur> [port1 port2 …] [service_port]")
        sys.exit(1)
    host = sys.argv[1]
    sequence: List[int] = [12001, 12002, 12003]
    service_port: int = 2223
    if len(sys.argv) > 2:
        try:
            *seq_args, service_arg = sys.argv[2:]
            if seq_args:
                sequence = [int(p) for p in seq_args]
            service_port = int(service_arg)
        except ValueError:
            print("Erreur: les ports doivent être des entiers.")
            sys.exit(1)
    print(f"[INFO] Séquence UDP envoyée vers {host} : {sequence}")
    for port in sequence:
        send_udp_knock(host, port)
        time.sleep(0.5)
    print(f"[INFO] Tentative de connexion au service TCP {service_port}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect((host, service_port))
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"[SUCCESS] Réponse du serveur : {response.strip()}")
    except Exception as exc:
        print(f"[ERROR] Échec de connexion au service : {exc}")

if __name__ == "__main__":
    main()
