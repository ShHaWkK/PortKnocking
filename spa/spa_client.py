#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client pour démontrer la Single Packet Authorization (SPA).
Le client envoie un paquet UDP unique contenant un préfixe "AUTH:"
suivi d'un secret partagé. Si le serveur reconnaît le secret, il
ouvrira un port TCP pour le client.
"""
import socket
import sys
import time

SECRET_KEY = "mot_de_passe_spa"
AUTH_PORT = 15000
SERVICE_PORT = 2225

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage : python3 spa.py <adresse_du_serveur> [service_port]")
        sys.exit(1)
    host = sys.argv[1]
    service_port = SERVICE_PORT
    if len(sys.argv) > 2:
        try:
            service_port = int(sys.argv[2])
        except ValueError:
            print("Erreur: le port de service doit être un entier.")
            sys.exit(1)
    message = f"AUTH:{SECRET_KEY}".encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, (host, AUTH_PORT))
    print(f"[INFO] Paquet SPA envoyé vers {host}:{AUTH_PORT}")
    time.sleep(1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect((host, service_port))
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"[SUCCESS] Réponse du serveur : {response.strip()}")
    except Exception as exc:
        print(f"[ERROR] Impossible de se connecter au service SPA : {exc}")

if __name__ == "__main__":
    main()
