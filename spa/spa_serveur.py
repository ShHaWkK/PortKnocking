#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur de Single Packet Authorization (SPA) simplifié.
Le SPA consiste à envoyer un seul paquet contenant des informations
d'authentification pour demander l'ouverture d'un port. Dans cette
implémentation basique, le client envoie un paquet UDP contenant un
secret partagé. Si le secret est correct, le serveur ouvre
temporairement un port TCP pour le client.
"""
import socket
import threading
import time

SECRET_KEY = "mot_de_passe_spa"
AUTH_PORT = 15000
SERVICE_PORT = 2225
SERVICE_TIMEOUT = 30

def open_service_for_client(client_ip: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('', SERVICE_PORT))
        srv.listen(1)
        print(f"[INFO] Service SPA ouvert sur {SERVICE_PORT} pour {client_ip}")
        srv.settimeout(SERVICE_TIMEOUT)
        start_time = time.time()
        try:
            while time.time() - start_time < SERVICE_TIMEOUT:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                if addr[0] != client_ip:
                    conn.close()
                    continue
                with conn:
                    conn.sendall( f"Bienvenue sur le service SPA, {client_ip}!".encode('utf-8'))
                    print(f"[INFO] Connexion acceptée de {addr[0]}")
                    data = conn.recv(1024)
                    print(f"[INFO] {addr[0]} s'est connecté au service SPA.")
                    break
        finally:
            print(f"[INFO] Fermeture du service SPA sur {SERVICE_PORT}")

def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('', AUTH_PORT))
        print(f"[INFO] Serveur SPA en écoute sur le port UDP {AUTH_PORT}")
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                client_ip, _ = addr
                message = data.decode('utf-8', errors='ignore')
                if message.startswith("AUTH:"):
                    token = message[5:].strip()
                    if token == SECRET_KEY:
                        print(f"[INFO] Paquet SPA valide reçu de {client_ip}. Ouverture du port...")
                        threading.Thread(target=open_service_for_client, args=(client_ip,), daemon=True).start()
                    else:
                        print(f"[WARN] Clé SPA invalide de {client_ip}")
        except KeyboardInterrupt:
            print("[INFO] Arrêt du serveur SPA")

if __name__ == "__main__":
    main()
