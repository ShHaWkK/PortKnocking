#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Port-Knocking "one-command":
- Envoie la séquence par défaut 7000->8000->9000 vers 127.0.0.1
- Lance automatiquement la commande SSH ensuite (interactive)
Usage: python3 port_knock_client.py
"""

import os, socket, time, subprocess, getpass

HOST = "127.0.0.1"
SEQUENCE = [7000, 8000, 9000]
DELAY = 0.5
OPEN_PORT = 2222

def main():
    print(f"[i] Cible: {HOST} | Séquence: {' -> '.join(map(str, SEQUENCE))} | Délai: {DELAY}s")
    for port in SEQUENCE:
        print(f"[*] Knock sur le port {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try: s.connect((HOST, port))   # émet un SYN
            except OSError: pass           # normal: fermé/filtré
        time.sleep(DELAY)
    print("[✓] Séquence envoyée. Tentative SSH automatique…")
    user = os.environ.get("USER") or getpass.getuser() or "user"
    try:
        subprocess.call(["ssh", "-p", str(OPEN_PORT), f"{user}@{HOST}"])
    except FileNotFoundError:
        print("[-] 'ssh' introuvable. Installe le client OpenSSH.")

if __name__ == "__main__":
    main()
