#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Port-Knocking (one-command) :
- Envoie 7000 -> 8000 -> 9000 vers 127.0.0.1 (TCP SYN)
- Installe automatiquement une clé SSH si besoin (id_ed25519)
- Lance la connexion SSH automatiquement (sans mot de passe)
Utilisation :  python3 port_knock_client.py
"""

import os, pathlib, socket, time, subprocess, getpass

HOST = "127.0.0.1"
SEQUENCE = [7000, 8000, 9000]
DELAY = 0.5
OPEN_PORT = 2222

def ensure_key_and_authorized_keys():
    home = pathlib.Path.home()
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    priv = ssh_dir / "id_ed25519"
    pub  = ssh_dir / "id_ed25519.pub"
    auth = ssh_dir / "authorized_keys"

    if not priv.exists() or not pub.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(priv), "-q"], check=True)

    auth.touch(mode=0o600, exist_ok=True)
    with open(pub, "r", encoding="utf-8") as f: pubkey = f.read().strip()
    with open(auth, "r+", encoding="utf-8") as f:
        content = f.read()
        if pubkey not in content:
            f.write(("\n" if content and not content.endswith("\n") else "") + pubkey + "\n")
    os.chmod(auth, 0o600)

def auto_ssh(user: str):
    # Confort démo : on ne bloque pas sur la vérification de l’empreinte
    subprocess.call([
        "ssh", "-p", str(OPEN_PORT),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        f"{user}@{HOST}"
    ])

def main():
    print(f"[i] Cible: {HOST} | Séquence: {' -> '.join(map(str, SEQUENCE))} | Délai: {DELAY}s")
    for port in SEQUENCE:
        print(f"[*] Knock sur le port {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try: s.connect((HOST, port))   # envoie un SYN
            except OSError: pass           # normal : fermé/filtré
        time.sleep(DELAY)

    # SSH auto par clé
    ensure_key_and_authorized_keys()
    user = os.environ.get("USER") or getpass.getuser() or "user"
    print("[✓] Séquence envoyée. Connexion SSH automatique…")
    auto_ssh(user)

if __name__ == "__main__":
    main()
