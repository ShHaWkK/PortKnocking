#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC3 - Client port-knocking (compatible serveur nftables).
- Calcule la séquence en HMAC(secret, window)
- Frappe P1 -> P2 -> P3 en TCP SYN (bloque pas en cas d'échec)
- Ouvre SSH automatiquement si demandé
"""

import os, sys, time, hmac, hashlib, base64, socket, argparse, subprocess, getpass, binascii

SSH_PORT        = 2222
SSH_LISTEN      = "127.0.0.1"
WINDOW_SECONDS  = 30
SEQUENCE_LEN    = 3
MIN_PORT, MAX_PORT = 40000, 50000
STEP_DELAY      = 0.5

DEFAULT_SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")

# ------------- Secret -------------
def b64_read_tolerant(raw: str) -> bytes:
    token = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        data = base64.b64decode(token)
        if not data: raise ValueError("secret vide")
        return data

def load_secret(env_var="KNOCK_SECRET_B64", file_path=DEFAULT_SECRET_FILE) -> bytes:
    if os.environ.get(env_var):
        return b64_read_tolerant(os.environ[env_var])
    if os.path.exists(file_path):
        with open(file_path,"r") as f:
            return b64_read_tolerant(f.read())
    print(f"[ERREUR] Secret introuvable. Exporte {env_var} ou crée {file_path}")
    sys.exit(1)

# ------------- Séquence -------------
def current_window(ts=None):
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, str(win).encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i + 2 <= len(digest):
        val = int.from_bytes(digest[i:i+2], "big")
        p   = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

# ------------- Réseau -------------
def send_syn(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError:
        pass
    finally:
        s.close()

def ensure_local_ssh_key():
    home = os.path.expanduser("~"); sshd = os.path.join(home, ".ssh")
    priv = os.path.join(sshd, "id_ed25519"); pub = priv + ".pub"; auth = os.path.join(sshd, "authorized_keys")
    os.makedirs(sshd, exist_ok=True)
    if not os.path.exists(priv):
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",priv], check=True)
    if not os.path.exists(pub):
        subprocess.run(["ssh-keygen","-y","-f",priv], check=True, stdout=open(pub,"w"))
    key = open(pub).read().strip()
    if not os.path.exists(auth) or key not in open(auth).read():
        with open(auth,"a") as f: f.write(key+"\n")
        os.chmod(auth, 0o600)

# ------------- Main -------------
def main():
    ap = argparse.ArgumentParser(description="POC3 Client - port-knocking dynamique (nftables)")
    ap.add_argument("server", nargs="?", default=SSH_LISTEN, help="IP/nom du serveur (défaut: 127.0.0.1)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer SSH après les knocks")
    ap.add_argument("--delay", type=float, default=STEP_DELAY, help="Délai entre knocks (défaut: 0.5s)")
    ap.add_argument("--secret-file", default=DEFAULT_SECRET_FILE, help=f"Chemin du secret (défaut: {DEFAULT_SECRET_FILE})")
    args = ap.parse_args()

    secret = load_secret(file_path=args.secret_file)
    server = args.server
    client_ip = "127.0.0.1" if server in ("127.0.0.1","localhost") else socket.gethostbyname(socket.gethostname())

    w   = current_window()
    seq = derive_sequence(secret, w)

    print(f"[i] Cible: {server} | Fenêtre: {w} ({WINDOW_SECONDS}s) | Séquence: {' -> '.join(map(str, seq))} | Délai: {args.delay}s")

    for p in seq:
        print(f"[*] Knock sur le port {p}")
        send_syn(server, p); time.sleep(args.delay)

    if args.no-ssh:
        return

    try:
        ensure_local_ssh_key()
    except Exception as e:
        print(f"[!] Clé SSH locale: {e}")

    user = getpass.getuser()
    print("[✓] Knocks envoyés. Connexion SSH automatique…")
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{server}"])

if __name__ == "__main__":
    main()
