#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC4 (client) — knocks HMAC (3 SYN) + SPA AES-GCM + TOTP + SSH auto
Usage: python3 poc4_client_spa_totp.py 127.0.0.1
"""

import os, sys, time, hmac, hashlib, base64, secrets, subprocess, getpass
import argparse, json, socket, shutil

SSH_PORT           = 2222
SSH_LISTEN         = "127.0.0.1"
WINDOW_SECONDS     = 30
SEQUENCE_LEN       = 3
MIN_PORT, MAX_PORT = 40000, 50000
DEFAULT_DELAY      = 0.5
SPA_PORT           = 45444

SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")
TOTP_FILE   = os.path.expanduser("~/.config/portknock/totp")

# ------- Dépendances -------
def _pip_install(pkg: str):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg], check=True)
        return True
    except Exception:
        return False

def _apt_install(*pkgs: str):
    if not shutil.which("apt"): return False
    try:
        subprocess.run(["sudo","apt","update"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","apt","install","-y",*pkgs], check=False)
        return True
    except Exception:
        return False

def ensure_pydeps():
    ok = True
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        print("[i] Installation cryptography…")
        ok = _pip_install("cryptography") or _apt_install("python3-cryptography") or ok
    try:
        import pyotp  # noqa
    except Exception:
        print("[i] Installation pyotp…")
        ok = _pip_install("pyotp") or _apt_install("python3-pyotp") or ok
    return ok

# ------- Utils -------
def load_secret(path=SECRET_FILE) -> bytes:
    if not os.path.exists(path):
        raise SystemExit(f"[ERREUR] Secret introuvable : {path}")
    token = open(path).read().strip().split()[0]
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        return base64.b64decode(token)

def load_totp_b32(path=TOTP_FILE) -> str:
    if not os.path.exists(path):
        raise SystemExit(f"[ERREUR] Clé TOTP introuvable : {path}")
    return open(path).read().strip().split()[0]

def epoch_window(ts=None): return int((ts or time.time()) // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"seq|{win}".encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2],"big")
        p = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

def derive_spa_key(secret: bytes, ip: str, win: int) -> bytes:
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

def send_syn(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except OSError: pass
    finally: s.close()

def ensure_local_ssh_key():
    home = os.path.expanduser("~"); d = os.path.join(home, ".ssh")
    priv = os.path.join(d, "id_ed25519"); pub = priv + ".pub"; auth = os.path.join(d, "authorized_keys")
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(priv):
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",priv], check=True)
    if not os.path.exists(pub):
        subprocess.run(["ssh-keygen","-y","-f",priv], check=True, stdout=open(pub,"w"))
    key = open(pub).read().strip()
    if not os.path.exists(auth) or key not in open(auth).read():
        with open(auth,"a") as f: f.write(key+"\n")
        os.chmod(auth, 0o600)

# ------- SPA -------
def build_spa_packet(secret: bytes, server_ip: str, client_ip: str, duration: int, totp_b32: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import pyotp
    code = pyotp.TOTP(totp_b32).now()
    payload = {
        "req":"open", "port": SSH_PORT,
        "ts": int(time.time()), "nonce": secrets.token_hex(12),
        "totp": code, "duration": int(duration),
    }
    raw = json.dumps(payload, separators=(",",":")).encode()
    w   = epoch_window()
    key = derive_spa_key(secret, client_ip, w)
    iv  = os.urandom(12)
    ct  = AESGCM(key).encrypt(iv, raw, None)
    print(f"[*] TOTP utilisé: {code}")
    return b"\x01" + iv + ct

def send_spa(pkt: bytes, server_ip: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (server_ip, SPA_PORT)); s.close()

# ------- Main -------
def main():
    ensure_pydeps()

    ap = argparse.ArgumentParser(description="POC4 Client — knocks HMAC + SPA + TOTP")
    ap.add_argument("server", nargs="?", default=SSH_LISTEN, help="IP/nom du serveur (défaut 127.0.0.1)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Délai entre knocks (s)")
    ap.add_argument("--duration", type=int, default=30, help="Durée d’ouverture (s, 0=longue)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer ssh après SPA")
    args = ap.parse_args()

    secret   = load_secret()
    totp_b32 = load_totp_b32()

    server = args.server
    client_ip = "127.0.0.1" if server in ("127.0.0.1","localhost") else socket.gethostbyname(socket.gethostname())

    w   = epoch_window()
    seq = derive_sequence(secret, w)
    print(f"[i] Cible: {server} | Fenêtre: {w} ({WINDOW_SECONDS}s) | Séquence: {' -> '.join(map(str,seq))} | Délai: {args.delay}s")

    for p in seq:
        print(f"[*] Knock sur le port {p}")
        send_syn(server, p); time.sleep(args.delay)

    print("[*] Envoi du SPA chiffré…")
    pkt = build_spa_packet(secret, server, client_ip, args.duration, totp_b32)
    send_spa(pkt, server)

    if args.no_ssh:
        print("[✓] SPA envoyé."); return

    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] Clé SSH locale: {e}")
    user = getpass.getuser()
    print("[✓] SPA envoyé. Connexion SSH automatique…")
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{server}"])

if __name__ == "__main__":
    main()
