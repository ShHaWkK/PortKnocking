#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC4+ — Client pour séquence HMAC (nftables) + SPA AES-GCM + TOTP.
- Calcule la séquence de la fenêtre, frappe P1->P2->P3
- Construit un SPA chiffré (nonce, ts, duration, totp) et l'envoie en UDP
- Enchaîne sur ssh -p 2222 (génère clé ed25519 si besoin)
"""

import os, sys, time, hmac, hashlib, base64, secrets, subprocess, argparse, getpass, socket, json, binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

SSH_PORT        = 2222
SSH_LISTEN      = "127.0.0.1"
WINDOW_SECONDS  = 30
SEQUENCE_LEN    = 3
MIN_PORT, MAX_PORT = 40000, 50000
DEFAULT_DELAY   = 0.5
SPA_PORT        = 45444

CFG_DIR         = os.path.expanduser("~/.config/portknock")
SECRET_FILE     = os.path.join(CFG_DIR, "secret")        # base64 (serveur la dépose)
TOTP_FILE       = os.path.join(CFG_DIR, "totp_secret")   # base32 (serveur la dépose)

# --------------- Helpers ---------------
def b64_read_tolerant(raw: str) -> bytes:
    """Lit un base64 avec tolérance."""
    tok = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(tok, validate=True)
    except Exception:
        data = base64.b64decode(tok)
        if not data: raise ValueError("secret vide")
        return data

def load_hmac_secret() -> bytes:
    """Charge le secret HMAC (base64) fourni par le serveur."""
    if not os.path.exists(SECRET_FILE):
        sys.exit(f"[ERREUR] Secret introuvable : {SECRET_FILE}")
    return b64_read_tolerant(open(SECRET_FILE).read())

def load_totp_secret() -> str:
    """Charge le secret TOTP (base32) fourni par le serveur."""
    if not os.path.exists(TOTP_FILE):
        sys.exit(f"[ERREUR] Secret TOTP introuvable : {TOTP_FILE}")
    return open(TOTP_FILE).read().strip()

def current_window(ts=None):
    """Fenêtre courante (ts // WINDOW_SECONDS)."""
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    """Retourne 3 ports [MIN_PORT,MAX_PORT] à partir de HMAC(secret, str(win))."""
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, str(win).encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2],"big")
        p   = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

def derive_spa_key(secret: bytes, ip: str, win: int)->bytes:
    """Clé AES-GCM liée à l'IP et à la fenêtre (même dérivation que côté serveur)."""
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

def send_syn(host, port, timeout=1.0):
    """Émet un TCP SYN (connexion échouera, c'est attendu)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except OSError: pass
    finally: s.close()

def ensure_local_ssh_key():
    """Génère une clé ed25519 et l'ajoute à authorized_keys si besoin (démo locale)."""
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

def build_spa_packet(hmac_secret: bytes, totp_secret: str, server_ip: str, client_ip: str, duration: int):
    """Construit un paquet SPA: 0x01 | IV(12) | AESGCM(JSON)."""
    payload = {
        "req": "open",
        "port": SSH_PORT,
        "ts":   int(time.time()),
        "nonce": secrets.token_hex(12),
        "user": getpass.getuser(),
        "duration": int(duration),
        "totp": pyotp.TOTP(totp_secret).now()
    }
    raw = json.dumps(payload, separators=(",",":")).encode()
    w   = current_window()
    key = derive_spa_key(hmac_secret, client_ip, w)
    iv  = os.urandom(12)
    ct  = AESGCM(key).encrypt(iv, raw, None)
    return b"\x01" + iv + ct

def send_spa(pkt: bytes, server_ip: str):
    """Envoie le SPA en UDP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (server_ip, SPA_PORT)); s.close()

# --------------- Main ---------------
def main():
    ap = argparse.ArgumentParser(description="POC3+ Client — knocks HMAC + SPA + TOTP")
    ap.add_argument("server", nargs="?", default=SSH_LISTEN, help="IP du serveur (défaut: 127.0.0.1)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Délai entre knocks (s)")
    ap.add_argument("--duration", type=int, default=0, help="Durée d'ouverture demandée (0 = long pour démo)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer SSH après SPA")
    args = ap.parse_args()

    hsecret = load_hmac_secret()
    tsecret = load_totp_secret()

    server = args.server
    client_ip = "127.0.0.1" if server in ("127.0.0.1","localhost") else socket.gethostbyname(socket.gethostname())

    w   = current_window()
    seq = derive_sequence(hsecret, w)
    print(f"[i] Cible: {server} | Fenêtre: {w} ({WINDOW_SECONDS}s) | Séquence: {seq[0]} -> {seq[1]} -> {seq[2]} | Délai: {args.delay}s")

    for p in seq:
        print(f"[*] Knock sur le port {p}")
        send_syn(server, p); time.sleep(args.delay)

    print("[*] Envoi du SPA chiffré + TOTP…")
    pkt = build_spa_packet(hsecret, tsecret, server, client_ip, args.duration)
    send_spa(pkt, server)

    if args.no_ssh: return
    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] Clé SSH locale: {e}")
    print("[✓] SPA envoyé. Connexion SSH automatique…")
    user = getpass.getuser()
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{server}"])

if __name__ == "__main__":
    import getpass, pyotp
    main()
