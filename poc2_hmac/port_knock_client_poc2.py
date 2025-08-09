#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC2 Client — Séquence HMAC + SPA AES-GCM
- Lit le secret base64 (tolérant) depuis ~/.config/portknock/secret
  ou depuis la variable d’environnement KNOCK_SECRET_B64
- Devine l’IP source réellement utilisée (utile hors loopback)
- Envoie 3 knocks (HMAC) puis un SPA (UDP) chiffré AES-GCM avec nonce anti-rejeu
- Ouvre ensuite automatiquement une session SSH (-p 2222)
"""
import os, sys, time, json, hmac, base64, hashlib, socket, argparse, getpass, subprocess, binascii, secrets

SSH_PORT        = 2222
SSH_LISTEN      = "127.0.0.1"
WINDOW_SECONDS  = 30
SEQUENCE_LEN    = 3
MIN_PORT, MAX_PORT = 40000, 50000
STEP_DELAY      = 0.5
SPA_PORT        = 45444
DEFAULT_SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")

# --------- Secret (tolérant) ----------
def b64_read_tolerant(raw: str) -> bytes:
    token = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        try:
            data = base64.b64decode(token)
            if not data: raise ValueError("vide")
            return data
        except Exception as e:
            raise ValueError(f"Secret local invalide : {e}")

def load_secret(env_var="KNOCK_SECRET_B64", file_path=DEFAULT_SECRET_FILE) -> bytes:
    if os.environ.get(env_var):
        return b64_read_tolerant(os.environ[env_var])
    if os.path.exists(file_path):
        with open(file_path,"r") as f:
            return b64_read_tolerant(f.read())
    raise SystemExit(f"[ERREUR] Secret introuvable. Exporte {env_var} ou crée {file_path}")

# --------- Dérivations ----------
def current_window(ts=None):
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, client_ip: str, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"{client_ip}|{win}".encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2], "big")
        p   = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

def derive_spa_key(secret: bytes, ip: str, win: int) -> bytes:
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# --------- Réseau ----------
def send_syn(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except OSError: pass
    finally: s.close()

def guess_source_ip(server_ip: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server_ip, 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1" if server_ip in ("127.0.0.1","localhost") else socket.gethostbyname(socket.gethostname())
    finally:
        try: s.close()
        except: pass
    return ip

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

def build_spa_packet(secret: bytes, server_ip: str, client_ip: str, user: str, duration: int):
    payload = {"req":"open","port":SSH_PORT,"ts":int(time.time()),
               "nonce":secrets.token_hex(12),"user":user,"duration":int(duration)}
    raw = json.dumps(payload, separators=(",",":")).encode()
    w   = current_window()
    key = derive_spa_key(secret, client_ip, w)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv  = os.urandom(12)
    ct  = AESGCM(key).encrypt(iv, raw, None)
    return b"\x01" + iv + ct

def send_spa_packet(pkt: bytes, server_ip: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (server_ip, SPA_PORT)); s.close()

# --------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="POC2 Client — Séquence HMAC + SPA AES-GCM")
    ap.add_argument("server", nargs="?", default=SSH_LISTEN, help="IP/nom du serveur (défaut: 127.0.0.1)")
    ap.add_argument("--duration", type=int, default=0, help="Durée d'ouverture demandée (0 = illimitée)")
    ap.add_argument("--secret-file", default=DEFAULT_SECRET_FILE, help=f"Chemin du secret (défaut: {DEFAULT_SECRET_FILE})")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer SSH après SPA")
    ap.add_argument("--dump-spa", metavar="spa.bin", help="Sauver le paquet SPA pour tests")
    args = ap.parse_args()

    secret = load_secret(file_path=args.secret_file)

    server = args.server
    server_ip = "127.0.0.1" if server in ("127.0.0.1","localhost") else socket.gethostbyname(server)
    client_ip = "127.0.0.1" if server_ip=="127.0.0.1" else guess_source_ip(server_ip)

    w   = current_window()
    seq = derive_sequence(secret, client_ip, w)
    print(f"[i] Cible: {server_ip} | IP vue: {client_ip} | Fenêtre: {w} ({WINDOW_SECONDS}s) | "
          f"Séquence: {' -> '.join(map(str, seq))} | Délai: {STEP_DELAY}s")

    for p in seq:
        print(f"[*] Knock sur le port {p}")
        send_syn(server_ip, p); time.sleep(STEP_DELAY)

    print("[*] Envoi du SPA chiffré…")
    user = getpass.getuser()
    pkt  = build_spa_packet(secret, server_ip, client_ip, user, args.duration)
    if args.dump_spa:
        with open(args.dump_spa,"wb") as f: f.write(pkt)
        print(f"[i] SPA sauvegardé dans {args.dump_spa} (hex {binascii.hexlify(pkt)[:32].decode()}…)")

    send_spa_packet(pkt, server_ip)

    if args.no_ssh: return
    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] Clé SSH locale: {e}")
    print("[✓] SPA envoyé. Connexion SSH automatique…")
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{server_ip}"])

if __name__ == "__main__":
    main()
