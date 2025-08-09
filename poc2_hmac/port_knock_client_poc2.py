#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC 2 — Client
- Envoie la séquence de knocks DYNAMIQUES (HMAC)
- Envoie ensuite un SPA AES-GCM (timestamp + nonce) → ouverture 2222
- Peut se connecter automatiquement en SSH
"""

import os, sys, time, json, hmac, base64, hashlib, socket, argparse, getpass, subprocess, binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ========== Paramètres (doivent matcher le serveur) ==========
DEMO_SECRET_B64 = "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY="
SSH_PORT        = 2222
SSH_LISTEN      = "127.0.0.1"
WINDOW_SECONDS  = 30
SEQUENCE_LEN    = 3
MIN_PORT, MAX_PORT = 40000, 50000
STEP_DELAY      = 0.5
SPA_PORT        = 45444

def derive_secret():
    b64 = os.environ.get("KNOCK_SECRET", DEMO_SECRET_B64)
    try:
        sec = base64.b64decode(b64, validate=True)
        if len(sec) < 16: raise ValueError("secret trop court")
        return sec
    except Exception as e:
        print("[ERREUR] Secret invalide (base64).", e); sys.exit(1)
SECRET = derive_secret()

def current_window(ts=None): return int((ts if ts is not None else time.time()) // WINDOW_SECONDS)

def derive_sequence(secret: bytes, client_ip: str, epoch_window: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"{client_ip}|{epoch_window}".encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2], "big")
        port = MIN_PORT + (val % rng)
        if port not in ports: ports.append(port)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        port = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if port not in ports: ports.append(port)
    return ports

def get_src_ip_towards(host: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9))  # port arbitraire; pas d’envoi réel
        return s.getsockname()[0]
    finally:
        s.close()

def send_syn(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))     # émet un SYN ; l’échec est normal
    except OSError: pass
    finally: s.close()

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

def derive_spa_key(secret: bytes, ip: str, window: int) -> bytes:
    return hmac.new(secret, f"spa|{ip}|{window}".encode(), hashlib.sha256).digest()

def build_spa_packet(server_ip: str, client_ip: str, user: str, duration: int):
    payload = {"req":"open","port":SSH_PORT,"ts":int(time.time()),"nonce":os.urandom(12).hex(),"user":user,"duration":duration}
    raw = json.dumps(payload, separators=(",",":")).encode()
    w   = current_window()
    key = derive_spa_key(SECRET, client_ip, w)
    iv  = os.urandom(12)
    ct  = AESGCM(key).encrypt(iv, raw, None)
    return b"\x01" + iv + ct

def send_spa_packet(pkt: bytes, server_ip: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (server_ip, SPA_PORT)); s.close()

def main():
    ap = argparse.ArgumentParser(description="POC2 Client - Knocks HMAC + SPA AES-GCM")
    ap.add_argument("server", nargs="?", default=SSH_LISTEN, help="IP/nom du serveur (défaut: %(default)s)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer SSH après SPA")
    ap.add_argument("--duration", type=int, default=0, help="Durée d'ouverture demandée (0 = illimitée)")
    ap.add_argument("--window-offset", type=int, default=0, help="Tester fenêtre courante (0) ou N-1 (-1)")
    ap.add_argument("--dump-spa", metavar="spa.bin", help="Sauver le paquet SPA pour replay")
    args = ap.parse_args()

    server = args.server
    client_ip = get_src_ip_towards(server)

    w   = current_window() + args.window_offset
    seq = derive_sequence(SECRET, client_ip, w)
    print(f"[i] Cible: {server} | IP vue: {client_ip} | Fenêtre: {w} ({WINDOW_SECONDS}s) | Séquence: {' -> '.join(map(str, seq))} | Délai: {STEP_DELAY}s")

    for p in seq:
        print(f"[*] Knock sur le port {p}")
        send_syn(server, p); time.sleep(STEP_DELAY)

    print("[*] Envoi du SPA chiffré…")
    user = getpass.getuser()
    pkt  = build_spa_packet(server, client_ip, user, args.duration)
    if args.dump_spa:
        with open(args.dump_spa,"wb") as f: f.write(pkt)
        print(f"[i] SPA sauvegardé dans {args.dump_spa} (hex {binascii.hexlify(pkt)[:32].decode()}…)")

    send_spa_packet(pkt, server)

    if args.no_ssh: return
    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] Clé SSH locale: {e}")
    print("[✓] SPA envoyé. Connexion SSH automatique…")
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{server}"])

if __name__ == "__main__":
    main()
