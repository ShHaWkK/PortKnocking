#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC2 - Client : envoie la séquence dynamique (HMAC, fenêtre 30 s) puis un SPA AES-GCM
- Récupère le secret automatiquement (env, ~/.config/portknock/secret, /etc/portknock/secret si local),
  sinon te demande de le coller (et l’enregistre pour la prochaine fois).
- Génère/installe une clé SSH ed25519 et ouvre la session SSH automatiquement après SPA.
Lance: python3 port_knock_client_poc2.py 127.0.0.1
"""
import os, sys, time, json, hmac, base64, hashlib, socket, argparse, getpass, subprocess, binascii
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SSH_PORT        = int(os.environ.get("KNOCK_SSH_PORT", "2222"))
WINDOW_SECONDS  = 30
SEQUENCE_LEN    = 3
MIN_PORT, MAX_PORT = 40000, 50000
STEP_DELAY      = 0.5
SPA_PORT        = 45444
REALM           = os.environ.get("KNOCK_REALM", "default")
ROTATION_MODE   = os.environ.get("KNOCK_ROTATION", "daily")
SECRET_FILE_FALLBACK = os.path.expanduser("~/.config/portknock/secret")

def read_secret(server: str) -> bytes:
    # 1) env direct
    env_b64 = os.environ.get("KNOCK_SECRET")
    if env_b64:
        return base64.b64decode(env_b64, validate=True)
    # 2) env fichier
    env_file = os.environ.get("KNOCK_SECRET_FILE")
    if env_file and os.path.exists(env_file):
        return base64.b64decode(open(env_file).read().strip(), validate=True)
    # 3) ~/.config/portknock/secret
    if os.path.exists(SECRET_FILE_FALLBACK):
        return base64.b64decode(open(SECRET_FILE_FALLBACK).read().strip(), validate=True)
    # 4) local: /etc/portknock/secret si accessible
    if server in ("127.0.0.1","localhost") and os.path.exists("/etc/portknock/secret"):
        try:
            sec = base64.b64decode(open("/etc/portknock/secret").read().strip(), validate=True)
            os.makedirs(os.path.dirname(SECRET_FILE_FALLBACK), exist_ok=True)
            open(SECRET_FILE_FALLBACK,"w").write(base64.b64encode(sec).decode()+"\n"); os.chmod(SECRET_FILE_FALLBACK, 0o600)
            return sec
        except Exception: pass
    # 5) dernier recours: on demande et on enregistre
    print("[?] Secret (base64) introuvable. Colle-le (il sera stocké dans ~/.config/portknock/secret) :")
    b64 = sys.stdin.readline().strip()
    sec = base64.b64decode(b64, validate=True)
    os.makedirs(os.path.dirname(SECRET_FILE_FALLBACK), exist_ok=True)
    open(SECRET_FILE_FALLBACK,"w").write(b64+"\n"); os.chmod(SECRET_FILE_FALLBACK, 0o600)
    return sec

def rotate_secret(master: bytes) -> bytes:
    stamp = datetime.utcnow().strftime("%Y-%m-%d:%H" if ROTATION_MODE=="hourly" else "%Y-%m-%d")
    return hmac.new(master, f"{REALM}|{stamp}".encode(), hashlib.sha256).digest()

def current_window(ts=None):
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def guess_client_ip(server_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((server_ip, 9))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def derive_sequence(sec_rot: bytes, client_ip: str, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(sec_rot, f"{client_ip}|{win}".encode(), hashlib.sha256).digest()
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

def send_syn(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except OSError: pass
    finally: s.close()

def ensure_local_ssh_key():
    home = os.path.expanduser("~"); sshd = os.path.join(home, ".ssh")
    priv = os.path.join(sshd, "id_ed25519"); pub = priv + ".pub"; auth = os.path.join(sshd, "authorized_keys")
    os.makedirs(sshd, exist_ok=True)
    if not os.path.exists(priv):
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",priv], check=True)
    if not os.path.exists(pub):
        out = subprocess.check_output(["ssh-keygen","-y","-f",priv], text=True).strip()
        open(pub,"w").write(out+"\n")
    key = open(pub).read().strip()
    if not os.path.exists(auth) or key not in open(auth).read():
        with open(auth,"a") as f: f.write(key+"\n")
        os.chmod(auth, 0o600)

def derive_spa_key(sec_rot: bytes, ip: str, win: int) -> bytes:
    return hmac.new(sec_rot, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

def build_spa_packet(sec_rot: bytes, client_ip: str, duration: int):
    payload = {"req":"open","port":SSH_PORT,"ts":int(time.time()),"nonce":os.urandom(12).hex(),"user":getpass.getuser(),"duration":duration}
    raw = json.dumps(payload, separators=(",",":")).encode()
    w   = current_window()
    key = derive_spa_key(sec_rot, client_ip, w)
    iv  = os.urandom(12)
    ct  = AESGCM(key).encrypt(iv, raw, None)
    return b"\x01" + iv + ct

def send_spa(server: str, pkt: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (server, SPA_PORT)); s.close()

def main():
    ap = argparse.ArgumentParser(description="POC2 Client - Knocks dynamiques + SPA AES-GCM")
    ap.add_argument("server", help="IP/nom du serveur (ex: 127.0.0.1)")
    ap.add_argument("--duration", type=int, default=0, help="Durée d'ouverture demandée (0 = illimitée)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer SSH automatiquement")
    ap.add_argument("--dump-spa", metavar="spa.bin", help="Sauver le paquet SPA pour tests/replay")
    args = ap.parse_args()

    server = args.server
    master = read_secret(server)
    sec_rot = rotate_secret(master)

    client_ip = "127.0.0.1" if server in ("127.0.0.1","localhost") else guess_client_ip(server)
    w = current_window()
    seq = derive_sequence(sec_rot, client_ip, w)
    print(f"[i] Cible: {server} | IP vue: {client_ip} | Fenêtre: {w} ({WINDOW_SECONDS}s) | Séquence: {' -> '.join(map(str,seq))} | Délai: {STEP_DELAY}s")

    for p in seq:
        print(f"[*] Knock sur le port {p}")
        send_syn(server, p); time.sleep(STEP_DELAY)

    print("[*] Envoi du SPA chiffré…")
    pkt = build_spa_packet(sec_rot, client_ip, args.duration)
    if args.dump_spa:
        with open(args.dump_spa,"wb") as f: f.write(pkt)
        print(f"[i] SPA écrit dans {args.dump_spa} (extrait hex {binascii.hexlify(pkt)[:32].decode()}…)")

    send_spa(server, pkt)

    if args.no_ssh: return
    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] Clé SSH locale: {e}")
    user = getpass.getuser()
    print("[✓] SPA envoyé. Connexion SSH automatique…")
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{server}"])

if __name__ == "__main__":
    main()
