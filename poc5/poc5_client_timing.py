#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 (client) — en 1 commande :
  sudo python3 poc5_client_timing_spa.py --host 203.0.113.10
(le script récupère le secret tout seul via SSH si besoin, envoie la trame, et ouvre SSH automatiquement)
"""

import os, sys, time, json, hmac, hashlib, base64, random, socket, subprocess, shutil, getpass, argparse
from typing import List
from scapy.all import IP, TCP, send  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

LURE_PORT       = 443
SSH_PORT        = 2222
PREAMBULE_BITS  = [1,0,1,0,1,0,1,0]
SECRET_FILE     = os.path.expanduser("~/.config/portknock/secret")  # base64

# --- deps ---
def _pip_install(pkg: str) -> bool:
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg], check=True); return True
    except Exception: return False

def _apt_install(*pkgs: str) -> bool:
    if not shutil.which("apt"): return False
    try:
        subprocess.run(["sudo","apt","update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","apt","install","-y",*pkgs], check=False); return True
    except Exception: return False

def ensure_pydeps():
    ok = True
    try: import scapy  # noqa
    except Exception:
        print("[i] Installation scapy…")
        ok = _pip_install("scapy") or _apt_install("python3-scapy") or ok
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        print("[i] Installation cryptography…")
        ok = _pip_install("cryptography") or _apt_install("python3-cryptography") or ok
    return ok

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance ce client avec sudo.", file=sys.stderr); sys.exit(1)

# --- secret auto ---
def b64_read_tolerant(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def ensure_local_secret(host: str, user: str, ssh_port: int) -> bytes:
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    if os.path.exists(SECRET_FILE):
        return b64_read_tolerant(open(SECRET_FILE).read())
    print("[i] Secret local absent → récupération automatique depuis le serveur…")
    # utilise ssh du système (demande ton mot de passe si nécessaire)
    cmd = ["ssh","-p",str(ssh_port), f"{user}@{host}", "sudo cat /etc/portknock/secret"]
    r = subprocess.run(cmd, text=True)
    if r.returncode != 0:
        print("[ERREUR] Impossible de récupérer le secret via ssh.", file=sys.stderr); sys.exit(1)
    with open(SECRET_FILE,"w") as f: f.write(r.stdout.strip().split()[0]+"\n")
    os.chmod(SECRET_FILE, 0o600)
    return b64_read_tolerant(open(SECRET_FILE).read())

# --- crypto + frame ---
def derive_keys(master: bytes):
    aes_key  = hashlib.sha256(master + b"|AES").digest()
    hmac_key = hashlib.sha256(master + b"|HMAC").digest()
    return aes_key, hmac_key

def canonical_hmac(hmac_key: bytes, duration: int, ts: int) -> str:
    payload = {"duration": int(duration), "timestamp": int(ts)}
    canon = json.dumps(payload, separators=(",",":"), sort_keys=True).encode()
    return hmac.new(hmac_key, canon, hashlib.sha256).hexdigest()

def build_spa_bytes(aes_key: bytes, hmac_key: bytes, duration: int) -> bytes:
    ts = int(time.time())
    spa_plain = {"timestamp": ts, "duration": int(duration)}
    spa_plain["hmac"] = canonical_hmac(hmac_key, spa_plain["duration"], spa_plain["timestamp"])
    pt = json.dumps(spa_plain, separators=(",",":"), sort_keys=True).encode()
    nonce = os.urandom(12)
    ct    = AESGCM(aes_key).encrypt(nonce, pt, None)
    tag   = ct[-16:]; body = ct[:-16]
    env = {"ciphertext": body.hex(), "nonce": nonce.hex(), "tag": tag.hex()}
    return json.dumps(env, separators=(",",":"), sort_keys=True).encode()

def bytes_to_bits(b: bytes) -> List[int]:
    return [int(bit) for byte in b for bit in f"{byte:08b}"]

def build_frame_bits(msg_bytes: bytes) -> List[int]:
    L = len(msg_bytes)
    len_bits = [int(bit) for bit in f"{L:016b}"]
    return PREAMBULE_BITS + len_bits + bytes_to_bits(msg_bytes)

def send_timing(bits: List[int], dst_ip: str, d0: float, d1: float, iface: str = None):
    sport = random.randint(1024, 65000)
    seq0  = random.randint(0, 2**32-1)
    for i, b in enumerate(bits):
        pkt = IP(dst=dst_ip)/TCP(dport=LURE_PORT, sport=sport, flags="S", seq=seq0+i)
        send(pkt, verbose=0, iface=iface)
        time.sleep(d1 if b else d0)
    print(f"[+] Trame envoyée ({len(bits)} paquets).")

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

def main():
    must_root()
    ensure_pydeps()

    ap = argparse.ArgumentParser(description="POC5 Client — timing+SPA auto")
    ap.add_argument("--host", help="IP/nom du serveur (si absent, on te le demande)")
    ap.add_argument("--user", default=getpass.getuser(), help="Utilisateur SSH pour récupérer le secret (défaut: ton user)")
    ap.add_argument("--ssh-port", type=int, default=22, help="Port SSH vers le serveur (défaut 22)")
    ap.add_argument("--duration", type=int, default=60, help="TTL d'ouverture (s)")
    ap.add_argument("--d0", type=float, default=0.08, help="Intervalle pour bit 0 (s)")
    ap.add_argument("--d1", type=float, default=0.24, help="Intervalle pour bit 1 (s)")
    ap.add_argument("--iface", default=None, help="Interface scapy (optionnel)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer ssh automatiquement")
    args = ap.parse_args()

    host = args.host or input("Adresse IP/nom du serveur : ").strip()
    try:
        dst_ip = socket.gethostbyname(host)
    except Exception:
        print("[ERREUR] Résolution serveur impossible.", file=sys.stderr); sys.exit(1)

    # secret auto (via ssh si absent)
    master = ensure_local_secret(host, args.user, args.ssh_port)
    aes_key, hmac_key = derive_keys(master)

    spa_bytes = build_spa_bytes(aes_key, hmac_key, args.duration)
    frame     = build_frame_bits(spa_bytes)

    print(f"[i] Cible={dst_ip} | d0={args.d0}s d1={args.d1}s | len={len(spa_bytes)}o → {len(frame)} bits")
    send_timing(frame, dst_ip, d0=args.d0, d1=args.d1, iface=args.iface)

    if args.no-ssh:  # l’utilisateur ne veut pas auto-ssh
        print("[✓] Terminé."); return

    # auto SSH
    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] Clé SSH locale: {e}")
    user = getpass.getuser()
    time.sleep(1.5)
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{user}@{host}"])

if __name__ == "__main__":
    main()
