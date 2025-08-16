#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 - Client (timing SYN -> SPA AES-GCM)
- Récupère automatiquement le secret via SSH si absent (~/.config/portknock/secret)
Usage simple : sudo python3 poc5_client_timing.py --host <IP/DNS> --auto-ssh
"""
import os, sys, time, json, hmac, hashlib, base64, random, socket, subprocess, shutil, argparse, getpass, traceback
from typing import List
from scapy.all import IP, TCP, send  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items())
    print(f"[{tag}]{(' '+s) if s else ''}", flush=True)

# ---- deps (au cas où)
def _pip(*pkgs):
    try: subprocess.run([sys.executable, "-m", "pip", "install", "-q", *pkgs], check=True); return True
    except Exception: return False
def _apt(*pkgs):
    if not shutil.which("apt"): return False
    try:
        subprocess.run(["sudo","apt","update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","apt","install","-y",*pkgs], check=False); return True
    except Exception: return False
def ensure_pydeps():
    try: import scapy.all  # noqa
    except Exception:
        LOG("BOOT", step="install_scapy")
        _pip("scapy") or _apt("python3-scapy")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        LOG("BOOT", step="install_crypto")
        _pip("cryptography") or _apt("python3-cryptography")

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance ce client avec sudo.", file=sys.stderr); sys.exit(1)

# ---- config
LURE_PORT      = 443
SSH_PORT       = 2222
PREAMBULE      = [1,0,1,0,1,0,1,0]
SECRET_FILE    = os.path.expanduser("~/.config/portknock/secret")

# ---- secret auto
def b64_read(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def ensure_local_secret(host: str, user: str, ssh_port: int) -> bytes:
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    if os.path.exists(SECRET_FILE):
        return b64_read(open(SECRET_FILE).read())
    LOG("SECRET", action="fetch_from_server")
    # demande ton mot de passe si nécessaire
    r = subprocess.run(["ssh","-p",str(ssh_port), f"{user}@{host}", "sudo cat /etc/portknock/secret"],
                       text=True, capture_output=True)
    if r.returncode != 0 or not r.stdout.strip():
        print("[ERREUR] Impossible de récupérer le secret via ssh.", file=sys.stderr); sys.exit(1)
    with open(SECRET_FILE,"w") as f: f.write(r.stdout.strip().split()[0]+"\n")
    os.chmod(SECRET_FILE, 0o600)
    return b64_read(open(SECRET_FILE).read())

# ---- crypto + trame
def derive_keys(master: bytes):
    return hashlib.sha256(master + b"|AES").digest(), hashlib.sha256(master + b"|HMAC").digest()

def canonical_hmac(key: bytes, duration: int, ts: int) -> str:
    payload = {"duration": int(duration), "timestamp": int(ts)}
    canon = json.dumps(payload, separators=(",",":"), sort_keys=True).encode()
    return hmac.new(key, canon, hashlib.sha256).hexdigest()

def build_spa_bytes(aes_key: bytes, hmac_key: bytes, duration: int) -> bytes:
    ts = int(time.time())
    spa_plain = {"timestamp": ts, "duration": int(duration)}
    spa_plain["hmac"] = canonical_hmac(hmac_key, spa_plain["duration"], spa_plain["timestamp"])
    pt = json.dumps(spa_plain, separators=(",",":"), sort_keys=True).encode()
    nonce = os.urandom(12)
    ct    = AESGCM(aes_key).encrypt(nonce, pt, None)
    tag   = ct[-16:]; body = ct[:-16]
    env   = {"ciphertext": body.hex(), "nonce": nonce.hex(), "tag": tag.hex()}
    return json.dumps(env, separators=(",",":"), sort_keys=True).encode()

def bytes_to_bits(b: bytes) -> List[int]:
    return [int(bit) for byte in b for bit in f"{byte:08b}"]

def build_frame_bits(msg_bytes: bytes) -> List[int]:
    L = len(msg_bytes)
    len_bits = [int(bit) for bit in f"{L:016b}"]
    return PREAMBULE + len_bits + bytes_to_bits(msg_bytes)

def send_timing(bits: List[int], dst_ip: str, d0: float, d1: float, iface: str = None):
    sport = random.randint(1024, 65000)
    seq0  = random.randint(0, 2**32-1)
    for i, b in enumerate(bits):
        pkt = IP(dst=dst_ip)/TCP(dport=LURE_PORT, sport=sport, flags="S", seq=seq0+i)
        send(pkt, verbose=0, iface=iface)
        time.sleep(d1 if b else d0)
    LOG("OK", sent=len(bits))

def main():
    must_root()
    ensure_pydeps()

    ap = argparse.ArgumentParser(description="POC5 client")
    ap.add_argument("--host", required=True, help="IP/DNS du serveur")
    ap.add_argument("--user", default=getpass.getuser(), help="Utilisateur SSH pour récupérer le secret")
    ap.add_argument("--ssh-port", type=int, default=22, help="Port SSH vers le serveur (défaut 22)")
    ap.add_argument("--duration", type=int, default=60, help="TTL d'ouverture (s)")
    ap.add_argument("--d0", type=float, default=0.08, help="intervalle bit 0 (s)")
    ap.add_argument("--d1", type=float, default=0.24, help="intervalle bit 1 (s)")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--auto-ssh", action="store_true")
    args = ap.parse_args()

    try:
        dst_ip = socket.gethostbyname(args.host)
    except Exception:
        print("[ERREUR] Résolution serveur impossible.", file=sys.stderr); sys.exit(1)

    master  = ensure_local_secret(args.host, args.user, args.ssh_port)
    aes_key, hmac_key = derive_keys(master)
    spa   = build_spa_bytes(aes_key, hmac_key, args.duration)
    frame = build_frame_bits(spa)

    LOG("INFO", target=dst_ip, bits=len(frame), d0=args.d0, d1=args.d1)
    send_timing(frame, dst_ip, args.d0, args.d1, iface=args.iface)

    if args.auto-ssh:
        time.sleep(1.5)
        os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new",f"{getpass.getuser()}@{args.host}"])

if __name__ == "__main__":
    try:
        main()
    except Exception:
        LOG("FATAL", trace=traceback.format_exc()); sys.exit(1)
