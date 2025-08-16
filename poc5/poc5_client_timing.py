#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# POC5 - Client (timing SYN -> SPA binaire AES-GCM)
# Usage: sudo python3 poc5_client_timing.py 127.0.0.1
import os, sys, time, hmac, hashlib, base64, random, socket, subprocess, shutil, argparse, getpass, traceback, struct
from typing import List
from scapy.all import IP, TCP, send  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items())
    print(f"[{tag}]{(' '+s) if s else ''}", flush=True)

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
        LOG("BOOT", step="install_scapy"); _pip("scapy") or _apt("python3-scapy")
    try: from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        LOG("BOOT", step="install_crypto"); _pip("cryptography") or _apt("python3-cryptography")
def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance ce client avec sudo.", file=sys.stderr); sys.exit(1)

LURE_PORT, SSH_PORT = 443, 2222
PREAMBULE = [1,0,1,0,1,0,1,0]
SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")
LOCAL_SECRET = "/etc/portknock/secret"

def b64_read(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def ensure_secret_for(server: str) -> bytes:
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    if os.path.exists(SECRET_FILE):
        LOG("SECRET", source="~/.config/portknock/secret (cached)"); return b64_read(open(SECRET_FILE).read())
    if server in ("127.0.0.1","localhost"):
        if not os.path.exists(LOCAL_SECRET):
            print("[ERREUR] /etc/portknock/secret introuvable en local (serveur lancé ?)", file=sys.stderr); sys.exit(1)
        raw = open(LOCAL_SECRET).read()
        with open(SECRET_FILE,"w") as f: f.write(raw.strip().split()[0]+"\n")
        os.chmod(SECRET_FILE, 0o600)
        LOG("SECRET", source=LOCAL_SECRET, copied_to=SECRET_FILE)
        return b64_read(raw)
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    LOG("SECRET", action="fetch_via_ssh", user=user, host=server)
    r = subprocess.run(["ssh", f"{user}@{server}", "sudo cat /etc/portknock/secret"], text=True, capture_output=True)
    if r.returncode != 0 or not r.stdout.strip():
        print("[ERREUR] Impossible de récupérer le secret via ssh.", file=sys.stderr); sys.exit(1)
    with open(SECRET_FILE,"w") as f: f.write(r.stdout.strip().split()[0]+"\n")
    os.chmod(SECRET_FILE, 0o600)
    return b64_read(r.stdout)

def derive_keys(master: bytes):
    return hashlib.sha256(master + b"|AES").digest(), hashlib.sha256(master + b"|HMAC").digest()

# --------- NOUVEAU: SPA binaire (version 1)
def build_spa_wire(aes_key: bytes, hmac_key: bytes, duration: int) -> bytes:
    t = int(time.time())
    d = int(duration) & 0xFFFF
    header = struct.pack("!IH", t, d)                 # t(4) | d(2)
    sig    = hmac.new(hmac_key, header, hashlib.sha256).digest()[:16]  # 16 bytes
    pt     = header + sig                             # 22 bytes
    nonce  = os.urandom(12)
    ctag   = AESGCM(aes_key).encrypt(nonce, pt, None) # ciphertext+tag
    wire   = b"\x01" + nonce + struct.pack("!H", len(ctag)) + ctag     # v(1) | nonce(12) | len(2) | ctag
    return wire

def bytes_to_bits(b: bytes) -> List[int]:
    return [int(bit) for byte in b for bit in f"{byte:08b}"]

def build_frame_bits(msg_bytes: bytes) -> List[int]:
    L = len(msg_bytes)
    len_bits = [int(bit) for bit in f"{L:016b}"]
    return PREAMBULE + len_bits + bytes_to_bits(msg_bytes)

def send_timing(bits: List[int], dst_ip: str, d0: float, d1: float, iface: str | None):
    sport = random.randint(1024, 65000)
    seq0  = random.randint(0, 2**32-1)
    total = len(bits)
    step  = max(1, total // 20)
    for i, b in enumerate(bits, 1):
        pkt = IP(dst=dst_ip)/TCP(dport=LURE_PORT, sport=sport, flags="S", seq=seq0+i)
        send(pkt, verbose=0, iface=iface)
        if i % step == 0 or i == total:
            LOG("SEND", progress=f"{i}/{total}")
        time.sleep(d1 if b else d0)
    LOG("OK", sent=total)

def main():
    must_root(); ensure_pydeps()
    ap = argparse.ArgumentParser(description="POC5 client (usage: sudo python3 poc5_client_timing.py 127.0.0.1)")
    ap.add_argument("server", help="IP/DNS du serveur")
    ap.add_argument("--duration", type=int, default=60, help="TTL d'ouverture (s)")
    ap.add_argument("--d0", type=float, default=0.02, help="intervalle bit 0 (s)")
    ap.add_argument("--d1", type=float, default=0.06, help="intervalle bit 1 (s)")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--no-ssh", action="store_true")
    args = ap.parse_args()

    try:
        dst_ip = socket.gethostbyname(args.server)
    except Exception:
        print("[ERREUR] Résolution serveur impossible.", file=sys.stderr); sys.exit(1)

    master  = ensure_secret_for(args.server)
    aes_key, hmac_key = derive_keys(master)

    wire  = build_spa_wire(aes_key, hmac_key, args.duration)
    frame = build_frame_bits(wire)

    LOG("INFO", target=dst_ip, bytes=len(wire), bits=len(frame), d0=args.d0, d1=args.d1)
    send_timing(frame, dst_ip, args.d0, args.d1, iface=args.iface)

    if not args.no_ssh:
        time.sleep(1.0)
        os.execvp("ssh", ["ssh","-p","2222","-o","StrictHostKeyChecking=accept-new",f"{getpass.getuser()}@{args.server}"])

if __name__ == "__main__":
    try: main()
    except Exception: LOG("FATAL", trace=traceback.format_exc()); sys.exit(1)
