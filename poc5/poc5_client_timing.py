#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Client timing+SPA (profil rapide par défaut)
Usage voulu :  sudo python3 poc5_client_timing.py 127.0.0.1
- lit automatiquement le secret (~/.config/portknock/secret), ou le copie depuis /etc/portknock/secret si cible=localhost
- encode un SPA binaire court (51 octets) : PREAMBULE(8) + WIRE(51) => 416 paquets
- timings rapides d0=0.005 / d1=0.015 (≈ 4–6 s en local) | --profile safe pour 0.02/0.06
- auto-SSH vers :2222 (désactive avec --no-ssh)
Compatible serveur ci-dessus (et serveur accepte aussi l’ancien format 448 bits si jamais).
"""
import os, sys, time, hmac, hashlib, base64, random, socket, subprocess, shutil, argparse, getpass, traceback, struct
from typing import List
from scapy.all import IP, TCP, send  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items()); print(f"[{tag}]{(' '+s) if s else ''}", flush=True)

LURE_PORT, SSH_PORT = 443, 2222
PREAMBULE = [1,0,1,0,1,0,1,0]
SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")
LOCAL_SECRET = "/etc/portknock/secret"

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance ce client avec sudo.", file=sys.stderr); sys.exit(1)

def b64_read(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def ensure_secret_for(server: str) -> bytes:
    # 1) déjà en cache (~/.config/portknock/secret)
    if os.path.exists(SECRET_FILE):
        LOG("SECRET", source="~/.config/portknock/secret (cached)")
        return b64_read(open(SECRET_FILE).read())
    # 2) localhost → lit /etc/portknock/secret et le copie
    if server in ("127.0.0.1", "localhost"):
        if not os.path.exists(LOCAL_SECRET):
            print("[ERREUR] /etc/portknock/secret introuvable (lance le serveur?)", file=sys.stderr); sys.exit(1)
        raw = open(LOCAL_SECRET).read()
        os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
        open(SECRET_FILE,"w").write(raw.strip().split()[0]+"\n")
        os.chmod(SECRET_FILE, 0o600)
        LOG("SECRET", source=LOCAL_SECRET, copied_to=SECRET_FILE)
        return b64_read(raw)
    # 3) distant → récupère via SSH (utilisateur SUDO_USER si présent)
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    LOG("SECRET", action="fetch_via_ssh", user=user, host=server)
    r = subprocess.run(["ssh", f"{user}@{server}", "sudo cat /etc/portknock/secret"], text=True, capture_output=True)
    if r.returncode != 0 or not r.stdout.strip():
        print("[ERREUR] Impossible de récupérer le secret via ssh.", file=sys.stderr); sys.exit(1)
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    open(SECRET_FILE,"w").write(r.stdout.strip().split()[0]+"\n")
    os.chmod(SECRET_FILE, 0o600)
    return b64_read(r.stdout)

def derive_keys(master: bytes):
    return hashlib.sha256(master + b"|AES").digest(), hashlib.sha256(master + b"|HMAC").digest()

# -------- wire v=1 (51 bytes) : 0x01 | nonce(12) | ctag(22+16)
# PT = t(4) | d(2) | hmac16( HMAC-SHA256( t||d ) )
def build_spa_wire(aes: bytes, mac: bytes, duration: int) -> bytes:
    t = int(time.time()); d = int(duration) & 0xFFFF
    head = struct.pack("!IH", t, d)
    sig  = hmac.new(mac, head, hashlib.sha256).digest()[:16]
    pt   = head + sig                          # 22 bytes
    nonce = os.urandom(12)
    ctag  = AESGCM(aes).encrypt(nonce, pt, None)  # 22 + 16
    return b"\x01" + nonce + ctag

def bytes_to_bits(b: bytes) -> List[int]:
    return [int(bit) for byte in b for bit in f"{byte:08b}"]

def build_frame_bits(msg_bytes: bytes) -> List[int]:
    # format "fast" : PREAMBULE (8) + WIRE (51*8)
    return PREAMBULE + bytes_to_bits(msg_bytes)

def send_timing(bits: List[int], dst_ip: str, d0: float, d1: float, iface: str | None):
    sport = random.randint(1024, 65000); seq0 = random.randint(0, 2**32-1)
    total = len(bits); step = max(1, total//20)
    for i, b in enumerate(bits, 1):
        send(IP(dst=dst_ip)/TCP(dport=LURE_PORT, sport=sport, flags="S", seq=seq0+i), verbose=0, iface=iface)
        if i % step == 0 or i == total: LOG("SEND", progress=f"{i}/{total}")
        time.sleep(d1 if b else d0)
    LOG("OK", sent=total)

def main():
    must_root()
    ap = argparse.ArgumentParser(description="POC5 client timing (rapide par défaut)")
    ap.add_argument("server", help="IP/DNS du serveur (ex: 127.0.0.1)")
    ap.add_argument("--duration", type=int, default=60, help="TTL d'ouverture (s)")
    ap.add_argument("--profile", choices=["fast","safe"], default="fast", help="Timings prédéfinis")
    ap.add_argument("--d0", type=float, default=None, help="Override intervalle bit 0")
    ap.add_argument("--d1", type=float, default=None, help="Override intervalle bit 1")
    ap.add_argument("--iface", default=None, help="Interface d'émission (optionnel)")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer ssh après knock")
    args = ap.parse_args()

    # profils
    if args.d0 is None or args.d1 is None:
        if args.profile == "fast":
            d0, d1 = 0.005, 0.015
        else:
            d0, d1 = 0.02, 0.06
    else:
        d0, d1 = args.d0, args.d1

    try: dst_ip = socket.gethostbyname(args.server)
    except Exception: print("[ERREUR] Résolution serveur impossible.", file=sys.stderr); sys.exit(1)

    master  = ensure_secret_for(args.server)
    aes_key, hmac_key = derive_keys(master)

    wire  = build_spa_wire(aes_key, hmac_key, args.duration)      # 51 bytes
    frame = build_frame_bits(wire)                                 # 416 bits

    LOG("INFO", target=dst_ip, bytes=len(wire), bits=len(frame), d0=d0, d1=d1, profile=args.profile)
    send_timing(frame, dst_ip, d0, d1, iface=args.iface)

    if not args.no_ssh:
        ssh_user = os.environ.get("SUDO_USER") or getpass.getuser()
        time.sleep(0.8)
        os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new", f"{ssh_user}@{args.server}"])

if __name__ == "__main__":
    try: main()
    except Exception:
        LOG("FATAL", trace=traceback.format_exc()); sys.exit(1)
