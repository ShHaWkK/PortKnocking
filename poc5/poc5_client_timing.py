#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 - Client (corrigé)
- Auto-installe scapy/cryptography si absents (pip ou apt)
- Encode un SPA AES-GCM (duration + timestamp + HMAC) dans une trame temporelle de SYN vers 443
Usage:
  sudo python3 poc5_client_timing.py <IP_SERVEUR> [--duration 60] [--d0 0.08 --d1 0.24]
"""
import os, sys, time, json, hmac, hashlib, base64, random, socket, subprocess, shutil, argparse

# ---------- bootstrap dépendances ----------
def _pip_install(*pkgs):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", *pkgs], check=True)
        return True
    except Exception:
        return False

def _apt_install(*pkgs):
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
        import scapy.all  # noqa
    except Exception:
        print("[i] Installation de scapy…")
        ok = _pip_install("scapy") or _apt_install("python3-scapy") or ok
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        print("[i] Installation de cryptography…")
        ok = _pip_install("cryptography") or _apt_install("python3-cryptography") or ok
    return ok

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance ce client avec sudo.", file=sys.stderr); sys.exit(1)

must_root()
ensure_pydeps()

# (import APRÈS bootstrap)
from scapy.all import IP, TCP, send  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

# ---------- config ----------
LURE_PORT      = 443
PREAMBULE      = [1,0,1,0,1,0,1,0]
DEFAULT_D0     = 0.08
DEFAULT_D1     = 0.24

# Secret maître lu côté client si présent (optionnel)
SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")

def b64_read_tolerant(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def load_or_dummy_secret() -> bytes:
    if os.path.exists(SECRET_FILE):
        try:
            return b64_read_tolerant(open(SECRET_FILE).read())
        except Exception:
            pass
    # fallback: clé éphémère locale (toujours la même session) – pour tests locaux
    return hashlib.sha256(b"poc5-local-fallback").digest()

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
    env   = {"ciphertext": body.hex(), "nonce": nonce.hex(), "tag": tag.hex()}
    return json.dumps(env, separators=(",",":"), sort_keys=True).encode()

def bytes_to_bits(b: bytes):
    return [int(bit) for byte in b for bit in f"{byte:08b}"]

def build_frame_bits(msg_bytes: bytes):
    L = len(msg_bytes)
    len_bits = [int(bit) for bit in f"{L:016b}"]
    return PREAMBULE + len_bits + bytes_to_bits(msg_bytes)

def send_timing(bits, dst_ip, d0, d1, iface=None):
    sport = random.randint(1024, 65000)
    seq0  = random.randint(0, 2**32-1)
    for i, b in enumerate(bits):
        pkt = IP(dst=dst_ip)/TCP(dport=LURE_PORT, sport=sport, flags="S", seq=seq0+i)
        send(pkt, verbose=0, iface=iface)
        time.sleep(d1 if b else d0)
    print(f"[+] Trame envoyée ({len(bits)} paquets).")

def main():
    ap = argparse.ArgumentParser(description="POC5 Client (timing + SPA)")
    ap.add_argument("server", help="IP ou nom du serveur (ex: 127.0.0.1)")
    ap.add_argument("--duration", type=int, default=60, help="TTL d'ouverture (s)")
    ap.add_argument("--d0", type=float, default=DEFAULT_D0, help="intervalle bit 0 (s)")
    ap.add_argument("--d1", type=float, default=DEFAULT_D1, help="intervalle bit 1 (s)")
    ap.add_argument("--iface", default=None, help="interface scapy (optionnel)")
    args = ap.parse_args()

    try:
        dst_ip = socket.gethostbyname(args.server)
    except Exception:
        print("[ERREUR] Résolution serveur impossible.", file=sys.stderr); sys.exit(1)

    master  = load_or_dummy_secret()
    aes_key, hmac_key = derive_keys(master)

    spa = build_spa_bytes(aes_key, hmac_key, args.duration)
    frame = build_frame_bits(spa)

    print(f"[i] Cible={dst_ip} | d0={args.d0}s d1={args.d1}s | len={len(spa)}o → {len(frame)} bits")
    send_timing(frame, dst_ip, args.d0, args.d1, iface=args.iface)

if __name__ == "__main__":
    main()
