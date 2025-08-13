#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, time, hmac, hashlib, base64, json, argparse, socket, secrets, getpass, random
from typing import List
#------ Paramètres ------

LURE_HOST = "127.0.0.1"
LURE_PORT = 443  # port leurre unique
SPA_PORT  = 45445 # port UDP pour le SPA
SSH_PORT  = 2222
WINDOW_S  = 30

# Encodage temporel
DELTA0    = 0.10         # 0 => 100 ms
DELTA1    = 0.20         # 1 => 200 ms
JITTER    = 0.012        # jitter 12 ms
PREAMBLE  = "10101010"   # connu du serveur

SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")

def _load_secret(path=SECRET_FILE)->bytes:
    tok = open(path).read().strip().split()[0]
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def _mac(secret:bytes, msg:bytes)->bytes:
    return hmac.new(secret, msg, hashlib.sha256).digest()[:16]

def _bits_from_bytes(b:bytes)->str:
    return "".join(f"{byte:08b}" for byte in b)

def _hamming74_encode(nibble:int)->int:
    d1=(nibble>>3)&1; d2=(nibble>>2)&1; d3=(nibble>>1)&1; d4=nibble&1
    p1=d1^d2^d4; p2=d1^d3^d4; p3=d2^d3^d4
    return (p1<<6)|(p2<<5)|(d1<<4)|(p3<<3)|(d2<<2)|(d3<<1)|d4

def encode_hamming74(data:bytes)->bytes:
    out=[]
    for b in data:
        out.append(_hamming74_encode(b>>4))
        out.append(_hamming74_encode(b & 0x0F))
    return bytes(out)

def build_payload(secret:bytes, duration:int)->bytes:
    user=getpass.getuser()
    payload={"req":"open","port":SSH_PORT,"ts":int(time.time()),"nonce":secrets.token_hex(12),
             "user":user,"duration":int(duration)}
    raw=json.dumps(payload, separators=(",",":")).encode()
    return raw + _mac(secret, raw)

def to_bitstring(frames:bytes, use_hamming=True)->str:
    data = encode_hamming74(frames) if use_hamming else frames
    return PREAMBLE + _bits_from_bytes(data)

def send_syn(host, port, timeout=0.3):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except Exception: pass
    finally: s.close()

def transmit_timings(host, bits:str):
    for i,b in enumerate(bits):
        if i>0:
            base = DELTA1 if b=="1" else DELTA0
            time.sleep(max(0.0, base + random.uniform(-JITTER, JITTER)))
        send_syn(host, LURE_PORT)

def send_spa(host, blob:bytes):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"\x01"+blob, (host, SPA_PORT)); s.close()

def main():
    ap=argparse.ArgumentParser(description="POC5 client — timing channel + SPA")
    ap.add_argument("server", nargs="?", default=LURE_HOST)
    ap.add_argument("--duration", type=int, default=45)
    ap.add_argument("--no-spa", action="store_true")
    args=ap.parse_args()

    secret=_load_secret()
    msg   =build_payload(secret, args.duration)
    bits  =to_bitstring(msg, use_hamming=True)

    print(f"[i] Trame bits={len(bits)} ; Δ0={int(DELTA0*1000)}ms Δ1={int(DELTA1*1000)}ms jitter±{int(JITTER*1000)}ms")
    transmit_timings(args.server, bits)
    print("[✓] Trame temporelle envoyée.")

    if not args.no_spa:
        send_spa(args.server, msg)
        print("[✓] SPA UDP envoyé.")

if __name__=="__main__":
    main()
