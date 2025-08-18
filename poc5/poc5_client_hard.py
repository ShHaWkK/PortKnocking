#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Client :
- Découverte /ports (p1, p2, expiration, ssh)
- Enrôlement /enroll (Ed25519) si nécessaire
- Séquence : TCP SYN -> UDP -> ICMP (root requis pour ICMP raw)
- SPA /knock signé Ed25519 (nonce, ts, duration); TOTP optionnel
- Connexion SSH automatique (désactivable)

Usage :
  sudo python3 poc5_client_hard_v3.py 127.0.0.1 [--duration 60] [--no-ssh] [--totp-file ~/.config/poc5/totp]
"""

import os, sys, time, json, base64, argparse, random, socket, http.client, hashlib, struct

STATE_DIR = os.path.expanduser("~/.config/poc5")
SK_PATH   = os.path.join(STATE_DIR, "ed25519_sk.pem")
PK_PATH   = os.path.join(STATE_DIR, "ed25519_pk.b64u")
TOTP_PATH = os.path.join(STATE_DIR, "totp")  # base32 si utilisé

SPA_HTTP_PORT = 45445

DEFAULT_DURATION = 60

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("Installe le paquet Python 'cryptography' (pip install cryptography).", file=sys.stderr)
    sys.exit(1)

def must_root():
    if os.geteuid()!=0:
        print("Lance en root (sudo), nécessaire pour l’ICMP).", file=sys.stderr); sys.exit(1)

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def de_b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def ensure_keys():
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(SK_PATH) and os.path.exists(PK_PATH):
        sk = serialization.load_pem_private_key(open(SK_PATH,"rb").read(), password=None)
        pk_raw = de_b64u(open(PK_PATH).read().strip())
    else:
        sk = Ed25519PrivateKey.generate()
        pk_raw = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(SK_PATH,"wb") as f: f.write(pem)
        os.chmod(SK_PATH, 0o600)
        with open(PK_PATH,"w") as f: f.write(b64u(pk_raw)+"\n")
    kid = hashlib.sha256(pk_raw).hexdigest()[:16]
    return sk, pk_raw, kid

def http_get_json(host: str, port: int, path: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection(host, port, timeout=3.5)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read()
    try:
        parsed = json.loads(data.decode())
    except Exception:
        parsed = {}
    conn.close()
    return resp.status, parsed

def http_post_json(host: str, port: int, path: str, obj: dict) -> tuple[int, dict]:
    body = json.dumps(obj).encode()
    conn = http.client.HTTPConnection(host, port, timeout=4.0)
    conn.request("POST", path, body=body, headers={"Content-Type":"application/json","Content-Length":str(len(body))})
    resp = conn.getresponse()
    data = resp.read()
    try:
        parsed = json.loads(data.decode())
    except Exception:
        parsed = {}
    conn.close()
    return resp.status, parsed

def knock_tcp(host: str, port: int, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except Exception: pass
    finally: s.close()

def knock_udp(host: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b"\x01", (host, port))
    except Exception: pass
    finally: s.close()

def knock_icmp(host: str):
    # ICMP echo, checksum correct
    def csum(b):
        s = 0
        for i in range(0, len(b), 2):
            w = b[i] + ((b[i+1] << 8) if i+1 < len(b) else 0)
            s = (s + w) & 0xffffffff
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        return (~s) & 0xffff
    ident = random.randint(0, 0xffff); seq = 1
    hdr = bytes([8,0,0,0, ident & 0xff, (ident>>8)&0xff, seq & 0xff, (seq>>8)&0xff])
    data = b"poc5"
    ch = csum(hdr[:2] + b"\x00\x00" + hdr[4:] + data)
    pkt = bytes([8,0,ch & 0xff,(ch>>8)&0xff]) + hdr[4:] + data
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try: s.sendto(pkt, (host,0))
    finally: s.close()

def read_totp_code(path: str) -> int | None:
    if not os.path.exists(path): return None
    raw = "".join(open(path).read().strip().split()).upper()
    try:
        sec = base64.b32decode(raw)
    except Exception:
        return None
    # TOTP 6 digits, SHA-1, 30s
    now = int(time.time())
    counter = now // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(sec, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    bin_code = ((digest[off] & 0x7F) << 24) | (digest[off+1] << 16) | (digest[off+2] << 8) | digest[off+3]
    return bin_code % (10**6)

def wait_ssh(host: str, port: int, timeout: float=8.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.8)
        try:
            s.connect((host, port)); s.close(); return True
        except Exception:
            time.sleep(0.3)
        finally:
            try: s.close()
            except: pass
    return False

def main():
    must_root()
    ap = argparse.ArgumentParser(description="POC5 Client — knock multi-protocol + SPA signé")
    ap.add_argument("server", help="IP ou nom du serveur")
    ap.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    ap.add_argument("--no-ssh", action="store_true")
    ap.add_argument("--totp-file", default=TOTP_PATH, help="Fichier base32 pour TOTP (optionnel)")
    args = ap.parse_args()

    try:
        dst_ip = socket.gethostbyname(args.server)
    except Exception:
        print("Résolution de l’hôte impossible.", file=sys.stderr); sys.exit(1)

    sk, pk_raw, kid = ensure_keys()

    # découverte des ports
    p1, p2, ssh = 47001, 47002, 2222
    try:
        code, meta = http_get_json(dst_ip, SPA_HTTP_PORT, "/ports")
        if code == 200:
            p1, p2 = int(meta["p1"]), int(meta["p2"])
            ssh = int(meta.get("ssh", 2222))
    except Exception:
        pass

    print(f"Cible={dst_ip} | kid={kid} | Séquence: TCP {p1} -> UDP {p2} -> ICMP")

    # enrôlement idempotent
    try:
        code, _ = http_post_json(dst_ip, SPA_HTTP_PORT, "/enroll", {"kid": kid, "pubkey": b64u(pk_raw)})
        if code != 200:
            print(f"[WARN] /enroll HTTP {code} (on continue)")
    except Exception:
        print("[WARN] /enroll indisponible (on continue)")

    # knocks
    print(f"TCP SYN -> {p1}")
    knock_tcp(dst_ip, p1); time.sleep(0.35)
    print(f"UDP -> {p2}")
    knock_udp(dst_ip, p2); time.sleep(0.35)
    print("ICMP echo")
    knock_icmp(dst_ip)

    # SPA signé
    ts = int(time.time())
    nonce = b64u(os.urandom(16))
    payload = {"kid": kid, "ts": ts, "duration": int(args.duration), "nonce": nonce}
    # TOTP si dispo
    code = read_totp_code(args.totp_file)
    if code is not None:
        payload["totp"] = int(code)
    sig = sk.sign(canon_bytes(payload))
    body = dict(payload); body["sig"] = b64u(sig)

    print("Envoi SPA signé...")
    rc, resp = http_post_json(dst_ip, SPA_HTTP_PORT, "/knock", body)
    if rc != 200:
        print(f"SPA refusé: HTTP {rc} {resp}")
        sys.exit(2)
    ttl = int(resp.get("ttl", args.duration))
    print(f"Ouverture accordée: {ttl}s")

    if args.no-ssh:
        print("Mode --no-ssh, fin du client."); return

    print("Vérification SSH…")
    if wait_ssh(dst_ip, port=ssh, timeout=8.0):
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        print("SSH ouvert, connexion auto.")
        os.execvp("ssh", ["ssh","-p",str(ssh),"-o","StrictHostKeyChecking=accept-new", f"{user}@{args.server}"])
    else:
        print("SSH semble encore fermé (timeout).")

if __name__ == "__main__":
    import hmac  # utilisé par read_totp_code
    main()