#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 — Client : Knock multi-protocole + SPA HTTP signé Ed25519.
Commande unique :
  sudo python3 poc5_client_hard.py 127.0.0.1
Comportement :
- Génère/charge une clé Ed25519 (~/.config/poc5).
- Enrôle la clé publique (/enroll) si nécessaire.
- Récupère P1/P2 via /ports puis séquence : TCP SYN -> UDP -> ICMP.
- Construit un SPA {duration,kid,nonce,ts[,totp]} signé Ed25519 (POST /knock).
- TOTP auto si ~/.config/poc5/totp_base32 existe (base32).
- SSH auto sur :2222 si ouverture accordée.
"""

import os, sys, time, json, base64, argparse, random, socket, http.client, hashlib

STATE_DIR = os.path.expanduser("~/.config/poc5")
SK_PATH   = os.path.join(STATE_DIR, "ed25519_sk.pem")
PK_PATH   = os.path.join(STATE_DIR, "ed25519_pk.b64u")
TOTP_PATH = os.path.join(STATE_DIR, "totp_base32")

SPA_HTTP_PORT = 45445
SSH_PORT      = 2222

DEFAULT_DELAY  = 0.35
DEFAULT_DUR    = 60

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("Installe le paquet Python 'cryptography' (pip install cryptography).", file=sys.stderr)
    sys.exit(1)

def must_root():
    if os.geteuid()!=0:
        print("Lance le client en root (sudo), pour l’ICMP raw.", file=sys.stderr)
        sys.exit(1)

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

def read_totp_secret_or_none():
    if os.path.exists(TOTP_PATH):
        tok = "".join(open(TOTP_PATH).read().strip().split()).upper()
        try:
            return base64.b32decode(tok)
        except Exception:
            pass
    return None

def totp_now(secret: bytes, for_time: int, step=30, digits=6) -> int:
    ctr = int(for_time//step)
    msg = ctr.to_bytes(8, "big")
    digest = hashlib.sha1(secret + msg).digest()  # simple, suffisant pour client démo
    off = digest[-1] & 0x0F
    code = ((digest[off] & 0x7F)<<24) | (digest[off+1]<<16) | (digest[off+2]<<8) | digest[off+3]
    return code % (10**digits)

def http_json(host: str, port: int, method: str, path: str, obj: dict|None=None, timeout=4.0):
    body = b""
    headers = {}
    if obj is not None:
        body = json.dumps(obj).encode()
        headers={"Content-Type":"application/json","Content-Length":str(len(body))}
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    try: parsed = json.loads(data.decode())
    except Exception: parsed = {}
    code = resp.status
    conn.close()
    return code, parsed

def knock_tcp(host: str, port: int, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except Exception: pass
    finally: 
        try: s.close()
        except: pass

def knock_udp(host: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b"\x01", (host, port))
    except Exception: pass
    finally:
        try: s.close()
        except: pass

def knock_icmp(host: str):
    # ICMP Echo type 8 code 0
    def csum(b):
        s = 0
        for i in range(0, len(b), 2):
            w = b[i] + ((b[i+1] << 8) if i+1 < len(b) else 0)
            s = (s + w) & 0xffffffff
        s = (s >> 16) + (s & 0xffff); s = s + (s >> 16)
        return (~s) & 0xffff
    ident = random.randint(0, 0xffff)
    seq = 1
    hdr = bytes([8, 0, 0, 0, ident & 0xff, (ident >> 8) & 0xff, seq & 0xff, (seq >> 8) & 0xff])
    data = b"poc5"
    ch = csum(hdr[:2] + b"\x00\x00" + hdr[4:] + data)
    pkt = bytes([8, 0, ch & 0xff, (ch >> 8) & 0xff]) + hdr[4:] + data
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try: s.sendto(pkt, (host, 0))
    finally:
        try: s.close()
        except: pass

def wait_ssh(host: str, port: int=SSH_PORT, timeout: float=8.0) -> bool:
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
    ap = argparse.ArgumentParser()
    ap.add_argument("server", help="IP ou nom du serveur (ex: 127.0.0.1)")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    ap.add_argument("--duration", type=int, default=DEFAULT_DUR)
    args = ap.parse_args()

    try:
        dst_ip = socket.gethostbyname(args.server)
    except Exception:
        print("Resolution hote impossible.", file=sys.stderr); sys.exit(1)

    sk, pk_raw, kid = ensure_keys()
    totp_secret = read_totp_secret_or_none()
    print(f"Cible={dst_ip} | kid={kid} | delay={args.delay}s | duration={args.duration}s")

    # 1) Info ports + enrollment (idempotent)
    code, ports = http_json(dst_ip, SPA_HTTP_PORT, "GET", "/ports")
    if code != 200 or "p1" not in ports or "p2" not in ports:
        print(f"Erreur /ports HTTP {code}", file=sys.stderr); sys.exit(2)
    p1, p2 = int(ports["p1"]), int(ports["p2"])
    print(f"Ports actifs : TCP {p1} -> UDP {p2} -> ICMP (expire={ports.get('expires')})")

    code, _ = http_json(dst_ip, SPA_HTTP_PORT, "POST", "/enroll",
                        {"kid": kid, "pubkey": b64u(pk_raw)})
    if code not in (200, 409):  # 409 non utilisé ici mais toléré si tu l'ajoutes plus tard
        print(f"Avertissement: /enroll HTTP {code}", file=sys.stderr)

    # 2) Knock
    print(f"TCP SYN -> {p1}")
    knock_tcp(dst_ip, p1); time.sleep(args.delay)
    print(f"UDP -> {p2}")
    knock_udp(dst_ip, p2); time.sleep(args.delay)
    print("ICMP echo")
    knock_icmp(dst_ip)

    # 3) SPA signé Ed25519 (+ TOTP si dispo)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    # recharger la clé (pour être sûr qu’elle marche)
    sk2 = serialization.load_pem_private_key(open(SK_PATH,"rb").read(), password=None)  # type: ignore
    ts = int(time.time())
    nonce = b64u(os.urandom(16))
    payload = {"duration": int(args.duration), "kid": kid, "nonce": nonce, "ts": ts}
    if totp_secret is not None:
        # calcule un TOTP simple sur la base du secret local (fenêtre actuelle)
        code = totp_now(totp_secret, ts)
        payload["totp"] = int(code)
    sig = sk2.sign(canon_bytes(payload))
    body = dict(payload); body["sig"] = b64u(sig)

    print("Envoi SPA signe...")
    code, resp = http_json(dst_ip, SPA_HTTP_PORT, "POST", "/knock", body)
    if code != 200:
        print(f"SPA refuse: HTTP {code} {resp}", file=sys.stderr)
        sys.exit(3)
    ttl = int(resp.get("ttl", args.duration))
    print(f"Ouverture accordee: {ttl}s")

    # 4) SSH auto
    print("Verification SSH...")
    if wait_ssh(dst_ip, timeout=8.0):
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        print("SSH ouvert, connexion automatique.")
        os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new", f"{user}@{args.server}"])
    else:
        print("SSH semble encore ferme (timeout).")

if __name__ == "__main__":
    from cryptography.hazmat.primitives import serialization  # noqa
    main()
