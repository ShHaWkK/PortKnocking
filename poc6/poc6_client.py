#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC6 — Client SPA 100% UDP
- Auto-découverte HTTP (/info), enrôlement (/enroll), puis envoi d’un SPA UDP.
- SPA: PoW + X25519/HKDF → AES-GCM + signature Ed25519 + TOTP (optionnel).
Usage minimal: sudo python3 poc6_client.py 127.0.0.1
"""

import os, sys, time, json, base64, argparse, socket, struct, hashlib, secrets, http.client

try:
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    print("Installez : pip install cryptography", file=sys.stderr); sys.exit(1)

STATE_DIR = os.path.expanduser("~/.config/poc6")
SK_PATH   = os.path.join(STATE_DIR, "ed25519_sk.pem")
PK_PATH   = os.path.join(STATE_DIR, "ed25519_pk.b64u")
TOTP_PATH = os.path.join(STATE_DIR, "totp_base32")

UDP_PORT_DEFAULT  = 45446
HTTP_PORT_DEFAULT = 45447
SSH_PORT          = 2222

def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj) -> bytes: return json.dumps(obj, separators=(",",":"), sort_keys=True, ensure_ascii=False).encode()

def ensure_keys():
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(SK_PATH) and os.path.exists(PK_PATH):
        sk = serialization.load_pem_private_key(open(SK_PATH,"rb").read(), password=None)
        pk_raw = de_b64u(open(PK_PATH).read().strip())
    else:
        sk = ed25519.Ed25519PrivateKey.generate()
        pk_raw = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        pem = sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        open(SK_PATH,"wb").write(pem); os.chmod(SK_PATH,0o600)
        open(PK_PATH,"w").write(b64u(pk_raw)+"\n")
    kid_hex = hashlib.sha256(pk_raw).hexdigest()[:16]        # pour /enroll et le JSON
    kid16   = hashlib.sha256(pk_raw).digest()[:16]           # 16 OCTETS BRUTS pour l'entête UDP
    return sk, pk_raw, kid_hex, kid16

def read_totp_code():
    if not os.path.exists(TOTP_PATH): return None
    try:
        sec = base64.b32decode("".join(open(TOTP_PATH).read().strip().split()).upper())
        import hmac, struct, hashlib as _hl
        def totp_now(secret: bytes, for_time: int, step=30, digits=6) -> int:
            ctr=int(for_time//step); msg=struct.pack(">Q", ctr)
            dig=hmac.new(secret,msg,_hl.sha1).digest(); off=dig[-1]&0x0F
            code=((dig[off]&0x7F)<<24)|(dig[off+1]<<16)|(dig[off+2]<<8)|dig[off+3]
            return code % (10**digits)
        return totp_now(sec, int(time.time()))
    except Exception:
        return None

def leading_zero_bits(h: bytes) -> int:
    n=0
    for b in h:
        if b == 0: n+=8
        else:
            for i in range(7,-1,-1):
                if (b>>i)&1: return n + (7-i)
            return n
    return n

def http_get_json(host: str, port: int, path: str):
    conn = http.client.HTTPConnection(host, port, timeout=4.0)
    conn.request("GET", path); r = conn.getresponse(); data=r.read(); conn.close()
    try: return r.status, json.loads(data.decode())
    except Exception: return r.status, {}
def http_post_json(host: str, port: int, path: str, obj: dict):
    raw = json.dumps(obj).encode()
    conn = http.client.HTTPConnection(host, port, timeout=4.0)
    conn.request("POST", path, body=raw, headers={"Content-Type":"application/json","Content-Length":str(len(raw))})
    r = conn.getresponse(); data=r.read(); conn.close()
    try: return r.status, json.loads(data.decode())
    except Exception: return r.status, {}

def pow_solve(kid16: bytes, c_eph_pub: bytes, window_id: int, salt: bytes, bits: int, limit_iters: int = 5_000_000) -> bytes:
    for _ in range(limit_iters):
        nonce = secrets.token_bytes(8)
        h = hashlib.sha256(b"PK6"+bytes([1])+struct.pack("!I",window_id)+salt+kid16+c_eph_pub+nonce).digest()
        if leading_zero_bits(h) >= bits: return nonce
    raise RuntimeError("PoW non trouvé (augmentez la limite/baissez la difficulté)")

def build_packet(server_pub_b64u: str, difficulty_bits: int, difficulty_salt_b64u: str,
                 duration: int, totp_required: bool, sk_ed: ed25519.Ed25519PrivateKey,
                 kid_hex: str, kid16: bytes):
    s_pub = de_b64u(server_pub_b64u); diff_salt = de_b64u(difficulty_salt_b64u)

    c_sk = x25519.X25519PrivateKey.generate()
    c_epub = c_sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    win = int(time.time()//30)
    pow_nonce = pow_solve(kid16, c_epub, win, diff_salt, difficulty_bits)

    shared = c_sk.exchange(x25519.X25519PublicKey.from_public_bytes(s_pub))
    salt = hashlib.sha256(s_pub + c_epub + struct.pack("!I", win)).digest()
    K = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"poc6/aead").derive(shared)
    aead = AESGCM(K); aead_nonce = secrets.token_bytes(12)

    payload = {"kid": kid_hex, "ts": int(time.time()), "duration": int(duration), "inner_nonce": b64u(secrets.token_bytes(8))}
    if totp_required:
        code = read_totp_code()
        if code is None:
            print("TOTP requis : placez votre secret base32 dans", TOTP_PATH, file=sys.stderr); sys.exit(1)
        payload["totp"] = int(code)
    sig = sk_ed.sign(canon_bytes(payload))
    payload_signed = dict(payload); payload_signed["sig"] = b64u(sig)
    pt = json.dumps(payload_signed, separators=(",",":"), sort_keys=True).encode()

    aad = b"PK6|" + struct.pack("!BIB", 1, win, difficulty_bits) + c_epub + kid16 + pow_nonce
    ct = aead.encrypt(aead_nonce, pt, aad)
    header = b"PK6" + bytes([1]) + struct.pack("!I", win) + bytes([difficulty_bits]) + c_epub + kid16 + pow_nonce + aead_nonce
    return header + ct

def wait_ssh(host: str, port: int=SSH_PORT, timeout: float=10.0) -> bool:
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            sock=socket.create_connection((host, port), timeout=0.8)
            sock.close(); return True
        except Exception:
            time.sleep(0.3)
    return False

def main():
    ap=argparse.ArgumentParser(description="POC6 client (SPA UDP)")
    ap.add_argument("server")
    ap.add_argument("--udp", type=int, default=UDP_PORT_DEFAULT)
    ap.add_argument("--http", type=int, default=HTTP_PORT_DEFAULT)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--no-ssh", action="store_true")
    args=ap.parse_args()

    dst = socket.gethostbyname(args.server)
    sk, pk_raw, kid_hex, kid16 = ensure_keys()
    print(f"[CLIENT] cible={dst} kid={kid_hex}")

    code, info = http_get_json(dst, args.http, "/info")
    if code != 200:
        print(f"[ERREUR] GET /info HTTP {code}", file=sys.stderr); sys.exit(1)
    s_pub = info.get("server_pub",""); diff_bits = int(info.get("difficulty_bits", 18))
    diff_salt = info.get("difficulty_salt",""); totp_required = bool(info.get("totp_required", False))
    print(f"[INFO] diff={diff_bits} totp_required={totp_required} udp={info.get('udp')} ssh={info.get('ssh')}")

    code, _ = http_post_json(dst, args.http, "/enroll", {"kid": kid_hex, "pubkey": b64u(pk_raw)})
    if code != 200:
        print(f"[WARN] /enroll HTTP {code} (peut être déjà enrôlé)", file=sys.stderr)

    pkt = build_packet(s_pub, diff_bits, diff_salt, args.duration, totp_required, sk, kid_hex, kid16)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(pkt, (dst, args.udp)); s.close()
    print("[SEND] SPA envoyé")

    if args.no_ssh: return
    print("[WAIT] ouverture SSH:2222...")
    if wait_ssh(dst, SSH_PORT, 10.0):
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        print("[SSH] connexion...")
        os.execvp("ssh", ["ssh", "-p", str(SSH_PORT), "-o", "StrictHostKeyChecking=accept-new", f"{user}@{args.server}"])
    else:
        print("[INFO] SSH encore fermé (timeout).")

if __name__=="__main__":
    main()
