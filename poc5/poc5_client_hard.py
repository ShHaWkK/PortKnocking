#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 — Client : Knock multi-protocole + SPA HTTP signé Ed25519.
- Génère une clé Ed25519 locale si absente (~/.config/poc5).
- /enroll (idempotent) -> enregistrement clé publique côté serveur.
- Séquence : TCP SYN -> P1, UDP -> P2, ICMP Echo.
- /knock : SPA JSON canonique signé Ed25519 (nonce + timestamp + duration).
- SSH auto sur :2222 si ouverture ok.

Usage :
  sudo python3 poc5_client_hard.py <IP_SERVEUR> [--p1 47001 --p2 47002 --delay 0.35 --duration 60 --no-ssh]
"""

import os, sys, time, json, base64, argparse, random, socket, http.client, hashlib

STATE_DIR = os.path.expanduser("~/.config/poc5")
SK_PATH   = os.path.join(STATE_DIR, "ed25519_sk.pem")
PK_PATH   = os.path.join(STATE_DIR, "ed25519_pk.b64u")

SPA_HTTP_PORT = 45445
SSH_PORT      = 2222

DEFAULT_P1     = 47001
DEFAULT_P2     = 47002
DEFAULT_DELAY  = 0.35
DEFAULT_DUR    = 60

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("✖ Installe 'cryptography' (pip install cryptography).", file=sys.stderr); sys.exit(1)

def must_root():
    if os.geteuid()!=0:
        print("✖ Lance le client en root (sudo), pour l’ICMP raw.", file=sys.stderr); sys.exit(1)

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
        open(SK_PATH,"wb").write(pem); os.chmod(SK_PATH, 0o600)
        open(PK_PATH,"w").write(b64u(pk_raw)+"\n")
    kid = hashlib.sha256(pk_raw).hexdigest()[:16]
    return sk, pk_raw, kid

def http_post_json(host: str, port: int, path: str, obj: dict) -> tuple[int, dict]:
    body = json.dumps(obj).encode()
    conn = http.client.HTTPConnection(host, port, timeout=4.0)
    conn.request("POST", path, body=body, headers={"Content-Type":"application/json","Content-Length":str(len(body))})
    resp = conn.getresponse(); data = resp.read()
    try: parsed = json.loads(data.decode())
    except Exception: parsed = {}
    conn.close()
    return resp.status, parsed

def knock_tcp(host: str, port: int, timeout=0.8):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except Exception: pass
    finally: s.close()

def knock_udp(host: str, port: int):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b"\x01", (host, port))
    except Exception: pass
    finally: s.close()

def knock_icmp(host: str):
    # ICMP Echo simple (raw socket)
    def csum(b):
        s=0
        for i in range(0,len(b),2):
            w=b[i] + ((b[i+1]<<8) if i+1<len(b) else 0)
            s=(s+w)&0xffffffff
        s=(s>>16)+(s&0xffff); s=s+(s>>16)
        return (~s)&0xffff
    ident=random.randint(0,0xffff); seq=1
    hdr=bytes([8,0,0,0, ident&0xff,(ident>>8)&0xff, seq&0xff,(seq>>8)&0xff]); data=b"poc5"
    ch=csum(hdr[:2]+b"\x00\x00"+hdr[4:]+data)
    pkt=bytes([8,0,ch&0xff,(ch>>8)&0xff])+hdr[4:]+data
    s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try: s.sendto(pkt, (host, 0))
    finally: s.close()

def wait_ssh(host: str, port: int=SSH_PORT, timeout: float=8.0) -> bool:
    t0=time.time()
    while time.time()-t0<timeout:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.8)
        try: s.connect((host, port)); s.close(); return True
        except Exception: time.sleep(0.3)
        finally:
            try: s.close()
            except: pass
    return False

def main():
    must_root()
    ap = argparse.ArgumentParser()
    ap.add_argument("server", help="IP/nom du serveur (ex: 127.0.0.1)")
    ap.add_argument("--p1", type=int, default=DEFAULT_P1)
    ap.add_argument("--p2", type=int, default=DEFAULT_P2)
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    ap.add_argument("--duration", type=int, default=DEFAULT_DUR)
    ap.add_argument("--no-ssh", action="store_true")
    args = ap.parse_args()

    try: dst_ip = socket.gethostbyname(args.server)
    except Exception:
        print("✖ Résolution de l’hôte impossible.", file=sys.stderr); sys.exit(1)

    sk, pk_raw, kid = ensure_keys()
    print(f"➡ Cible={dst_ip} | kid={kid} | Séquence: TCP {args.p1} → UDP {args.p2} → ICMP | delay={args.delay}s")

    # Enrôlement (idempotent : ok même si déjà fait)
    code, _ = http_post_json(dst_ip, SPA_HTTP_PORT, "/enroll", {"kid": kid, "pubkey": b64u(pk_raw)})
    if code != 200:
        print(f"⚠ /enroll HTTP {code} (continuons, il est peut-être déjà enregistré)")

    # Séquence multi-protocole
    print(f"[*] TCP SYN -> {args.p1}")
    knock_tcp(dst_ip, args.p1); time.sleep(args.delay)
    print(f"[*] UDP -> {args.p2}")
    knock_udp(dst_ip, args.p2); time.sleep(args.delay)
    print("[*] ICMP echo")
    knock_icmp(dst_ip)

    # SPA signé
    ts = int(time.time()); nonce = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    payload = {"duration": int(args.duration), "kid": kid, "nonce": nonce, "ts": ts}
    sig = sk.sign(canon_bytes(payload))
    body = dict(payload); body["sig"] = b64u(sig)

    print("[*] Envoi SPA signé…")
    code, resp = http_post_json(dst_ip, SPA_HTTP_PORT, "/knock", body)
    if code != 200:
        print(f"✖ SPA refusé : HTTP {code} {resp}"); sys.exit(2)

    ttl = int(resp.get("ttl", args.duration))
    print(f"✓ Ouverture accordée : {ttl}s")

    if args.no_ssh:
        print("ℹ Mode --no-ssh : fin ici."); return

    print("[i] Vérification SSH…")
    if wait_ssh(dst_ip, timeout=8.0):
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        print("✅ SSH ouvert, connexion…")
        os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new", f"{user}@{args.server}"])
    else:
        print("⚠ SSH semble fermé (timeout). Vérifie la fenêtre pending/open côté serveur.")

if __name__ == "__main__":
    main()
