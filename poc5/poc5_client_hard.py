#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 — Client : Knock multi-protocole + SPA signé Ed25519
- Génère/charge une clé Ed25519 (~/.config/poc5), kid = sha256(pub)[:16]
- Enrôle la clé : POST /enroll
- Découvre P1/P2 : GET /ports (par défaut)
- Séquence : TCP SYN -> P1 ; UDP -> P2 ; ICMP Echo
- SPA : JSON {duration,kid,nonce,ts[,totp]} signé -> POST /knock
- Connexion SSH auto vers :2222 (désactivable --no-ssh)
Usage :
  sudo python3 poc5_client_hard.py 127.0.0.1
"""

import os, sys, time, json, base64, argparse, random, socket, http.client, hashlib, struct, hmac

STATE_DIR = os.path.expanduser("~/.config/poc5")
SK_PATH   = os.path.join(STATE_DIR, "ed25519_sk.pem")
PK_PATH   = os.path.join(STATE_DIR, "ed25519_pk.b64u")

HTTP_PORT = 45445
SSH_PORT  = 2222

DEFAULT_DELAY = 0.35
DEFAULT_DUR   = 60

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("Installe : pip install cryptography", file=sys.stderr); sys.exit(1)

def must_root():
    if os.geteuid()!=0:
        print("Lance en root (sudo) pour l’ICMP raw.", file=sys.stderr); sys.exit(1)

def b64u(b:bytes)->str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s:str)->bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj)->bytes: return json.dumps(obj, separators=(",",":"), sort_keys=True).encode()

# TOTP minimal (client)
def b32_read(raw:str)->bytes:
    tok="".join(raw.strip().split()); return base64.b32decode(tok.upper())
def totp_now(secret:bytes, for_time:int, step=30, digits=6)->int:
    ctr=int(for_time//step)
    msg=struct.pack(">Q", ctr)
    dig=hmac.new(secret, msg, hashlib.sha1).digest()
    off=dig[-1]&0x0F
    code=((dig[off]&0x7F)<<24)|(dig[off+1]<<16)|(dig[off+2]<<8)|dig[off+3]
    return code % (10**digits)

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
        open(SK_PATH,"wb").write(pem); os.chmod(SK_PATH,0o600)
        open(PK_PATH,"w").write(b64u(pk_raw)+"\n")
    kid = hashlib.sha256(pk_raw).hexdigest()[:16]
    return sk, pk_raw, kid

def http_get_json(host:str, port:int, path:str, timeout=4.0):
    conn=http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request("GET", path)
    resp=conn.getresponse(); data=resp.read()
    try: obj=json.loads(data.decode())
    except Exception: obj={}
    conn.close(); return resp.status, obj

def http_post_json(host:str, port:int, path:str, obj:dict, timeout=4.0):
    body=json.dumps(obj).encode()
    conn=http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request("POST", path, body=body, headers={"Content-Type":"application/json","Content-Length":str(len(body))})
    resp=conn.getresponse(); data=resp.read()
    try: parsed=json.loads(data.decode())
    except Exception: parsed={}
    conn.close(); return resp.status, parsed

def knock_tcp(host:str, port:int, timeout=0.8):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except Exception: pass
    finally: s.close()

def knock_udp(host:str, port:int):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b"\x01",(host,port))
    except Exception: pass
    finally: s.close()

def knock_icmp(host:str):
    def csum(b):
        s=0
        for i in range(0,len(b),2):
            w=b[i]+((b[i+1]<<8) if i+1<len(b) else 0)
            s=(s+w)&0xffffffff
        s=(s>>16)+(s&0xffff); s=s+(s>>16)
        return (~s)&0xffff
    ident=random.randint(0,0xffff); seq=1
    hdr=bytes([8,0,0,0, ident&0xff,(ident>>8)&0xff, seq&0xff,(seq>>8)&0xff])
    data=b"poc5"
    ch=csum(hdr[:2]+b"\x00\x00"+hdr[4:]+data)
    pkt=bytes([8,0,ch&0xff,(ch>>8)&0xff])+hdr[4:]+data
    s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try: s.sendto(pkt,(host,0))
    finally: s.close()

def wait_ssh(host:str, port:int=SSH_PORT, timeout:float=8.0)->bool:
    t0=time.time()
    while time.time()-t0<timeout:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.8)
        try: s.connect((host,port)); s.close(); return True
        except Exception: time.sleep(0.3)
        finally:
            try: s.close()
            except: pass
    return False

def main():
    must_root()
    ap=argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    ap.add_argument("--duration", type=int, default=DEFAULT_DUR)
    ap.add_argument("--no-ssh", action="store_true")
    ap.add_argument("--no-fetch", action="store_true", help="ne pas appeler /ports (forcer --p1/--p2)")
    ap.add_argument("--p1", type=int, default=None)
    ap.add_argument("--p2", type=int, default=None)
    ap.add_argument("--totp-secret", default=None, help="fichier base32 (optionnel)")
    args=ap.parse_args()

    try: dst_ip=socket.gethostbyname(args.server)
    except Exception:
        print("Résolution hôte impossible.", file=sys.stderr); sys.exit(1)

    sk, pk_raw, kid = ensure_keys()
    # enrôlement (idempotent)
    http_post_json(dst_ip, HTTP_PORT, "/enroll", {"kid":kid, "pubkey": b64u(pk_raw)})

    p1=args.p1; p2=args.p2
    if not args.no_fetch or p1 is None or p2 is None:
        code,resp = http_get_json(dst_ip, HTTP_PORT, "/ports")
        if code==200:
            p1 = p1 or int(resp.get("p1",47001))
            p2 = p2 or int(resp.get("p2",47002))

    if p1 is None or p2 is None: p1,p2 = 47001,47002

    print(f"Cible={dst_ip} | kid={kid} | Séquence: TCP {p1} -> UDP {p2} -> ICMP | delay={args.delay}s")

    print(f"TCP SYN -> {p1}")
    knock_tcp(dst_ip,p1); time.sleep(args.delay)
    print(f"UDP -> {p2}")
    knock_udp(dst_ip,p2); time.sleep(args.delay)
    print("ICMP echo")
    knock_icmp(dst_ip)

    ts=int(time.time()); nonce=b64u(os.urandom(16))
    payload={"duration": int(args.duration), "kid": kid, "nonce": nonce, "ts": ts}

    # TOTP optionnel
    if args.totp_secret:
        if not os.path.exists(args.totp_secret):
            print(f"Secret TOTP introuvable : {args.totp_secret}", file=sys.stderr); sys.exit(1)
        sec=b32_read(open(args.totp_secret).read())
        payload["totp"]= totp_now(sec, ts)

    sig = sk.sign(canon_bytes(payload))
    body=dict(payload); body["sig"]=b64u(sig)

    print("Envoi SPA signé...")
    code, resp = http_post_json(dst_ip, HTTP_PORT, "/knock", body)
    if code!=200:
        print(f"SPA refusé: HTTP {code} {resp}", file=sys.stderr); sys.exit(2)

    ttl=int(resp.get("ttl", args.duration))
    print(f"Ouverture accordée: {ttl}s")

    if args.no_ssh:
        print("Mode --no-ssh, fin du client."); return

    print("Vérification SSH...")
    if wait_ssh(dst_ip, timeout=8.0):
        user=os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
        print("SSH ouvert, connexion auto.")
        os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new", f"{user}@{args.server}"])
    else:
        print("SSH encore fermé (timeout). Vérifie TTL pending/open côté serveur.")

if __name__=="__main__":
    main()
