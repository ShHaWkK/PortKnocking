#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 (serveur) — Knock multi-protocole + SPA chiffré (X25519+HKDF+ChaCha20-Poly1305) + signature Ed25519.
- Séquence noyau (nftables) : TCP P1 -> UDP P2 -> ICMP echo  => IP entre dans @pending (TTL court)
- SPA HTTP (:45445):
    GET /server-info     -> { kx_pub, ssh_port, alg }
    POST /enroll         -> { kid, pubkey } (Ed25519 raw 32B en b64url)
    POST /knock (JSON)   -> { kid, ts, nonce, epk, iv, ct, sig }
      * sig  = Ed25519.sign( canon({kid,ts,nonce,epk,iv,ct}) )
      * cle  = HKDF( X25519(server_sk, epk), salt="poc5|kid" )
      * ct   = ChaCha20Poly1305(key).encrypt(iv, plaintext={"svc":"ssh","ttl":60}, aad=canon({kid,ts,nonce,epk}))
- Si l’IP est dans @pending ET la vérif cryptographique passe : ajout @allowed { ip timeout ttl } -> SSH :2222 ouvert pour l’IP

Fichiers:
- /var/lib/poc5/server_kx.json         # X25519 (clé statique serveur, persistant)
- /var/lib/poc5/clients.json           # clients enrôlés: {kid: pubkey_b64u}
- /var/log/portknock/poc5.jsonl        # logs JSONL

Dépendances: python3-cryptography, nftables, openssh-server
Usage: sudo python3 poc5_server_fx.py [--p1 47001 --p2 47002 --step-ttl 10 --pending-ttl 15 --open-ttl 60]
"""

import os, sys, time, json, base64, signal, shutil, argparse, subprocess, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
from typing import Dict, Any

# --- paramètres
SSH_PORT      = 2222
SPA_HTTP_PORT = 45445
NFT_TABLE     = "knock5"
NFT_CHAIN_IN  = "inbound"
NFT_CHAIN_ST  = "steps"
SET_S1        = "s1"
SET_S2        = "s2"
SET_PENDING   = "pending"
SET_ALLOWED   = "allowed"

DEFAULT_P1       = 47001
DEFAULT_P2       = 47002
DEFAULT_STEP_TTL = 10
DEFAULT_PEND_TTL = 15
DEFAULT_OPEN_TTL = 60

STATE_DIR  = "/var/lib/poc5"
LOG_PATH   = "/var/log/portknock/poc5.jsonl"
CLIENTS_DB = os.path.join(STATE_DIR, "clients.json")
KX_PATH    = os.path.join(STATE_DIR, "server_kx.json")     # {"sk": b64u(32B), "pk": b64u(32B)}

NONCE_TTL_S = 180
_nonce_cache: Dict[str, float] = {}

# --- crypto
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except Exception:
    print("Installe 'cryptography' (pip install cryptography).", file=sys.stderr); sys.exit(1)

# --- outils simples
def must_root():
    if os.geteuid()!=0:
        print("Lancer en root (sudo).", file=sys.stderr); sys.exit(1)

def run(cmd: str, check=False, quiet=True):
    r = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and r.returncode != 0:
        print(r.stdout + r.stderr, file=sys.stderr)
        raise subprocess.CalledProcessError(r.returncode, cmd)
    if not quiet and r.stdout.strip():
        print(r.stdout.rstrip())
    return r

def jlog(event: str, **fields):
    row = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    row.update(fields)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f: f.write(json.dumps(row, ensure_ascii=False)+"\n")
    except Exception:
        pass

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def de_b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def canon_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

# --- état: clients + KX serveur
def load_clients() -> Dict[str, str]:
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(CLIENTS_DB):
        open(CLIENTS_DB,"w").write("{}\n")
        return {}
    try: return json.loads(open(CLIENTS_DB).read())
    except Exception: return {}

def save_clients(db: Dict[str,str]):
    os.makedirs(STATE_DIR, exist_ok=True)
    open(CLIENTS_DB,"w").write(json.dumps(db, ensure_ascii=False, indent=2)+"\n")

def load_or_create_kx():
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(KX_PATH):
        obj=json.loads(open(KX_PATH).read())
        sk=X25519PrivateKey.from_private_bytes(de_b64u(obj["sk"]))
        pk=de_b64u(obj["pk"])
        return sk, pk
    sk=X25519PrivateKey.generate()
    pk=sk.public_key().public_bytes()
    obj={"sk": b64u(sk.private_bytes()), "pk": b64u(pk)}
    open(KX_PATH,"w").write(json.dumps(obj)+"\n")
    os.chmod(KX_PATH, 0o600)
    return sk, pk

# --- anti-rejeu
def gc_nonces():
    now=time.time()
    for k,exp in list(_nonce_cache.items()):
        if exp<now: _nonce_cache.pop(k,None)

def seen_nonce(nonce: str) -> bool:
    gc_nonces(); return nonce in _nonce_cache

def mark_nonce(nonce: str):
    _nonce_cache[nonce]=time.time()+NONCE_TTL_S

# --- nftables
def nft_delete_table():
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def nft_install(p1: int, p2: int, step_ttl: int, pending_ttl: int, open_ttl: int):
    nft_delete_table()
    rules=f"""
add table inet {NFT_TABLE}

add set   inet {NFT_TABLE} {SET_S1}      {{ type ipv4_addr; flags timeout; timeout {step_ttl}s; }}
add set   inet {NFT_TABLE} {SET_S2}      {{ type ipv4_addr; flags timeout; timeout {step_ttl}s; }}
add set   inet {NFT_TABLE} {SET_PENDING} {{ type ipv4_addr; flags timeout; timeout {pending_ttl}s; }}
add set   inet {NFT_TABLE} {SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {open_ttl}s; }}

add chain inet {NFT_TABLE} {NFT_CHAIN_IN} {{ type filter hook input priority -150; policy accept; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_ST}

add rule  inet {NFT_TABLE} {NFT_CHAIN_IN} jump {NFT_CHAIN_ST}
add rule  inet {NFT_TABLE} {NFT_CHAIN_IN} tcp dport {SSH_PORT} ip saddr @{SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN_IN} tcp dport {SSH_PORT} drop

# progression : TCP SYN -> UDP -> ICMP echo
add rule  inet {NFT_TABLE} {NFT_CHAIN_ST} tcp flags syn tcp dport {p1} add @{SET_S1} {{ ip saddr timeout {step_ttl}s }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_ST} ip saddr @{SET_S1} udp dport {p2} add @{SET_S2} {{ ip saddr timeout {step_ttl}s }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_ST} ip saddr @{SET_S2} icmp type echo-request add @{SET_PENDING} {{ ip saddr timeout {pending_ttl}s }}
"""
    tmp="/tmp/poc5_fx.nft"; open(tmp,"w").write(rules)
    run(f"nft -f {tmp}", check=True)
    jlog("nft_ready", p1=p1, p2=p2, step_ttl=step_ttl, pending_ttl=pending_ttl, open_ttl=open_ttl)
    print(f"nftables OK  |  TCP {p1} -> UDP {p2} -> ICMP  |  SSH:{SSH_PORT}")

def nft_ip_in_set(setname: str, ip: str)->bool:
    r=run(f"nft get element inet {NFT_TABLE} {setname} '{{ {ip} }}'")
    return r.returncode==0

def nft_add_allowed(ip: str, ttl: int):
    run(f"nft add element inet {NFT_TABLE} {SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    jlog("open", ip=ip, ttl=ttl)
    print(f"IP autorisee: {ip}  TTL={ttl}s")

# --- sshd
def ensure_sshd():
    run("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
    cfg=f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path="/tmp/poc5_sshd.conf"; open(path,"w").write(cfg)
    subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    jlog("sshd_ready", port=SSH_PORT)
    print(f"sshd ephemere sur 0.0.0.0:{SSH_PORT}")

# --- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version="POC5FX/1.0"

    def _json(self, code:int, obj:Any):
        data=json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path=="/server-info":
            # expose pk X25519
            self._json(200, {"kx_pub": b64u(server_kx_pub), "ssh_port": SSH_PORT, "alg": "X25519+HKDF+ChaCha20-Poly1305,Ed25519"})
            return
        self._json(404, {"error":"not_found"})

    def do_POST(self):
        try:
            ln=int(self.headers.get("Content-Length","0") or "0")
            body=self.rfile.read(ln)
        except Exception:
            self._json(400, {"error":"bad_length"}); return

        if self.path=="/enroll": self.handle_enroll(body); return
        if self.path=="/knock":  self.handle_knock(body);  return
        self._json(404, {"error":"not_found"})

    def handle_enroll(self, body: bytes):
        db=load_clients()
        try:
            obj=json.loads(body.decode())
            kid=str(obj["kid"]).strip()
            pk_raw=de_b64u(str(obj["pubkey"]).strip())
            if len(pk_raw)!=32: self._json(400, {"error":"pubkey_len"}); return
            Ed25519PublicKey.from_public_bytes(pk_raw)  # validation
        except Exception as e:
            jlog("enroll_bad", err=str(e), ip=self.client_address[0])
            self._json(400, {"error":"bad_request"}); return

        prev=db.get(kid)
        db[kid]=b64u(pk_raw); save_clients(db)
        jlog("enroll_ok", kid=kid, ip=self.client_address[0], updated=int(prev is not None))
        self._json(200, {"status":"ok"})

    def handle_knock(self, body: bytes):
        ip=self.client_address[0]
        if not nft_ip_in_set(SET_PENDING, ip):
            jlog("no_pending", ip=ip); self._json(403, {"error":"no_pending"}); return
        try:
            obj=json.loads(body.decode())
            kid   = str(obj["kid"])
            ts    = int(obj["ts"])
            nonce = str(obj["nonce"])
            epk   = de_b64u(str(obj["epk"]))
            iv    = de_b64u(str(obj["iv"]))
            ct    = de_b64u(str(obj["ct"]))
            sig   = de_b64u(str(obj["sig"]))
        except Exception as e:
            jlog("spa_bad_json", ip=ip, err=str(e)); self._json(400, {"error":"bad_json"}); return

        skew=abs(int(time.time())-ts)
        if skew>90:
            jlog("spa_stale", ip=ip, skew=skew); self._json(403, {"error":"stale"}); return
        if seen_nonce(nonce):
            jlog("spa_replay", ip=ip); self._json(403, {"error":"replay"}); return

        db=load_clients()
        pk_b=db.get(kid)
        if not pk_b:
            jlog("unknown_kid", ip=ip, kid=kid); self._json(403, {"error":"unknown_kid"}); return

        try:
            # Vérif signature Ed25519 sur l'ensemble (lie epk/ct/iv au kid)
            edpk=Ed25519PublicKey.from_public_bytes(de_b64u(pk_b))
            to_sign={"kid":kid, "ts":ts, "nonce":nonce, "epk":b64u(epk), "iv":b64u(iv), "ct":b64u(ct)}
            edpk.verify(sig, canon_bytes(to_sign))
        except Exception as e:
            jlog("sig_bad", ip=ip, kid=kid, err=str(e)); self._json(403, {"error":"bad_sig"}); return

        try:
            # Déchiffrement : X25519 ECDH -> HKDF -> ChaCha20-Poly1305
            peer=X25519PublicKey.from_public_bytes(epk)
            shared=server_kx_sk.exchange(peer)
            hk=HKDF(algorithm=hashes.SHA256(), length=32, salt=b"poc5|"+kid.encode(), info=b"spa-v1")
            key=hk.derive(shared)
            aead=ChaCha20Poly1305(key)
            aad=canon_bytes({"kid":kid,"ts":ts,"nonce":nonce,"epk":b64u(epk)})
            pt=aead.decrypt(iv, ct, aad)
            inner=json.loads(pt.decode())
            svc=str(inner.get("svc","ssh")).lower()
            ttl=int(inner.get("ttl", DEFAULT_OPEN_TTL))
        except Exception as e:
            jlog("decrypt_fail", ip=ip, err=str(e)); self._json(403, {"error":"bad_cipher"}); return

        if svc!="ssh":
            jlog("svc_unsupported", ip=ip, svc=svc); self._json(403, {"error":"svc_unsupported"}); return

        ttl=max(5, min(3600, ttl))
        mark_nonce(nonce)
        nft_add_allowed(ip, ttl)
        jlog("verify_ok", ip=ip, kid=kid, svc=svc, ttl=ttl)
        self._json(200, {"status":"ok", "ttl":ttl, "svc":svc})

def nft_primer(p1,p2,step_ttl,pending_ttl,open_ttl):
    nft_install(p1,p2,step_ttl,pending_ttl,open_ttl)

def ensure_sshd():
    run("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
    cfg=f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path="/tmp/poc5_sshd.conf"; open(path,"w").write(cfg)
    subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    jlog("sshd_ready", port=SSH_PORT)
    print(f"sshd ephemere sur 0.0.0.0:{SSH_PORT}")

def main():
    global server_kx_sk, server_kx_pub
    must_root()
    missing=[]
    if not shutil.which("nft"): missing.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): missing.append("openssh-server")
    if missing:
        print("Paquets systeme absents:", ", ".join(missing))
        print("Installe-les (apt/dnf/pacman) avant d’exécuter.")
    ap=argparse.ArgumentParser()
    ap.add_argument("--p1", type=int, default=DEFAULT_P1)
    ap.add_argument("--p2", type=int, default=DEFAULT_P2)
    ap.add_argument("--step-ttl", type=int, default=DEFAULT_STEP_TTL)
    ap.add_argument("--pending-ttl", type=int, default=DEFAULT_PEND_TTL)
    ap.add_argument("--open-ttl", type=int, default=DEFAULT_OPEN_TTL)
    args=ap.parse_args()

    server_kx_sk, server_kx_pub = load_or_create_kx()
    nft_primer(args.p1, args.p2, args.step_ttl, args.pending_ttl, args.open_ttl)
    ensure_sshd()

    httpd=HTTPServer(("0.0.0.0", SPA_HTTP_PORT), Handler)
    t=threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    print(f"Serveur pret | SPA :{SPA_HTTP_PORT} | SSH :{SSH_PORT} | nft: table {NFT_TABLE}")

    def cleanup(*_):
        try: httpd.shutdown()
        except Exception: pass
        nft_delete_table()
        jlog("server_stop")
        print("Nettoyage: nftables supprime. Fin.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        cleanup()

if __name__=="__main__":
    main()
