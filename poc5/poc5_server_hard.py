#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 v3 — Serveur : TCP→UDP→ICMP → PENDING → SPA 2-temps (challenge + ECDH+Ed25519 + TOTP)
- Rotation p1/p2 périodique (annoncée via /ports).
- Rate-limit par IP (challenge/knock2).
- Anti-rejeu (nonce), horloge tolérante, challenge éphémère lié à l'IP.
- nftables ouvre SSH:2222 pour l’IP demandeuse avec TTL.
- sshd éphémère (port 2222).
Usage :
  sudo python3 poc5_server_hard_v3.py 127.0.0.1 --iface lo
"""

import os, sys, time, json, base64, signal, threading, argparse, subprocess, socket, hashlib, random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import deque, defaultdict
from typing import Dict, Tuple, Deque

# ---- Dépendances crypto/scapy/pyotp
def _need(mod, pipname=None):
    try:
        __import__(mod)
        return True
    except Exception:
        try:
            import subprocess
            subprocess.run([sys.executable,"-m","pip","install","-q",pipname or mod], check=True)
            __import__(mod); return True
        except Exception:
            print(f"[ERREUR] Module requis '{mod}'. Installez-le : pip install {pipname or mod}", file=sys.stderr)
            sys.exit(1)

_need("cryptography"); _need("scapy"); _need("pyotp")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import pyotp  # type: ignore

# ---- Constantes
SSH_PORT = 2222
HTTP_BIND_DEFAULT = "127.0.0.1"
HTTP_PORT_DEFAULT = 45445

PENDING_TTL_S = 12
OPEN_TTL_S    = 60
MAX_SKEW_S    = 20
NONCE_TTL_S   = 300
CHAL_TTL_S    = 12

ROTATE_S      = 60              # période de rotation p1/p2
PORT_MIN, PORT_MAX = 40000, 50000

NFT_TABLE = "knock5"
NFT_CHAIN = "inbound"
NFT_SET   = "allowed"

# ---- Utils
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj: dict) -> bytes: return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
def LOG(tag, **kw): print(f"[{tag}] " + " ".join(f"{k}={v}" for k,v in kw.items()), flush=True)
def sh(*cmd, check=False): return subprocess.run(list(cmd), text=True, capture_output=True, check=check)

# ---- État
class RateLimiter:
    def __init__(self, capacity:int, per_s:int):
        self.capacity=capacity; self.per_s=per_s
        self.buckets: Dict[str, Deque[float]] = defaultdict(deque)
    def allow(self, ip:str)->bool:
        now=time.time(); dq=self.buckets[ip]
        while dq and now-dq[0]>self.per_s: dq.popleft()
        if len(dq)>=self.capacity: return False
        dq.append(now); return True

class State:
    def __init__(self):
        self.listen_ip = "127.0.0.1"
        self.http_bind = HTTP_BIND_DEFAULT
        self.http_port = HTTP_PORT_DEFAULT

        self.enrolled: Dict[str, bytes] = {}     # kid -> Ed25519 pub (32)
        self.totp_b32: Dict[str, str] = {}       # kid -> base32 secret

        self.step1: Dict[str, float] = {}        # ip -> ts (TCP p1)
        self.step2: Dict[str, float] = {}        # ip -> ts (UDP p2)
        self.pending: Dict[str, float] = {}      # ip -> expire

        self.nonces: Dict[Tuple[str,str], float] = {}  # (kid,nonce)->expire
        self.chals: Dict[Tuple[str,str], dict]  = {}   # (ip,kid)->{chal,srv_priv,exp}

        self.open_ttl = OPEN_TTL_S
        self.pending_ttl = PENDING_TTL_S
        self.skew = MAX_SKEW_S

        # rotation p1/p2
        self.seed = os.urandom(32)
        self.windows = []  # list of {"p1":..,"p2":..,"exp":..}
        self.rotate_period = ROTATE_S

        self.sshd = None
        self.stop_evt = threading.Event()

        # Rate-limit (par IP)
        self.rl_chal   = RateLimiter(capacity=6, per_s=60)  # 6/min
        self.rl_knock2 = RateLimiter(capacity=6, per_s=60)  # 6/min

    # ports courants + fenêtre précédente (pour absorber les courses)
    def active_windows(self):
        if not self.windows: roll_ports()
        return self.windows[-2:] if len(self.windows)>=2 else self.windows

STATE = State()

# ---- nftables & sshd
def nft_install():
    sh("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 || nft add table inet {NFT_TABLE}")
    sh("bash","-lc", f"nft list set inet {NFT_TABLE} {NFT_SET} >/dev/null 2>&1 || "
                     f"nft add set inet {NFT_TABLE} {NFT_SET} '{{ type ipv4_addr; flags timeout; timeout {STATE.open_ttl}s; }}'")
    sh("bash","-lc", f"nft list chain inet {NFT_TABLE} {NFT_CHAIN} >/dev/null 2>&1 || "
                     f"nft add chain inet {NFT_TABLE} {NFT_CHAIN} '{{ type filter hook input priority -150; policy accept; }}'")
    sh("bash","-lc", f"nft list ruleset | grep -q '@{NFT_SET} .* tcp dport {SSH_PORT} accept' || "
                     f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr @{NFT_SET} tcp dport {SSH_PORT} accept")
    sh("bash","-lc", f"nft list ruleset | grep -q 'tcp dport {SSH_PORT} drop' || "
                     f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop")
    LOG("NFT_READY", table=NFT_TABLE, chain=NFT_CHAIN, set=NFT_SET)

def nft_add_allowed(ip:str, ttl:int):
    ttl=max(1,int(ttl))
    sh("bash","-lc", f"nft add element inet {NFT_TABLE} {NFT_SET} '{{ {ip} timeout {ttl}s }}'")
    LOG("OPEN", ip=ip, ttl=ttl)

def nft_cleanup():
    sh("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def ensure_host_keys(): sh("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
def start_sshd():
    ensure_host_keys()
    cfg=f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path="/tmp/poc5_sshd.conf"; open(path,"w").write(cfg)
    STATE.sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f":{SSH_PORT}")
def stop_sshd():
    p=STATE.sshd
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(2)
        except: p.kill()

# ---- Rotation ports
def _derive_port(tag:bytes)->int:
    h=hashlib.sha256(STATE.seed+tag).digest()
    return PORT_MIN + (int.from_bytes(h[:2],"big") % (PORT_MAX-PORT_MIN))
def roll_ports():
    now=time.time()
    p1=_derive_port(b"p1|"+now.to_bytes(8,"big",signed=False))
    p2=_derive_port(b"p2|"+now.to_bytes(8,"big",signed=False))
    if p2==p1: p2 = PORT_MIN + ((p1+137) % (PORT_MAX-PORT_MIN))
    exp = now + STATE.rotate_period
    STATE.windows.append({"p1":p1,"p2":p2,"exp":exp})
    STATE.windows[:] = STATE.windows[-3:]
    LOG("PORTS", p1=p1, p2=p2, exp=int(exp))

def rotator_thread():
    while not STATE.stop_evt.is_set():
        if not STATE.windows or STATE.windows[-1]["exp"] <= time.time():
            roll_ports()
        time.sleep(1.0)

# ---- GC
def gc():
    now=time.time()
    for d,ttl in ((STATE.step1,30),(STATE.step2,30)):
        for ip,t in list(d.items()):
            if now-t>ttl: d.pop(ip,None)
    for ip,ex in list(STATE.pending.items()):
        if now>ex: STATE.pending.pop(ip,None)
    for k,ex in list(STATE.nonces.items()):
        if now>ex: STATE.nonces.pop(k,None)
    for k,rec in list(STATE.chals.items()):
        if now>rec["exp"]: STATE.chals.pop(k,None)

# ---- API HTTP
class Api(BaseHTTPRequestHandler):
    server_version="poc5/3"
    def log_message(self, *a, **k): pass

    def _send(self, code, obj):
        b=json.dumps(obj,separators=(",",":")).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _read_json(self):
        ln=int(self.headers.get("Content-Length","0") or "0")
        raw=self.rfile.read(ln)
        try: return json.loads(raw.decode())
        except Exception: return None

    def do_GET(self):
        if self.path=="/ports":
            gc()
            cur = STATE.active_windows()[-1]
            return self._send(200, {"p1":cur["p1"], "p2":cur["p2"], "exp":int(cur["exp"])})
        return self._send(404, {"error":"not_found"})

    def do_POST(self):
        ip=self.client_address[0]
        gc()
        data=self._read_json() or {}

        if self.path=="/enroll":
            kid=data.get("kid",""); pkb64=data.get("pubkey",""); totp_b32=data.get("totp_b32")
            try:
                raw=de_b64u(pkb64); 
                if len(raw)!=32: return self._send(400, {"error":"pubkey_len"})
                STATE.enrolled[kid]=raw
            except Exception:
                return self._send(400, {"error":"pubkey_fmt"})
            # TOTP : si non fourni, on en génère un (POC)
            if not totp_b32:
                totp_b32=pyotp.random_base32()
            STATE.totp_b32[kid]=totp_b32
            LOG("ENROLL_OK", ip=ip, kid=kid)
            return self._send(200, {"ok":True, "totp_b32": totp_b32})

        if self.path=="/challenge":
            kid=data.get("kid","")
            if kid not in STATE.enrolled: return self._send(404, {"error":"kid_unknown"})
            if ip not in STATE.pending or STATE.pending[ip]<time.time():
                return self._send(409, {"error":"state_not_pending"})
            if not STATE.rl_chal.allow(ip): return self._send(429, {"error":"rate_limit"})
            chal=os.urandom(16); srv_priv=X25519PrivateKey.generate(); exp=time.time()+CHAL_TTL_S
            STATE.chals[(ip,kid)]={"chal":chal,"srv_priv":srv_priv,"exp":exp}
            LOG("CHAL", ip=ip, kid=kid, exp=int(exp))
            return self._send(200, {"chal":b64u(chal),
                                    "srv_pub": b64u(srv_priv.public_key().public_bytes(
                                        serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                                    "exp":int(exp)})

        if self.path=="/knock2":
            if not STATE.rl_knock2.allow(ip): return self._send(429, {"error":"rate_limit"})
            try:
                kid=data["kid"]; chal_b64=data["chal"]
                cli_pub=de_b64u(data["cli_pub"]); iv=de_b64u(data["iv"]); ct=de_b64u(data["ct"]); sig=de_b64u(data["sig"])
            except Exception:
                return self._send(400, {"error":"bad_json"})
            if kid not in STATE.enrolled: return self._send(404, {"error":"kid_unknown"})
            if ip not in STATE.pending or STATE.pending[ip]<time.time(): return self._send(409, {"error":"state_not_pending"})
            rec=STATE.chals.get((ip,kid)); 
            if not rec: return self._send(409, {"error":"challenge_missing"})
            chal=rec["chal"]; 
            if b64u(chal)!=chal_b64: return self._send(409, {"error":"challenge_mismatch"})
            # déchiffrement
            try:
                shared:bytes = rec["srv_priv"].exchange(X25519PublicKey.from_public_bytes(cli_pub))
                key=hashlib.sha256(shared+chal+b"|poc5v3").digest()
                aad=canon_bytes({"kid":kid,"chal":chal_b64})
                pt=AESGCM(key).decrypt(iv, ct, aad)
                payload=json.loads(pt.decode())
            except Exception:
                return self._send(400, {"error":"decrypt_fail"})
            # signature
            try:
                msg={"kid":kid,"chal":chal_b64,"duration":int(payload["duration"]),
                     "nonce":str(payload["nonce"]), "ts":int(payload["ts"]), "totp":str(payload["totp"])}
                Ed25519PublicKey.from_public_bytes(STATE.enrolled[kid]).verify(sig, canon_bytes(msg))
            except Exception:
                return self._send(400, {"error":"sig_bad"})
            # temps + anti-rejeu
            now=int(time.time())
            if abs(now-int(payload["ts"]))>STATE.skew: return self._send(400, {"error":"ts_skew"})
            nn=(kid,str(payload["nonce"]))
            if nn in STATE.nonces: return self._send(409, {"error":"nonce_replay"})
            STATE.nonces[nn]=time.time()+NONCE_TTL_S
            # TOTP
            tsec=STATE.totp_b32.get(kid)
            if not tsec: return self._send(500, {"error":"totp_missing"})
            totp=pyotp.TOTP(tsec)
            if not totp.verify(str(payload["totp"]), valid_window=1):  # fenêtre +/-30s
                return self._send(401, {"error":"totp_bad"})
            # open
            ttl=int(payload.get("duration") or STATE.open_ttl)
            nft_add_allowed(ip, ttl)
            return self._send(200, {"ok":True, "ttl":ttl})

        return self._send(404, {"error":"not_found"})

# ---- Sniffer Scapy
def start_sniffer(iface:str, listen_ip:str):
    from scapy.all import sniff, TCP, UDP, ICMP, IP  # type: ignore
    bpf=f"dst host {listen_ip} and (tcp or udp or icmp)"
    LOG("LISTEN", iface=iface, bpf=bpf)
    def _cb(p):
        try:
            if not p.haslayer(IP): return
            ip=p[IP].src; now=float(p.time)
            wins=STATE.active_windows()
            # Étape 1 : TCP SYN -> p1
            if p.haslayer(TCP):
                t=p[TCP]
                if any(t.dport==w["p1"] for w in wins) and (t.flags & 0x02) and not (t.flags & 0x10):
                    STATE.step1[ip]=now; LOG("STEP1", ip=ip); return
            # Étape 2 : UDP -> p2 (si STEP1<5s)
            if p.haslayer(UDP):
                u=p[UDP]
                if any(u.dport==w["p2"] for w in wins) and ip in STATE.step1 and now-STATE.step1[ip]<5:
                    STATE.step2[ip]=now; LOG("STEP2", ip=ip); return
            # PENDING : ICMP echo (si STEP2<5s)
            if p.haslayer(ICMP):
                ic=p[ICMP]
                if getattr(ic,"type",None)==8 and ip in STATE.step2 and now-STATE.step2[ip]<5:
                    STATE.pending[ip]=time.time()+STATE.pending_ttl
                    LOG("PENDING", ip=ip, ttl=STATE.pending_ttl); return
        except Exception as e:
            LOG("SNIFF_ERR", err=str(e))
    t=threading.Thread(target=lambda: sniff(iface=iface, filter=bpf, prn=_cb, store=False,
                                            stop_filter=lambda x: STATE.stop_evt.is_set()),
                       daemon=True)
    t.start(); return t

# ---- Cycle de vie
def cleanup():
    try: STATE.stop_evt.set()
    except: pass
    try: stop_sshd()
    except: pass
    try: nft_cleanup()
    except: pass
    LOG("CLEAN")

def main():
    if os.geteuid()!=0:
        print("Lancer en root (sudo).", file=sys.stderr); sys.exit(1)

    ap=argparse.ArgumentParser()
    ap.add_argument("listen_ip", help="IP sur laquelle on écoute les knocks (ex: 127.0.0.1)")
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--http-bind", default=HTTP_BIND_DEFAULT)
    ap.add_argument("--http-port", type=int, default=HTTP_PORT_DEFAULT)
    ap.add_argument("--open-ttl", type=int, default=OPEN_TTL_S)
    ap.add_argument("--rotate", type=int, default=ROTATE_S, help="période de rotation p1/p2")
    args=ap.parse_args()

    STATE.listen_ip=args.listen_ip
    STATE.http_bind=args.http_bind
    STATE.http_port=args.http_port
    STATE.open_ttl=args.open_ttl
    STATE.rotate_period=max(20,args.rotate)

    nft_install(); start_sshd()

    # API
    srv=ThreadingHTTPServer((STATE.http_bind, STATE.http_port), Api)
    th_api=threading.Thread(target=srv.serve_forever, daemon=True); th_api.start()
    LOG("HTTP", bind=f"{STATE.http_bind}:{STATE.http_port}")
    LOG("READY", ip=args.listen_ip, http=STATE.http_port, ssh=SSH_PORT)
    LOG("HINT", msg="Knock TCP->UDP->ICMP, puis /challenge et /knock2")

    # Rotation + Sniffer
    th_rot=threading.Thread(target=rotator_thread, daemon=True); th_rot.start()
    th_sniff=start_sniffer(args.iface, args.listen_ip)

    def _sig(*_):
        STATE.stop_evt.set()
        try: srv.shutdown()
        except: pass
    signal.signal(signal.SIGINT,_sig); signal.signal(signal.SIGTERM,_sig)

    try:
        while not STATE.stop_evt.is_set():
            time.sleep(0.5); gc()
    finally:
        cleanup()

if __name__=="__main__":
    main()
