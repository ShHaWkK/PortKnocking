#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 v2 — Serveur : Knock TCP→UDP→ICMP → fenêtre PENDING → SPA 2-temps (challenge + ECDH+Ed25519)
- Sniff Scapy (interfaces choisies) pour STEP1/STEP2/PENDING
- API HTTP locale :
    POST /enroll   {kid,pubkey}        -> enrôle Ed25519 (idempotent)
    POST /challenge{kid}               -> {chal,srv_pub,exp} (lié à ip et TTL court)
    POST /knock2   {kid,chal,cli_pub,iv,ct,sig} -> déchiffre/valide et nft allow TTL
- nftables: table inet knock5, chain inbound, set allowed (timeout)
- sshd éphémère sur :2222

Usage (local loopback) :
  sudo python3 poc5_server_hard_v2.py 127.0.0.1 --iface lo
"""

import os, sys, time, json, base64, signal, threading, argparse, subprocess, shutil, socket, pwd, getpass, hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple
from statistics import median

# --- crypto
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- constants
SSH_PORT = 2222
LURE_P1  = 47001      # TCP SYN
LURE_P2  = 47002      # UDP
HTTP_BIND_DEFAULT = "127.0.0.1"
HTTP_PORT_DEFAULT = 45445

PENDING_TTL_S = 12    # fenêtre (après ICMP) pour faire challenge + knock2
OPEN_TTL_S    = 60
MAX_SKEW_S    = 20    # tolérance d'horloge pour ts
NONCE_TTL_S   = 300
CHAL_TTL_S    = 12

NFT_TABLE = "knock5"
NFT_CHAIN = "inbound"
NFT_SET   = "allowed"

# --- helpers
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj: dict) -> bytes: return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items())
    print(f"[{tag}] {s}".rstrip(), flush=True)

def run_sh(*cmd, check=False):
    return subprocess.run(list(cmd), text=True, capture_output=True, check=check)

# --- state
class State:
    def __init__(self):
        self.enrolled: Dict[str, bytes] = {}       # kid -> ed25519 pub raw(32)
        self.step1: Dict[str, float] = {}          # ip -> ts
        self.step2: Dict[str, float] = {}
        self.pending: Dict[str, float] = {}        # ip -> expiry
        self.chals: Dict[Tuple[str,str], dict] = {}# (ip,kid)->{chal(str), srv_priv(X25519), exp(float)}
        self.nonces: Dict[Tuple[str,str], float] = {} # (kid,nonce)->exp
        self.open_ttl = OPEN_TTL_S
        self.pending_ttl = PENDING_TTL_S
        self.max_skew = MAX_SKEW_S
        self.http_bind = HTTP_BIND_DEFAULT
        self.http_port = HTTP_PORT_DEFAULT
        self.listen_ip = "127.0.0.1"
        self.sshd_proc = None
        self.stop_evt = threading.Event()

    def gc(self):
        now = time.time()
        for d in (self.step1, self.step2):
            for ip, ts in list(d.items()):
                if now - ts > 30: d.pop(ip, None)
        for ip, exp in list(self.pending.items()):
            if now > exp: self.pending.pop(ip, None)
        for k, exp in list(self.nonces.items()):
            if now > exp: self.nonces.pop(k, None)
        for k, rec in list(self.chals.items()):
            if now > rec["exp"]: self.chals.pop(k, None)

STATE = State()

# --- nftables
def nft_install():
    run_sh("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 || nft add table inet {NFT_TABLE}")
    run_sh("bash","-lc", f"nft list set inet {NFT_TABLE} {NFT_SET} >/dev/null 2>&1 || "
                         f"nft add set inet {NFT_TABLE} {NFT_SET} '{{ type ipv4_addr; flags timeout; timeout {STATE.open_ttl}s; }}'")
    run_sh("bash","-lc", f"nft list chain inet {NFT_TABLE} {NFT_CHAIN} >/dev/null 2>&1 || "
                         f"nft add chain inet {NFT_TABLE} {NFT_CHAIN} '{{ type filter hook input priority -150; policy accept; }}'")
    # accept si ip autorisée, sinon drop sur 2222
    run_sh("bash","-lc", f"nft list ruleset | grep -q '@{NFT_SET} .* tcp dport {SSH_PORT} accept' || "
                         f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr @{NFT_SET} tcp dport {SSH_PORT} accept")
    run_sh("bash","-lc", f"nft list ruleset | grep -q 'tcp dport {SSH_PORT} drop' || "
                         f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop")
    LOG("NFT_READY", table=NFT_TABLE, chain=NFT_CHAIN, set=f"{NFT_SET}=allowed")

def nft_add_allowed(ip: str, ttl: int):
    ttl = max(1, int(ttl))
    run_sh("bash","-lc", f"nft add element inet {NFT_TABLE} {NFT_SET} '{{ {ip} timeout {ttl}s }}'", check=False)
    LOG("OPEN", ip=ip, ttl=ttl)

def nft_cleanup():
    run_sh("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

# --- sshd ephémère
def ensure_host_keys(): run_sh("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
def start_sshd():
    ensure_host_keys()
    cfg = f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path = "/tmp/poc5_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    STATE.sshd_proc = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f":{SSH_PORT}")

def stop_sshd():
    p = STATE.sshd_proc
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(2)
        except: p.kill()

# --- API HTTP
class Api(BaseHTTPRequestHandler):
    server_version = "poc5/2"
    def log_message(self, *args): pass

    def _read_json(self):
        l = int(self.headers.get("Content-Length","0") or "0")
        raw = self.rfile.read(l)
        try: return json.loads(raw.decode()), None
        except Exception as e: return None, str(e)

    def _send(self, code, obj):
        body = json.dumps(obj, separators=(",",":")).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        ip = self.client_address[0]
        STATE.gc()
        data, err = self._read_json()
        if err: return self._send(400, {"error":"bad_json"})

        if self.path == "/enroll":
            kid = (data or {}).get("kid","")
            pkb64 = (data or {}).get("pubkey","")
            try:
                raw = de_b64u(pkb64)
                if len(raw) != 32: return self._send(400, {"error":"pubkey_len"})
                STATE.enrolled[kid] = raw
                LOG("ENROLL_OK", ip=ip, kid=kid)
                return self._send(200, {"ok":True})
            except Exception:
                return self._send(400, {"error":"pubkey_fmt"})

        if self.path == "/challenge":
            kid = (data or {}).get("kid","")
            if kid not in STATE.enrolled: return self._send(404, {"error":"kid_unknown"})
            if ip not in STATE.pending or STATE.pending[ip] < time.time():
                return self._send(409, {"error":"state_not_pending"})
            chal = os.urandom(16)
            srv_priv = X25519PrivateKey.generate()
            exp = time.time()+CHAL_TTL_S
            STATE.chals[(ip,kid)] = {"chal": chal, "srv_priv": srv_priv, "exp": exp}
            LOG("CHAL", ip=ip, kid=kid, exp=int(exp))
            return self._send(200, {"chal": b64u(chal),
                                    "srv_pub": b64u(srv_priv.public_key().public_bytes()),
                                    "exp": int(exp)})

        if self.path == "/knock2":
            try:
                kid   = data["kid"]; chal_b64 = data["chal"]
                cli_b = de_b64u(data["cli_pub"])
                iv    = de_b64u(data["iv"])
                ct    = de_b64u(data["ct"])
                sig   = de_b64u(data["sig"])
            except Exception:
                return self._send(400, {"error":"bad_json"})

            if kid not in STATE.enrolled: return self._send(404, {"error":"kid_unknown"})
            if ip not in STATE.pending or STATE.pending[ip] < time.time():
                return self._send(409, {"error":"state_not_pending"})

            rec = STATE.chals.get((ip,kid))
            if not rec: return self._send(409, {"error":"challenge_missing"})
            chal = rec["chal"]
            if b64u(chal) != chal_b64: return self._send(409, {"error":"challenge_mismatch"})

            # dérive clé ECDH (X25519) + chal
            try:
                srv_priv: X25519PrivateKey = rec["srv_priv"]
                shared = srv_priv.exchange(X25519PublicKey.from_public_bytes(cli_b))
                key = hashlib.sha256(shared + chal + b"|poc5v2").digest()
                aad = canon_bytes({"kid": kid, "chal": chal_b64})
                pt  = AESGCM(key).decrypt(iv, ct, aad)
                payload = json.loads(pt.decode())
            except Exception as e:
                return self._send(400, {"error":"decrypt_fail"})

            # signature Ed25519 sur {kid,chal,duration,nonce,ts} (canon)
            try:
                msg = {"kid": kid, "chal": chal_b64,
                       "duration": int(payload["duration"]),
                       "nonce": str(payload["nonce"]), "ts": int(payload["ts"])}
                Ed25519PublicKey.from_public_bytes(STATE.enrolled[kid]).verify(sig, canon_bytes(msg))
            except Exception:
                return self._send(400, {"error":"sig_bad"})

            # contrôles temps + anti-rejeu
            now = int(time.time())
            if abs(now - int(payload["ts"])) > STATE.max_skew:
                return self._send(400, {"error":"ts_skew"})
            kn = (kid, str(payload["nonce"]))
            if kn in STATE.nonces: return self._send(409, {"error":"nonce_replay"})
            STATE.nonces[kn] = time.time()+NONCE_TTL_S

            # ouverture
            ttl = int(payload.get("duration") or STATE.open_ttl)
            nft_add_allowed(ip, ttl)
            return self._send(200, {"ok": True, "ttl": ttl})

        return self._send(404, {"error":"not_found"})

# --- sniff Scapy
def start_sniffer(iface: str, listen_ip: str):
    from scapy.all import sniff, TCP, UDP, ICMP, IP  # type: ignore
    bpf = f"dst host {listen_ip} and (tcp or udp or icmp)"
    LOG("LISTEN", iface=iface, bpf=bpf)

    def cb(p):
        try:
            if not p.haslayer(IP): return
            ip = p[IP].src
            now = float(p.time)
            # STEP1 : TCP SYN -> LURE_P1
            if p.haslayer(TCP):
                t = p[TCP]
                if t.dport == LURE_P1 and (t.flags & 0x02) and not (t.flags & 0x10):
                    STATE.step1[ip] = now
                    LOG("STEP1", ip=ip); return
            # STEP2 : UDP -> LURE_P2 (si STEP1 récente)
            if p.haslayer(UDP):
                u = p[UDP]
                if u.dport == LURE_P2 and ip in STATE.step1 and now-STATE.step1[ip] < 5:
                    STATE.step2[ip] = now
                    LOG("STEP2", ip=ip); return
            # PENDING : ICMP echo (si STEP2 récente)
            if p.haslayer(ICMP):
                ic = p[ICMP]
                if getattr(ic, "type", None) == 8 and ip in STATE.step2 and now-STATE.step2[ip] < 5:
                    STATE.pending[ip] = time.time() + STATE.pending_ttl
                    LOG("PENDING", ip=ip, ttl=f"{STATE.pending_ttl:.1f}")
                    return
        except Exception as e:
            LOG("SNIFF_ERR", err=str(e))
    t = threading.Thread(target=lambda: sniff(iface=iface, filter=bpf, prn=cb, store=False,
                                              stop_filter=lambda x: STATE.stop_evt.is_set()),
                         daemon=True)
    t.start()
    return t

# --- lifecycle
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

    ap = argparse.ArgumentParser()
    ap.add_argument("listen_ip", help="IP du serveur (pour le BPF : dst host ...)")
    ap.add_argument("--iface", default="lo", help="Interface à sniffer (ex: lo,eth0)")
    ap.add_argument("--http-bind", default=HTTP_BIND_DEFAULT)
    ap.add_argument("--http-port", type=int, default=HTTP_PORT_DEFAULT)
    ap.add_argument("--p1", type=int, default=LURE_P1)
    ap.add_argument("--p2", type=int, default=LURE_P2)
    ap.add_argument("--open-ttl", type=int, default=OPEN_TTL_S)
    args = ap.parse_args()

    STATE.listen_ip = args.listen_ip
    STATE.http_bind = args.http_bind
    STATE.http_port = args.http_port
    STATE.open_ttl  = args.open_ttl

    # nftables + sshd
    nft_install()
    start_sshd()

    # API HTTP
    server = ThreadingHTTPServer((STATE.http_bind, STATE.http_port), Api)
    th_api = threading.Thread(target=server.serve_forever, daemon=True)
    th_api.start()
    LOG("HTTP", bind=f"{STATE.http_bind}:{STATE.http_port}")
    LOG("READY", bind=args.listen_ip, p1=args.p1, p2=args.p2, http=STATE.http_port, ssh=SSH_PORT)
    LOG("HINT", msg="sequence TCP->UDP->ICMP puis POST /challenge et /knock2 (SPA chiffré + signé)")

    # Scapy
    th_sniff = start_sniffer(args.iface, args.listen_ip)

    def _sig(*_):
        STATE.stop_evt.set()
        try: server.shutdown()
        except: pass
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)

    try:
        while not STATE.stop_evt.is_set():
            time.sleep(0.5); STATE.gc()
    finally:
        cleanup()

if __name__ == "__main__":
    try: main()
    except Exception as e:
        LOG("FATAL", err=str(e))
        cleanup()
        sys.exit(1)
