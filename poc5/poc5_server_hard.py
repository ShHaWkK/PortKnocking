#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Serveur : Knock multi-protocole + SPA HTTP signé Ed25519 + nftables.
- Écoute des knocks: TCP SYN -> P1, puis UDP -> P2, puis ICMP Echo.
- Fenêtre entre étapes (step_gap) et TTL de grâce pending (pending_ttl).
- API HTTP locale: /enroll (enrôlement clé pub) et /knock (SPA signé).
- Ouverture dynamique via nftables (set @allowed timeout=TTL).
- sshd éphémère sur :2222 (optionnel/automatique pour la démo).

Usage:
  sudo python3 poc5_server_hard.py <BIND_IP> [--p1 47001 --p2 47002 --iface lo --spa-http 45445]
"""

import os, sys, time, json, argparse, base64, signal, threading, subprocess, socket, hashlib
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    print("Installe le paquet Python 'cryptography' (pip install cryptography).", file=sys.stderr)
    sys.exit(1)

# ------- Constantes -------
SSH_PORT       = 2222
NFT_TABLE      = "knock5"
NFT_CHAIN      = "inbound"
NFT_SET        = "allowed"
KDB_PATH       = "/etc/portknock/poc5_enrolled.json"  # kid->pubkey(raw b64url)
LOG_PATH       = "/var/log/portknock/poc5_server.jsonl"
DEFAULT_P1     = 47001
DEFAULT_P2     = 47002
DEFAULT_HTTP   = 45445
STEP_GAP_S     = 2.0        # délai max entre étapes de la séquence
PENDING_TTL_S  = 8.0        # grâce SPA après ICMP ok
TS_SKEW_MAX    = 90         # anti-rejeu SPA (timestamp)
NONCE_TTL_S    = 180        # anti-rejeu SPA (nonce cache)

# ------- État -------
states = {}         # ip -> {"stage":0..2,"last":monotonic}
pending = {}        # ip -> expiry_monotonic
used_nonce = {}     # nonce -> expiry_monotonic
stop_evt = threading.Event()
httpd = None
_sshd = None

# ------- util -------
def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items())
    print(f"[{tag}] {s}", flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        row = {"ts": datetime.utcnow().isoformat()+"Z", "event": tag}
        row.update(kw)
        with open(LOG_PATH, "a") as f: f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass

def must_root():
    if os.geteuid()!=0:
        print("Lance ce serveur avec sudo.", file=sys.stderr)
        sys.exit(1)

def b64u(b: bytes) -> str:  return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj) -> bytes: return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def nft_run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def nft_setup(open_ttl_default=60):
    nft_run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 || nft add table inet {NFT_TABLE}", check=False)
    nft_run(f"nft list set inet {NFT_TABLE} {NFT_SET} >/dev/null 2>&1 || "
            f"nft add set inet {NFT_TABLE} {NFT_SET} '{{ type ipv4_addr; flags timeout; timeout {open_ttl_default}s; }}'", check=False)
    nft_run(f"nft list chain inet {NFT_TABLE} {NFT_CHAIN} >/dev/null 2>&1 || "
            f"nft add chain inet {NFT_TABLE} {NFT_CHAIN} '{{ type filter hook input priority -150; policy accept; }}'", check=False)
    # règle d'invisibilité SSH : autorise si @allowed, sinon drop
    nft_run(f"nft list ruleset | grep -q 'tcp dport {SSH_PORT} .* @{NFT_SET} ' || "
            f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} ip saddr @{NFT_SET} accept", check=False)
    nft_run(f"nft list ruleset | grep -q 'tcp dport {SSH_PORT} drop' || "
            f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop", check=False)
    LOG("NFT_READY", table=NFT_TABLE, chain=NFT_CHAIN, set=NFT_SET)

def nft_allow(ip: str, ttl: int):
    ttl = max(5, int(ttl))
    nft_run(f"nft add element inet {NFT_TABLE} {NFT_SET} '{{ {ip} timeout {ttl}s }}'", check=False)
    LOG("OPEN", ip=ip, ttl=ttl)

def nft_cleanup():
    nft_run(f"nft delete table inet {NFT_TABLE}", check=False)

def ensure_sshd():
    global _sshd
    cfg = f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    p = "/tmp/poc5_sshd.conf"
    with open(p,"w") as f: f.write(cfg)
    subprocess.run("ssh-keygen -A >/dev/null 2>&1", shell=True, check=False)
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",p],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f":{SSH_PORT}")

def stop_sshd():
    global _sshd
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()

def _gc():
    now = time.monotonic()
    for ip,exp in list(pending.items()):
        if now > exp: pending.pop(ip, None)
    for n,exp in list(used_nonce.items()):
        if now > exp: used_nonce.pop(n, None)

def load_kdb():
    if not os.path.exists(KDB_PATH): return {}
    try:
        return json.loads(open(KDB_PATH).read())
    except Exception:
        return {}

def save_kdb(kdb: dict):
    os.makedirs(os.path.dirname(KDB_PATH), exist_ok=True)
    tmp = KDB_PATH + ".tmp"
    with open(tmp, "w") as f: json.dump(kdb, f, ensure_ascii=False)
    os.replace(tmp, KDB_PATH)
    os.chmod(KDB_PATH, 0o600)

# ------- HTTP API (/enroll, /knock) -------
class Api(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n>0 else b"{}"
        try: return json.loads(raw.decode())
        except Exception: return {}

    def _send(self, code=200, obj=None):
        data = json.dumps(obj or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        _gc()
        ip = self.client_address[0]
        body = self._json()
        kdb = load_kdb()

        if self.path == "/enroll":
            kid = str(body.get("kid","")).strip()
            pkb = str(body.get("pubkey","")).strip()
            try:
                raw = de_b64u(pkb)
                if len(raw) != 32: raise ValueError("bad pub")
                calc = hashlib.sha256(raw).hexdigest()[:16]
                if calc != kid: raise ValueError("kid mismatch")
            except Exception:
                LOG("ENROLL_BAD", ip=ip)
                return self._send(400, {"ok": False, "err":"invalid_key"})
            if kid not in kdb:
                kdb[kid] = pkb
                save_kdb(kdb)
                LOG("ENROLL_OK", ip=ip, kid=kid)
            return self._send(200, {"ok": True})

        if self.path == "/knock":
            # SPA signé Ed25519
            if ip not in pending:
                LOG("SPA_NO_PENDING", ip=ip)
                return self._send(403, {"ok": False, "err":"no_pending"})
            kid  = str(body.get("kid",""))
            ts   = int(body.get("ts", 0))
            nonce= str(body.get("nonce",""))
            dur  = int(body.get("duration", 0))
            sigb = body.get("sig","")
            if not kid or not sigb or kid not in kdb:
                return self._send(400, {"ok": False, "err":"bad_kid"})
            if abs(int(time.time()) - ts) > TS_SKEW_MAX:
                return self._send(400, {"ok": False, "err":"stale"})
            if nonce in used_nonce:
                return self._send(409, {"ok": False, "err":"replay"})
            try:
                pk = Ed25519PublicKey.from_public_bytes(de_b64u(kdb[kid]))
                payload = {"duration": int(dur), "kid": kid, "nonce": nonce, "ts": int(ts)}
                pk.verify(de_b64u(sigb), canon_bytes(payload))
            except Exception:
                LOG("SPA_BAD_SIG", ip=ip, kid=kid)
                return self._send(403, {"ok": False, "err":"sig"})
            used_nonce[nonce] = time.monotonic() + NONCE_TTL_S
            pending.pop(ip, None)
            ttl = max(5, min(3600, int(dur) if dur else 60))
            nft_allow(ip, ttl)
            return self._send(200, {"ok": True, "ttl": ttl})

        self._send(404, {"ok": False})

# ------- Sniffer (Scapy) -------
def sniffer(bind_ip: str, iface: str, p1: int, p2: int):
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore
    bpf = f"dst host {bind_ip} and ((tcp and dst port {p1}) or (udp and dst port {p2}) or (icmp and icmp[icmptype]=8))"
    LOG("LISTEN", iface=iface, bpf=bpf)
    def _cb(pkt):
        try:
            if not pkt.haslayer(IP): return
            ip = pkt[IP].src
            now = time.monotonic()
            st = states.get(ip, {"stage":0,"last":0.0})

            # Étape 1: TCP SYN -> p1
            if pkt.haslayer(TCP) and pkt[TCP].dport == p1 and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
                st = {"stage":1, "last": now}
                states[ip] = st
                LOG("STEP1", ip=ip)
                return

            # Étape 2: UDP -> p2 (dans le délai)
            if st["stage"] == 1 and pkt.haslayer(UDP) and pkt[UDP].dport == p2 and (now - st["last"]) <= STEP_GAP_S:
                st["stage"] = 2; st["last"] = now
                states[ip] = st
                LOG("STEP2", ip=ip)
                return

            # Étape 3: ICMP Echo (dans le délai)
            if st["stage"] == 2 and pkt.haslayer(ICMP) and int(pkt[ICMP].type) == 8 and (now - st["last"]) <= STEP_GAP_S:
                states.pop(ip, None)
                pending[ip] = now + PENDING_TTL_S
                LOG("PENDING", ip=ip, ttl=PENDING_TTL_S)
                return

            # Reset si bruit hors séquence ou délai dépassé
            if st["stage"] and (now - st["last"]) > STEP_GAP_S:
                states.pop(ip, None)
        except Exception as e:
            LOG("SNIFF_ERR", err=str(e))

    sniff(iface=iface, filter=bpf, prn=_cb, store=False, stop_filter=lambda p: stop_evt.is_set())

# ------- HTTP thread -------
def start_http(bind: str, port: int):
    global httpd
    LOG("HTTP", bind=bind, port=port)
    httpd = HTTPServer((bind, port), Api)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

def stop_http():
    if httpd:
        try: httpd.shutdown()
        except Exception: pass

# ------- Main -------
def main():
    must_root()
    ap = argparse.ArgumentParser()
    ap.add_argument("bind", help="IP locale à protéger (ex: 127.0.0.1)")
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--p1", type=int, default=DEFAULT_P1)
    ap.add_argument("--p2", type=int, default=DEFAULT_P2)
    ap.add_argument("--spa-http", type=int, default=DEFAULT_HTTP)
    args = ap.parse_args()

    nft_setup()
    ensure_sshd()
    start_http(args.bind, args.spa_http)

    t = threading.Thread(target=sniffer, args=(args.bind, args.iface, args.p1, args.p2), daemon=True)
    t.start()

    LOG("READY", bind=args.bind, p1=args.p1, p2=args.p2, http=args.spa_http, ssh=SSH_PORT)
    LOG("HINT", msg="sequence TCP->UDP->ICMP puis POST /knock (SPA signé)")

    def _sig(_s,_f): stop_evt.set()
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)

    try:
        while not stop_evt.is_set():
            _gc(); time.sleep(0.3)
    finally:
        stop_http(); stop_sshd(); nft_cleanup()
        LOG("CLEANUP")

if __name__ == "__main__":
    main()
