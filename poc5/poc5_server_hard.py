#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Serveur « hard »
- Séquence : TCP SYN -> UDP -> ICMP Echo
- Rotation P1/P2 déterministe (HMAC(secret, window)) ; tolère fenêtre N-1
- API HTTP : GET /ports, POST /enroll, POST /knock (SPA signé Ed25519)
- TOTP optionnel (généré automatiquement si absent)
- Rate-limit côté API (token bucket), pas de rate-limit sur le sniff
- Ouverture via nftables (@allowed timeout) sur SSH:2222
Usage :
  sudo python3 poc5_server_hard.py 127.0.0.1 --iface lo
"""

import os, sys, time, json, base64, argparse, signal, threading, struct, hashlib, hmac, subprocess, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple, Optional

# ---------- paramètres
SSH_PORT, HTTP_PORT = 2222, 45445
NFT_TABLE, NFT_CHAIN, NFT_SET = "knock5", "inbound", "allowed"

OPEN_TTL_S      = 60      # TTL d'ouverture SSH
STEP_TTL_S      = 10      # délai max entre étapes
PENDING_TTL_S   = 8       # fenêtre SPA après l’ICMP
ROTATE_PERIOD_S = 30      # rotation P1/P2
PORT_MIN, PORT_MAX = 47000, 48999

MASTER_SECRET_PATH = "/etc/portknock/secret"        # base64
TOTP_PATH          = "/etc/portknock/totp_base32"   # base32
ENROLL_DB          = "/etc/portknock/keys.json"     # {kid: pub_raw_b64u}

# rate-limit pour l’API (pas le sniff)
RL_API_BURST = 20.0
RL_API_RATE  = 10.0   # jetons par seconde

# ---------- libs externes
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    print("Installer : pip install cryptography", file=sys.stderr); sys.exit(1)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore
except Exception:
    print("Installer : pip install scapy", file=sys.stderr); sys.exit(1)

# ---------- utilitaires
def must_root():
    if os.geteuid() != 0:
        print("Lancer en root (sudo).", file=sys.stderr); sys.exit(1)

def LOG(tag, **kw):
    print(f"[{tag}] " + " ".join(f"{k}={v}" for k, v in kw.items()), flush=True)

def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj) -> bytes: return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def run(cmd: str) -> Tuple[int, str, str]:
    p = subprocess.run(["bash","-lc",cmd], capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

# TOTP minimal (RFC6238, SHA-1, 6 digits)
def b32_read(raw: str) -> bytes:
    tok = "".join(raw.strip().split())
    return base64.b32decode(tok.upper())
def totp_now(secret: bytes, for_time: int, step=30, digits=6) -> int:
    ctr = int(for_time // step)
    msg = struct.pack(">Q", ctr)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = ((digest[off] & 0x7F) << 24) | (digest[off+1] << 16) | (digest[off+2] << 8) | digest[off+3]
    return code % (10**digits)
def totp_verify(secret: bytes, code: int, now_ts: int) -> bool:
    for k in (-1, 0, 1):
        if totp_now(secret, now_ts + 30*k) == code:
            return True
    return False

# dérivation P1/P2
def derive_port(secret: bytes, label: bytes, lo: int, hi: int) -> int:
    dig = hmac.new(secret, label, hashlib.sha256).digest()
    val = int.from_bytes(dig[:2], "big")
    return lo + (val % (hi - lo + 1))

def win_id(period: int) -> int: return int(time.time() // period)

# ---------- état
class State:
    bind_ip: str = "127.0.0.1"
    ifaces: list = []
    rotate_s: int = ROTATE_PERIOD_S
    step_ttl: int = STEP_TTL_S
    pending_ttl: int = PENDING_TTL_S
    open_ttl: int = OPEN_TTL_S
    master: bytes = b""
    totp_secret: Optional[bytes] = None
    windows: list = []              # [{win,p1,p2,exp}]
    prog: Dict[str, Tuple[int,int,float]] = {}    # ip -> (stage,win,last_mono)
    pending: Dict[str, float] = {}  # ip -> exp_mono
    nonces: Dict[str, float] = {}   # key -> exp_mono
    enrolled: Dict[str, bytes] = {} # kid -> public raw
    # rate-limit API
    rl_api: Dict[str, Tuple[float, float]] = {}   # ip -> (tokens,last_mono)
    stop_evt = threading.Event()

S = State()

# ---------- secrets / TOTP / enroll
def ensure_dirs():
    for p in (os.path.dirname(MASTER_SECRET_PATH),
              os.path.dirname(ENROLL_DB),
              os.path.dirname(TOTP_PATH)):
        if p: os.makedirs(p, exist_ok=True)

def ensure_master_secret() -> bytes:
    ensure_dirs()
    if not os.path.exists(MASTER_SECRET_PATH):
        raw = os.urandom(32)
        open(MASTER_SECRET_PATH, "w").write(base64.b64encode(raw).decode()+"\n")
        os.chmod(MASTER_SECRET_PATH, 0o600)
        LOG("READY", secret=MASTER_SECRET_PATH, created=1)
    else:
        LOG("READY", secret=MASTER_SECRET_PATH, created=0)
    tok = open(MASTER_SECRET_PATH).read().strip().split()[0]
    return base64.b64decode(tok)

def ensure_totp_secret() -> bytes:
    # auto-crée un secret si absent et le met aussi dans ~/.config/poc5/totp_base32 (pour le client)
    if not os.path.exists(TOTP_PATH):
        raw = base64.b32encode(os.urandom(20)).decode().strip().upper()
        open(TOTP_PATH, "w").write(raw+"\n")
        os.chmod(TOTP_PATH, 0o600)
        # copie côté user pour faciliter le client (même machine)
        home = os.path.expanduser("~")
        cli_path = os.path.join(home, ".config/poc5/totp_base32")
        os.makedirs(os.path.dirname(cli_path), exist_ok=True)
        open(cli_path, "w").write(raw+"\n")
        os.chmod(cli_path, 0o600)
        LOG("TOTP", created=True, path=TOTP_PATH, copy=cli_path)
    else:
        LOG("TOTP", created=False, path=TOTP_PATH)
    return b32_read(open(TOTP_PATH).read())

def load_enrolled():
    ensure_dirs()
    if os.path.exists(ENROLL_DB):
        try:
            S.enrolled = {k: de_b64u(v) for k, v in json.load(open(ENROLL_DB)).items()}
        except Exception:
            S.enrolled = {}
    else:
        S.enrolled = {}
def save_enrolled():
    ensure_dirs()
    json.dump({k: b64u(v) for k, v in S.enrolled.items()}, open(ENROLL_DB, "w"), indent=2)

# ---------- nftables + sshd
def nft_install():
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")
    conf = f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET} {{ type ipv4_addr; flags timeout; timeout {S.open_ttl}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} ip saddr @{NFT_SET} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop
"""
    tmp = "/tmp/poc5.nft"
    open(tmp, "w").write(conf)
    run(f"nft -f {tmp}")
    LOG("NFT_READY", table=NFT_TABLE, chain=NFT_CHAIN, set=NFT_SET)

def nft_open(ip: str, ttl: int):
    run(f"nft add element inet {NFT_TABLE} {NFT_SET} '{{ {ip} timeout {ttl}s }}'")
    LOG("OPEN", ip=ip, ttl=ttl)

def nft_cleanup():
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def ensure_host_keys():
    run("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A >/dev/null 2>&1 || true")

_sshd = None
def start_sshd():
    global _sshd
    ensure_host_keys()
    cfg = f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path = "/tmp/poc5_sshd.conf"; open(path,"w").write(cfg)
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f":{SSH_PORT}")

def stop_sshd():
    global _sshd
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()

# ---------- rotation P1/P2
def roll_ports():
    w = win_id(S.rotate_s)
    tbytes = struct.pack("!Q", w)
    p1 = derive_port(S.master, b"p1|"+tbytes, PORT_MIN, PORT_MAX)
    p2 = derive_port(S.master, b"p2|"+tbytes, PORT_MIN, PORT_MAX)
    if p2 == p1: p2 = PORT_MIN + ((p1 + 137) % (PORT_MAX - PORT_MIN + 1))
    exp = int(time.time() + S.rotate_s)
    S.windows.append({"win": w, "p1": p1, "p2": p2, "exp": exp})
    S.windows[:] = S.windows[-2:]  # garder fen. courante + précédente
    LOG("PORTS", p1=p1, p2=p2, exp=exp)

def rotator_thread():
    while not S.stop_evt.is_set():
        try:
            if not S.windows or S.windows[-1]["exp"] <= int(time.time()):
                roll_ports()
        except Exception as e:
            LOG("ROTATE_ERR", err=str(e))
        time.sleep(1)

# ---------- rate-limit API
def rl_api_ok(ip: str) -> bool:
    now = time.monotonic()
    tokens, last = S.rl_api.get(ip, (RL_API_BURST, now))
    tokens = min(RL_API_BURST, tokens + RL_API_RATE * (now - last))
    if tokens < 1.0:
        S.rl_api[ip] = (tokens, now); return False
    S.rl_api[ip] = (tokens - 1.0, now); return True

# ---------- API HTTP
class Api(BaseHTTPRequestHandler):
    server_version = "poc5/1.0"
    def log_message(self, *_): return
    def _json(self, code: int, obj: dict):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def _ip(self) -> str: return self.client_address[0]

    def do_GET(self):
        if self.path.split("?")[0] == "/ports":
            cur = S.windows[-1] if S.windows else None
            if not cur: roll_ports(); cur = S.windows[-1]
            return self._json(200, {"p1": cur["p1"], "p2": cur["p2"], "expires": cur["exp"],
                                    "rotate": S.rotate_s, "ssh": SSH_PORT, "http": HTTP_PORT,
                                    "totp_required": S.totp_secret is not None})
        if self.path == "/healthz": return self._json(200, {"ok": True})
        self._json(404, {"error":"not_found"})

    def do_POST(self):
        ip = self._ip()
        ln = int(self.headers.get("Content-Length","0") or "0")
        data = {}
        if ln > 0:
            try: data = json.loads(self.rfile.read(ln).decode())
            except Exception: return self._json(400, {"error":"bad_json"})

        if self.path == "/enroll":
            # pas de rate-limit agressif ici
            kid = str(data.get("kid",""))[:32]
            pub = str(data.get("pubkey",""))
            if not kid or not pub: return self._json(400, {"error":"missing_fields"})
            try:
                raw = de_b64u(pub); Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                return self._json(400, {"error":"bad_pubkey"})
            S.enrolled[kid] = raw; save_enrolled()
            LOG("ENROLL_OK", ip=ip, kid=kid)
            return self._json(200, {"ok": True})

        if self.path == "/knock":
            if not rl_api_ok(ip): return self._json(429, {"error":"rate_limited"})
            kid = str(data.get("kid",""))[:32]
            sig_b64 = str(data.get("sig",""))
            if not kid or not sig_b64: return self._json(400, {"error":"missing_fields"})

            # doit être en état pending
            if S.pending.get(ip, 0.0) < time.monotonic():
                return self._json(403, {"error":"not_pending"})

            # anti-rejeu
            nonce = str(data.get("nonce",""))[:64]
            nowm = time.monotonic()
            for k in list(S.nonces.keys()):
                if S.nonces[k] < nowm: S.nonces.pop(k, None)
            key = f"{kid}:{nonce}"
            if not nonce or key in S.nonces:
                return self._json(403, {"error":"replay_nonce"})
            S.nonces[key] = nowm + 300.0

            # signature
            pk_raw = S.enrolled.get(kid)
            if not pk_raw: return self._json(403, {"error":"unknown_kid"})
            pk = Ed25519PublicKey.from_public_bytes(pk_raw)
            payload = {k:v for k,v in data.items() if k != "sig"}
            try:
                pk.verify(de_b64u(sig_b64), canon_bytes(payload))
            except Exception:
                return self._json(403, {"error":"bad_sig"})

            # fraîcheur
            ts = int(data.get("ts",0))
            if ts <= 0 or abs(int(time.time()) - ts) > 90:
                return self._json(403, {"error":"stale_ts"})

            # TOTP si activé
            if S.totp_secret is not None:
                try: code = int(str(data.get("totp","")).strip())
                except Exception: return self._json(403, {"error":"totp_required"})
                if not totp_verify(S.totp_secret, code, int(time.time())):
                    return self._json(403, {"error":"totp_bad"})

            # ouverture
            ttl = max(5, min(3600, int(data.get("duration", S.open_ttl))))
            nft_open(ip, ttl)
            S.pending.pop(ip, None)
            return self._json(200, {"ok": True, "ttl": ttl})

        self._json(404, {"error":"not_found"})

# ---------- sniff (Scapy)
def handle_pkt(p):
    try:
        if not p.haslayer(IP): return
        if p[IP].dst != S.bind_ip: return
        ip = p[IP].src

        # purge progression expirée
        st = S.prog.get(ip)
        nowm = time.monotonic()
        if st and nowm - st[2] > S.step_ttl:
            S.prog.pop(ip, None); st = None

        wins = S.windows[-2:] if S.windows else []
        if not wins: return
        wmap = {w["win"]:(w["p1"], w["p2"]) for w in wins}

        # Étape 1 : TCP SYN -> p1 (fenêtre N ou N-1)
        if p.haslayer(TCP):
            f = int(p[TCP].flags)
            if (f & 0x02) and not (f & 0x10):
                d = int(p[TCP].dport)
                for w in wins:
                    if d == w["p1"]:
                        S.prog[ip] = (1, w["win"], nowm)
                        LOG("STEP1", ip=ip)
                        return

        # Étape 2 : UDP -> p2 (même fenêtre)
        if st and st[0] == 1 and p.haslayer(UDP):
            d = int(p[UDP].dport); p1, p2 = wmap.get(st[1], (None, None))
            if p2 and d == p2:
                S.prog[ip] = (2, st[1], nowm)
                LOG("STEP2", ip=ip)
                return

        # Étape 3 : ICMP echo
        if st and st[0] == 2 and p.haslayer(ICMP) and int(p[ICMP].type) == 8:
            S.prog.pop(ip, None)
            S.pending[ip] = time.monotonic() + S.pending_ttl
            LOG("PENDING", ip=ip, ttl=f"{S.pending_ttl:.1f}")
            return

        # purge pending
        for k,v in list(S.pending.items()):
            if v < nowm: S.pending.pop(k,None)
    except Exception as e:
        LOG("SNIFF_ERR", err=str(e))

def start_sniffer(iface: str):
    bpf = f"dst host {S.bind_ip} and (tcp or udp or icmp)"
    LOG("LISTEN", iface=iface, bpf=bpf)
    sniff(iface=iface, filter=bpf, prn=handle_pkt, store=False)

# ---------- interfaces
def pick_ifaces(user: Optional[str]) -> list:
    if user: return [s.strip() for s in user.split(",") if s.strip()]
    res = []
    try:
        from scapy.all import get_if_list  # type: ignore
        if "lo" in get_if_list(): res.append("lo")
    except Exception:
        res.append("lo")
    code, out, _ = run("ip route show default | awk '{print $5}' | head -n1")
    dev = (out or "").strip()
    if dev and dev not in res: res.append(dev)
    return res or ["lo"]

# ---------- main
def cleanup():
    try: nft_cleanup()
    except: pass
    try: stop_sshd()
    except: pass
    LOG("CLEANUP")

def main():
    must_root()
    ap = argparse.ArgumentParser()
    ap.add_argument("bind_ip")
    ap.add_argument("--iface", default=None, help="ex: lo,eth0")
    ap.add_argument("--rotate", type=int, default=ROTATE_PERIOD_S)
    ap.add_argument("--step-ttl", type=int, default=STEP_TTL_S)
    ap.add_argument("--pending-ttl", type=int, default=PENDING_TTL_S)
    ap.add_argument("--open-ttl", type=int, default=OPEN_TTL_S)
    ap.add_argument("--require-totp", action="store_true",
                    help="Active TOTP (auto-généré si absent)")
    args = ap.parse_args()

    S.bind_ip = args.bind_ip
    S.ifaces  = pick_ifaces(args.iface)
    S.rotate_s    = max(20, int(args.rotate))
    S.step_ttl    = max(2, int(args.step_ttl))
    S.pending_ttl = max(2, int(args.pending_ttl))
    S.open_ttl    = max(5, int(args.open_ttl))

    S.master = ensure_master_secret()
    if args.require_totp:
        S.totp_secret = ensure_totp_secret()
    load_enrolled()

    nft_install(); start_sshd()
    roll_ports(); threading.Thread(target=rotator_thread, daemon=True).start()

    httpd = ThreadingHTTPServer((S.bind_ip, HTTP_PORT), Api)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    LOG("HTTP", bind=f"{S.bind_ip}:{HTTP_PORT}", totp=bool(S.totp_secret))
    LOG("READY", ip=S.bind_ip, http=HTTP_PORT, ssh=SSH_PORT)

    for ifc in S.ifaces:
        threading.Thread(target=start_sniffer, args=(ifc,), daemon=True).start()

    def _sig(*_): S.stop_evt.set()
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)
    try:
        while not S.stop_evt.is_set(): time.sleep(0.5)
    finally:
        httpd.shutdown(); cleanup()

if __name__ == "__main__":
    main()
