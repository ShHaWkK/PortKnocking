#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Serveur « hard » :
- Séquence multi-protocole: TCP SYN -> UDP -> ICMP Echo
- Rotation périodique des ports P1/P2 (fenêtres successives) dérivés d’un secret
- SPA HTTP signé Ed25519 : /enroll (clé publique), /ports (découverte), /knock (SPA)
- Options: TOTP obligatoire, rate-limit par IP, tolérance fenêtre précédente
- Ouverture dynamique via nftables (set @allowed avec timeout) du port SSH dédié
- Sniff non bloquant (Scapy) + HTTPBaseServer + threads de rotation/collecte

Usage minimal :
  sudo python3 poc5_server_hard_v3.py 127.0.0.1 --iface lo
"""

import os, sys, time, json, base64, argparse, signal, threading, socket, struct, hashlib, hmac, random, shutil, subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from datetime import datetime

# ------------------------------ Configuration par défaut
SSH_PORT          = 2222
HTTP_PORT         = 45445
NFT_TABLE         = "knock5"
NFT_CHAIN         = "inbound"
NFT_SET_ALLOWED   = "allowed"
OPEN_TTL_S        = 60        # durée d’ouverture SSH
STEP_TTL_S        = 10        # TTL entre étapes (TCP->UDP->ICMP)
PENDING_TTL_S     = 8         # fenêtre pour recevoir le SPA après ICMP
ROTATE_PERIOD_S   = 30        # rotation des ports P1/P2
RANGE_MIN, RANGE_MAX = 47000, 48000

MASTER_SECRET_PATH = "/etc/portknock/secret"     # base64
TOTP_PATH          = "/etc/portknock/totp_base32"  # base32 (optionnel)
KEYS_DB            = "/etc/portknock/keys.json"  # {kid: pubkey_b64u}
LOG_PATH           = "/var/log/portknock/poc5_server.jsonl"

# rate limit SPA / IP (token bucket simple)
RL_CAPACITY   = 6      # jetons max
RL_REFILL_S   = 30     # fenêtre pour le remplissage complet

# ------------------------------ utilitaires simples

def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items())
    print(f"[{tag}] {s}".rstrip(), flush=True)

def jlog(event, **fields):
    row = {"ts": datetime.utcnow().isoformat()+"Z", "event": event}
    row.update(fields)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(row, ensure_ascii=False)+"\n")
    except Exception:
        pass

def run(*cmd, check=False):
    return subprocess.run(list(cmd), text=True, capture_output=True)

def b64_read_tolerant(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(tok, validate=True)
    except Exception:
        return base64.b64decode(tok)

def b32_read(raw: str) -> bytes:
    # base32 standard, tolérant aux espaces/saute-lignes
    tok = "".join(raw.strip().split())
    return base64.b32decode(tok.upper())

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def de_b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, separators=(",",":"), sort_keys=True).encode()

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lancer le serveur avec sudo.", file=sys.stderr)
        sys.exit(1)

# ------------------------------ dépendances Python
def ensure_pydeps():
    ok = True
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa
    except Exception:
        LOG("BOOT", note="installation cryptography")
        r = run(sys.executable, "-m", "pip", "install", "-q", "cryptography")
        ok = ok and (r.returncode == 0)
    try:
        import scapy.all  # noqa
    except Exception:
        LOG("BOOT", note="installation scapy")
        r = run(sys.executable, "-m", "pip", "install", "-q", "scapy")
        ok = ok and (r.returncode == 0)
    return ok

def ensure_sysbins():
    miss = []
    if not shutil.which("nft"): miss.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): miss.append("openssh-server")
    if miss:
        # tenter installation (apt/dnf/pacman), sinon continuer
        for mgr, cmd in (("apt", ["apt","update"]),
                         ("apt", ["apt","install","-y",*miss]),
                         ("dnf", ["dnf","install","-y",*miss]),
                         ("pacman", ["pacman","-Sy","--noconfirm",*miss])):
            if shutil.which(mgr):
                run("sudo", *cmd, check=False)

# ------------------------------ secrets/clé maître + TOTP
def load_or_create_master_secret() -> bytes:
    os.makedirs(os.path.dirname(MASTER_SECRET_PATH), exist_ok=True)
    if not os.path.exists(MASTER_SECRET_PATH):
        raw = os.urandom(32)
        with open(MASTER_SECRET_PATH, "w") as f:
            f.write(base64.b64encode(raw).decode()+"\n")
        os.chmod(MASTER_SECRET_PATH, 0o600)
        LOG("READY", secret=MASTER_SECRET_PATH, created=1)
    else:
        LOG("READY", secret=MASTER_SECRET_PATH, created=0)
    sec = b64_read_tolerant(open(MASTER_SECRET_PATH).read())
    if len(sec) < 16:
        print("[ERREUR] Secret maître trop court.", file=sys.stderr); sys.exit(1)
    return sec

def load_totp_secret_if_required(require: bool) -> bytes | None:
    if not require:
        return None
    if not os.path.exists(TOTP_PATH):
        print(f"[ERREUR] TOTP requis mais {TOTP_PATH} introuvable.", file=sys.stderr)
        sys.exit(1)
    return b32_read(open(TOTP_PATH).read())

# TOTP minimal (RFC 6238, SHA-1, 6 digits)
def totp_now(secret_b32: bytes, for_time: int, step: int = 30, digits: int = 6) -> int:
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_b32, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    bin_code = ((digest[off] & 0x7F) << 24) | (digest[off+1] << 16) | (digest[off+2] << 8) | digest[off+3]
    return bin_code % (10**digits)

def totp_verify(secret_b32: bytes, code: int, now_ts: int, drift_win=(-1,0,1)) -> bool:
    for k in drift_win:
        if totp_now(secret_b32, now_ts + k*30) == code:
            return True
    return False

# ------------------------------ dérivation des ports (rotation)
def derive_port(secret: bytes, label: bytes, low: int, high: int) -> int:
    # HMAC(secret, label) -> 16 bits -> map sur [low, high]
    digest = hmac.new(secret, label, hashlib.sha256).digest()
    val = int.from_bytes(digest[:2], "big")
    rng = high - low + 1
    return low + (val % rng)

def window_tuple(secret: bytes, ts_window: int) -> tuple[int,int]:
    # P1 = H(secret, "p1|<win>"), P2 = H(secret, "p2|<win>")
    tbytes = struct.pack("!Q", ts_window)
    p1 = derive_port(secret, b"p1|" + tbytes, RANGE_MIN, RANGE_MAX)
    p2 = derive_port(secret, b"p2|" + tbytes, RANGE_MIN, RANGE_MAX)
    if p2 == p1:
        p2 = RANGE_MIN + ((p1 + 137) % (RANGE_MAX - RANGE_MIN))
    return p1, p2

# ------------------------------ nftables
def nft_delete_table():
    run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def nft_install_base(ttl_open: int):
    nft_delete_table()
    conf = f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {ttl_open}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} ip saddr @{NFT_SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop
"""
    tmp="/tmp/poc5_nft.nft"
    with open(tmp,"w") as f: f.write(conf)
    run("nft","-f", tmp)
    LOG("NFT_READY", table=NFT_TABLE, chain=NFT_CHAIN, set=f"{NFT_SET_ALLOWED}")

def nft_add_allowed(ip: str, ttl: int):
    run("bash","-lc", f"nft add element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    LOG("OPEN", ip=ip, ttl=ttl)
    jlog("open", ip=ip, ttl=ttl)

# ------------------------------ sshd éphémère
_sshd = None
def start_sshd():
    global _sshd
    cfg = f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path = "/tmp/poc5_sshd.conf"
    with open(path,"w") as f: f.write(cfg)
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f":{SSH_PORT}")

def stop_sshd():
    global _sshd
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()
        LOG("SSHD", status="stopped")

# ------------------------------ état serveur
class State:
    def __init__(self):
        self.bind_ip    = "127.0.0.1"
        self.ifaces     = []
        self.rotate_s   = ROTATE_PERIOD_S
        self.step_ttl   = STEP_TTL_S
        self.pending_ttl= PENDING_TTL_S
        self.open_ttl   = OPEN_TTL_S
        self.require_totp = False
        self.master     = b""
        self.totp_sec   = None  # bytes or None
        self.windows    = []    # [{win:int, p1:int, p2:int, exp:float}]
        self.pending    = {}    # ip -> expiry monotonic
        self.states     = {}    # ip -> {stage, win, last}
        self.nonces     = {}    # nonce -> expiry monotonic
        self.ratelim    = {}    # ip -> {tokens, last}
        self.keys       = {}    # kid -> pubkey(raw 32 bytes)
        self.stop_evt   = threading.Event()

STATE = State()

def rl_ok(ip: str) -> bool:
    now = time.monotonic()
    r = STATE.ratelim.get(ip, {"tokens": RL_CAPACITY, "last": now})
    # refill linéaire
    elapsed = now - r["last"]
    refill = (elapsed / RL_REFILL_S) * RL_CAPACITY
    r["tokens"] = min(RL_CAPACITY, r["tokens"] + refill)
    r["last"] = now
    if r["tokens"] >= 1.0:
        r["tokens"] -= 1.0
        STATE.ratelim[ip] = r
        return True
    STATE.ratelim[ip] = r
    return False

def nonce_seen(nonce: str) -> bool:
    now = time.monotonic()
    # purge
    for k,exp in list(STATE.nonces.items()):
        if exp < now: STATE.nonces.pop(k, None)
    if nonce in STATE.nonces:
        return True
    STATE.nonces[nonce] = now + 300.0
    return False

def load_keys_db():
    try:
        if os.path.exists(KEYS_DB):
            data = json.loads(open(KEYS_DB).read())
        else:
            data = {}
        out = {}
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        for kid, b64u_pk in data.items():
            raw = de_b64u(b64u_pk)
            # vérification de longueur
            if len(raw) == 32:
                out[kid] = Ed25519PublicKey.from_public_bytes(raw)
        STATE.keys = out
    except Exception as e:
        LOG("KEYS_DB_ERR", err=str(e)); STATE.keys = {}

def save_keys_db():
    try:
        os.makedirs(os.path.dirname(KEYS_DB), exist_ok=True)
        data = {kid: b64u(pk.public_bytes(encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
                                          format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw))
                for kid, pk in STATE.keys.items()}
        with open(KEYS_DB, "w") as f: f.write(json.dumps(data, indent=2))
    except Exception as e:
        LOG("KEYS_DB_SAVE_ERR", err=str(e))

# ------------------------------ rotation P1/P2
def current_win_id() -> int:
    return int(time.time() // STATE.rotate_s)

def roll_ports():
    win = current_win_id()
    p1, p2 = window_tuple(STATE.master, win)
    exp = time.time() + STATE.rotate_s
    STATE.windows.append({"win": win, "p1": p1, "p2": p2, "exp": exp})
    # garder (courant + précédent) pour tolérance
    STATE.windows[:] = STATE.windows[-2:]
    LOG("PORTS", p1=p1, p2=p2, exp=int(exp))
    jlog("ports", p1=p1, p2=p2, win=win, exp=int(exp))

def rotator_thread():
    while not STATE.stop_evt.is_set():
        try:
            if not STATE.windows or STATE.windows[-1]["exp"] <= time.time():
                roll_ports()
        except Exception as e:
            LOG("ROTATE_ERR", err=str(e))
        time.sleep(1.0)

# ------------------------------ HTTP API
class API(BaseHTTPRequestHandler):
    server_version = "poc5/1.0"

    def _json(self, code: int, obj: dict):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        # silence BaseHTTPRequestHandler
        return

    def do_GET(self):
        ip = self.client_address[0]
        path = urlparse(self.path).path
        if path == "/ports":
            # expose fenêtre courante (et expiration)
            cur = STATE.windows[-1] if STATE.windows else None
            if not cur: roll_ports(); cur = STATE.windows[-1]
            self._json(200, {"p1": cur["p1"], "p2": cur["p2"], "expires": int(cur["exp"]),
                             "rotate": STATE.rotate_s, "ssh": SSH_PORT, "http": HTTP_PORT,
                             "totp_required": bool(STATE.totp_sec)})
            return
        if path == "/healthz":
            self._json(200, {"ok": True}); return
        self._json(404, {"error":"not_found"})

    def do_POST(self):
        ip = self.client_address[0]
        if not rl_ok(ip):
            self._json(429, {"error":"rate_limited"}); return

        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length","0"))
            body = self.rfile.read(length) if length>0 else b"{}"
            data = json.loads(body.decode())
        except Exception:
            self._json(400, {"error":"bad_json"}); return

        if path == "/enroll":
            kid = str(data.get("kid",""))
            pub = str(data.get("pubkey",""))
            if not kid or not pub:
                self._json(400, {"error":"missing_fields"}); return
            try:
                raw = de_b64u(pub)
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                pk = Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                self._json(400, {"error":"bad_pubkey"}); return
            STATE.keys[kid] = pk
            save_keys_db()
            LOG("ENROLL_OK", ip=ip, kid=kid)
            self._json(200, {"ok": True}); return

        if path == "/knock":
            # SPA : {kid, ts, duration, nonce, [totp], sig}
            kid = str(data.get("kid",""))
            sig_b64 = str(data.get("sig",""))
            if not kid or not sig_b64:
                self._json(400, {"error":"missing_fields"}); return

            # anti-rejeu nonce
            nonce = str(data.get("nonce",""))
            if not nonce or nonce_seen(f"{kid}:{nonce}"):
                self._json(400, {"error":"bad_nonce"}); return

            if ip not in STATE.pending or STATE.pending[ip] < time.monotonic():
                self._json(403, {"error":"state_not_pending"}); return

            pk = STATE.keys.get(kid)
            if pk is None:
                self._json(403, {"error":"unknown_kid"}); return

            # Vérification signature (sur JSON canonique sans 'sig')
            payload = {k: v for k,v in data.items() if k != "sig"}
            raw = canon_bytes(payload)
            try:
                sig = de_b64u(sig_b64)
                pk.verify(sig, raw)
            except Exception:
                self._json(403, {"error":"bad_signature"}); return

            # fraicheur du timestamp
            ts = int(data.get("ts", 0))
            if ts <= 0 or abs(int(time.time()) - ts) > 90:
                self._json(403, {"error":"stale_ts"}); return

            # TOTP (si requis)
            if STATE.totp_sec is not None:
                try:
                    code = int(str(data.get("totp","")).strip())
                except Exception:
                    self._json(403, {"error":"totp_required"}); return
                if not totp_verify(STATE.totp_sec, code, int(time.time())):
                    self._json(403, {"error":"totp_bad"}); return

            # ouverture
            ttl = int(data.get("duration", STATE.open_ttl)) or STATE.open_ttl
            nft_add_allowed(ip, ttl)
            STATE.pending.pop(ip, None)
            self._json(200, {"ok": True, "ttl": ttl}); return

        self._json(404, {"error":"not_found"})

# ------------------------------ sniffer (Scapy)
def start_sniffer_thread(iface: str):
    from scapy.all import sniff, TCP, UDP, ICMP, IP  # type: ignore
    def _prn(pkt):
        try:
            if not pkt.haslayer(IP): return
            if pkt[IP].dst != STATE.bind_ip: return
            now = time.monotonic()
            ip = pkt[IP].src

            # TTL machine d'état
            st = STATE.states.get(ip)
            if st and (now - st["last"] > STATE.step_ttl):
                STATE.states.pop(ip, None)
                st = None

            # fenêtres actives (courante + précédente)
            wins = STATE.windows[-2:] if STATE.windows else []
            if not wins:
                return
            # mapping win->(p1,p2)
            wmap = {w["win"]:(w["p1"], w["p2"]) for w in wins}

            # Étape 1: TCP SYN vers p1
            if pkt.haslayer(TCP):
                f = int(pkt[TCP].flags)
                if (f & 0x02) and not (f & 0x10):  # SYN sans ACK
                    dport = int(pkt[TCP].dport)
                    for w in wins:
                        if dport == w["p1"]:
                            STATE.states[ip] = {"stage":1, "win": w["win"], "last": now}
                            LOG("STEP1", ip=ip)
                            return

            # Étape 2: UDP vers p2 dans la même fenêtre
            if st and st["stage"] == 1 and pkt.haslayer(UDP):
                dport = int(pkt[UDP].dport)
                p1,p2 = wmap.get(st["win"], (None,None))
                if p2 and dport == p2:
                    st["stage"] = 2
                    st["last"]  = now
                    LOG("STEP2", ip=ip)
                    return

            # Étape 3: ICMP Echo
            if st and st["stage"] == 2 and pkt.haslayer(ICMP):
                typ = int(pkt[ICMP].type)
                if typ == 8:
                    # succès de la séquence
                    STATE.states.pop(ip, None)
                    STATE.pending[ip] = time.monotonic() + STATE.pending_ttl
                    LOG("PENDING", ip=ip, ttl=f"{STATE.pending_ttl:.1f}")
                    jlog("pending", ip=ip, ttl=STATE.pending_ttl)
                    return

            # ménage
            for k,v in list(STATE.pending.items()):
                if v < now: STATE.pending.pop(k, None)
        except Exception as e:
            LOG("SNIFF_ERR", err=str(e))

    bpf = f"dst host {STATE.bind_ip} and (tcp or udp or icmp)"
    LOG("LISTEN", iface=iface, bpf=bpf)
    t = threading.Thread(target=lambda: sniff(iface=iface, filter=bpf, prn=_prn, store=False,
                                              stop_filter=lambda p: STATE.stop_evt.is_set()),
                         daemon=True)
    t.start()
    return t

# ------------------------------ HTTP server thread
def start_http_thread():
    srv = HTTPServer((STATE.bind_ip, HTTP_PORT), API)
    LOG("HTTP", bind=f"{STATE.bind_ip}:{HTTP_PORT}")
    def _serve():
        while not STATE.stop_evt.is_set():
            srv.handle_request()
    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t

# ------------------------------ main / CLI
def cleanup():
    try: nft_delete_table()
    except Exception: pass
    try: stop_sshd()
    except Exception: pass
    LOG("CLEANUP"); jlog("server_stop")

def pick_ifaces(user_value: str|None):
    if user_value: return [x.strip() for x in user_value.split(",") if x.strip()]
    # sinon, tenter lo + interface par défaut
    try:
        from scapy.all import get_if_list
        ifs = set(get_if_list())
    except Exception:
        ifs = set()
    out = []
    if "lo" in ifs: out.append("lo")
    rt = run("bash","-lc","ip route show default | awk '{print $5}' | head -n1")
    dev = (rt.stdout or "").strip()
    if dev and dev in ifs and dev not in out: out.append(dev)
    return out or ["lo"]

def main():
    must_root()
    ensure_pydeps(); ensure_sysbins()

    ap = argparse.ArgumentParser(description="POC5 Serveur — Knock TCP/UDP/ICMP + SPA HTTP signé")
    ap.add_argument("bind", help="IP d’écoute (HTTP) et filtre sniff (ex: 127.0.0.1)")
    ap.add_argument("--iface", default=None, help="Interfaces à sniffer (ex: lo ou lo,eth0)")
    ap.add_argument("--rotate", type=int, default=ROTATE_PERIOD_S)
    ap.add_argument("--step-ttl", type=int, default=STEP_TTL_S)
    ap.add_argument("--pending-ttl", type=int, default=PENDING_TTL_S)
    ap.add_argument("--open-ttl", type=int, default=OPEN_TTL_S)
    ap.add_argument("--require-totp", action="store_true")
    args = ap.parse_args()

    # état
    STATE.bind_ip     = args.bind
    STATE.rotate_s    = max(10, int(args.rotate))
    STATE.step_ttl    = max(2, int(args.step_ttl))
    STATE.pending_ttl = max(3, int(args.pending_ttl))
    STATE.open_ttl    = max(5, int(args.open_ttl))
    STATE.ifaces      = pick_ifaces(args.iface)

    # secrets
    STATE.master   = load_or_create_master_secret()
    STATE.totp_sec = load_totp_secret_if_required(args.require_totp)
    load_keys_db()

    # nft + sshd + http + sniff + rotation
    nft_install_base(STATE.open_ttl)
    start_sshd()
    ht = start_http_thread()
    rt = threading.Thread(target=rotator_thread, daemon=True); rt.start()
    for iface in STATE.ifaces: start_sniffer_thread(iface)

    LOG("READY", ip=STATE.bind_ip, http=HTTP_PORT, ssh=SSH_PORT)
    LOG("HINT", msg="Knock TCP->UDP->ICMP, puis POST /knock (SPA signé)")
    jlog("server_start", bind=STATE.bind_ip, http=HTTP_PORT, ssh=SSH_PORT)

    # arrêt propre
    def _sig(_s,_f): STATE.stop_evt.set()
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)
    try:
        while not STATE.stop_evt.is_set():
            time.sleep(0.4)
    finally:
        cleanup()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        LOG("FATAL", err=str(e))
        cleanup()
        sys.exit(1)