#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC6 — Serveur SPA 100% UDP, avec UI temps réel (SSE) et audit.
- Single Packet Authorization : X25519/HKDF -> AES-GCM ; signature Ed25519 ; PoW ; TOTP (optionnel).
- Fenêtre temporelle N/N-1 (30s), anti-rejeu (cache 5 min).
- À succès : ajoute l'IP source dans nftables pour ouvrir SSH:2222 (sshd éphémère).
- HTTP: /info (config), /enroll (pubkey client), /status (set nft), /events (SSE), /ui (page live).
Usage: sudo python3 poc6_server.py --iface lo
"""

import os, sys, time, json, base64, argparse, socket, struct, hashlib, hmac, subprocess, signal, threading, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass, field

# --- deps
try:
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    print("Installez : pip install cryptography", file=sys.stderr); sys.exit(1)

# --- constants
MAGIC             = b"PK6"
VERSION           = 1
SSH_PORT          = 2222
UDP_PORT_DEFAULT  = 45446
HTTP_PORT_DEFAULT = 45447
NFT_TABLE         = "knock6"
NFT_CHAIN         = "inbound"
NFT_SET_ALLOWED   = "allowed"
OPEN_TTL_S_DEFAULT= 60
WINDOW_SEC        = 30
REPLAY_TTL        = 300
STATE_DIR         = "/etc/portknock6"
SKEY_PATH         = os.path.join(STATE_DIR, "server_x25519.pem")
ENROLL_DB         = os.path.join(STATE_DIR, "keys.json")
CONF_PATH         = os.path.join(STATE_DIR, "config.json")
TOTP_SECRET_PATH  = os.path.join(STATE_DIR, "totp_base32")
RL_CAPACITY       = 12.0
RL_REFILL         = 12.0

# --- colors (console)
class COL:
    R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; M="\033[35m"; RS="\033[0m"
def col(s, c): return f"{c}{s}{COL.RS}"

# --- utils
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj) -> bytes: return json.dumps(obj, separators=(",",":"), sort_keys=True, ensure_ascii=False).encode()
def run(cmd: str) -> Tuple[int,str,str]:
    p = subprocess.run(["bash","-lc",cmd], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr
def must_root():
    if os.geteuid()!=0:
        print("Lancez en root.", file=sys.stderr); sys.exit(1)
def now() -> int: return int(time.time())
def win_id() -> int: return int(now() // WINDOW_SEC)

# --- TOTP
def b32_read(text: str) -> bytes: return base64.b32decode("".join(text.strip().split()).upper())
def totp_now(secret: bytes, for_time: int, step=30, digits=6) -> int:
    ctr=int(for_time//step); msg=struct.pack(">Q", ctr)
    dig=hmac.new(secret,msg,hashlib.sha1).digest(); off=dig[-1]&0x0F
    code=((dig[off]&0x7F)<<24)|(dig[off+1]<<16)|(dig[off+2]<<8)|dig[off+3]
    return code % (10**digits)
def totp_verify(secret: bytes, code: int, t: int) -> bool:
    for k in (-1,0,1):
        if totp_now(secret, t+30*k) == code: return True
    return False

# --- state
@dataclass
class State:
    bind_ip: str = "127.0.0.1"
    udp_port: int = UDP_PORT_DEFAULT
    http_port: int = HTTP_PORT_DEFAULT
    difficulty_bits: int = 18
    difficulty_salt: bytes = b""
    totp_required: bool = False
    totp_secret: Optional[bytes] = None
    s_priv: Optional[x25519.X25519PrivateKey] = None
    s_pub: Optional[bytes] = None
    enrolled: Dict[str, bytes] = field(default_factory=dict)  # kid_hex -> Ed25519 raw pub
    replay: Dict[str, float] = field(default_factory=dict)    # anti-rejeu
    api_rl: Dict[str, Tuple[float,float]] = field(default_factory=dict)
    stop: bool = False
    sshd_proc: Optional[subprocess.Popen] = None
    # audit/metrics
    audit: bool = True
    csv_path: Optional[str] = "/tmp/poc6_events.csv"
    m_ok: int = 0
    m_reject: int = 0
    m_pow_avg_bits: float = 0.0
S = State()

# --- event bus (SSE + console + CSV)
E_BUF_MAX = 400
E_BUF: List[dict] = []
SSE_CLIENTS: List[BaseHTTPRequestHandler] = []
E_LOCK = threading.Lock()

def emit(evt: str, **kw):
    rec = {"ts": now(), "evt": evt, **kw}
    line = json.dumps(rec, separators=(",",":"))

    # Console
    if evt=="open":
        print(col(f"[OPEN] ip={kw.get('ip')} ttl={kw.get('ttl')}s", COL.G))
        print(col("╔════════════════════╗", COL.G))
        print(col("║     SSH OUVERT     ║", COL.G))
        print(col("╚════════════════════╝", COL.G))
    elif evt=="ok":
        print(col(f"[OK] kid={kw.get('kid')} ip={kw.get('ip')} dur={kw.get('dur')}s bits={kw.get('bits')}", COL.C))
    elif evt=="reject":
        print(col(f"[REJECT] {kw.get('reason')} ip={kw.get('ip','?')}", COL.R))
    elif evt=="info":
        print(col(f"[INFO] {kw}", COL.Y))
    else:
        print(f"[{evt}] {kw}")

    # Buffer, CSV, SSE
    with E_LOCK:
        E_BUF.append(rec)
        while len(E_BUF)>E_BUF_MAX: E_BUF.pop(0)
        try:
            if S.csv_path:
                hdr = not os.path.exists(S.csv_path)
                with open(S.csv_path,"a") as f:
                    if hdr: f.write("ts,evt,ip,kid,reason,bits,dur,ttl\n")
                    f.write(f"{rec.get('ts')},{evt},{rec.get('ip','')},{rec.get('kid','')},{rec.get('reason','')},{rec.get('bits','')},{rec.get('dur','')},{rec.get('ttl','')}\n")
        except Exception:
            pass
        dead=[]
        for cli in SSE_CLIENTS:
            try:
                cli.wfile.write(b"data: "+line.encode()+b"\n\n"); cli.wfile.flush()
            except Exception:
                dead.append(cli)
        for d in dead:
            try: SSE_CLIENTS.remove(d)
            except: pass

# --- storage & keys
def ensure_dirs(): os.makedirs(STATE_DIR, exist_ok=True)
def ensure_server_key():
    if os.path.exists(SKEY_PATH):
        sk = serialization.load_pem_private_key(open(SKEY_PATH,"rb").read(), password=None)
        if not isinstance(sk, x25519.X25519PrivateKey): raise ValueError("Clé serveur: mauvais type")
    else:
        sk = x25519.X25519PrivateKey.generate()
        pem = sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        open(SKEY_PATH,"wb").write(pem); os.chmod(SKEY_PATH,0o600)
    S.s_priv = sk
    S.s_pub  = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
def load_enrolled():
    if os.path.exists(ENROLL_DB):
        try: S.enrolled = {kid: de_b64u(b64) for kid,b64 in json.load(open(ENROLL_DB)).items()}
        except Exception: S.enrolled = {}
    else: S.enrolled = {}
def save_enrolled():
    json.dump({kid:b64u(raw) for kid,raw in S.enrolled.items()}, open(ENROLL_DB,"w"), indent=2)
def ensure_config(default_bits=18, difficulty_salt_b64u=None, totp_required=None):
    cfg={}
    if os.path.exists(CONF_PATH):
        try: cfg=json.load(open(CONF_PATH))
        except Exception: cfg={}
    if difficulty_salt_b64u is not None: cfg["difficulty_salt"]=difficulty_salt_b64u
    elif "difficulty_salt" not in cfg: cfg["difficulty_salt"]=b64u(os.urandom(16))
    cfg["difficulty_bits"]=int(cfg.get("difficulty_bits", default_bits))
    if totp_required is not None: cfg["totp_required"]=bool(totp_required)
    open(CONF_PATH,"w").write(json.dumps(cfg, indent=2))
    S.difficulty_bits=int(cfg["difficulty_bits"]); S.difficulty_salt=de_b64u(cfg["difficulty_salt"])
    S.totp_required=bool(cfg.get("totp_required", False))
def maybe_load_totp():
    if os.path.exists(TOTP_SECRET_PATH):
        try: S.totp_secret=b32_read(open(TOTP_SECRET_PATH).read()); S.totp_required=True
        except Exception: S.totp_secret=None

# --- nftables & sshd
def nft_install(open_ttl=OPEN_TTL_S_DEFAULT):
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")
    conf=f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {open_ttl}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} ip saddr @{NFT_SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop
"""
    tmp="/tmp/poc6.nft"; open(tmp,"w").write(conf)
    rc,_,err=run(f"nft -f {tmp}")
    if rc!=0: print("[ERREUR] nftables:", err, file=sys.stderr); sys.exit(1)
    emit("info", msg="nft ready", ssh=SSH_PORT, table=NFT_TABLE, set=NFT_SET_ALLOWED)
def nft_open(ip:str, ttl:int):
    run(f"nft add element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    emit("open", ip=ip, ttl=ttl)
def nft_status()->List[dict]:
    rc,out,err=run(f"nft -j list set inet {NFT_TABLE} {NFT_SET_ALLOWED}")
    lst=[]
    if rc==0 and out.strip():
        try:
            data=json.loads(out)
            for entry in data.get("nftables",[]):
                s=entry.get("set")
                if not s: continue
                for e in s.get("elem",[]):
                    if isinstance(e,dict) and "elem" in e:
                        val=e["elem"]
                        if isinstance(val,dict) and "val" in val: lst.append({"ip": val["val"]})
        except Exception:
            pass
    if not lst:
        rc2,out2,_=run(f"nft list set inet {NFT_TABLE} {NFT_SET_ALLOWED}")
        for ip,ttl in re.findall(r"(\d+\.\d+\.\d+\.\d+)(?:\s+timeout\s+(\d+)s)?", out2):
            lst.append({"ip":ip, "ttl": int(ttl) if ttl else None})
    return lst

def ensure_hostkeys():
    run("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A >/dev/null 2>&1 || true")
def start_sshd(bind_ip: str):
    ensure_hostkeys()
    cfg=f"Port {SSH_PORT}\nListenAddress {bind_ip}\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc6_sshd.pid\nLogLevel QUIET\n"
    path="/tmp/poc6_sshd.conf"; open(path,"w").write(cfg)
    S.sshd_proc=subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    emit("info", msg="sshd started", ip=bind_ip, port=SSH_PORT)
def stop_sshd():
    p=S.sshd_proc
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(2)
        except: p.kill()

def pick_bind_ip(iface: Optional[str]) -> str:
    if not iface: return "0.0.0.0"
    if iface.strip()=="lo": return "127.0.0.1"
    rc,out,_=run(f"ip -o -4 addr show dev {iface} | awk '{{print $4}}' | cut -d/ -f1 | head -n1")
    return (out or "0.0.0.0").strip()

def leading_zero_bits(h: bytes) -> int:
    n=0
    for b in h:
        if b==0: n+=8
        else:
            for i in range(7,-1,-1):
                if (b>>i)&1: return n+(7-i)
            return n
    return n

# --- HTTP

HTML_UI = """
<!doctype html>
<html><head><meta charset="utf-8"><title>POC6 Live</title>
<style>
body{
    font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;
    background:#0b1220;
    color:#e4ecff;
    margin:0;
}
header{
    padding:18px 24px;
    background:#1a2747;
    border-bottom:2px solid #2e4370;
    display:flex;
    gap:18px;
    align-items:center;
    box-shadow:0 2px 8px #0006;
}
.badge{
    background:#2e4370;
    border-radius:999px;
    padding:8px 16px;
    font-size:15px;
    font-weight:bold;
    color:#fff;
    letter-spacing:1px;
    box-shadow:0 1px 4px #0004;
    text-decoration:none;
    transition:background 0.2s;
}
.badge:hover{
    background:#3e5ca0;
}
#stream{
    padding:18px 24px;
}
.ev{
    padding:14px 18px;
    margin:10px 0;
    border-radius:12px;
    background:#101a33;
    border:2px solid #1e2b50;
    font-size:16px;
    box-shadow:0 2px 8px #0003;
    transition:background 0.2s, border-color 0.2s;
}
.ev.ok,.ev.open{
    border-color:#1e7845;
    background:#143d2a;
    color:#bfffd0;
}
.ev.open{
    border-color:#2eea7a;
    background:#1f5c3a;
    color:#eafff0;
    font-weight:bold;
}
.ev.reject{
    border-color:#c02e2e;
    background:#2a1212;
    color:#ffd0d0;
}
small{
    opacity:.7;
    font-size:13px;
}
b{
    font-size:17px;
    letter-spacing:1px;
}
code{
    font-size:15px;
    background:#1c2847;
    padding:3px 7px;
    border-radius:6px;
    color:#e4ecff;
    margin-top:4px;
    display:inline-block;
}
@media (max-width:600px){
    header,#stream{padding:10px;}
    .ev{padding:8px;}
}
</style></head>
<body>
<header>
  <div class="badge" style="font-size:18px;background:#2eea7a;color:#0b1220;">POC6</div>
  <div id="hdr">Live events — connecting…</div>
  <a class="badge" href="/status">/status</a>
  <a class="badge" href="/info">/info</a>
</header>
<div id="stream"></div>
<script>
const hdr=document.getElementById('hdr'); const root=document.getElementById('stream');
function line(rec){
  const d=document.createElement('div'); d.className='ev '+rec.evt;
  const ts=new Date(rec.ts*1000).toLocaleTimeString();
  d.innerHTML='<b>['+rec.evt.toUpperCase()+']</b> <small>'+ts+'</small><br><code>'+JSON.stringify(rec)+'</code>';
  root.prepend(d); while(root.childElementCount>200) root.lastChild.remove();
  d.style.animation="fadein 0.7s";
}
const es=new EventSource('/events'); hdr.textContent='Live events — connected';
es.onmessage=(e)=>{ try{ line(JSON.parse(e.data)); }catch{} };
es.onerror=()=>{ hdr.textContent='Live events — disconnected (retrying...)'; };
</script>
</body></html>"""

class Api(BaseHTTPRequestHandler):
    server_version = "poc6/udp/2.0"
    def log_message(self, *a, **k): return
    def _ip(self)->str: return self.client_address[0]
    def _json(self, code:int, obj:dict):
        raw=json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def _rl_ok(self)->bool:
        nowm=time.monotonic()
        tok,last=S.api_rl.get(self._ip(),(RL_CAPACITY,nowm))
        tok=min(RL_CAPACITY, tok + (nowm-last)*RL_REFILL)
        if tok<1.0: S.api_rl[self._ip()]=(tok,nowm); return False
        S.api_rl[self._ip()]=(tok-1.0,nowm); return True

    def do_GET(self):
        if self.path == "/info":
            return self._json(200, {"server_pub": b64u(S.s_pub or b""), "difficulty_bits": S.difficulty_bits,
                                    "difficulty_salt": b64u(S.difficulty_salt), "totp_required": S.totp_required,
                                    "udp": S.udp_port, "ssh": SSH_PORT})
        if self.path == "/status":
            return self._json(200, {"allowed": nft_status(), "metrics": {
                "ok": S.m_ok, "reject": S.m_reject, "pow_avg_bits": round(S.m_pow_avg_bits,2)
            }})
        if self.path == "/events":
            self.send_response(200); self.send_header("Content-Type","text/event-stream")
            self.send_header("Cache-Control","no-cache"); self.send_header("Connection","keep-alive")
            self.end_headers()
            with E_LOCK: SSE_CLIENTS.append(self)
            try:
                # replay des 20 derniers
                with E_LOCK:
                    for rec in E_BUF[-20:]:
                        self.wfile.write(b"data: "+json.dumps(rec,separators=(",",":")).encode()+b"\n\n"); self.wfile.flush()
                while True: time.sleep(60)
            except Exception:
                pass
            return
        if self.path == "/ui":
            raw=HTML_UI.encode()
            self.send_response(200); self.send_header("Content-Type","text/html")
            self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if self.path == "/healthz":
            return self._json(200, {"ok":True})
        self._json(404, {"error":"not_found"})

    def do_POST(self):
        if not self._rl_ok(): return self._json(429, {"error":"rate_limited"})
        ln=int(self.headers.get("Content-Length","0") or "0")
        try: data=json.loads(self.rfile.read(ln).decode()) if ln>0 else {}
        except Exception: return self._json(400, {"error":"bad_json"})
        if self.path == "/enroll":
            kid=str(data.get("kid",""))[:64]; pub=str(data.get("pubkey",""))
            if not kid or not pub: return self._json(400, {"error":"missing_fields"})
            try: raw=de_b64u(pub); ed25519.Ed25519PublicKey.from_public_bytes(raw)
            except Exception: return self._json(400, {"error":"bad_pubkey"})
            S.enrolled[kid]=raw; save_enrolled(); emit("info", msg="enroll", kid=kid)
            return self._json(200, {"ok":True})
        self._json(404, {"error":"not_found"})

# --- UDP SPA
def leading_zero_bits(h: bytes) -> int:
    n=0
    for b in h:
        if b==0: n+=8
        else:
            for i in range(7,-1,-1):
                if (b>>i)&1: return n+(7-i)
            return n
    return n

def handle_packet(pkt: bytes, src_ip: str, open_ttl_default: int):
    def reject(reason:str, **extra):
        if S.audit:
            S.m_reject += 1
            emit("reject", reason=reason, ip=src_ip, **extra)

    try:
        if len(pkt) < 3+1+4+1+32+16+8+12+16: return reject("too_short", ln=len(pkt))
        if pkt[0:3] != MAGIC: return reject("bad_magic")
        ver = pkt[3]
        if ver != VERSION: return reject("bad_version", ver=ver)
        off = 4
        win, = struct.unpack("!I", pkt[off:off+4]); off += 4
        diff = pkt[off]; off += 1
        c_eph = pkt[off:off+32]; off += 32
        kid16 = pkt[off:off+16]; off += 16
        pow_nonce = pkt[off:off+8]; off += 8
        aead_nonce = pkt[off:off+12]; off += 12
        ct = pkt[off:]

        cur = win_id()
        if win not in (cur, cur-1): return reject("win_miss", got=win, expect=cur)

        preimage = MAGIC + bytes([ver]) + struct.pack("!I", win) + S.difficulty_salt + kid16 + c_eph + pow_nonce
        bits = leading_zero_bits(hashlib.sha256(preimage).digest())
        S.m_pow_avg_bits = (S.m_pow_avg_bits*0.9 + bits*0.1) if S.m_ok+S.m_reject else bits
        if bits < min(diff, S.difficulty_bits): return reject("pow_fail", bits=bits, need=S.difficulty_bits)

        s_sk = S.s_priv; assert s_sk is not None
        shared = s_sk.exchange(x25519.X25519PublicKey.from_public_bytes(c_eph))
        salt = hashlib.sha256(S.s_pub + c_eph + struct.pack("!I", win)).digest()
        K = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"poc6/aead").derive(shared)
        aead = AESGCM(K)
        aad = b"PK6|" + struct.pack("!BIB", ver, win, diff) + c_eph + kid16 + pow_nonce
        try: pt = aead.decrypt(aead_nonce, ct, aad)
        except Exception: return reject("aead_fail")

        try: obj = json.loads(pt.decode())
        except Exception: return reject("json_fail")
        sig_b64 = obj.pop("sig", None)
        if not sig_b64: return reject("missing_sig")

        # anti-rejeu
        tnow = time.monotonic()
        for k in list(S.replay.keys()):
            if S.replay[k] < tnow: S.replay.pop(k, None)
        rkey = b64u(hashlib.sha256(pt).digest())
        if rkey in S.replay: return reject("replay")
        S.replay[rkey] = tnow + REPLAY_TTL

        kid_hex = obj.get("kid","")
        pub_raw = S.enrolled.get(kid_hex)
        if not pub_raw: return reject("unknown_kid", kid=kid_hex)
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(de_b64u(sig_b64), canon_bytes(obj))
        except Exception:
            return reject("bad_sig", kid=kid_hex)

        ts = int(obj.get("ts",0))
        if ts<=0 or abs(now()-ts)>90: return reject("stale_ts")
        duration = max(5, min(3600, int(obj.get("duration", open_ttl_default))))
        if S.totp_required and S.totp_secret is not None:
            code = obj.get("totp", None)
            try:
                if code is None: return reject("totp_required")
                if not totp_verify(S.totp_secret, int(code), now()): return reject("totp_bad")
            except Exception:
                return reject("totp_bad")

        nft_open(src_ip, duration)
        S.m_ok += 1
        emit("ok", kid=kid_hex, ip=src_ip, dur=duration, bits=bits)
    except Exception as e:
        emit("reject", reason="exception", error=str(e), ip=src_ip)

# --- main
def main():
    must_root()
    ap=argparse.ArgumentParser(description="POC6 serveur UDP (SPA chiffré) + UI SSE")
    ap.add_argument("--iface", default="lo", help="ex: lo, eth0")
    ap.add_argument("--bind", default=None, help="IP explicite (prioritaire)")
    ap.add_argument("--udp", type=int, default=UDP_PORT_DEFAULT)
    ap.add_argument("--http", type=int, default=HTTP_PORT_DEFAULT)
    ap.add_argument("--open-ttl", type=int, default=OPEN_TTL_S_DEFAULT)
    ap.add_argument("--difficulty", type=int, default=18)
    ap.add_argument("--difficulty-salt", default=None)
    ap.add_argument("--totp-required", action="store_true")
    ap.add_argument("--no-sshd", action="store_true")
    ap.add_argument("--no-audit", action="store_true")
    ap.add_argument("--show", action="store_true")
    args=ap.parse_args()

    ensure_dirs(); ensure_server_key(); ensure_config(args.difficulty, args.difficulty_salt, args.totp_required)
    maybe_load_totp(); load_enrolled()
    S.bind_ip = args.bind or pick_bind_ip(args.iface)
    S.udp_port = int(args.udp); S.http_port = int(args.http); S.audit = not args.no_audit

    if args.show:
        print("Server X25519 pub (b64url):", b64u(S.s_pub or b""))
        print("difficulty_bits:", S.difficulty_bits, "salt(b64u):", b64u(S.difficulty_salt))
        print("totp_required:", S.totp_required)
        print("enrolled_kids:", list(S.enrolled.keys())); return

    nft_install(args.open_ttl)
    if not args.no_sshd: start_sshd(S.bind_ip)

    httpd = ThreadingHTTPServer((S.bind_ip, S.http_port), Api)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    emit("info", msg="http ready", url=f"http://{S.bind_ip}:{S.http_port}/ui")
    print(col(f"[READY] UDP={S.bind_ip}:{S.udp_port} X25519_pub={b64u(S.s_pub or b'')} diff={S.difficulty_bits}", COL.M))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind((S.bind_ip, S.udp_port))

    def _sig(*_):
        S.stop=True
        try: sock.close()
        except: pass
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)

    try:
        while not S.stop:
            try:
                data, addr = sock.recvfrom(4096)
                handle_packet(data, addr[0], args.open_ttl)
            except OSError:
                break
            except Exception as e:
                emit("reject", reason="loop_err", error=str(e))
    finally:
        httpd.shutdown(); stop_sshd(); print(col("[CLEANUP] Bye.", COL.Y))

if __name__=="__main__":
    main()
