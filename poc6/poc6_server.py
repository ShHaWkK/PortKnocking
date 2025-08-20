#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC6 — Serveur SPA 100% UDP
- Un datagramme UDP chiffré (AES-GCM), dérivé via X25519/HKDF, signé Ed25519.
- PoW (bits zéro) + fenêtre temporelle (N/N-1) + anti-rejeu (cache 5 min).
- À succès : ajout IP dans set nftables → SSH:2222.
- Auto-découverte & enrôlement via HTTP (GET /info, POST /enroll).
- Démarre un sshd éphémère sur :2222 (désactivable).
Usage minimal: sudo python3 poc6_server.py --iface lo
"""

import os, sys, time, json, base64, argparse, socket, struct, hashlib, hmac, subprocess, signal, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple, Optional
from dataclasses import dataclass, field

# ---- Dépendances crypto
try:
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    print("Installez la dépendance Python : pip install cryptography", file=sys.stderr)
    sys.exit(1)

# ---- Constantes
SSH_PORT           = 2222
UDP_PORT_DEFAULT   = 45446
HTTP_PORT_DEFAULT  = 45447
NFT_TABLE          = "knock6"
NFT_CHAIN          = "inbound"
NFT_SET_ALLOWED    = "allowed"
OPEN_TTL_S_DEFAULT = 60
WINDOW_SEC         = 30
REPLAY_TTL         = 300  # s
STATE_DIR          = "/etc/portknock6"
SKEY_PATH          = os.path.join(STATE_DIR, "server_x25519.pem")   # PKCS8 PEM
ENROLL_DB          = os.path.join(STATE_DIR, "keys.json")           # {kid: raw_pub_b64u}
CONF_PATH          = os.path.join(STATE_DIR, "config.json")         # {"difficulty_bits":18,"difficulty_salt":"b64u","totp_required":false}
TOTP_SECRET_PATH   = os.path.join(STATE_DIR, "totp_base32")         # optionnel base32
RL_CAPACITY        = 10.0   # HTTP rate-limit (par IP)
RL_REFILL          = 10.0   # jetons / s

# ---- Utils
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def de_b64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def canon_bytes(obj) -> bytes: return json.dumps(obj, separators=(",",":"), sort_keys=True, ensure_ascii=False).encode()

def run(cmd: str) -> Tuple[int,str,str]:
    p = subprocess.run(["bash","-lc",cmd], capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def must_root():
    if os.geteuid()!=0:
        print("Erreur: lancez en root.", file=sys.stderr); sys.exit(1)

def now() -> int: return int(time.time())
def win_id() -> int: return int(now() // WINDOW_SEC)

# ---- TOTP
def b32_read(text: str) -> bytes:
    return base64.b32decode("".join(text.strip().split()).upper())

def totp_now(secret: bytes, for_time: int, step=30, digits=6) -> int:
    ctr = int(for_time // step)
    msg = struct.pack(">Q", ctr)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = ((digest[off] & 0x7F)<<24) | (digest[off+1]<<16) | (digest[off+2]<<8) | digest[off+3]
    return code % (10**digits)

def totp_verify(secret: bytes, code: int, t: int) -> bool:
    for k in (-1,0,1):
        if totp_now(secret, t + 30*k) == code: return True
    return False

# ---- État serveur
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
    s_pub: Optional[bytes] = None  # 32B raw
    enrolled: Dict[str, bytes] = field(default_factory=dict)  # kid -> raw Ed25519 pub
    replay: Dict[str, float] = field(default_factory=dict)    # key -> expiry mono
    api_rl: Dict[str, Tuple[float,float]] = field(default_factory=dict) # ip -> (tokens,last_mono)
    stop: bool = False
    sshd_proc: Optional[subprocess.Popen] = None
S = State()

# ---- Init stockage & clés
def ensure_dirs():
    os.makedirs(STATE_DIR, exist_ok=True)

def ensure_server_key():
    if os.path.exists(SKEY_PATH):
        sk = serialization.load_pem_private_key(open(SKEY_PATH,"rb").read(), password=None)
        if not isinstance(sk, x25519.X25519PrivateKey): raise ValueError("Clé serveur: mauvais type")
    else:
        sk = x25519.X25519PrivateKey.generate()
        pem = sk.private_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PrivateFormat.PKCS8,
                               encryption_algorithm=serialization.NoEncryption())
        open(SKEY_PATH,"wb").write(pem); os.chmod(SKEY_PATH, 0o600)
    S.s_priv = sk
    S.s_pub = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                           format=serialization.PublicFormat.Raw)

def load_enrolled():
    if os.path.exists(ENROLL_DB):
        try: S.enrolled = {kid: de_b64u(b64) for kid,b64 in json.load(open(ENROLL_DB)).items()}
        except Exception: S.enrolled = {}
    else: S.enrolled = {}

def save_enrolled():
    json.dump({kid:b64u(raw) for kid,raw in S.enrolled.items()}, open(ENROLL_DB,"w"), indent=2)

def ensure_config(default_bits: int = 18, difficulty_salt_b64u: Optional[str] = None, totp_required: Optional[bool]=None):
    cfg = {}
    if os.path.exists(CONF_PATH):
        try: cfg = json.load(open(CONF_PATH))
        except Exception: cfg = {}
    if difficulty_salt_b64u is not None:
        cfg["difficulty_salt"] = difficulty_salt_b64u
    elif "difficulty_salt" not in cfg:
        cfg["difficulty_salt"] = b64u(os.urandom(16))
    cfg["difficulty_bits"] = int(cfg.get("difficulty_bits", default_bits))
    if totp_required is not None:
        cfg["totp_required"] = bool(totp_required)
    open(CONF_PATH,"w").write(json.dumps(cfg, indent=2))
    S.difficulty_bits = int(cfg["difficulty_bits"])
    S.difficulty_salt = de_b64u(cfg["difficulty_salt"])
    S.totp_required = bool(cfg.get("totp_required", False))

def maybe_load_totp():
    if os.path.exists(TOTP_SECRET_PATH):
        try:
            S.totp_secret = b32_read(open(TOTP_SECRET_PATH).read()); S.totp_required = True
        except Exception:
            S.totp_secret = None

# ---- nftables + sshd
def nft_install(open_ttl: int = OPEN_TTL_S_DEFAULT):
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")
    conf=f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {open_ttl}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} ip saddr @{NFT_SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop
"""
    tmp="/tmp/poc6.nft"; open(tmp,"w").write(conf)
    rc,_,err = run(f"nft -f {tmp}")
    if rc!=0:
        print("[ERREUR] nftables :", err, file=sys.stderr); sys.exit(1)
    print("[NFT] prêt → table:", NFT_TABLE, "set:", NFT_SET_ALLOWED, "SSH:", SSH_PORT)

def nft_open(ip:str, ttl:int):
    run(f"nft add element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    print(f"[OPEN] ip={ip} ttl={ttl}s")

def ensure_hostkeys():
    run("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A >/dev/null 2>&1 || true")

def start_sshd(bind_ip: str):
    ensure_hostkeys()
    cfg=f"Port {SSH_PORT}\nListenAddress {bind_ip}\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc6_sshd.pid\nLogLevel QUIET\n"
    path="/tmp/poc6_sshd.conf"; open(path,"w").write(cfg)
    proc = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    S.sshd_proc = proc
    print(f"[SSHD] démarré sur {bind_ip}:{SSH_PORT}")

def stop_sshd():
    p=S.sshd_proc
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(2)
        except: p.kill()

# ---- Réseau util
def pick_bind_ip(iface: Optional[str]) -> str:
    if not iface: return "0.0.0.0"
    iface = iface.strip()
    if iface == "lo": return "127.0.0.1"
    rc,out,_ = run(f"ip -o -4 addr show dev {iface} | awk '{{print $4}}' | cut -d/ -f1 | head -n1")
    return out or "0.0.0.0"

def leading_zero_bits(h: bytes) -> int:
    n=0
    for b in h:
        if b == 0: n+=8
        else:
            for i in range(7,-1,-1):
                if (b>>i)&1: return n + (7-i)
            return n
    return n

# ---- HTTP API
class Api(BaseHTTPRequestHandler):
    server_version = "poc6/udp/1.0"
    def log_message(self, *a, **k): return
    def _ip(self)->str: return self.client_address[0]
    def _json(self, code:int, obj:dict):
        raw=json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers(); self.wfile.write(raw)
    def _rl_ok(self)->bool:
        nowm=time.monotonic()
        tok,last=S.api_rl.get(self._ip(),(RL_CAPACITY,nowm))
        tok=min(RL_CAPACITY, tok + (nowm-last)*RL_REFILL)
        if tok<1.0: S.api_rl[self._ip()]=(tok,nowm); return False
        S.api_rl[self._ip()]=(tok-1.0,nowm); return True

    def do_GET(self):
        if self.path == "/info":
            self._json(200, {"server_pub": b64u(S.s_pub or b""), "difficulty_bits": S.difficulty_bits,
                             "difficulty_salt": b64u(S.difficulty_salt), "totp_required": S.totp_required,
                             "udp": S.udp_port, "ssh": SSH_PORT})
            return
        if self.path == "/healthz":
            self._json(200, {"ok":True}); return
        self._json(404, {"error":"not_found"})

    def do_POST(self):
        if not self._rl_ok():
            return self._json(429, {"error":"rate_limited"})
        ln = int(self.headers.get("Content-Length","0") or "0")
        try:
            data = json.loads(self.rfile.read(ln).decode()) if ln>0 else {}
        except Exception:
            return self._json(400, {"error":"bad_json"})
        if self.path == "/enroll":
            kid = str(data.get("kid",""))[:64]; pub=str(data.get("pubkey",""))
            if not kid or not pub: return self._json(400, {"error":"missing_fields"})
            try:
                raw=de_b64u(pub); ed25519.Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                return self._json(400, {"error":"bad_pubkey"})
            S.enrolled[kid]=raw; save_enrolled()
            return self._json(200, {"ok":True})
        self._json(404, {"error":"not_found"})

# ---- Traitement du SPA UDP
def handle_packet(pkt: bytes, src_ip: str, open_ttl_default: int):
    try:
        if len(pkt) < 3+1+4+1+32+16+8+12+16:  # en-tête minimal
            return
        magic = pkt[0:3]
        if magic != b'PK6': return
        ver = pkt[3]
        if ver != 1: return
        off = 4
        win, = struct.unpack("!I", pkt[off:off+4]); off += 4
        diff = pkt[off]; off += 1
        c_eph = pkt[off:off+32]; off += 32
        kid16 = pkt[off:off+16]; off += 16
        pow_nonce = pkt[off:off+8]; off += 8
        aead_nonce = pkt[off:off+12]; off += 12
        ct = pkt[off:]

        # Fenêtre N/N-1
        cur = win_id()
        if win not in (cur, cur-1):
            return

        # PoW
        preimage = b'PK6' + bytes([ver]) + struct.pack("!I", win) + S.difficulty_salt + kid16 + c_eph + pow_nonce
        bits = leading_zero_bits(hashlib.sha256(preimage).digest())
        if bits < min(diff, S.difficulty_bits):
            return

        # AEAD
        s_sk = S.s_priv; assert s_sk is not None
        shared = s_sk.exchange(x25519.X25519PublicKey.from_public_bytes(c_eph))
        salt = hashlib.sha256(S.s_pub + c_eph + struct.pack("!I", win)).digest()
        K = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"poc6/aead").derive(shared)
        aead = AESGCM(K)
        aad = b"PK6|" + struct.pack("!BIB", ver, win, diff) + c_eph + kid16 + pow_nonce
        try:
            pt = aead.decrypt(aead_nonce, ct, aad)
        except Exception:
            return

        # Payload JSON signé
        try:
            obj = json.loads(pt.decode())
        except Exception:
            return
        sig_b64 = obj.pop("sig", None)
        if not sig_b64:
            return

        # Anti-rejeu (cache du payload)
        tnow = time.monotonic()
        for k in list(S.replay.keys()):
            if S.replay[k] < tnow: S.replay.pop(k, None)
        rkey = b64u(hashlib.sha256(pt).digest())
        if rkey in S.replay:
            return
        S.replay[rkey] = tnow + REPLAY_TTL

        # Signature Ed25519
        kid_hex = obj.get("kid","")
        pub_raw = S.enrolled.get(kid_hex)
        if not pub_raw:
            return
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(de_b64u(sig_b64), canon_bytes(obj))
        except Exception:
            return

        # Fraîcheur & TOTP
        ts = int(obj.get("ts",0))
        if ts<=0 or abs(now()-ts)>90: return
        duration = int(obj.get("duration", open_ttl_default))
        duration = max(5, min(3600, duration))
        if S.totp_required and S.totp_secret is not None:
            code = obj.get("totp", None)
            try:
                if code is None: return
                if not totp_verify(S.totp_secret, int(code), now()): return
            except Exception:
                return

        # OK -> ouvrir
        nft_open(src_ip, duration)
        print(f"[OK] kid={kid_hex} ip={src_ip} dur={duration}s bits={bits}")
    except Exception as e:
        print("[ERR]", e)

# ---- Main
def main():
    must_root()
    ap=argparse.ArgumentParser(description="POC6 serveur UDP (SPA chiffré)")
    ap.add_argument("--iface", default="lo", help="ex: lo, eth0 (choisit l'IP de bind)")
    ap.add_argument("--bind", default=None, help="IP explicite (prioritaire sur --iface)")
    ap.add_argument("--udp", type=int, default=UDP_PORT_DEFAULT)
    ap.add_argument("--http", type=int, default=HTTP_PORT_DEFAULT)
    ap.add_argument("--open-ttl", type=int, default=OPEN_TTL_S_DEFAULT)
    ap.add_argument("--difficulty", type=int, default=18)
    ap.add_argument("--difficulty-salt", default=None, help="b64url (sinon auto)")
    ap.add_argument("--totp-required", action="store_true", help="Active l'exigence TOTP si un secret est présent")
    ap.add_argument("--no-sshd", action="store_true", help="Ne pas lancer sshd éphémère")
    ap.add_argument("--show", action="store_true", help="Affiche la pub X25519 et la config puis quitte")
    args=ap.parse_args()

    ensure_dirs(); ensure_server_key(); ensure_config(args.difficulty, args.difficulty_salt, args.totp_required); maybe_load_totp(); load_enrolled()
    S.bind_ip = args.bind or pick_bind_ip(args.iface)
    S.udp_port = int(args.udp); S.http_port = int(args.http)

    if args.show:
        print("Server X25519 pub (b64url):", b64u(S.s_pub or b""))
        print("difficulty_bits:", S.difficulty_bits, "salt(b64u):", b64u(S.difficulty_salt))
        print("totp_required:", S.totp_required)
        print("enrolled_kids:", list(S.enrolled.keys()))
        return

    nft_install(args.open_ttl)
    if not args.no_sshd:
        start_sshd(S.bind_ip)

    # HTTP info/enroll
    httpd = ThreadingHTTPServer((S.bind_ip, S.http_port), Api)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[HTTP] /info,/enroll sur http://{S.bind_ip}:{S.http_port}")

    # UDP loop
    print(f"[READY] UDP={S.bind_ip}:{S.udp_port} X25519_pub={b64u(S.s_pub or b'')} diff={S.difficulty_bits}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((S.bind_ip, S.udp_port))

    def _sig(*_):
        S.stop=True
        try: sock.close()
        except: pass
    signal.signal(signal.SIGINT, _sig); signal.signal(signal.SIGTERM, _sig)

    try:
        while not S.stop:
            try:
                data, addr = sock.recvfrom(2048)
                handle_packet(data, addr[0], args.open_ttl)
            except OSError:
                break
            except Exception as e:
                print("[LOOP_ERR]", e)
    finally:
        httpd.shutdown()
        stop_sshd()
        print("[CLEANUP] Bye.")

if __name__=="__main__":
    main()
