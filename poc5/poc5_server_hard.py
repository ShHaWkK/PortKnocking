#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 — Serveur : Knock multi-protocole (TCP->UDP->ICMP) + SPA HTTP signé Ed25519.
- nftables : sets s1, s2, pending, allowed (timeouts).
- API HTTP (:45445) :
  * POST /enroll {kid, pubkey_b64u} : enregistre la clé publique d’un client (idempotent).
  * POST /knock  {kid, ts, nonce, duration, sig_b64u} : vérifie pending + signature Ed25519 + anti-rejeu, puis autorise IP (TTL).
- sshd éphémère sur :2222.
- logs JSONL : /var/log/portknock/poc5.jsonl

Usage :
  sudo python3 poc5_server_hard.py [--p1 47001 --p2 47002 --step-ttl 10 --pending-ttl 15 --open-ttl 60]
"""

import os, sys, time, json, base64, signal, shutil, argparse, subprocess, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
from typing import Dict, Any

# ---- Paramètres par défaut
SSH_PORT      = 2222
SPA_HTTP_PORT = 45445
NFT_TABLE     = "knock5"
NFT_CHAIN_IN  = "inbound"
NFT_CHAIN_ST  = "steps"
SET_S1        = "s1"
SET_S2        = "s2"
SET_PENDING   = "pending"
SET_ALLOWED   = "allowed"

DEFAULT_P1       = 47001   # TCP
DEFAULT_P2       = 47002   # UDP
DEFAULT_STEP_TTL = 10      # secondes entre étapes
DEFAULT_PEND_TTL = 15      # fenêtre SPA après séquence
DEFAULT_OPEN_TTL = 60      # durée d’ouverture SSH

STATE_DIR  = "/var/lib/poc5"
LOG_PATH   = "/var/log/portknock/poc5.jsonl"
CLIENTS_DB = os.path.join(STATE_DIR, "clients.json")  # { kid: pubkey_b64u }

NONCE_TTL_S = 180
_nonce_cache: Dict[str, float] = {}

# ---- Dépendance crypto (unique)
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    print("[ERREUR] Installe d’abord 'cryptography' (pip install cryptography)", file=sys.stderr)
    sys.exit(1)

# ---- Utilitaires "humains"
def must_root():
    if os.geteuid() != 0:
        print("✖ Lance ce serveur en root (sudo).", file=sys.stderr); sys.exit(1)

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
        with open(LOG_PATH, "a") as f: f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def de_b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def canon_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

# ---- nftables
def nft_delete_table():
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def nft_install(p1: int, p2: int, step_ttl: int, pending_ttl: int, open_ttl: int):
    nft_delete_table()
    rules = f"""
add table inet {NFT_TABLE}

add set   inet {NFT_TABLE} {SET_S1}      {{ type ipv4_addr; flags timeout; timeout {step_ttl}s; }}
add set   inet {NFT_TABLE} {SET_S2}      {{ type ipv4_addr; flags timeout; timeout {step_ttl}s; }}
add set   inet {NFT_TABLE} {SET_PENDING} {{ type ipv4_addr; flags timeout; timeout {pending_ttl}s; }}
add set   inet {NFT_TABLE} {SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {open_ttl}s; }}

add chain inet {NFT_TABLE} {NFT_CHAIN_IN} {{ type filter hook input priority -150; policy accept; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_ST}

add rule  inet {NFT_TABLE} {NFT_CHAIN_IN} jump {NFT_CHAIN_ST}

# SSH invisible par défaut
add rule  inet {NFT_TABLE} {NFT_CHAIN_IN} tcp dport {SSH_PORT} ip saddr @{SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN_IN} tcp dport {SSH_PORT} drop

# Séquence : TCP -> UDP -> ICMP
add rule  inet {NFT_TABLE} {NFT_CHAIN_ST} tcp flags syn tcp dport {p1} add @{SET_S1} {{ ip saddr timeout {step_ttl}s }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_ST} ip saddr @{SET_S1} udp dport {p2} add @{SET_S2} {{ ip saddr timeout {step_ttl}s }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_ST} ip saddr @{SET_S2} icmp type echo-request add @{SET_PENDING} {{ ip saddr timeout {pending_ttl}s }}
"""
    tmp = "/tmp/poc5.nft"
    with open(tmp, "w") as f: f.write(rules)
    run(f"nft -f {tmp}", check=True)
    print(f"✓ nftables prêt (TCP {p1} → UDP {p2} → ICMP | SSH:{SSH_PORT})")
    jlog("nft_ready", p1=p1, p2=p2, step_ttl=step_ttl, pending_ttl=pending_ttl, open_ttl=open_ttl)

def nft_ip_in_set(setname: str, ip: str) -> bool:
    r = run(f"nft get element inet {NFT_TABLE} {setname} '{{ {ip} }}'")
    return r.returncode == 0

def nft_add_allowed(ip: str, ttl: int):
    run(f"nft add element inet {NFT_TABLE} {SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    jlog("open", ip=ip, ttl=ttl)
    print(f"✅ IP autorisée : {ip} (TTL {ttl}s)")

# ---- sshd éphémère
def ensure_sshd():
    run("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
    cfg = f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path = "/tmp/poc5_sshd.conf"; open(path, "w").write(cfg)
    subprocess.Popen(["/usr/sbin/sshd", "-f", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    jlog("sshd_ready", port=SSH_PORT)
    print(f"✓ sshd éphémère :0.0.0.0:{SSH_PORT}")

# ---- DB clients (clé publique)
def load_clients() -> Dict[str, str]:
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(CLIENTS_DB): open(CLIENTS_DB, "w").write("{}\n")
    try: return json.loads(open(CLIENTS_DB).read())
    except Exception: return {}

def save_clients(db: Dict[str, str]):
    os.makedirs(STATE_DIR, exist_ok=True)
    open(CLIENTS_DB, "w").write(json.dumps(db, ensure_ascii=False, indent=2) + "\n")

# ---- Anti-rejeu
def gc_nonces():
    now = time.time()
    for k, exp in list(_nonce_cache.items()):
        if exp < now: _nonce_cache.pop(k, None)

def seen_nonce(nonce: str) -> bool:
    gc_nonces(); return nonce in _nonce_cache

def mark_nonce(nonce: str):
    _nonce_cache[nonce] = time.time() + NONCE_TTL_S

# ---- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "POC5/1.0"

    def _json(self, code: int, obj: Any):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass  # pas de spam console

    def do_POST(self):
        try:
            ln = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(ln)
        except Exception:
            self._json(400, {"error": "bad_length"}); return

        if self.path == "/enroll":
            self.handle_enroll(body); return
        if self.path == "/knock":
            self.handle_knock(body); return
        self._json(404, {"error": "not_found"})

    def handle_enroll(self, body: bytes):
        """
        { "kid":"abcd1234", "pubkey":"<b64u raw 32 bytes>" }
        """
        db = load_clients()
        try:
            obj = json.loads(body.decode())
            kid = str(obj["kid"]).strip()
            pk_raw = de_b64u(str(obj["pubkey"]).strip())
            if len(pk_raw) != 32:
                self._json(400, {"error": "pubkey_len"}); return
            # validate
            Ed25519PublicKey.from_public_bytes(pk_raw)
        except Exception as e:
            jlog("enroll_bad", err=str(e), ip=self.client_address[0])
            self._json(400, {"error": "bad_request"}); return

        prev = db.get(kid)
        db[kid] = b64u(pk_raw)
        save_clients(db)
        jlog("enroll_ok", kid=kid, ip=self.client_address[0], updated=int(prev is not None))
        self._json(200, {"status": "ok"})

    def handle_knock(self, body: bytes):
        """
        { kid, ts, nonce, duration, sig }
        sig = Ed25519( canon({duration,kid,nonce,ts}) )
        """
        ip = self.client_address[0]
        if not nft_ip_in_set(SET_PENDING, ip):
            jlog("no_pending", ip=ip)
            self._json(403, {"error": "no_pending"}); return

        try:
            obj = json.loads(body.decode())
            kid = str(obj["kid"])
            ts  = int(obj["ts"])
            nonce = str(obj["nonce"])
            duration = int(obj["duration"])
            sig = de_b64u(str(obj["sig"]))
        except Exception as e:
            jlog("spa_bad_json", err=str(e), ip=ip)
            self._json(400, {"error": "bad_json"}); return

        skew = abs(int(time.time()) - ts)
        if skew > 90:
            jlog("spa_stale", ip=ip, skew=skew); self._json(403, {"error": "stale"}); return
        if seen_nonce(nonce):
            jlog("spa_replay", ip=ip); self._json(403, {"error": "replay"}); return

        db = load_clients()
        pk_b = db.get(kid)
        if not pk_b:
            jlog("unknown_kid", ip=ip, kid=kid); self._json(403, {"error": "unknown_kid"}); return

        try:
            pk = Ed25519PublicKey.from_public_bytes(de_b64u(pk_b))
            payload = {"duration": duration, "kid": kid, "nonce": nonce, "ts": ts}
            pk.verify(sig, canon_bytes(payload))
        except Exception as e:
            jlog("sig_bad", ip=ip, kid=kid, err=str(e)); self._json(403, {"error": "bad_sig"}); return

        ttl = max(5, min(3600, duration))
        mark_nonce(nonce)
        nft_add_allowed(ip, ttl)
        jlog("verify_ok", ip=ip, kid=kid, ttl=ttl)
        self._json(200, {"status": "ok", "ttl": ttl})

def main():
    must_root()

    # Vérifs outils système (nft + sshd)
    missing = []
    if not shutil.which("nft"): missing.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): missing.append("openssh-server")
    if missing:
        print("⚠ Paquets manquants :", ", ".join(missing))
        print("  Installe-les via apt/dnf/pacman selon ta distro.")

    ap = argparse.ArgumentParser()
    ap.add_argument("--p1", type=int, default=DEFAULT_P1)
    ap.add_argument("--p2", type=int, default=DEFAULT_P2)
    ap.add_argument("--step-ttl", type=int, default=DEFAULT_STEP_TTL)
    ap.add_argument("--pending-ttl", type=int, default=DEFAULT_PEND_TTL)
    ap.add_argument("--open-ttl", type=int, default=DEFAULT_OPEN_TTL)
    args = ap.parse_args()

    nft_install(args.p1, args.p2, args.step_ttl, args.pending_ttl, args.open_ttl)
    ensure_sshd()

    httpd = HTTPServer(("0.0.0.0", SPA_HTTP_PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()

    print(f"🚀 Prêt : Séquence TCP {args.p1} → UDP {args.p2} → ICMP | SPA HTTP :{SPA_HTTP_PORT} | SSH :{SSH_PORT}")
    print("ℹ Astuce :  sudo nft list table inet knock5   |   sudo nft monitor")

    def cleanup(*_):
        try: httpd.shutdown()
        except Exception: pass
        nft_delete_table()
        jlog("server_stop")
        print("\n🧹 Nettoyage : table nft supprimée. Bye.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
