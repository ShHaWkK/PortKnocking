#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 - Serveur (corrigé)
- Auto-installe cryptography (pip/apt), nftables/openssh-server (apt/dnf/pacman)
- Ouvre UFW/Firewalld si actifs (sinon, ne touche à rien)
- Génère /etc/portknock/secret si absent (copie aussi pour l'utilisateur sudoer)
- Démarre un sshd éphémère sur 0.0.0.0:2222
- Pose nftables: table inet knock5, set @allowed (TTL), rule accept/dropping pour 2222
- Décode la trame timing (preamble 10101010 + length 16 bits + JSON AES-GCM)
Usage:
  sudo python3 poc5_server_timing.py
"""
import os, sys, time, json, hmac, hashlib, base64, shutil, socket, signal, subprocess, getpass, pwd
from datetime import datetime
from statistics import median
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

# ---------- bootstrap ----------
def _pip_install(*pkgs):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", *pkgs], check=True); return True
    except Exception: return False

def _apt_install(*pkgs):
    if not shutil.which("apt"): return False
    try:
        subprocess.run(["sudo","apt","update"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","apt","install","-y",*pkgs], check=False); return True
    except Exception: return False

def _dnf_install(*pkgs):
    if not shutil.which("dnf"): return False
    try:
        subprocess.run(["sudo","dnf","install","-y",*pkgs], check=False); return True
    except Exception: return False

def _pacman_install(*pkgs):
    if not shutil.which("pacman"): return False
    try:
        subprocess.run(["sudo","pacman","-Sy","--noconfirm",*pkgs], check=False); return True
    except Exception: return False

def ensure_pydeps():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        print("[i] Installation cryptography…")
        _pip_install("cryptography") or _apt_install("python3-cryptography")

def ensure_sysbins():
    missing = []
    if not shutil.which("nft"): missing.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): missing.append("openssh-server")
    if missing:
        print(f"[i] Installation système: {' '.join(missing)}")
        _apt_install(*missing) or _dnf_install(*missing) or _pacman_install(*missing)

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lancer ce serveur avec sudo.", file=sys.stderr); sys.exit(1)

# ---------- paramètres ----------
LURE_PORT          = 443
SSH_PORT           = 2222
LISTEN_ADDR_SSHD   = "0.0.0.0"
PREAMBULE          = [1,0,1,0,1,0,1,0]
MIN_TOTAL_BITS     = 8 + 16 + 8
ANTI_REPLAY_S      = 90
OPEN_TTL_S_DEFAULT = 60
LOG_FILE           = "/var/log/portknock/poc5_server.jsonl"
NFT_TABLE          = "knock5"
NFT_CHAIN_INPUT    = "inbound"
NFT_SET_ALLOWED    = "allowed"
MASTER_SECRET_PATH = "/etc/portknock/secret"
USER_COPY_FMT      = "{home}/.config/portknock/{name}"

arrivees, derniers, ips_autorisees = {}, {}, {}
_stop = False
_sshd_proc = None

# ---------- utils ----------
def jprint(event, **fields):
    msg = " ".join(f"{k}={v}" for k,v in fields.items())
    print(f"[{event}] {msg}".rstrip(), flush=True)

def jlog(event, **fields):
    row = {"ts": datetime.utcnow().isoformat()+"Z", "event": event}; row.update(fields)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f: f.write(json.dumps(row, ensure_ascii=False)+"\n")

def run(*cmd, check=True):
    r = subprocess.run(list(cmd), text=True, capture_output=True)
    if check and r.returncode != 0:
        raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, r.stderr)
    return r

def b64_read_tolerant(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def load_or_create_master_secret() -> bytes:
    os.makedirs(os.path.dirname(MASTER_SECRET_PATH), exist_ok=True)
    if not os.path.exists(MASTER_SECRET_PATH):
        raw = os.urandom(32)
        with open(MASTER_SECRET_PATH, "w") as f: f.write(base64.b64encode(raw).decode()+"\n")
        os.chmod(MASTER_SECRET_PATH, 0o600)
        print(f"[+] Secret maître généré : {MASTER_SECRET_PATH}")
    else:
        print(f"[i] Secret maître : {MASTER_SECRET_PATH}")
    sec = b64_read_tolerant(open(MASTER_SECRET_PATH).read())
    if len(sec) < 16: print("[ERREUR] Secret trop court.", file=sys.stderr); sys.exit(1)
    return sec

def copy_secret_for_user(name: str, content: str):
    import pwd, getpass
    sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pw = pwd.getpwnam(sudo_user); home, uid, gid = pw.pw_dir, pw.pw_uid, pw.pw_gid
    except Exception:
        home, uid, gid = os.path.expanduser("~"), None, None
    dst = USER_COPY_FMT.format(home=home, name=name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst,"w") as f: f.write(content.strip()+"\n")
    os.chmod(dst, 0o600)
    if uid is not None: os.chown(dst, uid, gid)
    print(f"[i] Copie secret → {dst}")

def derive_keys(master: bytes):
    aes_key  = hashlib.sha256(master + b"|AES").digest()
    hmac_key = hashlib.sha256(master + b"|HMAC").digest()
    return aes_key, hmac_key

# ---------- firewall externe ----------
def firewall_open_if_needed():
    # UFW
    if shutil.which("ufw"):
        try:
            st = run("bash","-lc","ufw status | grep -i active || true", check=False).stdout
            if "active" in (st or "").lower():
                run("bash","-lc", f"ufw allow {LURE_PORT}/tcp || true", check=False)
                run("bash","-lc", f"ufw allow {SSH_PORT}/tcp || true", check=False)
                jprint("ufw_rules_set", ports=f"{LURE_PORT}, {SSH_PORT}")
        except Exception: pass
    # Firewalld
    if shutil.which("firewall-cmd"):
        try:
            st = run("firewall-cmd","--state", check=False).stdout.strip()
            if st == "running":
                run("firewall-cmd","--add-port",f"{LURE_PORT}/tcp","--permanent", check=False)
                run("firewall-cmd","--add-port",f"{SSH_PORT}/tcp","--permanent", check=False)
                run("firewall-cmd","--reload", check=False)
                jprint("firewalld_rules_set", ports=f"{LURE_PORT}, {SSH_PORT}")
        except Exception: pass

# ---------- nftables ----------
def nft_delete_table():
    run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true",
        check=False)

def nft_install_base(ttl_open: int):
    nft_delete_table()
    base = f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} allowed {{ type ipv4_addr; flags timeout; timeout {ttl_open}s; }}
add chain inet {NFT_TABLE} inbound {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} inbound tcp dport {SSH_PORT} ip saddr @allowed accept
add rule  inet {NFT_TABLE} inbound tcp dport {SSH_PORT} drop
"""
    tmp = "/tmp/nft_knock5_base.nft"
    with open(tmp,"w") as f: f.write(base)
    run("nft","-f", tmp)
    jprint("nft_ready", table=NFT_TABLE, chain=NFT_CHAIN_INPUT, set=NFT_SET_ALLOWED)

def nft_add_allowed(ip: str, ttl: int):
    run("bash","-lc", f"nft add element inet {NFT_TABLE} allowed '{{ {ip} timeout {int(ttl)}s }}'", check=False)
    ips_autorisees[ip] = time.monotonic() + int(ttl)
    jprint("open", ip=ip, ttl=f"{ttl}s"); jlog("open", ip=ip, ttl=ttl)

def nft_gc():
    now = time.monotonic()
    for ip, exp in list(ips_autorisees.items()):
        if now > exp:
            run("bash","-lc", f"nft delete element inet {NFT_TABLE} allowed '{{ {ip} }}'", check=False)
            ips_autorisees.pop(ip, None)
            jprint("close", ip=ip); jlog("close", ip=ip)

# ---------- décodage timing + crypto ----------
def _classify(deltas):
    m = median(deltas); return [1 if d>m else 0 for d in deltas]

def _find(seq, pat):
    n, m = len(seq), len(pat)
    for i in range(0, n-m+1):
        if seq[i:i+m] == pat: return i
    return -1

def _bits_to_bytes(bits):
    if len(bits)%8: return b""
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int("".join(map(str,bits[i:i+8])),2))
    return bytes(out)

def spa_decrypt_and_verify(msg_bytes: bytes, aes_key: bytes, hmac_key: bytes):
    try:
        obj = json.loads(msg_bytes.decode())
        ciphertext = bytes.fromhex(obj["ciphertext"])
        nonce = bytes.fromhex(obj["nonce"])
        tag = bytes.fromhex(obj["tag"])
        pt = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)
        spa = json.loads(pt.decode())
        payload = {"duration": int(spa["duration"]), "timestamp": int(spa["timestamp"])}
        canon = json.dumps(payload, separators=(",",":"), sort_keys=True).encode()
        expect = hmac.new(hmac_key, canon, hashlib.sha256).hexdigest()
        if expect != spa.get("hmac",""): jprint("hmac_bad"); return None
        if abs(int(time.time()) - int(spa["timestamp"])) > ANTI_REPLAY_S:
            jprint("spa_stale"); return None
        return spa
    except Exception as e:
        jprint("spa_error", err=str(e)); return None

def try_decode_for_ip(src_ip, deltas, aes_key, hmac_key):
    if len(deltas) < MIN_TOTAL_BITS: return Fa
