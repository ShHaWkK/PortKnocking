#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 (serveur) — Timing SYN sur 443 + SPA AES-GCM + ouverture dynamique via nftables + firewall auto + sshd éphémère.
Commande unique :  sudo python3 poc5_server_timing_spa.py
"""

import os, sys, time, json, hmac, hashlib, base64, shutil, socket, signal, subprocess, getpass, pwd
from datetime import datetime
from statistics import median
from typing import Dict, List, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

# --- Paramètres ---
LURE_PORT          = 443
SSH_PORT           = 2222
LISTEN_ADDR_SSHD   = "0.0.0.0"
PREAMBULE_BITS     = [1,0,1,0,1,0,1,0]  # 10101010
MIN_TOTAL_BITS     = 8 + 16 + 8         # préambule + longueur + 1 octet mini
ANTI_REPLAY_S      = 90
OPEN_TTL_S_DEFAULT = 60
LOG_FILE           = "/var/log/portknock/poc5_server.jsonl"
NFT_TABLE          = "knock5"
NFT_CHAIN_INPUT    = "inbound"
NFT_SET_ALLOWED    = "allowed"
MASTER_SECRET_PATH = "/etc/portknock/secret"
USER_COPY_FMT      = "{home}/.config/portknock/{name}"

arrivees: Dict[str, List[float]] = {}
derniers: Dict[str, float] = {}
ips_autorisees: Dict[str, float] = {}
_stop = False
_sshd_proc: Optional[subprocess.Popen] = None

# --- Utils ---
def jprint(event: str, **fields):
    msg = " ".join(f"{k}={v}" for k,v in fields.items())
    print(f"[{event}] {msg}".rstrip(), flush=True)

def jlog(event: str, **fields):
    row = {"ts": datetime.utcnow().isoformat()+"Z", "event": event}
    row.update(fields)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(row, ensure_ascii=False)+"\n")

def run(*cmd, check=True) -> subprocess.CompletedProcess:
    r = subprocess.run(list(cmd), text=True, capture_output=True)
    if check and r.returncode != 0:
        raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, r.stderr)
    return r

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance ce serveur avec sudo.", file=sys.stderr); sys.exit(1)

# --- Dépendances ---
def _pip_install(pkg: str) -> bool:
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg], check=True); return True
    except Exception:
        return False

def _apt_install(*pkgs: str) -> bool:
    if not shutil.which("apt"): return False
    try:
        run("sudo","apt","update", check=False)
        run("sudo","apt","install","-y",*pkgs, check=False); return True
    except Exception: return False

def _dnf_install(*pkgs: str) -> bool:
    if not shutil.which("dnf"): return False
    try:
        run("sudo","dnf","install","-y",*pkgs, check=False); return True
    except Exception: return False

def _pacman_install(*pkgs: str) -> bool:
    if not shutil.which("pacman"): return False
    try:
        run("sudo","pacman","-Sy","--noconfirm",*pkgs, check=False); return True
    except Exception: return False

def ensure_pydeps():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        print("[i] Installation cryptography…")
        _pip_install("cryptography") or _apt_install("python3-cryptography") or _dnf_install("python3-cryptography") or _pacman_install("python-cryptography")

def ensure_sysbins():
    missing = []
    if not shutil.which("nft"): missing.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): missing.append("openssh-server")
    if missing:
        print(f"[i] Installation système : {' '.join(missing)}")
        _apt_install(*missing) or _dnf_install(*missing) or _pacman_install(*missing)

# --- Secrets ---
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
    sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pw = pwd.getpwnam(sudo_user); home, uid, gid = pw.pw_dir, pw.pw_uid, pw.pw_gid
    except Exception:
        home, uid, gid = os.path.expanduser("~"), None, None
    dst = USER_COPY_FMT.format(home=home, name=name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w") as f: f.write(content.strip()+"\n")
    os.chmod(dst, 0o600)
    if uid is not None: os.chown(dst, uid, gid)
    print(f"[i] Copie secret → {dst}")

def derive_keys(master: bytes) -> Tuple[bytes, bytes]:
    return hashlib.sha256(master + b"|AES").digest(), hashlib.sha256(master + b"|HMAC").digest()

# --- sshd éphémère ---
def ensure_host_keys():
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False)

def start_sshd():
    global _sshd_proc
    ensure_host_keys()
    cfg = f"""Port {SSH_PORT}
ListenAddress {LISTEN_ADDR_SSHD}
UsePAM yes
PasswordAuthentication yes
PubkeyAuthentication yes
PidFile /tmp/poc5_sshd.pid
LogLevel QUIET
"""
    path = "/tmp/poc5_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    _sshd_proc = subprocess.Popen(["/usr/sbin/sshd","-f",path],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    jprint("sshd_start", addr=LISTEN_ADDR_SSHD, port=SSH_PORT)

def stop_sshd():
    global _sshd_proc
    if _sshd_proc and _sshd_proc.poll() is None:
        _sshd_proc.terminate()
        try: _sshd_proc.wait(2)
        except: _sshd_proc.kill()
        jprint("sshd_stop")

# --- Firewall externe (UFW/Firewalld) auto ---
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

# --- nftables ---
def nft_delete_table():
    run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true",
        check=False)

def nft_install_base(ttl_open: int):
    nft_delete_table()
    base = f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {ttl_open}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_INPUT} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} ip saddr @{NFT_SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} drop
"""
    tmp = "/tmp/nft_knock5_base.nft"
    with open(tmp,"w") as f: f.write(base)
    run("nft","-f", tmp)
    jprint("nft_ready", table=NFT_TABLE, chain=NFT_CHAIN_INPUT, set=NFT_SET_ALLOWED)

def nft_add_allowed(ip: str, ttl: int):
    run("bash","-lc", f"nft add element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} timeout {int(ttl)}s }}'", check=False)
    ips_autorisees[ip] = time.monotonic() + int(ttl)
    jprint("open", ip=ip, ttl=f"{ttl}s"); jlog("open", ip=ip, ttl=ttl)

def nft_gc():
    now = time.monotonic()
    for ip, exp in list(ips_autorisees.items()):
        if now > exp:
            run("bash","-lc", f"nft delete element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} }}'", check=False)
            ips_autorisees.pop(ip, None)
            jprint("close", ip=ip); jlog("close", ip=ip)

# --- Décodage timing + SPA ---
def _oscillo(intervals):
    if not intervals: return
    m = median(intervals[-64:])
    bar = "".join("▮" if d>m else "▯" for d in intervals[-64:])
    print(f"[OSC] {bar} (med={m:.3f}s)")

def _classify(deltas):  # 0/1 par seuil médian (robuste)
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

def try_decode_for_ip(src_ip: str, aes_key: bytes, hmac_key: bytes):
    deltas = arrivees.get(src_ip, [])
    if len(deltas) < MIN_TOTAL_BITS: return False
    rough = _classify(deltas)
    idx = _find(rough, PREAMBULE_BITS)
    if idx < 0: return False
    after = rough[idx+len(PREAMBLE_BITS):]
    if len(after) < 16: return False
    L = int("".join(map(str, after[:16])), 2)
    total_bits = len(PREAMBLE_BITS) + 16 + 8*L
    if len(deltas) < idx + total_bits: return False
    seg = deltas[idx: idx+total_bits]
    seg_bits = _classify(seg)
    msg_bits = seg_bits[len(PREAMBLE_BITS)+16:]
    data = _bits_to_bytes(msg_bits)
    spa = spa_decrypt_and_verify(data, aes_key, hmac_key)
    arrivees[src_ip].clear()
    if not spa: return False
    ttl = int(spa.get("duration", OPEN_TTL_S_DEFAULT)) or OPEN_TTL_S_DEFAULT
    nft_add_allowed(src_ip, ttl)
    return True

# --- Main ---
def handle_signals(signum, frame):
    global _stop; _stop = True

def main():
    must_root()
    ensure_pydeps(); ensure_sysbins()
    firewall_open_if_needed()

    master = load_or_create_master_secret()
    aes_key = hashlib.sha256(master + b"|AES").digest()
    hmac_key = hashlib.sha256(master + b"|HMAC").digest()
    copy_secret_for_user("secret", base64.b64encode(master).decode())

    ttl_open = OPEN_TTL_S_DEFAULT if OPEN_TTL_S_DEFAULT>0 else (24*3600)
    nft_install_base(ttl_open)
    start_sshd()

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(1.0)
    jprint("server_listen", dport=LURE_PORT); jlog("server_start", lure=LURE_PORT, ssh=SSH_PORT)

    signal.signal(signal.SIGINT, handle_signals)
    signal.signal(signal.SIGTERM, handle_signals)

    try:
        while not _stop:
            try:
                pkt, _ = s.recvfrom(65535)
            except socket.timeout:
                nft_gc(); continue
            except Exception as e:
                jprint("recv_error", err=str(e)); continue

            if len(pkt) < 40: continue
            ihl = (pkt[0] & 0x0F) * 4
            if ihl < 20: continue
            src_ip = ".".join(str(b) for b in pkt[12:16])
            off = ihl
            dport = int.from_bytes(pkt[off+2:off+4], "big")
            flags = pkt[off+13]
            if dport != LURE_PORT: continue
            # SYN sans ACK
            if not (flags & 0x02) or (flags & 0x10): continue

            now = time.monotonic()
            last = derniers.get(src_ip); derniers[src_ip] = now
            if last is None:
                arrivees.setdefault(src_ip, []); continue

            delta = now - last
            arrivees.setdefault(src_ip, []).append(delta)
            # oscillo (optionnel)
            buf = arrivees[src_ip]
            if buf: 
                m = median(buf[-64:]); bar = "".join("▮" if d>m else "▯" for d in buf[-64:])
                print(f"[OSC] {bar} (med={m:.3f}s)")
            try:
                try_decode_for_ip(src_ip, aes_key, hmac_key)
            except Exception as e:
                jprint("decode_error", err=str(e))
            if len(buf) > 4096: buf[:] = buf[-1024:]
            nft_gc()
    finally:
        try: s.close()
        except: pass
        nft_delete_table()
        stop_sshd()
        jlog("server_stop")
        jprint("cleanup_done")

if __name__ == "__main__":
    main()
