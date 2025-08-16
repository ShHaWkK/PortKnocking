#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Serveur complet
Canal temporel via timings de SYN sur 443 + SPA binaire AES-GCM + ouverture dynamique via nftables.
Tout est automatisé :
- Dépendances Python (cryptography, scapy) et binaires (nftables, openssh-server) installés si besoin
- Génération/copier du secret maître (base64) : /etc/portknock/secret -> ~/.config/portknock/secret
- nftables : table inet knock5, set @allowed (TTL), chain inbound (drop SSH si pas allowed)
- sshd éphémère sur 0.0.0.0:2222 (mot de passe autorisé pour la démo)
- Sniff **multi-interfaces** (loopback compris) avec Scapy
- Décodage **compatible** 2 formats client :
    * legacy : PREAMBULE (8) + LEN(16) + WIRE(53 bytes)  => 448 bits
    * fast   : PREAMBULE (8) + WIRE(51 bytes)           => 416 bits
Usage : sudo python3 poc5_server_timing.py
(autodétection des interfaces à sniffer ; override possible : --iface lo,eth0)
"""
import os, sys, time, json, hmac, hashlib, base64, shutil, socket, signal, subprocess, getpass, pwd, traceback, struct, threading
from datetime import datetime
from statistics import median

try:
    # pour que les prints s'affichent au fil de l'eau
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

# -------------------- logging court --------------------
def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items())
    print(f"[{tag}]{(' '+s) if s else ''}", flush=True)

# -------------------- const --------------------
LURE_PORT, SSH_PORT = 443, 2222
PREAMBULE = [1,0,1,0,1,0,1,0]
WIRE_LEN_FIXED  = 51   # v1-fast : 1 + 12 + 38
WIRE_LEN_LEGACY = 53   # v1-legacy : 1 + 12 + 2 + 38
BITS_FIXED      = len(PREAMBULE) + 8*WIRE_LEN_FIXED  # 416
ANTI_REPLAY_S   = 90
OPEN_TTL_S      = 60     # TTL d'ouverture de @allowed
LOG_PATH        = "/var/log/portknock/poc5_server.jsonl"
NFT_TABLE, NFT_CHAIN_INPUT, NFT_SET_ALLOWED = "knock5", "inbound", "allowed"
MASTER_SECRET_PATH = "/etc/portknock/secret"
USER_COPY_FMT      = "{home}/.config/portknock/{name}"

arrivees, derniers, ips_autorisees = {}, {}, {}
stop_evt = threading.Event()
_sshd = None

# -------------------- install helpers --------------------
def _run(*cmd, **kw):
    return subprocess.run(list(cmd), text=True, capture_output=True, **kw)

def _pip(*pkgs):
    try: subprocess.run([sys.executable,"-m","pip","install","-q",*pkgs], check=True); return True
    except Exception: return False

def _apt(*pkgs):
    if not shutil.which("apt"): return False
    try:
        subprocess.run(["sudo","apt","update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","apt","install","-y",*pkgs], check=False)
        return True
    except Exception: return False

def _dnf(*pkgs):
    if not shutil.which("dnf"): return False
    try: subprocess.run(["sudo","dnf","install","-y",*pkgs], check=False); return True
    except Exception: return False

def _pacman(*pkgs):
    if not shutil.which("pacman"): return False
    try: subprocess.run(["sudo","pacman","-Sy","--noconfirm",*pkgs], check=False); return True
    except Exception: return False

def ensure_pydeps():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        LOG("BOOT", step="install_cryptography")
        _pip("cryptography") or _apt("python3-cryptography") or _dnf("python3-cryptography") or _pacman("python-cryptography")
    try:
        import scapy.all  # noqa
    except Exception:
        LOG("BOOT", step="install_scapy")
        _pip("scapy") or _apt("python3-scapy") or _dnf("python3-scapy") or _pacman("python-scapy")

def ensure_sysbins():
    missing = []
    if not shutil.which("nft"): missing.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): missing.append("openssh-server")
    if missing:
        LOG("BOOT", step="install_system", pkgs=" ".join(missing))
        _apt(*missing) or _dnf(*missing) or _pacman(*missing)

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lancer ce serveur avec sudo.", file=sys.stderr); sys.exit(1)

# -------------------- secrets --------------------
def b64_read(raw: str) -> bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    import base64
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def load_or_create_master_secret() -> bytes:
    os.makedirs(os.path.dirname(MASTER_SECRET_PATH), exist_ok=True)
    if not os.path.exists(MASTER_SECRET_PATH):
        raw = os.urandom(32)
        open(MASTER_SECRET_PATH,"w").write(__import__("base64").b64encode(raw).decode()+"\n")
        os.chmod(MASTER_SECRET_PATH, 0o600)
        LOG("READY", secret=MASTER_SECRET_PATH, created=1)
    else:
        LOG("READY", secret=MASTER_SECRET_PATH, created=0)
    sec = b64_read(open(MASTER_SECRET_PATH).read())
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
    open(dst,"w").write(content.strip()+"\n")
    os.chmod(dst, 0o600)
    if uid is not None: os.chown(dst, uid, gid)
    LOG("READY", copy_secret=dst)

# -------------------- firewall / nftables / sshd --------------------
def firewall_open_if_needed():
    # Ne force rien si firewall inactif
    if shutil.which("ufw"):
        st = _run("bash","-lc","ufw status | grep -i active || true").stdout
        if "active" in (st or "").lower():
            _run("bash","-lc", f"ufw allow {LURE_PORT}/tcp || true")
            _run("bash","-lc", f"ufw allow {SSH_PORT}/tcp || true")
            LOG("UFW", opened=f"{LURE_PORT}, {SSH_PORT}")
    if shutil.which("firewall-cmd"):
        st = _run("firewall-cmd","--state").stdout.strip()
        if st == "running":
            _run("firewall-cmd","--add-port",f"{LURE_PORT}/tcp","--permanent")
            _run("firewall-cmd","--add-port",f"{SSH_PORT}/tcp","--permanent")
            _run("firewall-cmd","--reload")
            LOG("FIREWALLD", opened=f"{LURE_PORT}, {SSH_PORT}")

def nft_delete_table():
    _run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def nft_install_base(ttl_open: int):
    nft_delete_table()
    conf = f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {ttl_open}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_INPUT} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} ip saddr @{NFT_SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} drop
"""
    tmp = "/tmp/poc5_nft.nft"
    open(tmp,"w").write(conf)
    subprocess.run(["nft","-f",tmp], check=False)
    LOG("NFT", table=NFT_TABLE, chain=NFT_CHAIN_INPUT, set=NFT_SET_ALLOWED)

def nft_add_allowed(ip: str, ttl: int):
    _run("bash","-lc", f"nft add element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    ips_autorisees[ip] = time.monotonic() + ttl
    LOG("OPEN", ip=ip, ttl=f"{ttl}s"); jlog("open", ip=ip, ttl=ttl)

def nft_gc():
    now = time.monotonic()
    for ip, exp in list(ips_autorisees.items()):
        if now > exp:
            _run("bash","-lc", f"nft delete element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} }}'")
            ips_autorisees.pop(ip, None)
            LOG("CLOSE", ip=ip); jlog("close", ip=ip)

def ensure_host_keys():
    _run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")

def start_sshd():
    global _sshd
    cfg = f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path = "/tmp/poc5_sshd_config"; open(path,"w").write(cfg)
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f"0.0.0.0:{SSH_PORT}")

def stop_sshd():
    global _sshd
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()
        LOG("SSHD", status="stopped")

# -------------------- logs JSONL --------------------
def jlog(event, **fields):
    row = {"ts": datetime.utcnow().isoformat()+"Z", "event": event}
    row.update(fields)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH,"a") as f: f.write(json.dumps(row, ensure_ascii=False)+"\n")
    except Exception:
        pass

# -------------------- timings -> bits --------------------
def _classify(deltas):
    m = median(deltas)
    return [1 if d > m else 0 for d in deltas]

def _find(seq, pat):
    n, m = len(seq), len(pat)
    for i in range(0, n - m + 1):
        if seq[i:i+m] == pat: return i
    return -1

def _bits_to_bytes(bits):
    if len(bits) % 8: return b""
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int("".join(map(str, bits[i:i+8])),2))
    return bytes(out)

# -------------------- SPA parse (51 et 53) --------------------
def spa_parse_wire(wire: bytes, aes_key: bytes, hmac_key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        if len(wire) < 1+12+16:
            LOG("SPA_WIRE_TOO_SHORT", n=len(wire)); return None
        if wire[0] != 0x01:
            LOG("SPA_BAD_VER", v=wire[0]); return None
        nonce = wire[1:13]
        if len(wire) == WIRE_LEN_FIXED:
            ctag = wire[13:]
        elif len(wire) >= WIRE_LEN_LEGACY:
            clen = struct.unpack("!H", wire[13:15])[0]
            ctag = wire[15:15+clen]
        else:
            LOG("SPA_WIRE_LEN_UNK", n=len(wire)); return None
        pt = AESGCM(aes_key).decrypt(nonce, ctag, None)  # 22 bytes
        if len(pt) != 22: LOG("SPA_PT_LEN", n=len(pt)); return None
        t, d = struct.unpack("!IH", pt[:6])
        mac  = pt[6:22]
        exp  = hmac.new(hmac_key, pt[:6], hashlib.sha256).digest()[:16]
        if mac != exp: LOG("HMAC_BAD"); return None
        if abs(int(time.time()) - int(t)) > ANTI_REPLAY_S: LOG("SPA_STALE"); return None
        return {"timestamp": int(t), "duration": int(d)}
    except Exception as e:
        LOG("SPA_ERROR", err=str(e)); return None

def try_decode_for_ip(src_ip, deltas, aes_key, hmac_key):
    if len(deltas) < len(PREAMBULE)+8: return False
    rough = _classify(deltas)
    idx = _find(rough, PREAMBULE)
    if idx < 0:
        if len(deltas) > 2000: deltas[:] = deltas[-1000:]
        return False

    # tentative format FIXED (416 bits)
    if len(rough) - idx >= BITS_FIXED:
        seg_bits = _classify(deltas[idx: idx + BITS_FIXED])
        msg_bits = seg_bits[len(PREAMBULE):]
        data = _bits_to_bytes(msg_bits)
        spa = spa_parse_wire(data, aes_key, hmac_key)
        if spa:
            deltas.clear()
            ttl = int(spa.get("duration", OPEN_TTL_S)) or OPEN_TTL_S
            nft_add_allowed(src_ip, ttl)
            return True

    # tentative format LEGACY : PREAMBULE + LEN(16) + PAYLOAD
    after = rough[idx + len(PREAMBULE):]
    if len(after) >= 16:
        L = int("".join(map(str, after[:16])), 2)
        need = len(PREAMBULE) + 16 + 8*L
        if len(rough) - idx >= need:
            seg_bits = _classify(deltas[idx: idx + need])
            msg_bits = seg_bits[len(PREAMBULE)+16:]
            data = _bits_to_bytes(msg_bits)
            spa = spa_parse_wire(data, aes_key, hmac_key)
            if spa:
                deltas.clear()
                ttl = int(spa.get("duration", OPEN_TTL_S)) or OPEN_TTL_S
                nft_add_allowed(src_ip, ttl)
                return True

    if len(deltas) > 2*BITS_FIXED: deltas[:] = deltas[-BITS_FIXED:]
    return False

# -------------------- sniff multi-interfaces (Scapy) --------------------
def pick_ifaces(user_value: str | None) -> list[str]:
    # 1) ifaces passées en CLI (comma-separated)
    if user_value:
        return [i.strip() for i in user_value.split(",") if i.strip()]
    # 2) auto : loopback + interface par défaut (route) si présente
    try:
        from scapy.all import get_if_list  # type: ignore
        ifaces = set(get_if_list())
    except Exception:
        ifaces = set()
    chosen = []
    if 'lo' in ifaces: chosen.append('lo')
    # récupère l'interface de la route par défaut
    r = _run("bash","-lc","ip route show default | awk '{print $5}' | head -n1")
    dev = (r.stdout or "").strip()
    if dev: chosen.append(dev)
    # fallback : si rien trouvé, essaie quelques noms communs
    for cand in ("eth0","ens3","enp0s3","en0"):
        if cand in ifaces and cand not in chosen:
            chosen.append(cand)
    # dédoublonne, garde au moins 'lo' si dispo
    return list(dict.fromkeys(chosen)) or (['lo'] if 'lo' in ifaces else [])

def start_sniffer_thread(iface, aes_key, hmac_key):
    from scapy.all import sniff, TCP, IP  # type: ignore
    LOG("LISTEN", mode="scapy", iface=iface, bpf=f"tcp and dst port {LURE_PORT}")
    def _prn(p):
        try:
            if not p.haslayer(TCP) or not p.haslayer(IP): return
            if p[TCP].dport != LURE_PORT: return
            f = int(p[TCP].flags)
            if (f & 0x02) == 0 or (f & 0x10) != 0: return  # SYN sans ACK
            src_ip = p[IP].src
            now = time.monotonic()
            last = derniers.get(src_ip); derniers[src_ip] = now
            if last is None:
                arrivees.setdefault(src_ip, []); LOG("PKT", ip=src_ip, first=1); return
            delta = now - last
            lst = arrivees.setdefault(src_ip, []); lst.append(delta)
            if len(lst) % 50 == 0: LOG("PKT", ip=src_ip, count=len(lst))
            try: try_decode_for_ip(src_ip, lst, aes_key, hmac_key)
            except Exception as e: LOG("DECODE_ERROR", err=str(e))
            if len(lst) > 4096: arrivees[src_ip] = lst[-1024:]
            nft_gc()
        except Exception as e:
            LOG("SCAPY_CB_ERROR", err=str(e))
    t = threading.Thread(target=lambda: sniff(iface=iface,
                                              filter=f"tcp and dst port {LURE_PORT}",
                                              prn=_prn, store=False,
                                              stop_filter=lambda p: stop_evt.is_set()),
                         daemon=True)
    t.start()
    return t

# -------------------- cleanup --------------------
def cleanup():
    try: nft_delete_table()
    except Exception: pass
    try: stop_sshd()
    except Exception: pass
    LOG("CLEANUP"); jlog("server_stop")

# -------------------- main --------------------
def main():
    import argparse, getpass
    LOG("BOOT", text="starting")
    must_root(); ensure_pydeps(); ensure_sysbins(); firewall_open_if_needed()

    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="Interfaces à sniffer (ex: 'lo' ou 'lo,eth0'). Par défaut : autodetect.")
    args = ap.parse_args()

    master = load_or_create_master_secret()
    aes_key = hashlib.sha256(master + b"|AES").digest()
    hmac_key = hashlib.sha256(master + b"|HMAC").digest()
    copy_secret_for_user("secret", __import__("base64").b64encode(master).decode())

    ttl = OPEN_TTL_S if OPEN_TTL_S>0 else 24*3600
    nft_install_base(ttl); ensure_host_keys(); start_sshd()
    LOG("READY", server="up", log=LOG_PATH); jlog("server_start", lure=LURE_PORT, ssh=SSH_PORT)

    # Sniffe sur 1..n interfaces (loopback compris)
    ifaces = pick_ifaces(args.iface)
    if not ifaces:
        print("[ERREUR] Aucune interface détectée pour sniffer.", file=sys.stderr); sys.exit(1)
    threads = [start_sniffer_thread(i, aes_key, hmac_key) for i in ifaces]

    def _sig(_s,_f): stop_evt.set()
    signal.signal(signal.SIGINT,_sig); signal.signal(signal.SIGTERM,_sig)

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    finally:
        cleanup()

if __name__ == "__main__":
    try: main()
    except Exception:
        LOG("FATAL", trace=traceback.format_exc()); cleanup(); sys.exit(1)
