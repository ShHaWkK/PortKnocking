#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, json, hmac, hashlib, base64, shutil, subprocess, threading, socket, argparse, getpass, secrets, pwd

# ===================== Paramètres =====================
SSH_PORT          = 2222
SSH_LISTEN        = "127.0.0.1"
IFACE_DEFAULT     = "lo"

KNOCKS_WINDOW_S   = 30       # taille de fenêtre HMAC
ALLOW_PAST_WINDOWS= 1        # tolère N-1
SEQUENCE_LEN      = 3
MIN_PORT, MAX_PORT= 40000, 50000
MAX_SEQ_JITTER    = 10       # max 10 s entre deux knocks
SPA_PORT          = 45444
SPA_TTL_S         = 120      # validité du nonce/ts dans SPA
SPA_GRACE_S       = 10       # délai max entre "sequence_ok" et SPA
OPEN_DURATION     = 0        # 0 = illimité (tant que serveur tourne)

QUARANTINE_THRESHOLD = 3     # après 3 erreurs => ipset
QUARANTINE_TIMEOUT   = 60
IPSET_NAME           = "knock_quarantine"

MASTER_SECRET_PATH   = "/etc/portknock/secret"          # base64 (32 octets typ.)
USER_COPY_PATH_FMT   = "{home}/.config/portknock/secret"
JSONL_PATH           = "knockd_poc2.jsonl"
PRINT_RULES_CMD      = ["bash","-lc","iptables-save | egrep '2222|knock_quarantine' || true"]

# ===================== Dépendances Python =====================
def _pip_install(pkg):
    subprocess.run([sys.executable,"-m","pip","install","-q",pkg], check=True)
def ensure_pydeps():
    import importlib
    try: importlib.import_module("scapy.all")
    except Exception:
        _pip_install("scapy"); import importlib as _; _.import_module("scapy.all")
    try: importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
    except Exception:
        _pip_install("cryptography")
ensure_pydeps()
from scapy.all import sniff, TCP, IP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ===================== Utils =====================
def which(x): return shutil.which(x) is not None
def run(*cmd, check=True, quiet=False):
    res = subprocess.run(list(cmd), text=True, capture_output=True)
    if not quiet and res.stdout.strip(): print(res.stdout.rstrip())
    if check and res.returncode != 0:
        if res.stderr.strip(): print(res.stderr.rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance le serveur en root (sudo)."); sys.exit(1)

def log_event(ev):
    ev = {"ts": f"{time.time():.3f}", **ev}
    with open(JSONL_PATH,"a") as f: f.write(json.dumps(ev, ensure_ascii=False)+"\n")
    shown = {k:v for k,v in ev.items() if k not in ("ts",)}
    print(f"[{ev['event']}] {shown}")

# ----- Secrets (lecture tolérante) -----
def b64_read_tolerant(raw: str) -> bytes:
    token = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        data = base64.b64decode(token)
        if not data: raise ValueError("vide")
        return data

def load_or_create_master_secret(path=MASTER_SECRET_PATH) -> bytes:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        raw = secrets.token_bytes(32)
        with open(path,"w") as f:
            f.write(base64.b64encode(raw).decode()+"\n")
        os.chmod(path, 0o600)
        print(f"[+] Secret maître généré : {path}")
    else:
        print(f"[i] Secret maître : {path}")
    with open(path,"r") as f:
        sec = b64_read_tolerant(f.read())
    if len(sec) < 16:
        raise SystemExit("[ERREUR] Secret trop court (<16 octets).")
    return sec

def copy_secret_for_user(secret_b64: str):
    # propriétaire = SUDO_USER si présent, sinon l’utilisateur courant
    sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pw = pwd.getpwnam(sudo_user)
        home = pw.pw_dir
        uid, gid = pw.pw_uid, pw.pw_gid
    except Exception:
        home = os.path.expanduser("~")
        uid, gid = os.getuid(), os.getgid()
    dst = USER_COPY_PATH_FMT.format(home=home)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst,"w") as f: f.write(secret_b64 + "\n")
    os.chmod(dst, 0o600)
    try:
        os.chown(dst, uid, gid)  # <-- donne la bonne propriété
    except PermissionError:
        pass
    print(f"[i] Copie du secret pour {sudo_user}: {dst} (chmod 600, owner {sudo_user})")

def epoch_window(ts=None):
    if ts is None: ts = time.time()
    return int(ts // KNOCKS_WINDOW_S)

def derive_sequence(secret: bytes, ip: str, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"{ip}|{win}".encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2], "big")
        p   = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

def derive_spa_key(secret: bytes, ip: str, win: int) -> bytes:
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# ===================== sshd éphémère =====================
_sshd_proc = None
def ensure_host_keys():
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False, quiet=True)
def start_ephemeral_sshd():
    global _sshd_proc
    ensure_host_keys()
    cfg = f"""Port {SSH_PORT}
ListenAddress {SSH_LISTEN}
Protocol 2
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
PidFile /tmp/poc2_sshd.pid
LogLevel QUIET
"""
    path = "/tmp/poc2_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    _sshd_proc = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] sshd éphémère sur {SSH_LISTEN}:{SSH_PORT}")

def stop_ephemeral_sshd():
    if _sshd_proc and _sshd_proc.poll() is None:
        _sshd_proc.terminate()
        try: _sshd_proc.wait(2)
        except: _sshd_proc.kill()
        print("[i] sshd éphémère arrêté.")

# ===================== iptables/ipset =====================
added_accept_rules = set()
drop_rule_installed = False
set_installed  = False

def iptables_insert_drop():
    global drop_rule_installed
    run("bash","-lc", f"iptables -C INPUT -p tcp --dport {SSH_PORT} -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport {SSH_PORT} -j DROP")
    drop_rule_installed = True

def ipset_prepare():
    global set_installed
    run("bash","-lc", f"ipset list {IPSET_NAME} >/dev/null 2>&1 || ipset create {IPSET_NAME} hash:ip timeout {QUARANTINE_TIMEOUT}")
    run("bash","-lc", f"iptables -C INPUT -m set --match-set {IPSET_NAME} src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set {IPSET_NAME} src -j DROP")
    set_installed = True

def accept_for_ip(ip):
    run("bash","-lc", f"iptables -I INPUT -s {ip}/32 -p tcp -m tcp --dport {SSH_PORT} -j ACCEPT")
    added_accept_rules.add(ip)

def remove_accept_for_ip(ip):
    run("bash","-lc", f"iptables -D INPUT -s {ip}/32 -p tcp -m tcp --dport {SSH_PORT} -j ACCEPT", check=False)
    added_accept_rules.discard(ip)

def quarantine_ip(ip):
    run("bash","-lc", f"ipset add {IPSET_NAME} {ip} timeout {QUARANTINE_TIMEOUT}", check=False)

def cleanup():
    print("\n[+] Nettoyage …")
    for ip in list(added_accept_rules): remove_accept_for_ip(ip)
    if set_installed:
        run("bash","-lc", f"iptables -D INPUT -m set --match-set {IPSET_NAME} src -j DROP", check=False)
        run("bash","-lc", f"ipset destroy {IPSET_NAME}", check=False)
    if drop_rule_installed:
        run("bash","-lc", f"iptables -D INPUT -p tcp --dport {SSH_PORT} -j DROP", check=False)
    stop_ephemeral_sshd()
    print("\n[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)

# ===================== États + SPA =====================
states = {}      # ip -> {progress,last_ts,last_port,win,bad}
pending_spa = {} # ip -> deadline
used_nonces = {} # nonce_hex -> expiry_ts
SECRET = b""

def now(): return time.time()
def forget_expired_nonces():
    t = now()
    for k,exp in list(used_nonces.items()):
        if exp < t: del used_nonces[k]
def mark_nonce(hexv): used_nonces[hexv] = now() + SPA_TTL_S
def seen_nonce(hexv)->bool:
    forget_expired_nonces(); return hexv in used_nonces

def valid_sequences_for_ip(ip):
    w_now = epoch_window()
    wins = [w_now - i for i in range(ALLOW_PAST_WINDOWS+1)]
    return {w: derive_sequence(SECRET, ip, w) for w in wins}

def in_knock_range(port: int) -> bool:
    return MIN_PORT <= port <= MAX_PORT

def on_tcp_syn(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
    dport = int(pkt[TCP].dport)
    ip    = pkt[IP].src  # on autorise 127.0.0.1 pour test loopback

    # On ignore tout ce qui n'est pas dans le range de knocks
    if not in_knock_range(dport):
        return

    seqs = valid_sequences_for_ip(ip)
    # fenêtre verrouillée à la 1re frappe
    st = states.get(ip, {"progress":0,"last_ts":0,"last_port":-1,"win":max(seqs.keys()),"bad":0})
    win = st["win"]
    seq = seqs.get(win, seqs[max(seqs.keys())])
    expected = seq[st["progress"]]
    t = now()

    if dport == expected and (t - st["last_ts"] <= MAX_SEQ_JITTER or st["progress"]==0) and dport != st["last_port"]:
        st.update({"progress": st["progress"]+1, "last_ts": t, "last_port": dport})
        states[ip] = st
        log_event({"event":"step","ip":ip,"received":dport,"expected":expected,"progress":st["progress"]})
        if st["progress"] >= SEQUENCE_LEN:
            log_event({"event":"sequence_ok","ip":ip})
            states[ip]["progress"]=0
            pending_spa[ip] = t + SPA_GRACE_S
    else:
        # on ne compte l'erreur que si le port est dans notre range (déjà garanti)
        st.update({"progress":0,"last_ts":t,"last_port":dport,"bad": st.get("bad",0)+1})
        states[ip]=st
        log_event({"event":"invalid_seq","ip":ip,"count":st["bad"]})
        if st["bad"] >= QUARANTINE_THRESHOLD:
            quarantine_ip(ip)
            log_event({"event":"quarantine","ip":ip,"timeout":QUARANTINE_TIMEOUT})
            st["bad"]=0

def spa_listener(stop_evt):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((SSH_LISTEN, SPA_PORT))
    s.settimeout(0.5)
    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(8192)
        except socket.timeout:
            continue
        ip = addr[0]
        if ip not in pending_spa or pending_spa[ip] < now():
            log_event({"event":"spa_without_sequence","ip":ip}); continue
        if not data or data[0] != 0x01 or len(data) < 1+12+16:
            log_event({"event":"spa_invalid_format","ip":ip}); continue

        iv = data[1:13]; ct = data[13:]
        payload = None; ok=False
        for w in (epoch_window(), epoch_window()-1):
            key = derive_spa_key(SECRET, ip, w)
            try:
                payload = AESGCM(key).decrypt(iv, ct, None); ok=True; break
            except Exception:
                continue
        if not ok:
            log_event({"event":"spa_decrypt_fail","ip":ip}); continue

        try:
            obj = json.loads(payload.decode())
        except Exception:
            log_event({"event":"spa_bad_json","ip":ip}); continue

        nonce = obj.get("nonce","")
        if seen_nonce(nonce):
            log_event({"event":"replay_spa","ip":ip}); continue
        mark_nonce(nonce)
        ts = obj.get("ts",0)
        if abs(now()-ts) > SPA_TTL_S:
            log_event({"event":"spa_expired","ip":ip}); continue

        # OK => ouverture
        accept_for_ip(ip)
        print("\n[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)
        dur = int(obj.get("duration", OPEN_DURATION))
        log_event({"event":"open","ip":ip,"port":SSH_PORT,"duration":"infinite" if dur==0 else dur})
        if dur > 0:
            threading.Thread(target=_delayed_close, args=(ip,dur), daemon=True).start()
        del pending_spa[ip]
    s.close()

def _delayed_close(ip, delay):
    time.sleep(delay)
    remove_accept_for_ip(ip)
    log_event({"event":"close","ip":ip,"port":SSH_PORT})
    print("\n[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)

# ===================== Main =====================
def ensure_system_deps():
    for b in ("iptables","ipset","sshd"):
        if not which(b):
            print(f"[ERREUR] Binaire manquant: {b}"); sys.exit(1)

def main():
    global SECRET
    must_root(); ensure_system_deps()

    ap = argparse.ArgumentParser(description="POC2 Serveur — Séquence HMAC dynamique + SPA AES-GCM")
    ap.add_argument("-i","--iface", default=IFACE_DEFAULT, help=f"Interface à sniffer (défaut: {IFACE_DEFAULT})")
    args = ap.parse_args()

    # Secret maître
    SECRET = load_or_create_master_secret()
    copy_secret_for_user(base64.b64encode(SECRET).decode())

    start_ephemeral_sshd()
    iptables_insert_drop()
    ipset_prepare()

    print(f"[i] Interface: {args.iface} | SSH protégé: {SSH_LISTEN}:{SSH_PORT}")
    print(f"[i] Fenêtre knocks: {KNOCKS_WINDOW_S}s | SPA UDP: {SSH_LISTEN}:{SPA_PORT}")
    print("\n[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)

    stop_evt = threading.Event()
    t_spa = threading.Thread(target=spa_listener, args=(stop_evt,), daemon=True); t_spa.start()

    # --------- BPF serré : SYN + dport dans 40000-50000 ---------
    bpf = f"tcp and (dst portrange {MIN_PORT}-{MAX_PORT}) and (tcp[13] & 2 != 0)"
    try:
        sniff(filter=bpf, prn=on_tcp_syn, store=0, iface=args.iface)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set(); t_spa.join(timeout=1.0)
        cleanup()

if __name__ == "__main__":
    main()
