#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC2 - Serveur : Port-knocking dynamique (HMAC + fenêtre temporelle) + SPA AES-GCM
- Secret maître stocké hors code (auto-généré au premier démarrage)
- Rotation quotidienne du secret (HMAC(date UTC + realm))
- Séquence de knocks dérivée par HMAC(secret_rot, IP, fenêtre de 30 s)
- SPA chiffré (AES-GCM) avec nonce/TTL et anti-rejeu
- iptables: DROP par défaut sur 2222, ACCEPT ciblé au-dessus pour l’IP qui réussit
- ipset de quarantaine après 3 séquences invalides
- sshd éphémère 127.0.0.1:2222 si rien n’écoute
- Logs JSONL + affichage des règles pertinentes avant/après
Lance: sudo python3 port_knock_server_poc2.py -i lo
"""
import os, sys, time, json, hmac, base64, hashlib, socket, argparse, threading, signal, shutil, subprocess, getpass
from datetime import datetime
# --- Dépendances Python ---
def _pip_install(pkg): subprocess.run([sys.executable,"-m","pip","install","-q",pkg], check=True)
def ensure_python_deps():
    import importlib
    try: importlib.import_module("scapy.all")
    except Exception: _pip_install("scapy")
    try: importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
    except Exception: _pip_install("cryptography")
ensure_python_deps()
from scapy.all import sniff, IP, TCP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Paramètres POC ---
SSH_PORT         = int(os.environ.get("KNOCK_SSH_PORT", "2222"))
SSH_LISTEN       = os.environ.get("KNOCK_SSH_LISTEN", "127.0.0.1")
WINDOW_SECONDS   = 30
ALLOW_PAST_WINDOWS = 1
SEQUENCE_LEN     = 3
MIN_PORT, MAX_PORT = 40000, 50000
MAX_SEQ_JITTER   = 10
SPA_PORT         = 45444
NONCE_TTL        = 120
SPA_GRACE_SECONDS= 10
OPEN_DURATION    = int(os.environ.get("KNOCK_OPEN_DURATION", "0"))  # 0 = illimité tant que le serveur tourne
QUARANTINE_THRESHOLD = 3
QUARANTINE_TIMEOUT   = 60
IPSET_NAME       = "knock_quarantine"
JSONL_PATH       = "knockd_poc2.jsonl"
RULES_GREP       = f"iptables-save | egrep '{SSH_PORT}|{IPSET_NAME}' || true"
REALM            = os.environ.get("KNOCK_REALM", "default")
ROTATION_MODE    = os.environ.get("KNOCK_ROTATION", "daily")  # "daily" | "hourly"
SECRET_FILE      = os.environ.get("KNOCK_SECRET_FILE", "/etc/portknock/secret")

# --- Vérifs système / auto-install minimal ---
def which(x): return shutil.which(x) is not None
def apt_like(): return which("apt") or which("apt-get")
def dnf_like(): return which("dnf") or which("yum")
def pacman_like(): return which("pacman")
def auto_install_pkgs(pkgs):
    if os.geteuid() != 0: return  # on n’insiste pas si pas root
    cmd = None
    if apt_like():   cmd=["bash","-lc","apt-get update -y >/dev/null 2>&1 && apt-get install -y " + " ".join(pkgs)]
    elif dnf_like(): cmd=["bash","-lc","dnf install -y " + " ".join(pkgs)]
    elif pacman_like(): cmd=["bash","-lc","pacman -Sy --noconfirm " + " ".join(pkgs)]
    if cmd: subprocess.run(cmd, check=False)

def ensure_system_deps():
    need = [b for b in ("iptables","ipset","sshd","ssh-keygen") if not which(b)]
    if need: auto_install_pkgs(need)
ensure_system_deps()

# --- Utilitaires ---
def log_event(ev: dict):
    ev = {"ts": f"{time.time():.3f}", **ev}
    with open(JSONL_PATH,"a") as f: f.write(json.dumps(ev, ensure_ascii=False)+"\n")
    pretty = {k:v for k,v in ev.items() if k not in ("ts")}
    print(f"[{ev.get('event','log')}] {pretty}")

def must_root():
    if os.geteuid() != 0:
        print("[-] Lance le serveur en root (sudo)."); sys.exit(1)

def read_or_create_master_secret() -> bytes:
    # priorité à la variable KNOCK_SECRET si fournie
    env_b64 = os.environ.get("KNOCK_SECRET")
    if env_b64:
        try: return base64.b64decode(env_b64, validate=True)
        except Exception: print("[-] KNOCK_SECRET invalide (base64)."); sys.exit(1)
    # sinon fichier secret (généré si absent)
    if not os.path.exists(SECRET_FILE):
        os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
        rnd = base64.b64encode(os.urandom(32)).decode()
        with open(SECRET_FILE,"w") as f: f.write(rnd+"\n")
        os.chmod(SECRET_FILE, 0o600)
        print(f"[+] Secret maître généré: {SECRET_FILE}")
        # copie conviviale pour l’utilisateur sudoant (client local)
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            user_home = os.path.expanduser(f"~{sudo_user}")
            user_cfg  = os.path.join(user_home, ".config/portknock")
            os.makedirs(user_cfg, exist_ok=True)
            dst = os.path.join(user_cfg, "secret")
            try:
                shutil.copy2(SECRET_FILE, dst); os.chmod(dst, 0o600); os.chown(dst, uid_of(sudo_user), gid_of(sudo_user))
                print(f"[i] Copie du secret pour {sudo_user}: {dst}")
            except Exception as e:
                print(f"[!] Copie du secret vers {dst} échouée: {e}")
    try:
        b64 = open(SECRET_FILE).read().strip()
        return base64.b64decode(b64, validate=True)
    except Exception as e:
        print("[-] Secret fichier invalide.", e); sys.exit(1)

def uid_of(user): import pwd; return pwd.getpwnam(user).pw_uid
def gid_of(user): import pwd; return pwd.getpwnam(user).pw_gid

def rotate_secret(master: bytes) -> bytes:
    # rotation “daily” ou “hourly” côté serveur et client → même formule
    if ROTATION_MODE == "hourly":
        stamp = datetime.utcnow().strftime("%Y-%m-%d:%H")
    else:
        stamp = datetime.utcnow().strftime("%Y-%m-%d")
    msg = f"{REALM}|{stamp}".encode()
    return hmac.new(master, msg, hashlib.sha256).digest()

def epoch_window(ts=None): 
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(sec_rot: bytes, ip: str, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(sec_rot, f"{ip}|{win}".encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2],"big")
        p = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

def derive_spa_key(sec_rot: bytes, ip: str, win: int) -> bytes:
    return hmac.new(sec_rot, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# --- iptables / ipset / sshd ---
added_accept = set()
drop_installed = False
ipset_installed = False
_sshd = None

def runsh(cmd, check=True, quiet=False):
    res = subprocess.run(["bash","-lc",cmd], text=True, capture_output=True)
    if not quiet and res.stdout.strip(): print(res.stdout.rstrip())
    if check and res.returncode != 0:
        if not quiet and res.stderr.strip(): print(res.stderr.rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def start_sshd_ephemeral():
    global _sshd
    # clés hôtes si absentes
    runsh("test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False)
    cfg = f"""Port {SSH_PORT}
ListenAddress {SSH_LISTEN}
Protocol 2
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
PidFile /tmp/poc2_sshd.pid
LogLevel QUIET
"""
    path="/tmp/poc2_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] sshd éphémère sur {SSH_LISTEN}:{SSH_PORT}")

def stop_sshd_ephemeral():
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()
        print("[i] sshd éphémère arrêté.")

def iptables_drop_on():
    global drop_installed
    runsh(f"iptables -C INPUT -p tcp --dport {SSH_PORT} -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport {SSH_PORT} -j DROP", check=False)
    drop_installed = True

def iptables_drop_off():
    global drop_installed
    runsh(f"iptables -D INPUT -p tcp --dport {SSH_PORT} -j DROP", check=False)
    drop_installed = False

def ipset_prepare():
    global ipset_installed
    runsh(f"ipset list {IPSET_NAME} >/dev/null 2>&1 || ipset create {IPSET_NAME} hash:ip timeout {QUARANTINE_TIMEOUT}", check=False)
    runsh(f"iptables -C INPUT -m set --match-set {IPSET_NAME} src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set {IPSET_NAME} src -j DROP", check=False)
    ipset_installed = True

def ipset_destroy():
    if ipset_installed:
        runsh(f"iptables -D INPUT -m set --match-set {IPSET_NAME} src -j DROP", check=False)
        runsh(f"ipset destroy {IPSET_NAME}", check=False)

def accept_for_ip(ip):
    runsh(f"iptables -I INPUT -s {ip}/32 -p tcp --dport {SSH_PORT} -j ACCEPT", check=False)
    added_accept.add(ip)

def remove_accept_for_ip(ip):
    runsh(f"iptables -D INPUT -s {ip}/32 -p tcp --dport {SSH_PORT} -j ACCEPT", check=False)
    added_accept.discard(ip)

def quarantine_ip(ip):
    runsh(f"ipset add {IPSET_NAME} {ip} timeout {QUARANTINE_TIMEOUT}", check=False)

def print_rules():
    print("\n[ Règles pertinentes ]")
    runsh(RULES_GREP, check=False)

# --- ACL utilisateurs ---
ACL_FILE = "/etc/portknock/allow.list"
def ensure_acl():
    if not os.path.exists(ACL_FILE):
        os.makedirs(os.path.dirname(ACL_FILE), exist_ok=True)
        user = os.environ.get("SUDO_USER") or getpass.getuser()
        with open(ACL_FILE,"w") as f: f.write(user+"\n")
        os.chmod(ACL_FILE, 0o600)
        print(f"[+] ACL créée avec l’utilisateur autorisé: {user}")
def user_allowed(u: str) -> bool:
    try:
        allow = [x.strip() for x in open(ACL_FILE) if x.strip() and not x.startswith("#")]
        return u in allow
    except Exception:
        return True  # fail-open pour la démo si ACL illisible

# --- États / anti-rejeu ---
states = {}      # ip -> {"progress":0..3, "last_ts":float, "last_port":int, "win":int, "bad":int}
pending_spa = {} # ip -> deadline time
used_nonce = {}  # hex -> expiry

def now(): return time.time()
def gc_nonce():
    t = now()
    for k,exp in list(used_nonce.items()):
        if exp < t: del used_nonce[k]
def mark_nonce(nhex): used_nonce[nhex] = now() + NONCE_TTL
def nonce_seen(nhex)->bool:
    gc_nonce()
    return nhex in used_nonce

# --- Traitement SYN (knocks dynamiques) ---
MASTER = None
SEC_ROT = None
def valid_sequences_for_ip(ip):
    w0 = epoch_window()
    wins = [w0 - i for i in range(ALLOW_PAST_WINDOWS+1)]
    return {w: derive_sequence(SEC_ROT, ip, w) for w in wins}

def on_syn(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
    if (int(pkt[TCP].flags) & 0x02) == 0: return  # SYN seulement
    dport = int(pkt[TCP].dport); ip = pkt[IP].src
    if ip == SSH_LISTEN: return
    seqs = valid_sequences_for_ip(ip)
    st = states.get(ip, {"progress":0,"last_ts":0.0,"last_port":-1,"win":None,"bad":0})
    win = st["win"]
    if win not in seqs: win = max(seqs.keys())
    seq = seqs[win]
    expected = seq[st["progress"]]
    t = now()
    if dport == expected and (t - st["last_ts"] <= MAX_SEQ_JITTER or st["progress"]==0) and dport != st["last_port"]:
        st.update({"progress":st["progress"]+1, "last_ts":t, "last_port":dport, "win":win})
        states[ip] = st
        log_event({"event":"step","ip":ip,"received":dport,"expected":expected,"progress":st["progress"]})
        if st["progress"] >= SEQUENCE_LEN:
            log_event({"event":"sequence_ok","ip":ip})
            st["progress"]=0; states[ip]=st
            pending_spa[ip] = t + SPA_GRACE_SECONDS
    else:
        st.update({"progress":0,"last_ts":t,"last_port":dport,"bad":st.get("bad",0)+1})
        states[ip]=st
        log_event({"event":"invalid_seq","ip":ip,"count":st["bad"]})
        if st["bad"] >= QUARANTINE_THRESHOLD:
            quarantine_ip(ip); st["bad"]=0; states[ip]=st
            log_event({"event":"quarantine","ip":ip,"timeout":QUARANTINE_TIMEOUT})

# --- SPA UDP (AES-GCM) ---
def spa_thread(stop_evt):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((SSH_LISTEN, SPA_PORT))
    s.settimeout(0.5)
    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        ip = addr[0]
        if ip not in pending_spa or pending_spa[ip] < now():
            log_event({"event":"spa_without_sequence","ip":ip}); continue
        if not data or data[0] != 0x01 or len(data) < 1+12+16:
            log_event({"event":"spa_invalid_format","ip":ip}); continue
        iv = data[1:13]; ct = data[13:]
        ok=False; payload=None
        for w in (epoch_window(), epoch_window()-1):
            key = derive_spa_key(SEC_ROT, ip, w)
            try:
                payload = AESGCM(key).decrypt(iv, ct, None); ok=True; break
            except Exception: pass
        if not ok:
            log_event({"event":"spa_decrypt_fail","ip":ip}); continue
        try:
            obj = json.loads(payload.decode())
        except Exception:
            log_event({"event":"spa_bad_json","ip":ip}); continue
        # {req:"open", port, ts, nonce, user, duration}
        if abs(now()-obj.get("ts",0)) > NONCE_TTL:
            log_event({"event":"spa_expired","ip":ip}); continue
        nonce = obj.get("nonce","")
        if nonce_seen(nonce):
            log_event({"event":"spa_replay","ip":ip}); continue
        mark_nonce(nonce)
        user = obj.get("user","")
        if not user_allowed(user):
            log_event({"event":"acl_denied","ip":ip,"user":user}); continue
        # OK → ouverture
        accept_for_ip(ip); print_rules()
        dur = int(obj.get("duration", OPEN_DURATION))
        log_event({"event":"open","ip":ip,"port":SSH_PORT,"duration":"infinite" if dur==0 else dur})
        if dur>0:
            threading.Thread(target=delayed_close, args=(ip,dur), daemon=True).start()
        del pending_spa[ip]
    s.close()

def delayed_close(ip, delay):
    time.sleep(delay)
    remove_accept_for_ip(ip)
    log_event({"event":"close","ip":ip,"port":SSH_PORT}); print_rules()

# --- Cleanup ---
def cleanup(*_a):
    print("\n[+] Nettoyage…")
    for ip in list(added_accept): remove_accept_for_ip(ip)
    iptables_drop_off()
    ipset_destroy()
    stop_sshd_ephemeral()
    print_rules()
    sys.exit(0)

# --- main ---
def main():
    must_root()
    ap = argparse.ArgumentParser(description="POC2 Serveur - Knocks dynamiques + SPA AES-GCM")
    ap.add_argument("-i","--iface", default="lo", help="Interface à sniffer (défaut: lo)")
    args = ap.parse_args()

    ensure_acl()
    master = read_or_create_master_secret()
    global MASTER, SEC_ROT
    MASTER = master
    SEC_ROT = rotate_secret(MASTER)

    start_sshd_ephemeral()
    iptables_drop_on()
    ipset_prepare()

    print(f"[i] Interface: {args.iface} | SSH protégé: {SSH_LISTEN}:{SSH_PORT}")
    print(f"[i] Rotation: {ROTATION_MODE} | Fenêtre knocks: {WINDOW_SECONDS}s | SPA UDP: {SSH_LISTEN}:{SPA_PORT}")
    print_rules()

    stop_evt = threading.Event()
    t = threading.Thread(target=spa_thread, args=(stop_evt,), daemon=True)
    t.start()

    signal.signal(signal.SIGINT, cleanup); signal.signal(signal.SIGTERM, cleanup)
    bpf = "tcp[tcpflags] & tcp-syn != 0"
    try:
        sniff(filter=bpf, prn=on_syn, store=0, iface=args.iface)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set(); t.join(timeout=1.0); cleanup()

if __name__ == "__main__":
    main()
