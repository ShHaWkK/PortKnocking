#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, json, hmac, hashlib, base64, signal, shutil, subprocess, threading, socket, argparse
from datetime import datetime, timedelta

# ========== Paramètres (modifiables) ==========
DEMO_SECRET_B64 = "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY="  # "0123456789ABCDEF0123456789ABCDEF" (base64)
SSH_PORT        = 2222
SSH_LISTEN      = "127.0.0.1"
WINDOW_SECONDS  = 30
ALLOW_PAST_WINDOWS = 1
SEQUENCE_LEN    = 3
MIN_PORT, MAX_PORT = 40000, 50000
STEP_DELAY_HINT = 0.5
MAX_SEQ_JITTER  = 10
SPA_PORT        = 45444
SPA_GRACE_SECONDS = 10
NONCE_TTL       = 120
OPEN_DURATION   = 0     # 0 = illimité tant que le serveur tourne
QUARANTINE_THRESHOLD = 3
QUARANTINE_TIMEOUT   = 60
IPSET_NAME      = "knock_quarantine"
JSONL_PATH      = "knockd_poc2.jsonl"
PRINT_RULES_CMD = ["bash","-lc", "iptables-save | egrep '2222|knock_quarantine' || true"]

# ========== Auto-install Python deps ==========
def _pip_install(pkg):
    subprocess.run([sys.executable,"-m","pip","install","-q",pkg], check=True)

def ensure_python_deps():
    import importlib
    try: importlib.import_module("scapy.all")
    except Exception:
        _pip_install("scapy"); importlib.import_module("scapy.all")
    try: importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
    except Exception:
        _pip_install("cryptography")
ensure_python_deps()
from scapy.all import sniff, TCP, IP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ========== Vérifs système / auto-install ==========
def which(x): return shutil.which(x) is not None

def apt_like():   return which("apt") or which("apt-get")
def dnf_like():   return which("dnf") or which("yum")
def pacman_like():return which("pacman")

def auto_install_pkgs(pkgs):
    if os.geteuid() != 0:
        print("[!] Dépendances manquantes:", ", ".join(pkgs))
        print("    Lance en root OU installe manuellement. Exemples :")
        if apt_like():    print("    sudo apt install -y " + " ".join(pkgs))
        elif dnf_like():  print("    sudo dnf install -y " + " ".join(pkgs))
        elif pacman_like(): print("    sudo pacman -S --noconfirm " + " ".join(pkgs))
        else:             print("    Installe ces paquets via ton gestionnaire (iptables, ipset, openssh-server, nmap).")
        sys.exit(1)
    # root => tentative d’install
    cmd = None
    if apt_like():      cmd = ["bash","-lc","apt-get update -y >/dev/null 2>&1 && apt-get install -y " + " ".join(pkgs)]
    elif dnf_like():    cmd = ["bash","-lc","dnf install -y " + " ".join(pkgs)]
    elif pacman_like(): cmd = ["bash","-lc","pacman -Sy --noconfirm " + " ".join(pkgs)]
    if cmd:
        print("[i] Installation automatique des paquets : " + " ".join(pkgs))
        subprocess.run(cmd, check=True)
    else:
        print("[!] Gestionnaire inconnu, installe manuellement :", " ".join(pkgs)); sys.exit(1)

def ensure_system_deps():
    need = []
    for b in ("iptables","ipset","sshd","ssh-keygen","nmap"):
        if not which(b): need.append(b)
    if need: auto_install_pkgs(need)
ensure_system_deps()

# ========== Utilitaires ==========
def log_event(ev):
    ev = {"ts": f"{time.time():.3f}", **ev}
    with open(JSONL_PATH,"a") as f: f.write(json.dumps(ev, ensure_ascii=False)+"\n")
    # petite sortie lisible
    tag = next(iter(ev.get("event","").split()))
    print(f"[{ev['event']}] { {k:v for k,v in ev.items() if k!='event' and k!='ts'} }")

def derive_secret():
    b64 = os.environ.get("KNOCK_SECRET", DEMO_SECRET_B64)
    try:
        sec = base64.b64decode(b64, validate=True)
        if len(sec) < 16: raise ValueError("secret trop court")
        return sec
    except Exception as e:
        print("[ERREUR] Secret invalide (base64).", e); sys.exit(1)

SECRET = derive_secret()

def epoch_window(ts=None):
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, ip: str, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"{ip}|{win}".encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i+2 <= len(digest):
        val = int.from_bytes(digest[i:i+2],"big")
        p   = MIN_PORT + (val % rng)
        if p not in ports: ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2],"big") % rng)
        if p not in ports: ports.append(p)
    return ports

def derive_spa_key(secret: bytes, ip: str, win: int)->bytes:
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# ========== sshd éphémère 127.0.0.1:2222 ==========
_sshd_proc = None
def ensure_host_keys():
    # génère les clés si absentes
    subprocess.run(["bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A"], check=True)

def start_ephemeral_sshd():
    global _sshd_proc
    ensure_host_keys()
    cfg = f"""
Port {SSH_PORT}
ListenAddress {SSH_LISTEN}
Protocol 2
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
KexAlgorithms +sntrup761x25519-sha512@openssh.com
PidFile /tmp/poc2_sshd.pid
LogLevel QUIET
"""
    path = "/tmp/poc2_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    _sshd_proc = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Démarrage d'un sshd éphémère sur {SSH_LISTEN}:{SSH_PORT} …")

def stop_ephemeral_sshd():
    if _sshd_proc and _sshd_proc.poll() is None:
        _sshd_proc.terminate()
        try: _sshd_proc.wait(2)
        except: _sshd_proc.kill()
        print("[i] sshd éphémère arrêté.")

# ========== iptables/ipset (invisibilité + quarantaine) ==========
added_accept_rules = set()  # {ip}
drop_rule_installed = False
set_installed = False

def run(*cmd, check=True, quiet=False):
    res = subprocess.run(list(cmd), text=True, capture_output=True)
    if not quiet and res.stdout.strip(): print(res.stdout.rstrip())
    if check and res.returncode != 0:
        print(res.stderr); raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def iptables_insert_drop():
    global drop_rule_installed
    if drop_rule_installed: return
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
    for ip in list(added_accept_rules):
        remove_accept_for_ip(ip)
    if set_installed:
        run("bash","-lc", f"iptables -D INPUT -m set --match-set {IPSET_NAME} src -j DROP", check=False)
        run("bash","-lc", f"ipset destroy {IPSET_NAME}", check=False)
    if drop_rule_installed:
        run("bash","-lc", f"iptables -D INPUT -p tcp --dport {SSH_PORT} -j DROP", check=False)
    stop_ephemeral_sshd()
    print("[i] État final des règles :")
    run(*PRINT_RULES_CMD, check=False)

# ========== Machine d'états (knocks) + SPA ==========
states = {}      # ip => {"progress":0..3, "last_ts":float, "last_port":int, "win":int, "bad":int}
pending_spa = {} # ip => deadline (time)
used_nonces = {} # nonce hex -> expiry

def now(): return time.time()

def forget_expired_nonces():
    t = now()
    for k,exp in list(used_nonces.items()):
        if exp < t: del used_nonces[k]

def mark_nonce(nonce_hex):
    used_nonces[nonce_hex] = now() + NONCE_TTL

def check_nonce(nonce_hex)->bool:
    forget_expired_nonces()
    return nonce_hex in used_nonces

def valid_sequences_for_ip(ip):
    w_now = epoch_window()
    wins = [w_now - i for i in range(ALLOW_PAST_WINDOWS+1)]
    return {w: derive_sequence(SECRET, ip, w) for w in wins}

def on_tcp_syn(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
    dport = int(pkt[TCP].dport)
    ip    = pkt[IP].src
    if ip == SSH_LISTEN: return
    seqs = valid_sequences_for_ip(ip)
    st = states.get(ip, {"progress":0,"last_ts":0,"last_port":-1,"win":None,"bad":0})
    win = st["win"]
    # (ré)aligner sur la bonne fenêtre si besoin
    if win not in seqs: win = max(seqs.keys())
    seq = seqs[win]
    expected_port = seq[st["progress"]]
    t = now()
    if dport == expected_port and (t - st["last_ts"] <= MAX_SEQ_JITTER or st["progress"]==0) and dport != st["last_port"]:
        st.update({"progress": st["progress"]+1, "last_ts": t, "last_port": dport, "win": win})
        states[ip] = st
        log_event({"event":"step","ip":ip,"received":dport,"expected":expected_port,"progress":st["progress"]})
        if st["progress"] >= SEQUENCE_LEN:
            log_event({"event":"sequence_ok","ip":ip})
            states[ip]["progress"]=0
            pending_spa[ip] = t + SPA_GRACE_SECONDS
    else:
        st["progress"]=0; st["last_ts"]=t; st["last_port"]=dport; st["bad"]=st.get("bad",0)+1
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
            log_event({"event":"spa_without_sequence","ip":ip})
            continue
        if not data or data[0] != 0x01 or len(data) < 1+12+16:
            log_event({"event":"spa_invalid_format","ip":ip}); continue
        iv = data[1:13]; ct = data[13:]
        ok = False; payload = None
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
        if check_nonce(nonce):
            log_event({"event":"replay_spa","ip":ip}); continue
        mark_nonce(nonce)
        # basic TTL
        if abs(now()-obj.get("ts",0)) > NONCE_TTL:
            log_event({"event":"spa_expired","ip":ip}); continue
        # OK → ouverture
        accept_for_ip(ip)
        print("\n[ Règles pertinentes ]")
        run(*PRINT_RULES_CMD, check=False)
        dur = obj.get("duration", OPEN_DURATION)
        log_event({"event":"open","ip":ip,"port":SSH_PORT,"duration": "infinite" if dur==0 else dur})
        if dur and dur>0:
            threading.Thread(target=_delayed_close, args=(ip,dur), daemon=True).start()
        # ce SPA est consommé
        del pending_spa[ip]
    s.close()

def _delayed_close(ip, delay):
    time.sleep(delay)
    remove_accept_for_ip(ip)
    log_event({"event":"close","ip":ip,"port":SSH_PORT})
    print("\n[ Règles pertinentes ]")
    run(*PRINT_RULES_CMD, check=False)

# ========== main ==========
def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance le serveur en root (sudo)."); sys.exit(1)

def main():
    must_root()
    ap = argparse.ArgumentParser(description="POC2 Serveur - Knocks HMAC + SPA AES-GCM (auto-deps)")
    ap.add_argument("-i","--iface", default="lo", help="Interface à sniffer (défaut: lo)")
    args = ap.parse_args()

    start_ephemeral_sshd()
    iptables_insert_drop()
    ipset_prepare()

    print("[i] Écoute sur", args.iface, "| séquence: dynamique HMAC(IP, fenêtre)", f"| port à ouvrir: {SSH_PORT} (∞ si OPEN_DURATION=0)")
    print("\n[ Règles pertinentes ]")
    run(*PRINT_RULES_CMD, check=False)

    stop_evt = threading.Event()
    t_spa = threading.Thread(target=spa_listener, args=(stop_evt,), daemon=True)
    t_spa.start()

    bpf = "tcp[tcpflags] & tcp-syn != 0"
    try:
        sniff(filter=bpf, prn=on_tcp_syn, store=0, iface=args.iface)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set(); t_spa.join(timeout=1.0); cleanup()

if __name__ == "__main__":
    main()