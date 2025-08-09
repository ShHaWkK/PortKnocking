#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, json, hmac, hashlib, base64, secrets, shutil, argparse
import socket, subprocess, threading, binascii, signal
from datetime import datetime
# ---- deps python ----
def _pip(pkg): subprocess.run([sys.executable,"-m","pip","install","-q",pkg], check=True)
def _ensure_pydeps():
    import importlib
    try: importlib.import_module("scapy.all")
    except Exception: _pip("scapy"); importlib.import_module("scapy.all")
    try: importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
    except Exception: _pip("cryptography")
_ensure_pydeps()
from scapy.all import sniff, TCP, IP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==== paramètres ====
SSH_PORT      = 2222
SSH_LISTEN    = "127.0.0.1"
SPA_PORT      = 45444
WINDOW_SECONDS = 30            # fenêtre de knocks
ALLOW_PAST_WINDOWS = 1         # tolère N-1
SEQUENCE_LEN  = 3
MIN_PORT, MAX_PORT = 40000, 50000
MAX_SEQ_JITTER = 10            # s entre deux knocks
OPEN_DURATION  = 0             # 0 = illimité tant que le serveur tourne
QUARANTINE_THRESHOLD = 3       # après 3 séquences invalides
QUARANTINE_TIMEOUT   = 60      # s
IPSET_NAME    = "knock_quarantine"
JSONL_PATH    = "knockd_poc2.jsonl"
MASTER_DIR    = "/etc/portknock"
MASTER_PATH   = f"{MASTER_DIR}/secret"     # secret maître
PRINT_RULES_CMD = ["bash","-lc","iptables-save | egrep '2222|knock_quarantine' || true"]

# ==== utils ====
def run(*cmd, check=True, quiet=False):
    p = subprocess.run(list(cmd), text=True, capture_output=True)
    if not quiet and p.stdout.strip(): print(p.stdout.rstrip())
    if check and p.returncode != 0:
        if p.stderr: print(p.stderr.rstrip())
        raise subprocess.CalledProcessError(p.returncode, cmd)
    return p

def need(b): return shutil.which(b) is None
def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance le serveur en root (sudo)."); sys.exit(1)

def log_event(ev):
    ev = {"ts": f"{time.time():.3f}", **ev}
    with open(JSONL_PATH, "a") as f: f.write(json.dumps(ev, ensure_ascii=False)+"\n")
    tag = ev.get("event","evt")
    print(f"[{tag}] { {k:v for k,v in ev.items() if k not in ('event','ts')} }")

# ==== secrets (rotation quotidienne) ====
def ensure_master_secret():
    os.makedirs(MASTER_DIR, exist_ok=True)
    if not os.path.exists(MASTER_PATH):
        sec = secrets.token_bytes(32)
        open(MASTER_PATH,"wb").write(sec)
        os.chmod(MASTER_PATH, 0o600)
        print(f"[+] Secret maître généré : {MASTER_PATH}")
    else:
        print(f"[i] Secret maître : {MASTER_PATH}")

def derive_daily_secret() -> bytes:
    master = open(MASTER_PATH,"rb").read()
    day = datetime.utcnow().strftime("%Y-%m-%d")
    return hmac.new(master, f"day:{day}".encode(), hashlib.sha256).digest()

def install_user_secret(username: str, secret: bytes):
    # copie b64 dans ~/.config/portknock/secret de l'utilisateur autorisé
    from pwd import getpwnam
    u = getpwnam(username)
    uconf = os.path.join(u.pw_dir, ".config/portknock")
    os.makedirs(uconf, exist_ok=True)
    upath = os.path.join(uconf,"secret")
    open(upath,"wb").write(base64.b64encode(secret))
    os.chown(uconf, u.pw_uid, u.pw_gid)
    os.chown(upath, u.pw_uid, u.pw_gid)
    os.chmod(upath, 0o600)
    print(f"[i] Copie du secret pour {username}: {upath}")

# ==== sshd éphémère ====
_sshd = None
def ensure_host_keys():
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False)
def start_ephemeral_sshd():
    global _sshd
    ensure_host_keys()
    cfg = f"""Port {SSH_PORT}
ListenAddress {SSH_LISTEN}
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
LogLevel QUIET
PidFile /tmp/poc2_sshd.pid
"""
    path = "/tmp/poc2_sshd_config"
    open(path,"w").write(cfg)
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] sshd éphémère sur {SSH_LISTEN}:{SSH_PORT}")

def stop_ephemeral_sshd():
    global _sshd
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()
        print("[i] sshd éphémère arrêté.")

# ==== iptables/ipset ====
added_accept = set(); drop_installed=False; set_installed=False
def iptables_insert_drop():
    global drop_installed
    run("bash","-lc", f"iptables -C INPUT -p tcp --dport {SSH_PORT} -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport {SSH_PORT} -j DROP")
    drop_installed=True
def ipset_prepare():
    global set_installed
    run("bash","-lc", f"ipset list {IPSET_NAME} >/dev/null 2>&1 || ipset create {IPSET_NAME} hash:ip timeout {QUARANTINE_TIMEOUT}")
    run("bash","-lc", f"iptables -C INPUT -m set --match-set {IPSET_NAME} src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set {IPSET_NAME} src -j DROP")
    set_installed=True
def accept_for_ip(ip):
    run("bash","-lc", f"iptables -I INPUT -s {ip}/32 -p tcp -m tcp --dport {SSH_PORT} -j ACCEPT")
    added_accept.add(ip)
def remove_accept_for_ip(ip):
    run("bash","-lc", f"iptables -D INPUT -s {ip}/32 -p tcp -m tcp --dport {SSH_PORT} -j ACCEPT", check=False)
    added_accept.discard(ip)
def quarantine_ip(ip):
    run("bash","-lc", f"ipset add {IPSET_NAME} {ip} timeout {QUARANTINE_TIMEOUT}", check=False)

def cleanup():
    print("\n[+] Nettoyage …")
    for ip in list(added_accept): remove_accept_for_ip(ip)
    if set_installed:
        run("bash","-lc", f"iptables -D INPUT -m set --match-set {IPSET_NAME} src -j DROP", check=False)
        run("bash","-lc", f"ipset destroy {IPSET_NAME}", check=False)
    if drop_installed:
        run("bash","-lc", f"iptables -D INPUT -p tcp --dport {SSH_PORT} -j DROP", check=False)
    stop_ephemeral_sshd()
    print("\n[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)

# ==== dérivation HMAC / SPA ====
def epoch_window(ts=None): 
    if ts is None: ts=time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, ip: str, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"{ip}|{win}".encode(), hashlib.sha256).digest()
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

def derive_spa_key(secret: bytes, ip: str, win: int)->bytes:
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# ==== états + SPA ====
states = {}        # ip -> {progress,last_ts,last_port,win,bad}
pending_spa = {}   # ip -> deadline autorisé pour SPA
used_nonces = {}   # nonce -> expiry
NONCE_TTL = 120

def now(): return time.time()
def forget_expired_nonces():
    t=now()
    for k,e in list(used_nonces.items()):
        if e < t: del used_nonces[k]
def mark_nonce(nonce): used_nonces[nonce]=now()+NONCE_TTL
def seen_nonce(nonce): forget_expired_nonces(); return nonce in used_nonces

DAY_SECRET = None

def valid_sequences_for_ip(ip):
    wins = [epoch_window()-i for i in range(ALLOW_PAST_WINDOWS+1)]
    return {w: derive_sequence(DAY_SECRET, ip, w) for w in wins}

def on_tcp_syn(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
    dport = int(pkt[TCP].dport)
    ip    = pkt[IP].src
    # correctif : on ignore uniquement les SYN VERS le SSH protégé, pas les knocks
    if dport == SSH_PORT:
        return
    seqs = valid_sequences_for_ip(ip)
    st = states.get(ip, {"progress":0,"last_ts":0,"last_port":-1,"win":None,"bad":0})
    win = st["win"]
    if win not in seqs: win = max(seqs.keys())
    seq = seqs[win]
    expected = seq[st["progress"]]
    t = now()
    ok_timing = (t - st["last_ts"] <= MAX_SEQ_JITTER) or st["progress"]==0
    if dport == expected and ok_timing and dport != st["last_port"]:
        st.update({"progress": st["progress"]+1, "last_ts": t, "last_port": dport, "win": win})
        states[ip]=st
        log_event({"event":"step","ip":ip,"received":dport,"expected":expected,"progress":st["progress"]})
        if st["progress"] >= SEQUENCE_LEN:
            log_event({"event":"sequence_ok","ip":ip})
            states[ip]["progress"]=0
            pending_spa[ip] = t + 10   # 10 s pour envoyer le SPA
    else:
        st.update({"progress":0,"last_ts":t,"last_port":dport,"bad":st.get("bad",0)+1})
        states[ip]=st
        log_event({"event":"invalid_seq","ip":ip,"count":st["bad"]})
        if st["bad"] >= QUARANTINE_THRESHOLD:
            quarantine_ip(ip); st["bad"]=0
            log_event({"event":"quarantine","ip":ip,"timeout":QUARANTINE_TIMEOUT})

def spa_thread(stop_evt):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((SSH_LISTEN, SPA_PORT)); s.settimeout(0.5)
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
        payload=None; ok=False
        for w in (epoch_window(), epoch_window()-1):
            key = derive_spa_key(DAY_SECRET, ip, w)
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
        if abs(now()-obj.get("ts",0)) > NONCE_TTL:
            log_event({"event":"spa_expired","ip":ip}); continue
        # Ouverture
        accept_for_ip(ip)
        print("\n[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)
        dur = obj.get("duration", OPEN_DURATION)
        log_event({"event":"open","ip":ip,"port":SSH_PORT,"duration":"infinite" if dur==0 else dur})
        if dur and dur>0:
            threading.Thread(target=lambda: (time.sleep(dur), remove_accept_for_ip(ip), log_event({"event":"close","ip":ip,"port":SSH_PORT}), print("\n[ Règles pertinentes ]") or run(*PRINT_RULES_CMD, check=False)),
                             daemon=True).start()
        if ip in pending_spa: del pending_spa[ip]
    s.close()

def main():
    must_root()
    for b in ("iptables","ipset","sshd","ssh-keygen"):
        if need(b):
            print(f"[ERREUR] Binaire manquant : {b}"); sys.exit(1)

    ap = argparse.ArgumentParser(description="POC2 serveur : HMAC + SPA, rotation quotidienne")
    ap.add_argument("-i","--iface", default="lo", help="Interface à sniffer (défaut: lo)")
    ap.add_argument("-u","--user", default=None, help="Utilisateur autorisé (pour copier le secret du jour)")
    args = ap.parse_args()

    # ACL utilisateur (optionnelle mais pratique en démo)
    if args.user:
        print(f"[+] ACL créée avec l’utilisateur autorisé : {args.user}")

    ensure_master_secret()
    global DAY_SECRET
    DAY_SECRET = derive_daily_secret()
    if args.user:
        try: install_user_secret(args.user, DAY_SECRET)
        except Exception as e:
            print(f"[!] Impossible de copier le secret pour {args.user} : {e}")

    start_ephemeral_sshd()
    iptables_insert_drop()
    ipset_prepare()

    print(f"[i] Interface: {args.iface} | SSH protégé: {SSH_LISTEN}:{SSH_PORT}")
    print(f"[i] Rotation: daily | Fenêtre knocks: {WINDOW_SECONDS}s | SPA UDP: {SSH_LISTEN}:{SPA_PORT}\n")
    print("[ Règles pertinentes ]"); run(*PRINT_RULES_CMD, check=False)

    stop_evt = threading.Event()
    t = threading.Thread(target=spa_thread, args=(stop_evt,), daemon=True); t.start()

    bpf = "tcp[tcpflags] & tcp-syn != 0"
    try:
        sniff(filter=bpf, prn=on_tcp_syn, store=0, iface=args.iface)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set(); t.join(timeout=1.0); cleanup()

if __name__ == "__main__":
    main()