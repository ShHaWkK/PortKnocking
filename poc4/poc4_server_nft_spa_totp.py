#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC4 (serveur) — Port-knocking dynamique (nftables) + SPA AES-GCM + TOTP
Lance: sudo python3 poc4_server_nft_spa_totp.py -i lo
"""

import os, sys, time, hmac, hashlib, base64, secrets, subprocess, getpass, argparse, json, shutil, socket, pwd, threading

# ---------------- Paramètres ajustables ----------------
SSH_PORT           = 2222
SSH_LISTEN         = "127.0.0.1"

WINDOW_SECONDS     = 30
SEQUENCE_LEN       = 3
MIN_PORT, MAX_PORT = 40000, 50000

STEP_TIMEOUT_S     = 10        # TTL entre étapes (s1_now/s2_now)
PENDING_TTL_S      = 10        # fenêtre de grâce pour SPA après séquence
OPEN_DURATION_S    = 30        # TTL d'ouverture (0 => longue durée par défaut 24h)
SPA_PORT           = 45444
SPA_TTL_S          = 120       # validité timestamp SPA
NONCE_TTL_S        = 180       # anti-rejeu

MASTER_SECRET_PATH = "/etc/portknock/secret"       # base64
TOTP_PATH          = "/etc/portknock/totp_base32"  # base32
USER_COPY_FMT      = "{home}/.config/portknock/{name}"

NFT_TABLE          = "knock"
NFT_CHAIN_INPUT    = "input"
NFT_CHAIN_STEPS    = "steps"

# --------------- Shell helpers ---------------
def run(*cmd, check=True, quiet=False):
    res = subprocess.run(list(cmd), text=True, capture_output=True)
    if not quiet and res.stdout.strip():
        print(res.stdout.rstrip())
    if check and res.returncode != 0:
        if res.stderr.strip():
            print(res.stderr.rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lancer ce serveur avec sudo.")
        sys.exit(1)

# --------------- Dépendances ---------------
def _pip_install(pkg: str):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg], check=True)
        return True
    except Exception as e:
        print(f"[!] pip a échoué pour {pkg}: {e}")
        return False

def _apt_install(*pkgs: str):
    if not shutil.which("apt"): return False
    print(f"[i] Tentative d’installation via apt: {' '.join(pkgs)}")
    try:
        run("sudo","apt","update", check=False, quiet=True)
        run("sudo","apt","install","-y",*pkgs, check=False)
        return True
    except Exception:
        return False

def ensure_pydeps():
    ok = True
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except Exception:
        print("[i] cryptography manquante → installation…")
        ok = _pip_install("cryptography") or _apt_install("python3-cryptography") or ok
    try:
        import pyotp  # noqa: F401
    except Exception:
        print("[i] pyotp manquante → installation…")
        ok = _pip_install("pyotp") or _apt_install("python3-pyotp") or ok
    return ok

def ensure_sysbins():
    missing = []
    if not shutil.which("nft"): missing.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): missing.append("openssh-server")
    if missing:
        print(f"[!] Binaires manquants: {', '.join(missing)}")
        _apt_install(*missing)

# --------------- Secrets ---------------
def b64_read_tolerant(raw: str) -> bytes:
    token = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        data = base64.b64decode(token)
        if not data: raise ValueError("secret vide")
        return data

def load_or_create_master_secret():
    os.makedirs(os.path.dirname(MASTER_SECRET_PATH), exist_ok=True)
    if not os.path.exists(MASTER_SECRET_PATH):
        raw = secrets.token_bytes(32)
        with open(MASTER_SECRET_PATH, "w") as f:
            f.write(base64.b64encode(raw).decode()+"\n")
        os.chmod(MASTER_SECRET_PATH, 0o600)
        print(f"[+] Secret maître généré : {MASTER_SECRET_PATH}")
    else:
        print(f"[i] Secret maître : {MASTER_SECRET_PATH}")
    with open(MASTER_SECRET_PATH,"r") as f:
        sec = b64_read_tolerant(f.read())
    if len(sec) < 16:
        print("[ERREUR] Secret trop court."); sys.exit(1)
    return sec

def load_or_create_totp_base32():
    try:
        import pyotp
    except Exception:
        _pip_install("pyotp"); import pyotp  # type: ignore
    os.makedirs(os.path.dirname(TOTP_PATH), exist_ok=True)
    if not os.path.exists(TOTP_PATH):
        val = pyotp.random_base32()
        with open(TOTP_PATH,"w") as f: f.write(val+"\n")
        os.chmod(TOTP_PATH, 0o600)
        print(f"[+] Secret TOTP généré : {TOTP_PATH}")
    else:
        print(f"[i] Secret TOTP : {TOTP_PATH}")
    return open(TOTP_PATH).read().strip().split()[0]

def copy_secret_for_user(name: str, content: str):
    sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pw = pwd.getpwnam(sudo_user)
        home, uid, gid = pw.pw_dir, pw.pw_uid, pw.pw_gid
    except Exception:
        home, uid, gid = os.path.expanduser("~"), None, None
    dst = USER_COPY_FMT.format(home=home, name=name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst,"w") as f: f.write(content.strip()+"\n")
    os.chmod(dst, 0o600)
    if uid is not None: os.chown(dst, uid, gid)
    print(f"[i] Copie du secret {name} → {dst} (chmod 600, owner {sudo_user})")

# --------------- Dérivations HMAC/AES ---------------
def epoch_window(ts=None):
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"seq|{win}".encode(), hashlib.sha256).digest()
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

def derive_spa_key(secret: bytes, ip: str, win: int) -> bytes:
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# --------------- sshd éphémère ---------------
_sshd_proc = None
def ensure_host_keys():
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False, quiet=True)

def start_sshd():
    global _sshd_proc
    ensure_host_keys()
    cfg = f"""Port {SSH_PORT}
ListenAddress {SSH_LISTEN}
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
PidFile /tmp/poc4_sshd.pid
LogLevel QUIET
"""
    path = "/tmp/poc4_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    _sshd_proc = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] sshd éphémère sur {SSH_LISTEN}:{SSH_PORT}")

def stop_sshd():
    if _sshd_proc and _sshd_proc.poll() is None:
        _sshd_proc.terminate()
        try: _sshd_proc.wait(2)
        except: _sshd_proc.kill()
        print("[i] sshd éphémère arrêté.")

# --------------- nftables ---------------
def nft_delete_table():
    run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true", check=False, quiet=True)

def nft_install_base():
    nft_delete_table()
    allowed_ttl = (24*3600) if OPEN_DURATION_S == 0 else OPEN_DURATION_S
    base = f"""
add table inet {NFT_TABLE}

add set inet {NFT_TABLE} s1_now   {{ type ipv4_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
add set inet {NFT_TABLE} s2_now   {{ type ipv4_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
add set inet {NFT_TABLE} pending  {{ type ipv4_addr; flags timeout; timeout {PENDING_TTL_S}s; }}
add set inet {NFT_TABLE} allowed  {{ type ipv4_addr; flags timeout; timeout {allowed_ttl}s; }}

add chain inet {NFT_TABLE} {NFT_CHAIN_INPUT} {{ type filter hook input priority 0; policy accept; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_STEPS}

add rule inet {NFT_TABLE} {NFT_CHAIN_INPUT} jump {NFT_CHAIN_STEPS}
add rule inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} ip saddr != @allowed drop
"""
    tmp = "/tmp/nft_knock_base.nft"
    with open(tmp,"w") as f: f.write(base)
    run("nft","-f", tmp)

def nft_set_steps(p1: int, p2: int, p3: int):
    run("bash","-lc", f"nft flush chain inet {NFT_TABLE} {NFT_CHAIN_STEPS}")
    run("bash","-lc", f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} tcp flags syn tcp dport {p1} add @s1_now {{ ip saddr timeout {STEP_TIMEOUT_S}s }}")
    run("bash","-lc", f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} ip saddr @s1_now tcp flags syn tcp dport {p2} add @s2_now {{ ip saddr timeout {STEP_TIMEOUT_S}s }}")
    run("bash","-lc", f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} ip saddr @s2_now tcp flags syn tcp dport {p3} add @pending {{ ip saddr timeout {PENDING_TTL_S}s }}")

def nft_show():
    print("\n[ Règles nftables ]")
    run("bash","-lc", f"nft list table inet {NFT_TABLE}")

def nft_add_allowed(ip: str, ttl: int):
    if ttl and ttl > 0:
        run("bash","-lc", f"nft add element inet {NFT_TABLE} allowed {{ {ip} timeout {ttl}s }}", check=False)
    else:
        run("bash","-lc", f"nft add element inet {NFT_TABLE} allowed {{ {ip} }}", check=False)

def nft_ip_in_set(setname: str, ip: str) -> bool:
    res = run("bash","-lc", f"nft get element inet {NFT_TABLE} {setname} {{ {ip} }}", check=False, quiet=True)
    return res.returncode == 0

# --------------- SPA UDP (AES-GCM + TOTP) ---------------
used_nonces = {}  # nonce_hex -> expiry

def gc_nonces():
    t = time.time()
    for k,exp in list(used_nonces.items()):
        if exp < t: del used_nonces[k]

def mark_nonce(nonce_hex: str):
    used_nonces[nonce_hex] = time.time() + NONCE_TTL_S

def seen_nonce(nonce_hex: str) -> bool:
    gc_nonces(); return nonce_hex in used_nonces

def print_totp_help(totp_b32: str):
    # URL otpauth + QR ASCII si possible
    label = "POC4@localhost"
    issuer = "PortKnock"
    url = f"otpauth://totp/{label}?secret={totp_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    print(f"\n[TOTP] URL: {url}")
    if shutil.which("qrencode"):
        print("[TOTP] QR (ASCII) :")
        try:
            run("qrencode","-t","ANSIUTF8",url, check=True)
        except Exception:
            pass
    else:
        print("[TOTP] Installe 'qrencode' pour afficher le QR en ASCII (apt install qrencode).")

def spa_listener(secret: bytes, totp_base32: str, stop_evt):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import pyotp

    totp_verifier = pyotp.TOTP(totp_base32)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((SSH_LISTEN, SPA_PORT))
    s.settimeout(0.5)

    print(f"[i] Écoute SPA UDP: {SSH_LISTEN}:{SPA_PORT}")
    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(8192)
        except socket.timeout:
            continue

        ip = addr[0]
        print(f"[spa] paquet reçu de {ip}, len={len(data)}")

        if not nft_ip_in_set("pending", ip):
            print(f"[spa] ignoré: IP {ip} n'est pas en 'pending' (séquence non complétée)")
            continue

        if not data or data[0] != 0x01 or len(data) < 1+12+16:
            print(f"[spa] format invalide (magic/longueur)"); continue

        iv = data[1:13]; ct = data[13:]
        payload = None; ok=False
        for w in (epoch_window(), epoch_window()-1):
            key = derive_spa_key(secret, ip, w)
            try:
                payload = AESGCM(key).decrypt(iv, ct, None); ok=True; break
            except Exception:
                continue
        if not ok:
            print("[spa] échec de déchiffrement"); continue

        try:
            obj = json.loads(payload.decode())
        except Exception:
            print("[spa] JSON invalide"); continue

        # Anti-rejeu + fraîcheur
        nonce = obj.get("nonce","")
        if seen_nonce(nonce):
            print("[spa] rejeu détecté (nonce déjà vu)"); continue
        mark_nonce(nonce)

        ts = obj.get("ts",0)
        skew = int(time.time()-ts)
        if abs(skew) > SPA_TTL_S:
            print(f"[spa] timestamp expiré (skew={skew}s)"); continue

        # Vérif TOTP avec fenêtre −1/0/+1 pour afficher le décalage accepté
        code = str(obj.get("totp","")).strip()
        accepted = None
        for off in (-1,0,1):
            if totp_verifier.verify(code, for_time=time.time()+off*30):
                accepted = off
                break
        if accepted is None:
            print(f"[spa] TOTP KO (code={code})"); continue
        print(f"[spa] TOTP OK (code={code}, fenêtre={accepted:+d}*30s, skew={skew}s)")

        # Autorisation
        dur = int(obj.get("duration", OPEN_DURATION_S))
        nft_add_allowed(ip, dur)
        print(f"[open] ip={ip} port={SSH_PORT} durée={'par défaut' if dur==0 else str(dur)+'s'}")
        nft_show()

    s.close()

# --------------- Main ---------------
def main():
    must_root()
    ensure_pydeps()
    ensure_sysbins()

    ap = argparse.ArgumentParser(description="POC4 Serveur — nftables + SPA + TOTP")
    ap.add_argument("-i","--iface", default="lo", help="Interface (affichage)")
    args = ap.parse_args()

    secret = load_or_create_master_secret()
    totp_b32 = load_or_create_totp_base32()
    copy_secret_for_user("secret", base64.b64encode(secret).decode())
    copy_secret_for_user("totp",   totp_b32)

    start_sshd()
    nft_install_base()

    last_win = epoch_window()
    p1,p2,p3 = derive_sequence(secret, last_win)
    print(f"[i] Interface: {args.iface} | fenêtre: {WINDOW_SECONDS}s | séquence: {p1} -> {p2} -> {p3}")
    nft_set_steps(p1,p2,p3)
    nft_show()
    print_totp_help(totp_b32)

    stop_evt = threading.Event()
    t = threading.Thread(target=spa_listener, args=(secret, totp_b32, stop_evt), daemon=True)
    t.start()

    try:
        while True:
            time.sleep(0.25)
            w = epoch_window()
            if w != last_win:
                last_win = w
                p1,p2,p3 = derive_sequence(secret, w)
                print(f"[rotation] nouvelle séquence {p1} -> {p2} -> {p3}")
                nft_set_steps(p1,p2,p3)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        nft_delete_table()
        stop_sshd()
        print("[+] Nettoyage terminé.")

if __name__ == "__main__":
    main()
