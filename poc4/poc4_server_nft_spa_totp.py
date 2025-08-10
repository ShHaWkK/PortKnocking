#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC3+ — Serveur port-knocking dynamique (nftables) + SPA chiffré + TOTP.
- Séquence P1->P2->P3 dérivée par HMAC(secret, fenêtre de 30 s)
- nftables mémorise l'état (s1_now, s2_now) et marque la fin de séquence dans @pending (TTL court)
- Un listener UDP attend un SPA chiffré (AES-GCM) incluant nonce, timestamp, durée, TOTP
- Si le SPA est valide et l'IP est dans @pending, on ajoute l'IP dans @allowed → SSH (2222) s'ouvre pour cette IP
"""

import os, sys, time, hmac, hashlib, base64, secrets, subprocess, getpass, argparse, shutil, socket, json, threading
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

# ---------------- Paramètres généraux ----------------
SSH_PORT            = 2222
SSH_LISTEN          = "127.0.0.1"

WINDOW_SECONDS      = 30              # fenêtre de dérivation des knocks
SEQUENCE_LEN        = 3
MIN_PORT, MAX_PORT  = 40000, 50000
STEP_TIMEOUT_S      = 10              # TTL mémoire entre étapes 1 et 2
PENDING_TTL_S       = 15              # TTL du "droit" à envoyer le SPA après la 3e frappe
OPEN_DURATION_S     = 30              # durée d'ouverture (0 => 24h pour la démo)
STEP_DELAY_HINT     = 0.5             # indication côté client

SPA_PORT            = 45444           # port UDP pour le SPA
NONCE_TTL_S         = 120             # mémoire anti-rejeu pour le SPA

MASTER_SECRET_PATH  = "/etc/portknock/secret"          # secret HMAC (base64)
TOTP_SECRET_PATH    = "/etc/portknock/totp_secret"     # secret TOTP (base32)
USER_COPY_FMT       = "{home}/.config/portknock/{name}"

NFT_TABLE           = "knock"
NFT_CHAIN_INPUT     = "input"
NFT_CHAIN_STEPS     = "steps"

# ---------------- Helpers systèmes ----------------
def run(*cmd, check=True, quiet=False):
    """Exécute une commande et retourne le résultat (stdout/stderr capturés)."""
    res = subprocess.run(list(cmd), text=True, capture_output=True)
    if not quiet and res.stdout.strip():
        print(res.stdout.rstrip())
    if check and res.returncode != 0:
        if res.stderr.strip():
            print(res.stderr.rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def must_root():
    """Refuse de se lancer si non root."""
    if os.geteuid() != 0:
        print("[ERREUR] Lancer le serveur en root (sudo)."); sys.exit(1)

def ensure_bins():
    """Vérifie la présence de nft et sshd."""
    if not shutil.which("nft"):  print("[ERREUR] nft manquant.");  sys.exit(1)
    if not os.path.exists("/usr/sbin/sshd"): print("[ERREUR] /usr/sbin/sshd manquant."); sys.exit(1)

# ---------------- Secrets HMAC / TOTP ----------------
def b64_read_tolerant(raw: str) -> bytes:
    """Lit un base64 (tolère espaces/retours à la ligne)."""
    tok = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(tok, validate=True)
    except Exception:
        data = base64.b64decode(tok)  # sans validate (tolérant)
        if not data:
            raise ValueError("secret vide")
        return data

def load_or_create_hmac_secret(path=MASTER_SECRET_PATH) -> bytes:
    """Crée/charge le secret HMAC (32 octets)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        raw = secrets.token_bytes(32)
        with open(path, "w") as f: f.write(base64.b64encode(raw).decode()+"\n")
        os.chmod(path, 0o600)
        print(f"[+] Secret HMAC généré : {path}")
    else:
        print(f"[i] Secret HMAC : {path}")
    with open(path,"r") as f: sec = b64_read_tolerant(f.read())
    if len(sec) < 16: print("[ERREUR] Secret HMAC trop court."); sys.exit(1)
    return sec

def load_or_create_totp_secret(path=TOTP_SECRET_PATH) -> str:
    """Crée/charge le secret TOTP (base32)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        base32 = pyotp.random_base32()
        with open(path,"w") as f: f.write(base32+"\n")
        os.chmod(path, 0o600)
        print(f"[+] Secret TOTP généré : {path}")
        # Optionnel: fournir une URI à enregistrer dans une app TOTP
        uri = pyotp.totp.TOTP(base32).provisioning_uri(name="poc3@localhost", issuer_name="PortKnockPOC")
        print(f"[i] URI TOTP (à scanner si besoin): {uri}")
    else:
        print(f"[i] Secret TOTP : {path}")
    return open(path).read().strip()

def copy_to_user(name: str, content: str):
    """Copie un contenu (secret) dans ~/.config/portknock/<name> (chmod 600 + chown)."""
    sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        import pwd
        pw = pwd.getpwnam(sudo_user); home, uid, gid = pw.pw_dir, pw.pw_uid, pw.pw_gid
    except Exception:
        home = os.path.expanduser("~"); uid = gid = None
    dst = USER_COPY_FMT.format(home=home, name=name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst,"w") as f: f.write(content+"\n")
    os.chmod(dst, 0o600)
    if uid is not None: os.chown(dst, uid, gid)
    print(f"[i] Copie pour {sudo_user}: {dst} (600, owner {sudo_user})")

# ---------------- Dérivation de séquence ----------------
def epoch_window(ts=None):
    """Retourne la fenêtre discrète (ts // WINDOW_SECONDS)."""
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    """Retourne 3 ports [MIN_PORT, MAX_PORT] à partir de HMAC(secret, str(win))."""
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, str(win).encode(), hashlib.sha256).digest()
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

def derive_spa_key(secret: bytes, ip: str, win: int) -> bytes:
    """Clé AES-GCM dérivée (HMAC) pour le SPA, liée à l'IP et à la fenêtre."""
    return hmac.new(secret, f"spa|{ip}|{win}".encode(), hashlib.sha256).digest()

# ---------------- sshd éphémère (démo) ----------------
_sshd = None
def ensure_host_keys():
    """Génère les clés hôte SSH si absentes."""
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False, quiet=True)

def start_sshd():
    """Lance un sshd sur 127.0.0.1:2222 pour la démo."""
    global _sshd
    ensure_host_keys()
    cfg = f"""Port {SSH_PORT}
ListenAddress {SSH_LISTEN}
Protocol 2
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
PidFile /tmp/poc3_sshd.pid
LogLevel QUIET
"""
    path = "/tmp/poc3_sshd.cfg"
    with open(path,"w") as f: f.write(cfg)
    _sshd = subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] sshd éphémère sur {SSH_LISTEN}:{SSH_PORT}")

def stop_sshd():
    """Arrête sshd si lancé."""
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try: _sshd.wait(2)
        except: _sshd.kill()
        print("[i] sshd arrêté.")

# ---------------- nftables ----------------
def nft_delete_table():
    """Supprime la table inet knock si présente."""
    run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true",
        check=False, quiet=True)

def nft_install_base():
    """Crée table/sets/chains + règles d'invisibilité, plus la chain 'steps'."""
    nft_delete_table()
    allowed_ttl = max(OPEN_DURATION_S, 24*3600) if OPEN_DURATION_S==0 else OPEN_DURATION_S
    base = f"""
add table inet {NFT_TABLE}

add set inet {NFT_TABLE} s1_now   {{ type ipv4_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
add set inet {NFT_TABLE} s2_now   {{ type ipv4_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
add set inet {NFT_TABLE} pending  {{ type ipv4_addr; flags timeout; timeout {PENDING_TTL_S}s; }}
add set inet {NFT_TABLE} allowed  {{ type ipv4_addr; flags timeout; timeout {allowed_ttl}s; }}

add chain inet {NFT_TABLE} {NFT_CHAIN_INPUT} {{ type filter hook input priority 0; policy accept; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_STEPS}

# On évalue la machine d'états d'abord
add rule inet {NFT_TABLE} {NFT_CHAIN_INPUT} jump {NFT_CHAIN_STEPS}

# Invisibilité SSH : si l'IP n'est pas autorisée -> DROP
add rule inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} ip saddr != @allowed drop
"""
    tmp = "/tmp/nft_knock_base.nft"
    with open(tmp,"w") as f: f.write(base)
    run("bash","-lc", f"nft -f {tmp}")

def nft_set_steps(p1:int, p2:int, p3:int):
    """Programme la machine d'états (3 règles) pour la fenêtre en cours."""
    run("bash","-lc", f"nft flush chain inet {NFT_TABLE} {NFT_CHAIN_STEPS}")
    run("bash","-lc", f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} tcp flags syn tcp dport {p1} add @s1_now {{ ip saddr timeout {STEP_TIMEOUT_S}s }}")
    run("bash","-lc", f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} ip saddr @s1_now tcp flags syn tcp dport {p2} add @s2_now {{ ip saddr timeout {STEP_TIMEOUT_S}s }}")
    # Étape 3 : au lieu d'ouvrir, on place l'IP dans @pending (fenêtre de grâce pour le SPA)
    run("bash","-lc", f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} ip saddr @s2_now tcp flags syn tcp dport {p3} add @pending {{ ip saddr timeout {PENDING_TTL_S}s }}")

def nft_add_allowed(ip: str):
    """Ajoute ip à @allowed (avec son timeout)."""
    run("bash","-lc", f"nft add element inet {NFT_TABLE} allowed {{ {ip} }}", check=False)

def nft_ip_in_set(setname: str, ip: str) -> bool:
    """Retourne True si l'IP est présente dans un set (utilise 'nft get element')."""
    r = run("bash","-lc", f"nft get element inet {NFT_TABLE} {setname} {{ {ip} }}", check=False, quiet=True)
    return r.returncode == 0

def nft_show():
    """Affiche la table pour debug/rapport."""
    print("\n[ Règles nftables ]")
    run("bash","-lc", f"nft list table inet {NFT_TABLE}")

# ---------------- Anti-rejeu SPA ----------------
_used_nonces = {}  # nonce_hex -> expiry (epoch)

def mark_nonce(nonce_hex: str):
    """Mémorise un nonce pour NONCE_TTL_S."""
    _used_nonces[nonce_hex] = time.time() + NONCE_TTL_S

def seen_nonce(nonce_hex: str) -> bool:
    """True si nonce déjà vu (après purge des expirés)."""
    now = time.time()
    for k,exp in list(_used_nonces.items()):
        if exp < now: del _used_nonces[k]
    return nonce_hex in _used_nonces

# ---------------- SPA listener ----------------
def spa_listener(stop_evt, hmac_secret: bytes, totp_secret_base32: str):
    """Écoute le SPA UDP, vérifie AES-GCM + TOTP + pending, puis autorise l'IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((SSH_LISTEN, SPA_PORT))
    s.settimeout(0.5)
    print(f"[i] SPA UDP en écoute sur {SSH_LISTEN}:{SPA_PORT}")
    totp = pyotp.TOTP(totp_secret_base32)

    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(8192)
        except socket.timeout:
            continue

        ip = addr[0]
        if not data or data[0] != 0x01 or len(data) < 1+12+16:
            print(f"[spa_invalid] paquet invalide de {ip}"); continue

        # Il faut que l'IP soit passée par la 3e frappe récemment
        if not nft_ip_in_set("pending", ip):
            print(f"[spa_without_sequence] {ip} (pas dans @pending)"); continue

        iv = data[1:13]; ct = data[13:]
        payload = None; ok=False
        # tolère fenêtre courante et N-1 pour décalage
        for w in (epoch_window(), epoch_window()-1):
            key = derive_spa_key(hmac_secret, ip, w)
            try:
                payload = AESGCM(key).decrypt(iv, ct, None)
                ok=True; break
            except Exception:
                continue
        if not ok:
            print(f"[spa_decrypt_fail] ip={ip}"); continue

        try:
            obj = json.loads(payload.decode())
        except Exception:
            print(f"[spa_bad_json] ip={ip}"); continue

        # Anti-rejeu + horloge
        nonce = obj.get("nonce","")
        ts    = obj.get("ts",0)
        dur   = int(obj.get("duration", OPEN_DURATION_S))
        code  = str(obj.get("totp",""))

        if seen_nonce(nonce):         print(f"[replay] ip={ip}"); continue
        mark_nonce(nonce)
        if abs(time.time()-ts) > NONCE_TTL_S:  print(f"[spa_expired] ip={ip}"); continue

        # Vérifie TOTP (drift ±1 période de 30s)
        if not totp.verify(code, valid_window=1):
            print(f"[totp_invalid] ip={ip}"); continue

        # OK → autorise l'IP
        nft_add_allowed(ip)
        print(f"[open] ip={ip} port={SSH_PORT} duration={'infinite' if dur==0 else dur}s")
    s.close()

# ---------------- Main ----------------
def main():
    must_root(); ensure_bins()
    ap = argparse.ArgumentParser(description="POC3+ Serveur — nftables + SPA + TOTP")
    ap.add_argument("-i","--iface", default="lo", help="Interface (info affichage)")
    args = ap.parse_args()

    # Secrets
    hmac_secret = load_or_create_hmac_secret()
    totp_secret = load_or_create_totp_secret()

    # Copie côté utilisateur (client)
    copy_to_user("secret", base64.b64encode(hmac_secret).decode())
    copy_to_user("totp_secret", totp_secret)

    # sshd & nft
    start_sshd()
    nft_install_base()

    # première programmation des règles
    last_win = epoch_window()
    p1,p2,p3 = derive_sequence(hmac_secret, last_win)
    nft_set_steps(p1,p2,p3)

    print(f"[i] Interface: {args.iface} | fenêtre: {WINDOW_SECONDS}s | séquence: {p1} -> {p2} -> {p3} | délai client ≈ {STEP_DELAY_HINT}s")
    nft_show()

    # Listener SPA
    stop_evt = threading.Event()
    t = threading.Thread(target=spa_listener, args=(stop_evt,hmac_secret,totp_secret), daemon=True)
    t.start()

    try:
        while True:
            time.sleep(0.2)
            w = epoch_window()
            if w != last_win:
                last_win = w
                p1,p2,p3 = derive_sequence(hmac_secret, w)
                nft_set_steps(p1,p2,p3)
                print(f"[i] Rotation: {p1} -> {p2} -> {p3}")
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set(); t.join(timeout=1.0)
        cleanup()

def cleanup():
    """Nettoie nftables et sshd."""
    print("\n[+] Nettoyage …")
    nft_delete_table()
    stop_sshd()

if __name__ == "__main__":
    main()
