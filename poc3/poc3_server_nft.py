#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC3 - Serveur port-knocking dynamique avec nftables.
- Invisibilité SSH (DROP par défaut sur 2222, sauf IP autorisées)
- Séquence de knocks P1->P2->P3 dérivée par HMAC(secret, window)
- Mémoire d'état en nftables (sets avec timeout) : s1_now, s2_now, allowed
- Rotation automatique des ports (toutes les WINDOW_SECONDS)
- sshd éphémère sur 127.0.0.1:2222 pour la démo
- Journalisation simple sur stdout
"""

import os, sys, time, hmac, hashlib, base64, secrets, subprocess, getpass, argparse
from datetime import datetime

# ---------------------- Paramètres modifiables ----------------------
SSH_PORT          = 2222
SSH_LISTEN        = "127.0.0.1"

WINDOW_SECONDS    = 30         # taille de fenêtre pour la séquence
SEQUENCE_LEN      = 3
MIN_PORT, MAX_PORT= 40000, 50000
STEP_DELAY_HINT   = 0.5        # pour l'affichage côté serveur
STEP_TIMEOUT_S    = 10         # TTL mémoire entre étapes
OPEN_DURATION_S   = 30         # TTL d'ouverture (0 => "long" 24h pour la démo)

# Fichiers “secrets” (base64)
MASTER_SECRET_PATH   = "/etc/portknock/secret"                # côté root
USER_COPY_PATH_FMT   = "{home}/.config/portknock/secret"      # copie chown + 600 pour l'utilisateur

# ---------------------- Helpers système ----------------------
def run(*cmd, check=True, quiet=False):
    """Exécute une commande système, affiche stdout sauf quiet=True."""
    res = subprocess.run(list(cmd), text=True, capture_output=True)
    if not quiet and res.stdout.strip():
        print(res.stdout.rstrip())
    if check and res.returncode != 0:
        if res.stderr.strip():
            print(res.stderr.rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def must_root():
    """Vérifie l'exécution en root."""
    if os.geteuid() != 0:
        print("[ERREUR] Lancer en root (sudo).")
        sys.exit(1)

def ensure_deps():
    """Vérifie la présence de nft & sshd."""
    for b in ("nft", "/usr/sbin/sshd"):
        if not shutil.which(b) if b != "/usr/sbin/sshd" else not os.path.exists(b):
            print(f"[ERREUR] Binaire manquant: {b}")
            sys.exit(1)

# On évite l'import manquant de shutil si Python minimal
import shutil

# ---------------------- Gestion secret HMAC ----------------------
def b64_read_tolerant(raw: str) -> bytes:
    """Lit un base64 tolérant aux retours ligne/espaces, sinon lève ValueError."""
    token = raw.strip().split()[0] if raw.strip() else ""
    try:
        return base64.b64decode(token, validate=True)
    except Exception:
        try:
            data = base64.b64decode(token)
            if not data: raise ValueError("secret vide")
            return data
        except Exception as e:
            raise ValueError(f"secret base64 invalide: {e}")

def load_or_create_master_secret(path=MASTER_SECRET_PATH) -> bytes:
    """Crée un secret maître (32o aléatoires) si absent, puis le lit (base64)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        raw = secrets.token_bytes(32)
        with open(path, "w") as f:
            f.write(base64.b64encode(raw).decode() + "\n")
        os.chmod(path, 0o600)
        print(f"[+] Secret maître généré : {path}")
    else:
        print(f"[i] Secret maître : {path}")
    with open(path, "r") as f:
        sec = b64_read_tolerant(f.read())
    if len(sec) < 16:
        print("[ERREUR] Secret trop court.")
        sys.exit(1)
    return sec

def copy_secret_for_user(secret_b64: str):
    """Copie le secret pour l'utilisateur sudoer (chmod 600 + chown)."""
    sudo_user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        import pwd
        pw = pwd.getpwnam(sudo_user)
        home = pw.pw_dir
        uid, gid = pw.pw_uid, pw.pw_gid
    except Exception:
        home = os.path.expanduser("~")
        uid = gid = None

    dst = USER_COPY_PATH_FMT.format(home=home)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w") as f:
        f.write(secret_b64 + "\n")
    os.chmod(dst, 0o600)
    if uid is not None:
        os.chown(dst, uid, gid)
    print(f"[i] Copie du secret pour {sudo_user}: {dst} (chmod 600, owner {sudo_user})")

# ---------------------- Dérivation de séquence ----------------------
def epoch_window(ts=None):
    """Fenêtre discrète (ts // WINDOW_SECONDS)."""
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    """Calcule 3 ports dans [MIN_PORT,MAX_PORT] via HMAC(secret, str(win))."""
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, str(win).encode(), hashlib.sha256).digest()
    ports, i = [], 0
    while len(ports) < SEQUENCE_LEN and i + 2 <= len(digest):
        val = int.from_bytes(digest[i:i+2], "big")
        p   = MIN_PORT + (val % rng)
        if p not in ports:
            ports.append(p)
        i += 2
    while len(ports) < SEQUENCE_LEN:
        digest = hashlib.sha256(digest).digest()
        p = MIN_PORT + (int.from_bytes(digest[:2], "big") % rng)
        if p not in ports:
            ports.append(p)
    return ports

# ---------------------- sshd éphémère (démo) ----------------------
_sshd_proc = None
def ensure_host_keys():
    """Génère des clés hôte SSH si absentes."""
    run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A", check=False, quiet=True)

def start_ephemeral_sshd():
    """Lance un sshd lié à 127.0.0.1:2222 pour la démo."""
    global _sshd_proc
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
    path = "/tmp/poc3_sshd_config"
    with open(path,"w") as f: f.write(cfg)
    _sshd_proc = subprocess.Popen(
        ["/usr/sbin/sshd","-f",path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print(f"[+] sshd éphémère sur {SSH_LISTEN}:{SSH_PORT}")

def stop_sshd():
    """Arrête le sshd éphémère si lancé."""
    if _sshd_proc and _sshd_proc.poll() is None:
        _sshd_proc.terminate()
        try: _sshd_proc.wait(2)
        except: _sshd_proc.kill()
        print("[i] sshd éphémère arrêté.")

# ---------------------- nftables ----------------------
NFT_TABLE = "knock"
NFT_CHAIN_INPUT = "input"
NFT_CHAIN_STEPS = "steps"

def nft_delete_table():
    """Supprime la table si elle existe (ignore l'erreur sinon)."""
    run("bash","-lc", f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true",
        check=False, quiet=True)

def nft_install_base():
    """Crée table/sets/chains + règles de base (avec ports bouchons remplacés ensuite)."""
    # on part propre
    nft_delete_table()
    base = f"""
add table inet {NFT_TABLE}

add set inet {NFT_TABLE} s1_now   {{ type ipv4_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
add set inet {NFT_TABLE} s2_now   {{ type ipv4_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
add set inet {NFT_TABLE} allowed  {{ type ipv4_addr; flags timeout; timeout {max(OPEN_DURATION_S, 24*3600) if OPEN_DURATION_S==0 else OPEN_DURATION_S}s; }}

add chain inet {NFT_TABLE} {NFT_CHAIN_INPUT} {{ type filter hook input priority 0; policy accept; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_STEPS}

# sauter dans la chaîne d'étapes en début
add rule inet {NFT_TABLE} {NFT_CHAIN_INPUT} jump {NFT_CHAIN_STEPS}

# invisibilité SSH: si pas autorisé -> drop
add rule inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} ip saddr != @allowed drop
"""
    tmp = "/tmp/nft_knock_base.nft"
    with open(tmp,"w") as f: f.write(base)
    run("bash","-lc", f"nft -f {tmp}")

def nft_set_steps(p1:int, p2:int, p3:int):
    """Remplit la chaîne 'steps' avec les 3 règles d'étapes pour P1,P2,P3."""
    # On flush la chaîne d'étapes puis on réinsère les règles
    run("bash","-lc", f"nft flush chain inet {NFT_TABLE} {NFT_CHAIN_STEPS}")
    run("bash","-lc",
        f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} tcp flags syn tcp dport {p1} add @s1_now {{ ip saddr timeout {STEP_TIMEOUT_S}s }}")
    run("bash","-lc",
        f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} ip saddr @s1_now tcp flags syn tcp dport {p2} add @s2_now {{ ip saddr timeout {STEP_TIMEOUT_S}s }}")
    # Étape 3 -> on autorise (ajout dans allowed, timeout défini au set)
    run("bash","-lc",
        f"nft add rule inet {NFT_TABLE} {NFT_CHAIN_STEPS} ip saddr @s2_now tcp flags syn tcp dport {p3} add @allowed {{ ip saddr }}")

def nft_show():
    """Affiche les règles pertinentes."""
    print("\n[ Règles nftables ]")
    run("bash","-lc", f"nft list table inet {NFT_TABLE}")

def cleanup():
    """Nettoie table nft + sshd."""
    print("\n[+] Nettoyage …")
    nft_delete_table()
    stop_sshd()

# ---------------------- Boucle principale ----------------------
def main():
    must_root()
    ap = argparse.ArgumentParser(description="POC3 Serveur - port-knocking dynamique avec nftables")
    ap.add_argument("-i","--iface", default="lo", help="Interface (info affichage uniquement)")
    args = ap.parse_args()

    # Secret HMAC
    secret = load_or_create_master_secret()
    copy_secret_for_user(base64.b64encode(secret).decode())

    # sshd + nft
    start_sshd()
    nft_install_base()

    # rotation initiale
    last_win = epoch_window()
    p1, p2, p3 = derive_sequence(secret, last_win)
    nft_set_steps(p1, p2, p3)

    print(f"[i] Interface: {args.iface} | fenêtre: {WINDOW_SECONDS}s | séquence courante: {p1} -> {p2} -> {p3} | délai conseillé côté client ≈ {STEP_DELAY_HINT}s")
    nft_show()

    try:
        while True:
            time.sleep(0.2)
            w = epoch_window()
            if w != last_win:
                last_win = w
                p1, p2, p3 = derive_sequence(secret, w)
                nft_set_steps(p1, p2, p3)
                print(f"[i] Rotation: nouvelle séquence {p1} -> {p2} -> {p3}")
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

def start_sshd():
    start_ephemeral_sshd()

if __name__ == "__main__":
    main()
