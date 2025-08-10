#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC3 — Port-knocking pure nftables (dynsets) + séquence rotative (HMAC/TOTP)
- Ouvre 2222/tcp uniquement pour l'IP qui réussit la séquence en 3 étapes
- Séquence change toutes les WINDOW_SECONDS (tolérance fenêtre N et N-1)
- Pare-feu nftables : sets avec timeout pour mémoriser la progression par IP
- Pas de SPA ici : on reste sur du "knock only" (contrôle ouverture de port)
"""

import os, sys, time, hmac, base64, hashlib, secrets, argparse, subprocess, pwd, grp, signal

# ------- Paramètres modifiables -------
SSH_PORT           = 2222
WINDOW_SECONDS     = 30          # rotation de séquence
STEP_TIMEOUT_S     = 10          # délai max entre 2 knocks
OPEN_DURATION_S    = 30          # durée d'ouverture de 2222 pour l'IP
SEQUENCE_LEN       = 3
MIN_PORT, MAX_PORT = 40000, 50000

TABLE_NAME         = "knock"
CHAIN_INPUT        = "input"     # hook input
CHAIN_STEPS        = "steps"     # règles dynamiques par fenêtre
CHAIN_PROTECT      = "protect"   # drop/accept 2222
SET_S1             = "s1_now"
SET_S2             = "s2_now"
SET_S1_PREV        = "s1_prev"
SET_S2_PREV        = "s2_prev"
SET_ALLOWED        = "allowed"

SECRET_SYS_PATH    = "/etc/portknock/secret"                  # base64
USER_SECRET_FMT    = "{home}/.config/portknock/secret"        # base64
ROTATE_PIDFILE     = "/tmp/poc3_nft_rotate.pid"

# ------- Helpers shell -------
def run(cmd: str, check=True) -> str:
    res = subprocess.run(["bash","-lc", cmd], text=True, capture_output=True)
    if check and res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"Commande échouée: {cmd}")
    return res.stdout

def must_root():
    if os.geteuid() != 0:
        print("[ERREUR] Lance en root.")
        sys.exit(1)

# ------- Secret maître -------
def load_or_create_secret(path=SECRET_SYS_PATH) -> bytes:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        raw = secrets.token_bytes(32)
        with open(path,"w") as f: f.write(base64.b64encode(raw).decode()+"\n")
        os.chmod(path, 0o600)
        print(f"[+] Secret maître généré: {path}")
    with open(path,"r") as f:
        token = f.read().strip().split()[0]
    try:
        sec = base64.b64decode(token, validate=False)
    except Exception:
        print("[ERREUR] Secret maître invalide (base64)."); sys.exit(1)
    if len(sec) < 16:
        print("[ERREUR] Secret trop court (<16)."); sys.exit(1)
    return sec

def copy_secret_for_user(secret_b64: str):
    # Copie vers l'utilisateur ayant lancé sudo, avec bons droits (TA DEMANDE)
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    try:
        pw = pwd.getpwnam(sudo_user)
        home = pw.pw_dir
        uid, gid = pw.pw_uid, pw.pw_gid
    except Exception:
        home = os.path.expanduser("~")
        uid, gid = os.getuid(), os.getgid()
    dst = USER_SECRET_FMT.format(home=home)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst,"w") as f: f.write(secret_b64+"\n")
    os.chmod(dst, 0o600)
    os.chown(dst, uid, gid)
    print(f"[i] Secret copié pour {sudo_user}: {dst} (600, propriétaire ok)")

# ------- Séquence HMAC(time-window) -------
def epoch_window(ts=None):  # fenêtre glissante
    if ts is None: ts = time.time()
    return int(ts // WINDOW_SECONDS)

def derive_sequence(secret: bytes, win: int):
    rng = MAX_PORT - MIN_PORT + 1
    digest = hmac.new(secret, f"W{win}".encode(), hashlib.sha256).digest()
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

# ------- nftables : installation/rotation/cleanup -------
def nft_exists_table():
    out = run("nft list tables", check=False)
    return f"table inet {TABLE_NAME}" in out

def nft_install_base():
    # Table + sets + chaines de base (sans les règles de steps)
    script = f"""
flush table inet {TABLE_NAME} 2>/dev/null
table inet {TABLE_NAME} {{
  set {SET_S1}      {{ type inet_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
  set {SET_S2}      {{ type inet_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
  set {SET_S1_PREV} {{ type inet_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
  set {SET_S2_PREV} {{ type inet_addr; flags timeout; timeout {STEP_TIMEOUT_S}s; }}
  set {SET_ALLOWED} {{ type inet_addr; flags timeout; timeout {OPEN_DURATION_S}s; }}

  chain {CHAIN_INPUT} {{
    type filter hook input priority 0; policy accept;
    ct state new tcp flags & (syn|ack) == syn jump {CHAIN_STEPS}
    jump {CHAIN_PROTECT}
  }}

  chain {CHAIN_STEPS} {{
    # (rempli par rotate_steps)
  }}

  chain {CHAIN_PROTECT} {{
    tcp dport {SSH_PORT} ip saddr @${{allowed_set:={SET_ALLOWED}}} accept
    tcp dport {SSH_PORT} drop
  }}
}}
"""
    # Le trick ${allowed_set:=...} évite les soucis d'expansion : on laisse tel quel
    run(f"cat > /tmp/nft_knock_base.nft <<'EOF'\n{script}\nEOF")
    run("nft -f /tmp/nft_knock_base.nft")
    print("[+] Table nft installée.")

def nft_flush_steps():
    run(f"nft flush chain inet {TABLE_NAME} {CHAIN_STEPS}")

def nft_add_step_rules(seq_now, seq_prev):
    # Règles dynamiques : NOW
    p1, p2, p3 = seq_now
    rules_now = [
        f"add rule inet {TABLE_NAME} {CHAIN_STEPS} tcp dport {p1} add @{SET_S1} {{ ip saddr timeout {STEP_TIMEOUT_S}s }}",
        f"add rule inet {TABLE_NAME} {CHAIN_STEPS} ip saddr @{SET_S1} tcp dport {p2} add @{SET_S2} {{ ip saddr timeout {STEP_TIMEOUT_S}s }}",
        f"add rule inet {TABLE_NAME} {CHAIN_STEPS} ip saddr @{SET_S2} tcp dport {p3} add @{SET_ALLOWED} {{ ip saddr timeout {OPEN_DURATION_S}s }}",
    ]
    # Règles dynamiques : PREV (tolérance bord de fenêtre)
    q1, q2, q3 = seq_prev
    rules_prev = [
        f"add rule inet {TABLE_NAME} {CHAIN_STEPS} tcp dport {q1} add @{SET_S1_PREV} {{ ip saddr timeout {STEP_TIMEOUT_S}s }}",
        f"add rule inet {TABLE_NAME} {CHAIN_STEPS} ip saddr @{SET_S1_PREV} tcp dport {q2} add @{SET_S2_PREV} {{ ip saddr timeout {STEP_TIMEOUT_S}s }}",
        f"add rule inet {TABLE_NAME} {CHAIN_STEPS} ip saddr @{SET_S2_PREV} tcp dport {q3} add @{SET_ALLOWED} {{ ip saddr timeout {OPEN_DURATION_S}s }}",
    ]
    for r in rules_now + rules_prev:
        run(r)

def rotate_steps(secret: bytes):
    w   = epoch_window()
    seq_now  = derive_sequence(secret, w)
    seq_prev = derive_sequence(secret, w-1)
    nft_flush_steps()
    nft_add_step_rules(seq_now, seq_prev)
    print(f"[i] Séquence NOW : {' → '.join(map(str,seq_now))} | PREV : {' → '.join(map(str,seq_prev))}")

def install(secret: bytes):
    if not nft_exists_table():
        nft_install_base()
    rotate_steps(secret)
    print(f"[i] Protection 2222 : DROP par défaut, ACCEPT si ip saddr ∈ {SET_ALLOWED}")

def uninstall():
    run(f"nft list table inet {TABLE_NAME}", check=False)  # pour log
    run(f"nft delete table inet {TABLE_NAME}", check=False)
    print("[i] Table nft supprimée.")

# ------- Daemon de rotation -------
def write_pidfile():
    with open(ROTATE_PIDFILE,"w") as f: f.write(str(os.getpid()))
def read_pidfile():
    try: return int(open(ROTATE_PIDFILE).read().strip())
    except Exception: return None

def start_daemon(secret: bytes):
    pid = read_pidfile()
    if pid and os.path.exists(f"/proc/{pid}"):
        print("[i] Déjà en cours."); return
    print("[+] Démarrage rotation… (Ctrl+C pour stop)")
    write_pidfile()
    try:
        while True:
            rotate_steps(secret)
            # dort jusqu'au prochain front de fenêtre
            now = time.time(); next_t = (int(now//WINDOW_SECONDS)+1)*WINDOW_SECONDS
            time.sleep(max(1, next_t - now))
    except KeyboardInterrupt:
        pass
    finally:
        try: os.remove(ROTATE_PIDFILE)
        except: pass

def stop_daemon():
    pid = read_pidfile()
    if not pid: print("[i] Pas de pidfile."); return
    try:
        os.kill(pid, signal.SIGTERM)
        print("[i] Signalé.")
    except ProcessLookupError:
        print("[i] Pas de process.")
    try: os.remove(ROTATE_PIDFILE)
    except: pass

# ------- Main -------
def main():
    must_root()
    ap = argparse.ArgumentParser(description="POC3 — Port-knocking nftables (dynsets) + séquence rotative")
    ap.add_argument("action", choices=["install","rotate","daemon","stop","uninstall"], help="Action")
    args = ap.parse_args()

    secret = load_or_create_secret()
    # Copie pour l'utilisateur (lecture client). Respecte owner/600.
    copy_secret_for_user(base64.b64encode(secret).decode())

    if args.action == "install":
        install(secret)
    elif args.action == "rotate":
        # pratique pour forcer une rotation manuelle
        if not nft_exists_table():
            nft_install_base()
        rotate_steps(secret)
    elif args.action == "daemon":
        if not nft_exists_table():
            nft_install_base()
        start_daemon(secret)
    elif args.action == "stop":
        stop_daemon()
    elif args.action == "uninstall":
        stop_daemon()
        uninstall()

if __name__ == "__main__":
    main()