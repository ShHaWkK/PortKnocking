#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC3 Client 
 calcule la séquence TOTP/HMAC et "frappe" les ports, puis SSH.
"""
import os, sys, time, hmac, base64, hashlib, socket, argparse, getpass, subprocess

WINDOW_SECONDS     = 30
SEQUENCE_LEN       = 3
MIN_PORT, MAX_PORT = 40000, 50000
STEP_DELAY         = 0.5
SSH_PORT           = 2222
DEFAULT_SECRET_FILE= os.path.expanduser("~/.config/portknock/secret")

def load_secret(path=DEFAULT_SECRET_FILE) -> bytes:
    if not os.path.exists(path):
        sys.exit(f"[ERREUR] Secret introuvable: {path}")
    token = open(path).read().strip().split()[0]
    try:
        return base64.b64decode(token, validate=False)
    except Exception:
        sys.exit("[ERREUR] Secret local invalide (base64).")

def epoch_window(ts=None):
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

def send_syn(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try: s.connect((host, port))
    except OSError: pass
    finally: s.close()

def ensure_local_ssh_key():
    home = os.path.expanduser("~"); d = os.path.join(home, ".ssh")
    priv = os.path.join(d, "id_ed25519"); pub = priv + ".pub"; auth = os.path.join(d, "authorized_keys")
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(priv):
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",priv], check=True)
    if not os.path.exists(pub):
        subprocess.run(["ssh-keygen","-y","-f",priv], stdout=open(pub,"w"), check=True)
    if not os.path.exists(auth) or open(pub).read().strip() not in open(auth).read():
        with open(auth,"a") as f: f.write(open(pub).read().strip()+"\n")
        os.chmod(auth, 0o600)

def main():
    ap = argparse.ArgumentParser(description="POC3 Client — knock TOTP/HMAC + SSH")
    ap.add_argument("server", nargs="?", default="127.0.0.1", help="IP/nom du serveur")
    ap.add_argument("--window-offset", type=int, default=0, help="0 = fenêtre courante, -1 = précédente")
    ap.add_argument("--no-ssh", action="store_true", help="Ne pas lancer SSH")
    args = ap.parse_args()

    secret = load_secret()
    w = epoch_window() + args.window_offset
    seq = derive_sequence(secret, w)
    print(f"[i] Séquence: {' => '.join(map(str,seq))} (fenêtre {w}, {WINDOW_SECONDS}s)")

    for p in seq:
        print(f"[*] Knock {p}")
        send_syn(args.server, p); time.sleep(STEP_DELAY)

    if args.no_ssh:
        return
    try: ensure_local_ssh_key()
    except Exception as e: print(f"[!] ssh-key: {e}")
    user = getpass.getuser()
    os.execvp("ssh", ["ssh","-p",str(SSH_PORT),"-o","StrictHostKeyChecking=accept-new", f"{user}@{args.server}"])

if __name__ == "__main__":
    main()