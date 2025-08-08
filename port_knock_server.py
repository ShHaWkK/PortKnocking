#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur Port-Knocking (one-command, tout s'affiche dans le terminal)

- Démarre un sshd éphémère sur 127.0.0.1:2222 si rien n'écoute
- Ajoute un DROP par défaut sur 2222 (invisibilité) et l'enlève au cleanup
- Sniff (Scapy+BPF) des TCP SYN sur 7000->8000->9000 (iface lo)
- Suivi d'état par IP + tolérance au jitter (10s) + anti-doublons
- Après séquence valide : INSERT d’une règle ACCEPT pour l’IP (ouverture **illimitée** par défaut)
- Anti-spam : 3 séquences invalides => quarantaine ipset 60s (si ipset présent)
- Affiche les règles iptables pertinentes AVANT/APRÈS + écrit un JSONL

Usage :  sudo python3 port_knock_server.py
"""

from __future__ import annotations
import os, sys, time, json, shutil, signal, threading, subprocess
from typing import Dict, Tuple, Optional

# ---- Réglages par défaut (aucun argument à passer) ----
IFACE = "lo"
SEQUENCE = [7000, 8000, 9000]
OPEN_PORT = 2222
OPEN_DURATION = 0         # 0 = illimité (pas d’auto-fermeture)
STEP_TIMEOUT = 10         # délai max entre knocks
QUARANTINE_SET = "knock_quarantine"
QUARANTINE_TIMEOUT = 60   # secondes
ANTI_SPAM_MAX = 3
JSON_LOG = "knockd.jsonl"

# ---- Scapy requis ----
try:
    from scapy.all import IP, TCP, sniff  # type: ignore
except Exception:
    print("[-] Scapy requis. Installe :  pip install scapy", file=sys.stderr)
    sys.exit(1)

# ---------- utils ----------
def require_root():
    if os.geteuid() != 0:
        print("[-] Lance ce script en root (sudo).", file=sys.stderr); sys.exit(1)

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run(cmd: list[str], check=False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)

def print_rules():
    out = run(["iptables-save"]).stdout if have("iptables") else ""
    lines = [l for l in out.splitlines()
             if f"--dport {OPEN_PORT}" in l or QUARANTINE_SET in l or "match-set" in l]
    print("\n[ Règles pertinentes ]")
    print("\n".join(lines) if lines else "(aucune règle correspondante)")
    print()

def jprint(event: str, **kw):
    rec = {"ts": round(time.time(), 3), "event": event, **kw}
    print(f"[{event}] {kw}")
    try:
        with open(JSON_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def ensure_quarantine() -> bool:
    if not (have("ipset") and have("iptables")):
        print("[i] ipset/iptables non détectés : quarantaine désactivée.")
        return False
    run(["ipset", "create", QUARANTINE_SET, "hash:ip", "timeout", str(QUARANTINE_TIMEOUT)], check=False)
    # Règle DROP si membre du set (si absente)
    chk = run(["iptables","-C","INPUT","-m","set","--match-set",QUARANTINE_SET,"src","-j","DROP"])
    if chk.returncode != 0:
        run(["iptables","-I","INPUT","1","-m","set","--match-set",QUARANTINE_SET,"src","-j","DROP"])
    return True

def quarantine(ip: str):
    if have("ipset"):
        run(["ipset","add",QUARANTINE_SET,ip,"timeout",str(QUARANTINE_TIMEOUT)], check=False)
        jprint("quarantine", ip=ip, seconds=QUARANTINE_TIMEOUT)

def open_rule(ip: str):
    # évite les doublons
    chk = run(["iptables","-C","INPUT","-s",ip,"-p","tcp","--dport",str(OPEN_PORT),"-j","ACCEPT"])
    if chk.returncode != 0:
        run(["iptables","-I","INPUT","-s",ip,"-p","tcp","--dport",str(OPEN_PORT),"-j","ACCEPT"], check=False)
    jprint("open", ip=ip, port=OPEN_PORT, duration=("infinite" if OPEN_DURATION==0 else OPEN_DURATION))
    print_rules()

def close_rule(ip: str):
    run(["iptables","-D","INPUT","-s",ip,"-p","tcp","--dport",str(OPEN_PORT),"-j","ACCEPT"], check=False)
    jprint("close", ip=ip, port=OPEN_PORT)
    print_rules()

def default_drop_enable():
    # rend 2222 invisible par défaut (DROP)
    run(["iptables","-I","INPUT","1","-p","tcp","--dport",str(OPEN_PORT),"-j","DROP"], check=False)

def default_drop_disable():
    run(["iptables","-D","INPUT","-p","tcp","--dport",str(OPEN_PORT),"-j","DROP"], check=False)

def _port_listening(port: int) -> bool:
    if have("ss"):
        out = run(["ss","-lnt"]).stdout
        return f":{port} " in out or f":{port}\n" in out
    if have("netstat"):
        out = run(["netstat","-lnt"]).stdout
        return f":{port} " in out
    return False

def start_sshd() -> Optional[subprocess.Popen]:
    if _port_listening(OPEN_PORT):
        print(f"[i] Un service écoute déjà sur {OPEN_PORT}.")
        return None
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        print("[!] sshd introuvable (installe openssh-server). Je continue sans.")
        return None
    print(f"[+] Démarrage d'un sshd éphémère sur 127.0.0.1:{OPEN_PORT} …")
    devnull = open(os.devnull, "wb")
    return subprocess.Popen(
        [sshd, "-D", "-p", str(OPEN_PORT),
         "-o", "ListenAddress=127.0.0.1",
         "-o", "PasswordAuthentication=yes",
         "-o", "PermitRootLogin=no",
         "-o", "KbdInteractiveAuthentication=no",
         "-o", "PubkeyAuthentication=yes",
         "-o", "UsePAM=yes"],
        stdout=devnull, stderr=devnull
    )

# ---------- programme ----------
def main():
    require_root()
    if not have("iptables"):
        print("[-] iptables requis.", file=sys.stderr); sys.exit(1)

    quarantine_enabled = ensure_quarantine()
    default_drop_enable()
    sshd_proc = start_sshd()

    state: Dict[str, Tuple[int, float, Optional[int]]] = {}
    invalid: Dict[str, int] = {}
    opened: set[str] = set()
    timers: Dict[str, threading.Thread] = {}
    lock = threading.Lock()

    print(f"[i] Écoute sur {IFACE} | séquence: {' -> '.join(map(str, SEQUENCE))} | port à ouvrir: {OPEN_PORT} ({'∞' if OPEN_DURATION==0 else f'{OPEN_DURATION}s'})")
    print_rules()

    def reset(ip: str): state[ip] = (0, 0.0, None)

    def punish(ip: str):
        invalid[ip] = invalid.get(ip, 0) + 1
        jprint("invalid_seq", ip=ip, count=invalid[ip])
        if quarantine_enabled and invalid[ip] >= ANTI_SPAM_MAX:
            quarantine(ip); invalid[ip] = 0

    def open_for(ip: str):
        with lock:
            if ip in opened: return
            open_rule(ip)
            opened.add(ip)
            user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "user"
            print(f"[+] Séquence OK pour {ip} → port {OPEN_PORT} OUVERT {'∞' if OPEN_DURATION==0 else f'{OPEN_DURATION}s'}")
            print(f"    👉  ssh -p {OPEN_PORT} {user}@{ip}")
            if OPEN_DURATION > 0:
                def worker():
                    time.sleep(OPEN_DURATION)
                    with lock:
                        if ip in opened:
                            close_rule(ip); opened.discard(ip)
                t = threading.Thread(target=worker, daemon=False); timers[ip]=t; t.start()

    def process(pkt):
        if TCP not in pkt or IP not in pkt: return
        if not (int(pkt[TCP].flags) & 0x02): return  # SYN uniquement
        ip = pkt[IP].src
        dport = int(pkt[TCP].dport)
        step, last_ts, last_port = state.get(ip, (0, 0.0, None))

        # doublon
        if dport == last_port: return

        now = time.time()
        if step > 0 and now - last_ts > STEP_TIMEOUT:
            # timeout au milieu d'une séquence
            reset(ip); punish(ip); step, last_ts, last_port = state[ip]

        expected = SEQUENCE[step]
        if dport != expected:
            # On ne punit que si une séquence était en cours
            if step > 0:
                reset(ip); punish(ip)
            return

        step += 1
        state[ip] = (step, now, dport)
        jprint("step", ip=ip, received=dport, expected=expected, progress=step)

        if step == len(SEQUENCE):
            jprint("sequence_ok", ip=ip)
            reset(ip); open_for(ip)

    def cleanup(signum, frame):
        print("\n[+] Nettoyage…")
        for ip in list(opened): close_rule(ip)
        for t in list(timers.values()): t.join(timeout=1)
        default_drop_disable()
        if sshd_proc:
            try: sshd_proc.terminate()
            except Exception: pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    bpf = "tcp and (" + " or ".join(f"dst port {p}" for p in SEQUENCE) + ")"
    sniff(filter=bpf, prn=process, store=0, iface=IFACE)

if __name__ == "__main__":
    main()
