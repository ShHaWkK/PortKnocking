#!/usr/bin/env python3
"""
Serveur Port-Knocking (iptables) — affichage complet dans le terminal.

Fonctions :
- Vérif root et présence d'iptables (ipset optionnel).
- Sniff Scapy des TCP SYN vers la séquence (par défaut 7000->8000->9000).
- Tolérance au jitter (--timeout), anti-doublons.
- Après séquence valide : ouverture d'une règle iptables ACCEPT vers --open-port (par défaut 2222) pour l'IP source, pendant --duration secondes.
- Affichage des règles iptables AVANT/APRÈS (preuve).
- Anti-spam : 3 séquences invalides -> quarantaine ipset 60 s (si ipset dispo).
- Logs JSONL (écrit et aussi imprimé à l’écran).

Utilisation simple :
  sudo python3 port_knock_server.py
Options utiles :
  --iface lo --seq "7000 8000 9000" --timeout 10 --open-port 2222 --duration 20
"""

from __future__ import annotations
import argparse, json, os, sys, time, shutil, signal, socket, threading, subprocess
from typing import Dict, Tuple, Optional

# --- Dépendance sniff ---
try:
    from scapy.all import IP, TCP, sniff  # type: ignore
except Exception:
    print("[-] Scapy requis. Installe :  pip install scapy", file=sys.stderr)
    sys.exit(1)

# ---------- CLI ----------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Serveur Port-Knocking (iptables)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--iface", default="lo", help="Interface à sniffer")
    p.add_argument("--seq", default="7000 8000 9000", help="Séquence de ports (espaces)")
    p.add_argument("--timeout", type=int, default=10, help="Délai max entre knocks (s)")
    p.add_argument("--open-port", dest="open_port", type=int, default=2222, help="Port à ouvrir")
    p.add_argument("--duration", type=int, default=20, help="Durée d'ouverture (s)")
    p.add_argument("--json-log", default="knockd.jsonl", help="Fichier de logs JSONL")
    p.add_argument("--quarantine-set", default="knock_quarantine", help="Nom du set ipset")
    p.add_argument("--quarantine-timeout", type=int, default=60, help="Durée quarantaine (s)")
    p.add_argument("--anti-spam", type=int, default=3, help="Échecs avant quarantaine")
    return p.parse_args()

# ---------- Utilitaires ----------
def require_root():
    if os.geteuid() != 0:
        print("[-] Lance ce script en root (sudo).", file=sys.stderr)
        sys.exit(1)

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run(cmd: list[str], check=False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)

def print_rules(open_port: int, qset: str):
    out = run(["iptables-save"]).stdout
    lines = [l for l in out.splitlines() if f"--dport {open_port}" in l or qset in l or "match-set" in l]
    print("\n[ Règles pertinentes ]")
    print("\n".join(lines) if lines else "(aucune règle correspondante)")
    print()

def jprint(event: str, **kw):
    msg = {"ts": round(time.time(), 3), "event": event, **kw}
    print(f"[{event}] {kw}")
    with open(ARGS.json_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")

def ensure_quarantine(qset: str, qtimeout: int) -> bool:
    if not have("ipset"):
        print("[i] ipset non détecté : quarantaine désactivée.")
        return False
    run(["ipset","create", qset, "hash:ip", "timeout", str(qtimeout)], check=False)
    # Règle DROP si membre du set (si absente)
    chk = run(["iptables","-C","INPUT","-m","set","--match-set", qset, "src","-j","DROP"])
    if chk.returncode != 0:
        run(["iptables","-I","INPUT","1","-m","set","--match-set", qset, "src","-j","DROP"])
    return True

def quarantine(ip: str):
    if have("ipset"):
        run(["ipset","add", ARGS.quarantine_set, ip, "timeout", str(ARGS.quarantine_timeout)], check=False)
        jprint("quarantine", ip=ip, seconds=ARGS.quarantine_timeout)

def open_rule(ip: str, port: int):
    # évite les doublons
    chk = run(["iptables","-C","INPUT","-s",ip,"-p","tcp","--dport",str(port),"-j","ACCEPT"])
    if chk.returncode != 0:
        run(["iptables","-I","INPUT","-s",ip,"-p","tcp","--dport",str(port),"-j","ACCEPT"], check=False)

def close_rule(ip: str, port: int):
    run(["iptables","-D","INPUT","-s",ip,"-p","tcp","--dport",str(port),"-j","ACCEPT"], check=False)

# ---------- Programme ----------
def main():
    global ARGS
    ARGS = parse_args()
    require_root()
    if not have("iptables"):
        print("[-] iptables requis.", file=sys.stderr); sys.exit(1)

    seq = [int(p) for p in ARGS.seq.split() if p]
    timeout = ARGS.timeout
    port = ARGS.open_port
    duration = ARGS.duration

    quarantine_enabled = ensure_quarantine(ARGS.quarantine_set, ARGS.quarantine_timeout)

    # États
    state: Dict[str, Tuple[int, float, Optional[int]]] = {}
    invalid: Dict[str, int] = {}
    opened: set[str] = set()
    timers: Dict[str, threading.Thread] = {}
    lock = threading.Lock()

    print(f"[i] Écoute sur {ARGS.iface} | séquence: {' -> '.join(map(str, seq))} | "
          f"port à ouvrir: {port} ({duration}s)")
    print_rules(port, ARGS.quarantine_set)

    def reset(ip: str):
        state[ip] = (0, 0.0, None)

    def punish(ip: str):
        invalid[ip] = invalid.get(ip, 0) + 1
        jprint("invalid_seq", ip=ip, count=invalid[ip])
        if quarantine_enabled and invalid[ip] >= ARGS.anti_spam:
            quarantine(ip)
            invalid[ip] = 0

    def open_for(ip: str):
        with lock:
            if ip in opened:
                return
            open_rule(ip, port)
            opened.add(ip)
            jprint("open", ip=ip, port=port, duration=duration)
            print_rules(port, ARGS.quarantine_set)
            print(f"[+] Séquence OK pour {ip} → port {port} OUVERT {duration}s")
            print(f"    👉  ssh -p {port} <user>@{ip}")

            def worker():
                time.sleep(duration)
                with lock:
                    if ip in opened:
                        close_rule(ip, port)
                        opened.discard(ip)
                        jprint("close", ip=ip, port=port)
                        print_rules(port, ARGS.quarantine_set)

            t = threading.Thread(target=worker, daemon=False)
            timers[ip] = t
            t.start()

    def process(pkt):
        if TCP not in pkt or IP not in pkt:
            return
        if not (int(pkt[TCP].flags) & 0x02):  # SYN uniquement
            return

        ip = pkt[IP].src
        dport = int(pkt[TCP].dport)
        step, last_ts, last_port = state.get(ip, (0, 0.0, None))

        # anti-doublons
        if dport == last_port:
            return

        now = time.time()
        if step > 0 and now - last_ts > timeout:
            reset(ip); punish(ip)
            step, last_ts, last_port = state[ip]

        expected = seq[step]
        if dport != expected:
            reset(ip); punish(ip); return

        step += 1
        state[ip] = (step, now, dport)
        jprint("step", ip=ip, received=dport, expected=expected, progress=step)

        if step == len(seq):
            jprint("sequence_ok", ip=ip)
            reset(ip)
            open_for(ip)

    def cleanup(signum, frame):
        print("\n[+] Nettoyage…")
        for ip in list(opened):
            close_rule(ip, port)
            jprint("close", ip=ip, port=port)
        for t in list(timers.values()):
            t.join(timeout=1)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Sniffer (sans dépendre de libpcap : filtre Python)
    lfilter = lambda p: TCP in p and IP in p and int(p[TCP].dport) in seq
    sniff(prn=process, store=0, iface=ARGS.iface, lfilter=lfilter)

if __name__ == "__main__":
    main()
