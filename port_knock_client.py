#!/usr/bin/env python3
"""Client très simple pour démontrer le mécanisme de port knocking.

Le programme envoie successivement des paquets TCP SYN sur une série de ports
afin de déclencher l'ouverture d'un service distant si la séquence est
correcte.
"""

import argparse, socket, time, sys

def parse_args():
    p = argparse.ArgumentParser(
        description="Client de port knocking",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("host", nargs="?", default="127.0.0.1", help="Hôte cible")
    p.add_argument("--seq", default="7000 8000 9000", help="Séquence de ports (espaces)")
    p.add_argument("--delay", type=float, default=0.5, help="Délai entre knocks (s)")
    return p.parse_args()

def main():
    a = parse_args()
    seq = [int(x) for x in a.seq.split() if x.strip()]
    print(f"[i] Cible: {a.host} | Séquence: {' -> '.join(map(str, seq))} | Délai: {a.delay}s")
    for port in seq:
        print(f"[*] Knock sur le port {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((a.host, port))  # émet un SYN
            except OSError:
                pass  # normal : le port est fermé/filtré
        time.sleep(a.delay)
    print("[✓] Séquence envoyée. Tente la connexion SSH si le serveur a validé la séquence.")

if __name__ == "__main__":
    main()
