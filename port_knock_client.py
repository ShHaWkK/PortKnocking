#!/usr/bin/env python3
"""Client très simple pour démontrer le mécanisme de port knocking.

Le programme envoie successivement des paquets TCP SYN sur une série de ports
afin de déclencher l'ouverture d'un service distant si la séquence est
correcte.
"""

import argparse
import socket
import time


def parse_args() -> argparse.Namespace:
    """Récupère les paramètres fournis par l'utilisateur."""

    parser = argparse.ArgumentParser(
        description="Client de port knocking",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "host",
        nargs="?",
        default="127.0.0.1",
        help="Hôte cible",
    )
    parser.add_argument(
        "--seq",
        default="7000 8000 9000",
        help="Séquence de ports à frapper",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Délai entre deux knocks en secondes",
    )
    return parser.parse_args()


def main() -> None:
    """Envoie un SYN sur chaque port spécifié."""

    args = parse_args()
    sequence = [int(p) for p in args.seq.split() if p]

    for port in sequence:
        print(f"[*] Knock sur le port {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                sock.connect((args.host, port))
            except OSError:
                pass  # Ignore toutes les erreurs, seul le SYN compte
        time.sleep(args.delay)


if __name__ == "__main__":
    main()

