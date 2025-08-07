#!/usr/bin/env python3
"""Serveur de démonstration pour un mécanisme simple de port knocking.

Le script écoute des paquets TCP SYN sur une séquence de ports. Lorsqu'une
adresse IP frappe les bons ports dans l'ordre défini et dans un délai
raisonnable, une règle *iptables* est insérée afin d'autoriser temporairement
la connexion sur un port spécifique.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import threading
import time

# Vérification de la disponibilité de Scapy -------------------------------
try:  # noqa: SIM105 - bloc pour émettre un message d'erreur clair
    from scapy.all import IP, TCP, sniff  # type: ignore
except Exception:  # pragma: no cover - Scapy manquant
    print(
        "[-] Le module Scapy est requis. Installez-le avec 'pip install scapy'.",
        file=sys.stderr,
    )
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    """Analyse les arguments de la ligne de commande."""

    parser = argparse.ArgumentParser(
        description="Serveur de port knocking minimal",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--iface",
        default="lo",
        help="Interface réseau à sniffer",
    )
    parser.add_argument(
        "--seq",
        default="7000 8000 9000",
        help="Séquence de ports attendus (séparés par des espaces)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Délai maximum entre deux knocks en secondes",
    )
    parser.add_argument(
        "--open-port",
        dest="open_port",
        type=int,
        default=2222,
        help="Port à ouvrir lorsque la séquence est correcte",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Durée d'ouverture du port en secondes",
    )
    return parser.parse_args()


def require_root() -> None:
    """Vérifie que le script est exécuté avec les privilèges administrateur."""

    if os.geteuid() != 0:
        print("[-] Ce script doit être exécuté en tant que root.", file=sys.stderr)
        sys.exit(1)


def main() -> None:  # noqa: C901 - complexité gérée par commentaires
    """Point d'entrée principal du serveur."""

    args = parse_args()
    require_root()

    # Préparation de la séquence et des paramètres -----------------------
    sequence = [int(p) for p in args.seq.split() if p]
    timeout = args.timeout
    open_port = args.open_port
    duration = args.duration

    # Journalisation dans un fichier knockd.log --------------------------
    logging.basicConfig(
        filename="knockd.log",
        level=logging.INFO,
        format="%(asctime)s %(message)s",
    )

    # État courant des knocks : {ip: (étape, timestamp, dernier_port)}
    state: dict[str, tuple[int, float, int | None]] = {}
    # IP ayant une règle iptables ouverte afin de pouvoir nettoyer
    opened_rules: set[str] = set()

    # ------------------------------------------------------------------
    def reset(ip: str) -> None:
        """Réinitialise l'état de knock pour l'adresse IP donnée."""

        state[ip] = (0, 0.0, None)

    # ------------------------------------------------------------------
    def close_rule(ip: str) -> None:
        """Supprime la règle iptables associée à l'IP."""

        subprocess.run(
            [
                "iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(open_port),
                "-j",
                "ACCEPT",
            ],
            check=False,
        )
        opened_rules.discard(ip)
        logging.info("Fermeture du port %d pour %s", open_port, ip)

    # ------------------------------------------------------------------
    def open_rule(ip: str) -> None:
        """Ajoute la règle iptables pour l'IP puis programme sa suppression."""

        subprocess.run(
            [
                "iptables",
                "-I",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(open_port),
                "-j",
                "ACCEPT",
            ],
            check=False,
        )
        opened_rules.add(ip)
        logging.info("Ouverture du port %d pour %s", open_port, ip)

        # Thread non-daemon pour supprimer la règle après `duration` secondes
        def worker() -> None:
            time.sleep(duration)
            close_rule(ip)

        threading.Thread(target=worker, daemon=False).start()

    # ------------------------------------------------------------------
    def process(packet) -> None:
        """Traite chaque paquet capturé par Scapy."""

        if TCP not in packet or IP not in packet:
            return
        if not (int(packet[TCP].flags) & 0x02):  # Ne prendre que les SYN
            return

        src_ip = packet[IP].src
        dst_port = int(packet[TCP].dport)

        # Port attendu
        step, last_ts, last_port = state.get(src_ip, (0, 0.0, None))

        # Ignorer les doublons
        if dst_port == last_port:
            return

        now = time.time()
        if step > 0 and now - last_ts > timeout:
            reset(src_ip)
            step, last_ts, last_port = state[src_ip]

        expected = sequence[step]
        if dst_port != expected:
            reset(src_ip)
            return

        step += 1
        state[src_ip] = (step, now, dst_port)

        if step == len(sequence):
            logging.info("Séquence correcte pour %s", src_ip)
            reset(src_ip)
            open_rule(src_ip)

    # ------------------------------------------------------------------
    def cleanup(signum: int, frame: object) -> None:  # noqa: ARG001 - exigence signal
        """Supprime les règles iptables ouvertes avant de quitter."""

        for ip in list(opened_rules):
            close_rule(ip)
        sys.exit(0)

    # Gestion des signaux pour un arrêt propre
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    ports_filter = " or ".join(f"dst port {p}" for p in sequence)
    bpf = f"tcp and ({ports_filter})"

    # Démarrage du sniffer ------------------------------------------------
    sniff(filter=bpf, prn=process, store=0, iface=args.iface)


if __name__ == "__main__":
    main()

