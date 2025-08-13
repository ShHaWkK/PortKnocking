#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 - Serveur
Canal temporel (inter-arrival timing) + SPA AES-GCM + ouverture dynamique via nftables
"""

import socket
import time
import numpy as np
import subprocess
import json
import hmac
import hashlib
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- CONFIGURATION ---
PORT_LEURRE = 443
PREAMBULE = [1, 0, 1, 0]  # pour synchroniser la séquence
CLE_AES = b"azertyazertyazertyazertyazertyaz"   # 32 bytes = AES-256
CLE_HMAC = b"responsresponsresponsrespons"      # clé HMAC
FENETRE_TEMPS = 60  # en secondes (anti-rejeu)
DUREE_PAR_DEFAUT = 60  # durée d'ouverture IP
ips_autorisees = {}

LOG_FILE = "poc5_server.log"  # logs JSONL
OSCILLOSCOPE = True  # affichage visuel des timings

# --- FONCTIONS ---
def log_event(data):
    """Enregistre un événement en JSONL."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def oscilloscope_ascii(intervals):
    """Affiche une visualisation simple des timings."""
    if OSCILLOSCOPE:
        line = "".join("▮" if t > np.median(intervals) else "▯" for t in intervals)
        print(f"[OSCILLO] {line}")

def decode_intervales(intervalles):
    """Convertit les timings en bits (1 ou 0 selon médiane)."""
    mediane = np.median(intervalles)
    bits = [1 if delta > mediane else 0 for delta in intervalles]
    if bits[:len(PREAMBULE)] == PREAMBULE:
        return bits[len(PREAMBULE):]
    return None

def decrypter_spa(message_bytes):
    """Décrypte le SPA AES-GCM et vérifie le HMAC."""
    try:
        obj = json.loads(message_bytes.decode())
        ciphertext = bytes.fromhex(obj["ciphertext"])
        nonce = bytes.fromhex(obj["nonce"])
        tag = bytes.fromhex(obj["tag"])

        aesgcm = AESGCM(CLE_AES)
        donnees = aesgcm.decrypt(nonce, ciphertext + tag, None)
        spa = json.loads(donnees.decode())

        # Vérif HMAC
        hmac_attendu = hmac.new(CLE_HMAC, donnees[:-32], hashlib.sha256).digest()
        if hmac_attendu != bytes.fromhex(spa["hmac"]):
            return None

        # Anti-rejeu : vérif timestamp
        maintenant = int(time.time())
        if abs(maintenant - spa["timestamp"]) > FENETRE_TEMPS:
            return None

        return spa
    except Exception:
        return None

def autoriser_ip(ip, duree=DUREE_PAR_DEFAUT):
    """Ajoute l'IP dans nftables."""
    subprocess.run(["nft", "add", "element", "inet", "filter", "allowed", f"{{ {ip} }}"])
    ips_autorisees[ip] = time.time() + duree
    print(f"[+] IP autorisée : {ip} ({duree}s)")

def nettoyer_ips_expirees():
    """Retire les IP expirées."""
    maintenant = time.time()
    for ip in list(ips_autorisees):
        if maintenant > ips_autorisees[ip]:
            subprocess.run(["nft", "delete", "element", "inet", "filter", "allowed", f"{{ {ip} }}"])
            del ips_autorisees[ip]
            print(f"[-] IP retirée : {ip}")

# --- LANCEMENT ---
def serveur():
    # Configuration nftables au démarrage
    os.system("sudo nft add table inet filter 2>/dev/null")
    os.system("sudo nft add set inet filter allowed { type ipv4_addr\; flags timeout\; } 2>/dev/null")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind(("", PORT_LEURRE))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    derniers = {}
    arrivees = {}

    print(f"[SERVEUR] Écoute sur port leurre {PORT_LEURRE}...")

    while True:
        paquet = sock.recv(65535)
        ip_src = ".".join(map(str, paquet[12:16]))
        flags = paquet[33]
        if flags != 0x02:  # SYN uniquement
            continue

        maintenant = time.time()
        if ip_src not in derniers:
            derniers[ip_src] = maintenant
            arrivees[ip_src] = []
            continue

        delta = maintenant - derniers[ip_src]
        derniers[ip_src] = maintenant
        arrivees[ip_src].append(delta)

        # Oscilloscope
        oscilloscope_ascii(arrivees[ip_src])

        # Si on a assez de bits
        if len(arrivees[ip_src]) >= len(PREAMBULE) + 64:
            bits = decode_intervales(arrivees[ip_src])
            arrivees[ip_src] = []
            if bits:
                octets = bytes([int("".join(map(str, bits[i:i+8])), 2)
                               for i in range(0, len(bits), 8)])
                spa = decrypter_spa(octets)
                if spa and spa["ip"] == ip_src:
                    autoriser_ip(ip_src, spa["duration"])
                    log_event({"time": datetime.now().isoformat(), "ip": ip_src, "action": "allowed"})

        nettoyer_ips_expirees()

if __name__ == "__main__":
    serveur()
