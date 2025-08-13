#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 - Serveur complet et autonome
Canal temporel (inter-arrival timing) + SPA AES-GCM + ouverture dynamique via nftables
Tout est configuré automatiquement : nftables est préparé par le script.
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
PORT_LEURRE = 443                     # Port leurre (un seul ouvert)
PREAMBULE = [1, 0, 1, 0]               # Séquence pour synchronisation
CLE_AES = b"azertyazertyazertyazertyazertyaz"  # Clé AES-256 (32 octets)
CLE_HMAC = b"responsresponsresponsrespons"     # Clé HMAC
FENETRE_TEMPS = 60                     # Anti-rejeu (en secondes)
DUREE_PAR_DEFAUT = 60                  # Durée d’ouverture IP autorisée
ips_autorisees = {}

LOG_FILE = "poc5_server.log"           # Fichier de logs JSONL
OSCILLOSCOPE = True                    # Affichage visuel des timings

# --- PRÉPARATION NFTABLES ---
def configurer_nftables():
    """Crée la configuration nftables complète pour autoriser dynamiquement des IP."""
    cmds = [
        "nft add table inet filter",
        "nft add set inet filter allowed { type ipv4_addr; flags timeout; }",
        "nft add chain inet filter input { type filter hook input priority 0; }",
        "nft add rule inet filter input ip saddr @allowed accept",
        f"nft add rule inet filter input tcp dport {PORT_LEURRE} drop"
    ]
    for cmd in cmds:
        subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
    print("[OK] nftables configuré automatiquement.")

# --- LOGGING ---
def log_event(data):
    """Enregistre un événement en JSONL."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def oscilloscope_ascii(intervals):
    """Affiche une visualisation simple des timings."""
    if OSCILLOSCOPE:
        mediane = np.median(intervals)
        line = "".join("▮" if t > mediane else "▯" for t in intervals)
        print(f"[OSCILLO] {line}")

# --- DÉCODAGE ---
def decode_intervalles(intervalles):
    """Convertit les timings en bits, avec tolérance au jitter."""
    mediane = np.median(intervalles)
    bits = [1 if delta > mediane else 0 for delta in intervalles]
    if bits[:len(PREAMBULE)] == PREAMBULE:
        return bits[len(PREAMBULE):]
    return None

# --- SPA ---
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
            print("[!] HMAC invalide")
            return None

        # Anti-rejeu
        maintenant = int(time.time())
        if abs(maintenant - spa["timestamp"]) > FENETRE_TEMPS:
            print("[!] Timestamp expiré")
            return None

        return spa
    except Exception as e:
        print("[!] Erreur SPA :", e)
        return None

# --- AUTORISATION IP ---
def autoriser_ip(ip, duree=DUREE_PAR_DEFAUT):
    """Ajoute l'IP dans le set nftables avec un timeout."""
    subprocess.run(f"nft add element inet filter allowed {{ {ip} timeout {duree}s }}", shell=True)
    ips_autorisees[ip] = time.time() + duree
    print(f"[+] IP autorisée : {ip} ({duree}s)")

def nettoyer_ips_expirees():
    """Retire les IP expirées."""
    maintenant = time.time()
    for ip in list(ips_autorisees):
        if maintenant > ips_autorisees[ip]:
            subprocess.run(f"nft delete element inet filter allowed {{ {ip} }}", shell=True)
            del ips_autorisees[ip]
            print(f"[-] IP retirée : {ip}")

# --- SERVEUR ---
def serveur():
    configurer_nftables()

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

        oscilloscope_ascii(arrivees[ip_src])

        # Si on a reçu assez de bits
        if len(arrivees[ip_src]) >= len(PREAMBULE) + 64:
            bits = decode_intervalles(arrivees[ip_src])
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
