#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC5 - Client
Envoi de la séquence temporelle + SPA AES-GCM
"""

import time
import json
import random
import hmac
import hashlib
from scapy.all import IP, TCP, send
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- CONFIGURATION ---
CLE_AES = b"azertyazertyazertyazertyazertyaz"
CLE_HMAC = b"responsresponsresponsrespons"
PORT = 443
IP_CIBLE = "127.0.0.1"
INTER_0 = 0.05
INTER_1 = 0.15

def generer_spa(ip, duree=60):
    """Construit un message SPA chiffré."""
    timestamp = int(time.time())
    spa = {
        "timestamp": timestamp,
        "ip": ip,
        "duration": duree
    }

    spa_bytes = json.dumps(spa).encode()
    h = hmac.new(CLE_HMAC, spa_bytes, hashlib.sha256).digest()
    spa["hmac"] = h.hex()

    final = json.dumps(spa).encode()
    nonce = random.randbytes(12)
    aesgcm = AESGCM(CLE_AES)
    chiffré = aesgcm.encrypt(nonce, final, None)
    tag = chiffré[-16:]
    contenu = chiffré[:-16]

    return json.dumps({
        "ciphertext": contenu.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex()
    }).encode()

def encodage_bits(msg):
    """Transforme le message en bits."""
    return [int(b) for byte in msg for b in f"{byte:08b}"]

def envoyer(bits, ip, port):
    """Envoie la séquence SYN avec timings."""
    preambule = [1, 0, 1, 0]
    total = preambule + bits
    for b in total:
        p = IP(dst=ip)/TCP(dport=port, flags="S")
        send(p, verbose=0)
        time.sleep(INTER_1 if b else INTER_0)
    print("[+] Knock envoyé.")

if __name__ == "__main__":
    spa = generer_spa(IP_CIBLE)
    bits = encodage_bits(spa)
    envoyer(bits, IP_CIBLE, PORT)
