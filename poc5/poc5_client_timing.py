#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 - Client 
Envoie : PREAMBULE (8 bits) + LONGUEUR (16 bits) + MESSAGE(JSON chiffré) encodé en bits,
au moyen d'une séquence de paquets SYN espacés dans le temps.
"""
import time
import json
import hmac
import hashlib
import os
import socket
import random
from scapy.all import IP, TCP, send 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- CONFIGURATION ---
CLE_AES = b"azertyazertyazertyazertyazertyaz"  # 32 octets
CLE_HMAC = b"responsresponsresponsrespons"
PORT = 443
IP_CIBLE = "127.0.0.1"
INTER_0 = 0.05
INTER_1 = 0.15
PREAMBULE = [1,0,1,0,1,0,1,0]

def generer_spa(ip: str, duree: int = 60) -> bytes:
    """
    Construit un message SPA chiffré AES-GCM, renvoyé sous forme de JSON:
    {"ciphertext": "<hex>", "nonce": "<hex>", "tag": "<hex>"}  puis encodé en bytes.
    HMAC est calculé sur le JSON "canonique" (tri des clés + séparateurs compacts).
    """
    timestamp = int(time.time())
    payload = {"timestamp": timestamp, "ip": ip, "duration": int(duree)}
    # JSON canonique sans hmac
    canon = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    h = hmac.new(CLE_HMAC, canon, hashlib.sha256).hexdigest()
    payload["hmac"] = h
    final = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    nonce = os.urandom(12)  # 96-bit
    aesgcm = AESGCM(CLE_AES)
    chiffré = aesgcm.encrypt(nonce, final, None)  # ciphertext + tag
    tag = chiffré[-16:]
    contenu = chiffré[:-16]

    env = {
        "ciphertext": contenu.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex()
    }
    return json.dumps(env, separators=(",", ":"), sort_keys=True).encode()

def bytes_to_bits(b: bytes):
    return [int(bit) for byte in b for bit in f"{byte:08b}"]

def envoyer_sequence(bits, ip, port):
    """
    Envoie PREAMBULE + TAILLE(16 bits) + MESSAGE(bits) via des SYN sur 'port'.
    """
    # header longueur en octets
    L = len(bits)//8
    if len(bits) % 8 != 0:
        raise ValueError("Le message binaire doit être un multiple de 8 bits.")
    len_bits = [int(bit) for bit in f"{L:016b}"]

    total = PREAMBULE + len_bits + bits

    # garder un sport/seq constants pendant la séquence (optionnel)
    sport = random.randint(1024, 65000)
    seq0 = random.randint(0, 2**32-1)

    for i, b in enumerate(total):
        p = IP(dst=ip)/TCP(dport=port, sport=sport, flags="S", seq=seq0+i)
        send(p, verbose=0)
        time.sleep(INTER_1 if b else INTER_0)
    print(f"[+] Knock envoyé ({len(total)} paquets).")

if __name__ == "__main__":
    # Résolution (au cas où l'utilisateur met un hostname dans IP_CIBLE)
    try:
        dst_ip = socket.gethostbyname(IP_CIBLE)
    except Exception:
        print("Impossible de résoudre l'adresse cible.")
        raise SystemExit(1)

    spa = generer_spa(dst_ip)
    bits = bytes_to_bits(spa)
    envoyer_sequence(bits, dst_ip, PORT)
