#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 - Serveur complet et autonome
Canal temporel (inter-arrival timing) + SPA AES-GCM + ouverture dynamique via nftables.
- Preamble 8 bits "10101010"
- Longueur du message sur 16 bits (big-endian, nombre d'octets du JSON chiffré)
- Message JSON (hex) encodé en bits puis envoyé via SYN timings sur 443
- Déchiffrement AES-GCM + vérification HMAC (sur JSON canonique {"duration","ip","timestamp"})
- Ouverture dynamique via nftables d'un set d'IP autorisées avec timeout
"""
import socket
import sys
import time
import subprocess
import json
import hmac
import hashlib
import os
from datetime import datetime
from statistics import median
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

# --- CONFIGURATION ---
PORT_LEURRE = 443
PREAMBULE = [1,0,1,0,1,0,1,0]   # 8 bits "10101010"
CLE_AES = b"azertyazertyazertyazertyazertyaz"  # 32 octets (AES-256)
CLE_HMAC = b"responsresponsresponsrespons"     # clé HMAC
FENETRE_TEMPS = 60               # anti-rejeu (secondes)
DUREE_PAR_DEFAUT = 60            # TTL par défaut (secondes) si absent
LOG_FILE = "poc5_server.log"     # logs JSONL
OSCILLOSCOPE = True              # affichage simple des timings

NFT_TABLE = "knock5"
NFT_CHAIN = "inbound"
NFT_SET   = "allowed"
SSH_PORT  = 2222                 # port protégé par le knock

# --- ÉTAT ---
arrivees = {}  
derniers = {}   # ip -> dernier timestamp 
ips_autorisees = {}

# --- OUTILS ---
def log_event(data: dict):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def oscilloscope_ascii(intervals):
    if not OSCILLOSCOPE or not intervals:
        return
    m = median(intervals)
    line = "".join("▮" if t > m else "▯" for t in intervals[-64:])
    print(f"[OSCILLO] {line} (med={m:.3f}s)")

def bits_to_bytes(bits):
    return bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8))

def classifier_bits(intervals):
    m = median(intervals)
    return [1 if d > m else 0 for d in intervals]

def trouver_preambule(bits, preambule):
    n, m = len(bits), len(preambule)
    for i in range(0, n - m + 1):
        if bits[i:i+m] == preambule:
            return i
    return -1

# --- NFTABLES ---
def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def nft_configurer():
    run(f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 || nft add table inet {NFT_TABLE}", check=False)
    run(f"nft list set inet {NFT_TABLE} {NFT_SET} >/dev/null 2>&1 || "
        f"nft add set inet {NFT_TABLE} {NFT_SET} '{{ type ipv4_addr; flags timeout; }}'", check=False)
    run(f"nft list chain inet {NFT_TABLE} {NFT_CHAIN} >/dev/null 2>&1 || "
        f"nft add chain inet {NFT_TABLE} {NFT_CHAIN} '{{ type filter hook input priority -150; policy accept; }}'",
        check=False)
    # allow si ip in set, sinon drop pour 2222 seulement
    run(f"nft list ruleset | grep -q 'tcp dport {SSH_PORT} .* @{NFT_SET} ' || "
        f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} ip saddr @{NFT_SET} accept", check=False)
    run(f"nft list ruleset | grep -q 'tcp dport {SSH_PORT} drop' || "
        f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} tcp dport {SSH_PORT} drop", check=False)
    print("[OK] nftables configuré (table=inet:{} chain={} set={})".format(NFT_TABLE, NFT_CHAIN, NFT_SET))

def nft_autoriser_ip(ip, duree):
    run(f"nft add element inet {NFT_TABLE} {NFT_SET} '{{ {ip} timeout {int(duree)}s }}'", check=False)
    ips_autorisees[ip] = time.monotonic() + int(duree)
    print(f"[+] IP autorisée : {ip} ({int(duree)}s)")

def nft_nettoyer_ips():
    now = time.monotonic()
    for ip, expiry in list(ips_autorisees.items()):
        if now > expiry:
            run(f"nft delete element inet {NFT_TABLE} {NFT_SET} '{{ {ip} }}'", check=False)
            ips_autorisees.pop(ip, None)
            print(f"[-] IP retirée : {ip}")

# --- CRYPTO ---
def spa_decrypter_et_verifier(message_bytes: bytes):
    """
    message_bytes = JSON encodé des champs {"ciphertext","nonce","tag"} (hex)
    Retourne le dict déchiffré si HMAC OK et timestamp frais, sinon None.
    """
    try:
        obj = json.loads(message_bytes.decode())
        ciphertext = bytes.fromhex(obj["ciphertext"])
        nonce = bytes.fromhex(obj["nonce"])
        tag = bytes.fromhex(obj["tag"])

        aesgcm = AESGCM(CLE_AES)
        donnees = aesgcm.decrypt(nonce, ciphertext + tag, None)  # bytes JSON
        spa = json.loads(donnees.decode())  # {"timestamp","ip","duration","hmac"}

        # Recalcule HMAC sur JSON canonique sans le champ hmac
        payload = {"duration": int(spa["duration"]), "ip": str(spa["ip"]), "timestamp": int(spa["timestamp"])}
        canon = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        hmac_attendu = hmac.new(CLE_HMAC, canon, hashlib.sha256).hexdigest()
        if hmac_attendu != spa.get("hmac", ""):
            print("[!] HMAC invalide")
            return None

        # anti-rejeu
        maintenant = int(time.time())
        if abs(maintenant - int(spa["timestamp"])) > FENETRE_TEMPS:
            print("[!] Timestamp expiré")
            return None

        return spa
    except Exception as e:
        print("[!] Erreur SPA :", e)
        return None

# --- DÉCODAGE TEMPOREL ---
def tenter_decode(ip):
    """
    Essaie de décoder un message complet pour l'IP donnée :
    PREAMBULE (8) + TAILLE (16 bits) + MESSAGE (N octets => 8*N bits)
    """
    intervals = arrivees.get(ip, [])
    if len(intervals) < len(PREAMBULE) + 16 + 8:
        return False

    bits = classifier_bits(intervals)
    idx = trouver_preambule(bits, PREAMBULE)
    if idx < 0:
        return False

    after = bits[idx + len(PREAMBULE):]
    if len(after) < 16:
        return False

    length_bits = after[:16]
    L = int("".join(map(str, length_bits)), 2)
    needed = len(PREAMBULE) + 16 + 8*L
    if len(intervals) < needed:
        return False

    msg_bits = after[16:16+8*L]
    data = bits_to_bytes(msg_bits)

    spa = spa_decrypter_et_verifier(data)
    arrivees[ip].clear()

    if not spa:
        return False

    if spa.get("ip") != ip:
        print("[!] IP SPA != IP source timings")
        return False

    duree = int(spa.get("duration", DUREE_PAR_DEFAUT))
    nft_autoriser_ip(ip, duree)
    log_event({"time": datetime.utcnow().isoformat()+"Z", "ip": ip, "action": "allowed", "ttl": duree})
    return True

# --- SERVEUR ---
def serveur():
    if os.geteuid() != 0:
        print("Ce serveur doit être exécuté en root.", file=sys.stderr)
        raise SystemExit(1)

    nft_configurer()

    # socket brut IPv4 pour TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.settimeout(1.0)

    print(f"[SERVEUR] Écoute des SYN timings sur TCP dport {PORT_LEURRE} ...")

    while True:
        try:
            paquet, addr = sock.recvfrom(65535)
        except socket.timeout:
            nft_nettoyer_ips()
            continue

        if len(paquet) < 40:  # IP (20) + TCP (20) minimum
            continue

        # IP header
        ihl = (paquet[0] & 0x0F) * 4
        if ihl < 20:
            continue
        src_ip = ".".join(str(b) for b in paquet[12:16])
        # TCP header fields
        tcp_off = ihl
        dport = int.from_bytes(paquet[tcp_off+2:tcp_off+4], "big")
        flags = paquet[tcp_off+13]

        if dport != PORT_LEURRE:
            continue
        # SYN sans ACK
        if not (flags & 0x02) or (flags & 0x10):
            continue

        now = time.monotonic()
        last = derniers.get(src_ip)
        derniers[src_ip] = now
        if last is None:
            arrivees.setdefault(src_ip, [])
            continue

        delta = now - last
        lst = arrivees.setdefault(src_ip, [])
        lst.append(delta)

        oscilloscope_ascii(lst)

        try:
            tenter_decode(src_ip)
        except Exception as e:
            print("[!] Erreur decode:", e)

        nft_nettoyer_ips()

if __name__ == "__main__":
    serveur()
