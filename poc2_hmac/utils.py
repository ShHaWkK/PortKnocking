"""
Author : ShHawK 
Ce fichier contient des fonctions utilitaires pour la gestion de HMAC et la journalisation.
"""


import hmac
import hashlib
import time
import logging

def setup_logger(log_path):
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def compute_hmac(secret: bytes, src_ip: str, timestamp: int) -> str:
    msg = f"{src_ip}|{timestamp}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def verify_hmac(secret: bytes, src_ip: str, timestamp: int, received: str) -> bool:
    expected = compute_hmac(secret, src_ip, timestamp)
    return hmac.compare_digest(expected, received)

def is_fresh(timestamp: int, tolerance: int) -> bool:
    return abs(time.time() - timestamp) <= tolerance
