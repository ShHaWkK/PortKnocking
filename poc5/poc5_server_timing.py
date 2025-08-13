#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 serveur  timing channel + HMM/Viterbi + SPA + ouverture nftables
- Dépendances Python : numpy, scapy
- Dépendances système : nftables, openssh-server, libpcap, qrencode
- Port leurre TCP 443, SPA UDP 45445, SSH 2222
"""

import os, sys, time, json, base64, hmac, hashlib, math, argparse, threading, subprocess, socket
from typing import List, Tuple

import numpy as np
from scapy.all import sniff, TCP, IP

#----------  Paramètres  ----------
LURE_IF   = "lo"
LURE_PORT = 443
SPA_PORT  = 45445
SSH_PORT  = 2222
NFT_TABLE = "knock5"
OPEN_TTL  = 60
PREAMBLE  = "10101010"
SECRET_FILE = "/etc/portknock/secret"  # base64

def run(*cmd, check=True, quiet=False):
    r = subprocess.run(cmd, text=True, capture_output=True)
    if not quiet and r.stdout.strip():
        print(r.stdout.rstrip())
    if check and r.returncode != 0:
        if r.stderr.strip():
            print(r.stderr.rstrip())
        raise RuntimeError(r.stderr.strip())
    return r

def _load_secret(path=SECRET_FILE) -> bytes:
    tok = open(path).read().strip().split()[0]
    try:
        return base64.b64decode(tok, validate=True)
    except Exception:
        return base64.b64decode(tok)

def _hmac_ok(secret: bytes, raw: bytes) -> bool:
    if len(raw) < 16:
        return False
    mac = raw[-16:]
    msg = raw[:-16]
    calc = hmac.new(secret, msg, hashlib.sha256).digest()[:16]
    return hmac.compare_digest(mac, calc)

#----------  nftables ----------
def nft_setup():
    run(["bash", "-lc", f"nft delete table inet {NFT_TABLE} >/dev/null 2>&1 || true"], check=False)
    rules = f"""
add table inet {NFT_TABLE}
add set inet {NFT_TABLE} allowed {{ type ipv4_addr; flags timeout; timeout {OPEN_TTL}s; }}
add chain inet {NFT_TABLE} input {{ type filter hook input priority 0; policy accept; }}
add rule  inet {NFT_TABLE} input tcp dport {SSH_PORT} ip saddr != @allowed drop
"""
    with open("/tmp/nft5.nft", "w") as f:
        f.write(rules)
    run(["nft", "-f", "/tmp/nft5.nft"])

def nft_allow(ip: str, ttl: int = OPEN_TTL):
    run(["bash", "-lc", f"nft add element inet {NFT_TABLE} allowed {{ {ip} timeout {ttl}s }}"], check=False)

#---------- HMM / Viterbi ----------
def fit_gaussians(preamble_delays: List[float], preamble_bits: str) -> Tuple[Tuple[float, float], Tuple[float, float]]:
    zs0 = [d for d, b in zip(preamble_delays, preamble_bits) if b == "0"]
    zs1 = [d for d, b in zip(preamble_delays, preamble_bits) if b == "1"]
    mu0 = float(np.median(zs0))
    mu1 = float(np.median(zs1))
    sig0 = float(np.std(zs0) or 1e-3)
    sig1 = float(np.std(zs1) or 1e-3)
    return (mu0, sig0), (mu1, sig1)

def logp_gauss(x, mu, sigma):
    return -0.5 * math.log(2 * math.pi * sigma * sigma) - ((x - mu) ** 2) / (2 * sigma * sigma)

def viterbi_delays(delays: List[float], g0, g1) -> str:
    n = len(delays)
    dp = np.full((n, 2), -1e18)
    prev = np.zeros((n, 2), dtype=int)
    logA = np.log(np.array([[0.90, 0.10], [0.10, 0.90]]))
    logpi = np.log(np.array([0.5, 0.5]))
    dp[0, 0] = logpi[0] + logp_gauss(delays[0], *g0)
    dp[0, 1] = logpi[1] + logp_gauss(delays[0], *g1)

    for i in range(1, n):
        o0 = logp_gauss(delays[i], *g0)
        o1 = logp_gauss(delays[i], *g1)
        ps0 = dp[i-1, 0] + logA[0, 0]
        ps1 = dp[i-1, 1] + logA[1, 0]
        dp[i, 0], prev[i, 0] = (ps0 + o0, 0) if ps0 > ps1 else (ps1 + o0, 1)

        ps0 = dp[i-1, 0] + logA[0, 1]
        ps1 = dp[i-1, 1] + logA[1, 1]
        dp[i, 1], prev[i, 1] = (ps0 + o1, 0) if ps0 > ps1 else (ps1 + o1, 1)

    s = 0 if dp[-1, 0] > dp[-1, 1] else 1
    states = [s]
    for i in range(n-1, 0, -1):
        s = prev[i, s]
        states.append(s)
    return "".join("1" if s == 1 else "0" for s in reversed(states))

def bits_to_bytes(bits: str) -> bytes:
    L = (len(bits) // 8) * 8
    if L <= 0:
        return b""
    return int(bits[:L], 2).to_bytes(L // 8, "big")

#---------- Sniff + SPA ----------
def start_sniffer(events, iface, stop_evt):
    def _cb(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        if int(pkt[TCP].dport) != LURE_PORT:
            return
        if (pkt[TCP].flags & 0x02) == 0:  # SYN
            return
        events.append((pkt[IP].src, pkt.time))

    sniff(store=0, iface=iface,
          filter=f"tcp and dst port {LURE_PORT} and (tcp[13] & 2 != 0)",
          prn=_cb, stop_filter=lambda p: stop_evt.is_set())

def spa_listener(secret: bytes, stop_evt, on_open):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", SPA_PORT))
    s.settimeout(0.2)
    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(8192)
        except socket.timeout:
            continue
        if not data or data[0] != 0x01:
            continue
        blob = data[1:]
        if _hmac_ok(secret, blob):
            try:
                msg = json.loads(blob[:-16].decode())
                ip = addr[0]
                dur = int(msg.get("duration", OPEN_TTL))
                on_open(ip, dur)
            except Exception:
                pass
    s.close()

#---------- SSHD éphémère ----------
def start_sshd_ephemeral():
    cfg = f"""Port {SSH_PORT}
ListenAddress 127.0.0.1
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
PidFile /tmp/poc5_sshd.pid
LogLevel QUIET
"""
    path = "/tmp/poc5_sshd_config"
    with open(path, "w") as f:
        f.write(cfg)
    run(["/usr/sbin/sshd", "-f", path], check=False)
    print(f"[+] sshd éphémère sur 127.0.0.1:{SSH_PORT}")

#---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="POC5 serveur — timing channel + SPA + nftables")
    ap.add_argument("-i", "--iface", default=LURE_IF)
    args = ap.parse_args()

    if not os.path.exists(SECRET_FILE):
        os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
        raw = os.urandom(32)
        with open(SECRET_FILE, "w") as f:
            f.write(base64.b64encode(raw).decode() + "\n")
        os.chmod(SECRET_FILE, 0o600)
        print(f"[+] Secret maître généré : {SECRET_FILE}")

    secret = _load_secret()
    nft_setup()
    start_sshd_ephemeral()

    events = []
    stop_evt = threading.Event()

    th_sniff = threading.Thread(target=start_sniffer, args=(events, args.iface, stop_evt), daemon=True)
    th_sniff.start()

    def on_open(ip, dur):
        nft_allow(ip, dur)
        print(f"[OPEN] {ip} -> {SSH_PORT} for {dur}s")

    th_spa = threading.Thread(target=spa_listener, args=(secret, stop_evt, on_open), daemon=True)
    th_spa.start()

    print(f"[i] Sniff timings on {args.iface}:{LURE_PORT} | SPA UDP {SPA_PORT} | SSH {SSH_PORT}")

    try:
        while True:
            time.sleep(0.5)
            by_ip = {}
            for ip, ts in events:
                by_ip.setdefault(ip, []).append(ts)

            for ip, arr in by_ip.items():
                arr.sort()
                if len(arr) < len(PREAMBLE) + 10:
                    continue
                delays = [arr[i] - arr[i - 1] for i in range(1, len(arr))]
                sym = delays[:len(PREAMBLE)]
                g0, g1 = fit_gaussians(sym, PREAMBLE)
                bits = viterbi_delays(delays, g0, g1)
                idx = bits.find(PREAMBLE)
                if idx < 0:
                    continue
                payload_bits = bits[idx + len(PREAMBLE):]
                raw = bits_to_bytes(payload_bits)
                if _hmac_ok(secret, raw):
                    msg = json.loads(raw[:-16].decode())
                    dur = int(msg.get("duration", OPEN_TTL))
                    nft_allow(ip, dur)
                    print(f"[DECODED] {ip} -> open {SSH_PORT} for {dur}s")
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        run(["bash", "-lc", f"nft delete table inet {NFT_TABLE} >/dev/null 2>&1 || true"], check=False)
        print("[+] Nettoyage nftables OK.")

if __name__ == "__main__":
    main()
