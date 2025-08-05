#!/usr/bin/env python3
"""Simple port knocking server.

This script listens for connection attempts on TCP ports 7000 -> 8000 -> 9000.
If a client hits these ports in the correct order with less than 10 seconds
between knocks, the script inserts an iptables rule to allow that IP to access
port 2222 for 20 seconds.

The script must be run as root because it uses raw sockets via scapy and
modifies iptables rules.
"""

import subprocess
import threading
import time
from scapy.all import sniff, TCP, IP

# Ports that compose the knocking sequence
KNOCK_SEQUENCE = [7000, 8000, 9000]
# Max delay allowed between two successive knocks (seconds)
STEP_TIMEOUT = 10
# Port to open if the knocking sequence is correct
SSH_PORT = 2222
# Time during which the SSH port stays open (seconds)
OPEN_DURATION = 20

# Dictionary mapping source IP -> (index of next expected port, time of last knock, last port)
knock_state: dict[str, tuple[int, float, int]] = {}

def reset_state(ip: str) -> None:
    """Reset the stored knock state for a given IP."""
    knock_state[ip] = (0, 0, -1)

def open_port_for(ip: str) -> None:
    """Insert an iptables rule to allow ip to access SSH_PORT."""
    print(f"[+] Ouverture du port {SSH_PORT} pour {ip}")
    subprocess.run([
        "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(SSH_PORT),
        "-s", ip, "-j", "ACCEPT"
    ], check=False)

    def close_later() -> None:
        time.sleep(OPEN_DURATION)
        print(f"[-] Fermeture du port {SSH_PORT} pour {ip}")
        subprocess.run([
            "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(SSH_PORT),
            "-s", ip, "-j", "ACCEPT"
        ], check=False)

    threading.Thread(target=close_later, daemon=True).start()

def process_packet(packet) -> None:
    """Callback executed for each sniffed packet."""
    if TCP not in packet or IP not in packet:
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport
    flags = int(packet[TCP].flags)

    # Only consider SYN packets to avoid counting resets
    if not (flags & 0x02):  # 0x02 = SYN flag
        return

    # Ignore packets that are not part of the knocking sequence
    if dst_port not in KNOCK_SEQUENCE:
        return

    index, last_time, last_port = knock_state.get(src_ip, (0, 0, -1))
    expected_port = KNOCK_SEQUENCE[index]

    # Ignore duplicate packets for the same port
    if dst_port == last_port:
        return

    print(f"[*] Knock reçu de {src_ip} sur le port {dst_port}")

    # Check if the received port is the expected one
    if dst_port != expected_port:
        reset_state(src_ip)
        return

    # Check timing between knocks
    now = time.time()
    if index > 0 and now - last_time > STEP_TIMEOUT:
        reset_state(src_ip)
        return

    # Update state
    index += 1
    knock_state[src_ip] = (index, now, dst_port)

    # Sequence complete?
    if index == len(KNOCK_SEQUENCE):
        print(f"[+] Séquence correcte pour {src_ip}")
        reset_state(src_ip)
        open_port_for(src_ip)


def main() -> None:
    print("Port knocking en écoute sur 7000 -> 8000 -> 9000")
    # Sniff TCP packets on the three ports. store=0 avoids storing packets in memory.
    sniff(
        filter="tcp and (dst port 7000 or dst port 8000 or dst port 9000)",
        prn=process_packet,
        store=0,
        iface="lo",  # Listen on loopback for local testing
    )


if __name__ == "__main__":
    main()
