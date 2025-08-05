#!/usr/bin/env python3
"""Simple port knocking client."""

import socket  # Used to create TCP connections
import sys  # Access to command-line arguments
import time  # Allows delays between knocks

# Default host to knock; can be overridden via CLI
DEFAULT_HOST = "127.0.0.1"
# Default sequence of ports to knock
DEFAULT_SEQUENCE = [7000, 8000, 9000]
# Delay between knocks in seconds
DEFAULT_DELAY = 0.5

def knock(host: str, sequence: list[int], delay: float) -> None:
    """Send a TCP connection attempt to each port in sequence."""
    for port in sequence:
        print(f"[*] Knock on port {port}")  # Log the knock
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # Create TCP socket
            s.settimeout(1)  # Short timeout; we don't expect a response
            try:
                s.connect((host, port))  # Attempt to connect
            except OSError:
                pass  # Ignore errors; the knock is sent regardless
        time.sleep(delay)  # Wait before next knock

def parse_args() -> tuple[str, list[int]]:
    """Parse host and port arguments from the command line."""
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    ports = [int(p) for p in sys.argv[2:]] if len(sys.argv) > 2 else DEFAULT_SEQUENCE
    return host, ports

def main() -> None:
    host, sequence = parse_args()  # Retrieve target and ports
    knock(host, sequence, DEFAULT_DELAY)  # Send knocks

if __name__ == "__main__":
    main()  # Execute only when run directly
