#!/usr/bin/env python3
"""
knock_client.py - simple client for the knockd proof of concept.

This script sends a predefined sequence of TCP connection attempts to a
remote host. If the server is configured with knockd, the sequence will
temporarily open the SSH service on port 2222. The script then checks the
port and reports whether the connection succeeded. It can also send the
reverse sequence to close the port again.

The code is intentionally verbose and heavily commented so it can be used
for demonstrations, lab reports or exam presentations.
"""

import argparse                      # Parse command-line arguments
import logging                       # Write events to a log file
import socket                        # Create TCP connection attempts
import sys                           # Provide access to stdout for fancy output
import time                          # Insert small pauses between knocks

# --------------------------- logging setup ---------------------------------
logger = logging.getLogger("knockd_demo")    # Name of the logger
logger.setLevel(logging.INFO)                # Log only informative messages
handler = logging.FileHandler("knockd_demo.log")  # Log file name
fmt = logging.Formatter("%(asctime)s %(message)s") # Timestamped format
handler.setFormatter(fmt)                    # Apply format to handler
logger.addHandler(handler)                   # Add handler to logger

# --------------------------- utility functions -----------------------------
def knock(host: str, port: int) -> None:
    """Send a single TCP SYN to the target host and port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Build TCP socket
    sock.settimeout(0.5)                # Do not wait too long for responses
    try:
        sock.connect((host, port))      # Attempt connection
    except Exception:
        pass                            # Ignore errors; knockd only needs the SYN
    finally:
        sock.close()                    # Always close the socket

def check_port(host: str, port: int) -> bool:
    """Return True if the TCP port appears open, False otherwise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Build TCP socket
    sock.settimeout(2)                 # Two-second timeout for the test
    result = sock.connect_ex((host, port))  # 0 means success
    sock.close()                       # Clean up
    return result == 0                 # Convert numeric code to boolean

# --------------------------- argument parsing ------------------------------
parser = argparse.ArgumentParser(description="Knock then test an SSH port")
parser.add_argument("--host", required=True, help="IP address of the server")
parser.add_argument("--port", type=int, default=2222, help="SSH port to verify")
parser.add_argument("--close", action="store_true", help="Send reverse sequence")
args = parser.parse_args()             # Read arguments into 'args'

OPEN_SEQ = [8881, 7777, 9991]          # Sequence to open the port
CLOSE_SEQ = [9991, 7777, 8881]         # Sequence to close the port

# ------------------------------ main routine -------------------------------
for p in OPEN_SEQ:                     # Iterate over the opening sequence
    sys.stdout.write(f"[>] Knocking {p}\n")  # Pretty output with no buffering
    sys.stdout.flush()                 # Force immediate display
    logger.info("knock %s", p)         # Log the knock
    knock(args.host, p)                # Fire the knock packet
    time.sleep(0.5)                    # Short pause between knocks

sys.stdout.write("[*] Waiting for the door to open...\n")
sys.stdout.flush()
time.sleep(3)                          # Allow knockd to open the port

if check_port(args.host, args.port):   # Test if the SSH port is open
    sys.stdout.write(f"[+] Port {args.port} is open!\n")
    logger.info("port %s open", args.port)
else:
    sys.stdout.write(f"[-] Port {args.port} is still closed.\n")
    logger.info("port %s closed", args.port)

if args.close:                         # Optionally send closing sequence
    sys.stdout.write("[*] Sending closing sequence...\n")
    sys.stdout.flush()
    for p in CLOSE_SEQ:                # Iterate over closing ports
        sys.stdout.write(f"[<] Knocking {p}\n")
        sys.stdout.flush()
        logger.info("close %s", p)     # Log the closing knock
        knock(args.host, p)            # Send knock
        time.sleep(0.5)

logger.info("done")                    # Log completion of the script
