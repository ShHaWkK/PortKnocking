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

import argparse                      
import logging                      
import socket                       
import sys                          
import time                

# --------------------------- logging setup ---------------------------------
logger = logging.getLogger("knockd_demo")    
logger.setLevel(logging.INFO)              
handler = logging.FileHandler("knockd_demo.log")  
fmt = logging.Formatter("%(asctime)s %(message)s") 
handler.setFormatter(fmt)                   
logger.addHandler(handler)                  

# --------------------------- utility functions -----------------------------
def knock(host: str, port: int) -> None:
    """Send a single TCP SYN to the target host and port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    sock.settimeout(0.5)                
    try:
        sock.connect((host, port))     
    except Exception:
        pass                        
    finally:
        sock.close()              

def check_port(host: str, port: int) -> bool:
    """Return True if the TCP port appears open, False otherwise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sock.settimeout(2)               
    result = sock.connect_ex((host, port)) 
    sock.close()                  
    return result == 0             
# --------------------------- argument parsing ------------------------------
parser = argparse.ArgumentParser(description="Knock then test an SSH port")
parser.add_argument("--host", required=True, help="IP address of the server")
parser.add_argument("--port", type=int, default=2222, help="SSH port to verify")
parser.add_argument("--close", action="store_true", help="Send reverse sequence")
args = parser.parse_args()            
OPEN_SEQ = [8881, 7777, 9991]        
CLOSE_SEQ = [9991, 7777, 8881]        

# ------------------------------ main routine -------------------------------
for p in OPEN_SEQ:                     
    sys.stdout.write(f"[>] Knocking {p}\n")  
    sys.stdout.flush()               
    logger.info("knock %s", p)    
    knock(args.host, p)              
    time.sleep(0.5)                

sys.stdout.write("[*] Waiting for the door to open...\n")
sys.stdout.flush()
time.sleep(3)                         

if check_port(args.host, args.port):  
    sys.stdout.write(f"[+] Port {args.port} is open!\n")
    logger.info("port %s open", args.port)
else:
    sys.stdout.write(f"[-] Port {args.port} is still closed.\n")
    logger.info("port %s closed", args.port)

if args.close:                       
    sys.stdout.write("[*] Sending closing sequence...\n")
    sys.stdout.flush()
    for p in CLOSE_SEQ:              
        sys.stdout.write(f"[<] Knocking {p}\n")
        sys.stdout.flush()
        logger.info("close %s", p)    
        knock(args.host, p)           
        time.sleep(0.5)

logger.info("done")               
