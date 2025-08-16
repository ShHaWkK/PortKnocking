#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# POC5 - Client (timing SYN -> SPA binaire AES-GCM)
import os, sys, time, hmac, hashlib, base64, random, socket, subprocess, shutil, argparse, getpass, traceback, struct
from typing import List
from scapy.all import IP, TCP, send  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

def LOG(t, **kw): print(f"[{t}]"+(" "+" ".join(f"{k}={v}" for k,v in kw.items()) if kw else ""), flush=True)
def _pip(*p): 
    try: subprocess.run([sys.executable,"-m","pip","install","-q",*p], check=True); return True
    except Exception: return False
def _apt(*p):
    if not shutil.which("apt"): return False
    try: subprocess.run(["sudo","apt","update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass
    try: subprocess.run(["sudo","apt","install","-y",*p], check=False); return True
    except Exception: return False
def ensure_pydeps():
    try: import scapy.all  # noqa
    except Exception: _pip("scapy") or _apt("python3-scapy")
    try: from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception: _pip("cryptography") or _apt("python3-cryptography")
def must_root():
    if os.geteuid()!=0: print("[ERREUR] Lance avec sudo.", file=sys.stderr); sys.exit(1)

LURE_PORT, SSH_PORT = 443, 2222
PREAMBULE = [1,0,1,0,1,0,1,0]
SECRET_FILE = os.path.expanduser("~/.config/portknock/secret")
LOCAL_SECRET = "/etc/portknock/secret"

def b64_read(s:str)->bytes:
    tok=s.strip().split()[0] if s.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def ensure_secret_for(server:str)->bytes:
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    if os.path.exists(SECRET_FILE):
        LOG("SECRET", source="~/.config/portknock/secret (cached)"); return b64_read(open(SECRET_FILE).read())
    if server in ("127.0.0.1","localhost"):
        raw=open(LOCAL_SECRET).read()
        with open(SECRET_FILE,"w") as f: f.write(raw.strip().split()[0]+"\n"); os.chmod(SECRET_FILE,0o600)
        LOG("SECRET", source=LOCAL_SECRET, copied_to=SECRET_FILE); return b64_read(raw)
    user=os.environ.get("SUDO_USER") or getpass.getuser()
    LOG("SECRET", action="fetch_via_ssh", user=user, host=server)
    r=subprocess.run(["ssh", f"{user}@{server}", "sudo cat /etc/portknock/secret"], text=True, capture_output=True)
    if r.returncode!=0 or not r.stdout.strip(): print("[ERREUR] secret via ssh", file=sys.stderr); sys.exit(1)
    open(SECRET_FILE,"w").write(r.stdout.strip().split()[0]+"\n"); os.chmod(SECRET_FILE,0o600)
    return b64_read(r.stdout)

def derive(master:bytes):
    return hashlib.sha256(master+b"|AES").digest(), hashlib.sha256(master+b"|HMAC").digest()

# wire v1-fixed = 51 bytes ; PT = t(4)|d(2)|H(16)
def build_wire(aes:bytes, mac:bytes, duration:int)->bytes:
    t=int(time.time()); d=int(duration)&0xFFFF
    head=struct.pack("!IH", t, d); sig=hmac.new(mac, head, hashlib.sha256).digest()[:16]
    pt=head+sig
    nonce=os.urandom(12); ctag=AESGCM(aes).encrypt(nonce, pt, None)
    return b"\x01"+nonce+ctag

def to_bits(b:bytes)->List[int]: return [int(bit) for byte in b for bit in f"{byte:08b}"]
def frame(msg:bytes)->List[int]:   return PREAMBULE + to_bits(msg)

def send_timing(bits:List[int], dst:str, d0:float, d1:float, iface:str|None):
    sport=random.randint(1024,65000); seq0=random.randint(0,2**32-1); n=len(bits); step=max(1,n//20)
    for i,b in enumerate(bits,1):
        send(IP(dst=dst)/TCP(dport=LURE_PORT, sport=sport, flags="S", seq=seq0+i), verbose=0, iface=iface)
        if i%step==0 or i==n: LOG("SEND", progress=f"{i}/{n}")
        time.sleep(d1 if b else d0)
    LOG("OK", sent=n)

def main():
    must_root(); ensure_pydeps()
    ap=argparse.ArgumentParser(description="POC5 client FAST (sudo python3 poc5_client_timing.py 127.0.0.1)")
    ap.add_argument("server")
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--d0", type=float, default=0.005)   # fast par défaut
    ap.add_argument("--d1", type=float, default=0.015)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--no-ssh", action="store_true")
    args=ap.parse_args()

    try: dst_ip=socket.gethostbyname(args.server)
    except Exception: print("[ERREUR] résolution serveur", file=sys.stderr); sys.exit(1)

    master=ensure_secret_for(args.server); aes,mac=derive(master)
    wire=build_wire(aes,mac,args.duration); bits=frame(wire)
    LOG("INFO", target=dst_ip, bytes=len(wire), bits=len(bits), d0=args.d0, d1=args.d1)
    send_timing(bits, dst_ip, args.d0, args.d1, iface=args.iface)

    if not args.no_ssh:
        ssh_user=os.environ.get("SUDO_USER") or getpass.getuser()
        time.sleep(0.7)
        os.execvp("ssh", ["ssh","-p","2222","-o","StrictHostKeyChecking=accept-new", f"{ssh_user}@{args.server}"])

if __name__=="__main__":
    try: main()
    except Exception:
        LOG("FATAL", trace=traceback.format_exc()); sys.exit(1)

