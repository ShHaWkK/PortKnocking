#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POC5 — Serveur covert channel + SPA AES-GCM + nftables + sshd
Canaux décodés :
  - win    : nibbles via TCP.window (par défaut, fiable sur lo)
  - timing : inter-arrival timings (héritage POC5)
"""

import os, sys, time, json, hmac, hashlib, base64, shutil, signal, subprocess, getpass, pwd, struct, threading, traceback
from datetime import datetime
from statistics import median

try: sys.stdout.reconfigure(line_buffering=True)
except Exception: pass

def LOG(tag, **kw):
    s = " ".join(f"{k}={v}" for k,v in kw.items()); print(f"[{tag}]{(' '+s) if s else ''}", flush=True)

# ---- Constantes
LURE_PORT, SSH_PORT = 443, 2222
# timing
PREAMBULE = [1,0,1,0,1,0,1,0]
WIRE_LEN_FIXED, WIRE_LEN_LEGACY = 51, 53
BITS_FIXED = len(PREAMBULE) + 8*WIRE_LEN_FIXED
# window
WIN_BASE = 4096
WIN_PREAMBLE = [0xC, 0xA, 0xF, 0xE]  # "CAFE"
DEDUP_WINDOW = 0.050  # 50 ms (loopback)
ANTI_REPLAY_S, OPEN_TTL_S = 90, 60

LOG_PATH = "/var/log/portknock/poc5_server.jsonl"
NFT_TABLE, NFT_CHAIN_INPUT, NFT_SET_ALLOWED = "knock5", "inbound", "allowed"
MASTER_SECRET_PATH = "/etc/portknock/secret"
USER_COPY_FMT = "{home}/.config/portknock/{name}"

# ---- État
arrivees, derniers, ips_autorisees = {}, {}, {}
win_state = {}  # ip -> {stage, buf, need, nibbles}
_recent = {}    # dédup (sport, seq) -> last_time
stop_evt = threading.Event()
_sshd = None

# ---------- utils install ----------
def _run(*cmd): return subprocess.run(list(cmd), text=True, capture_output=True)
def _pip(*p):
    try: subprocess.run([sys.executable,"-m","pip","install","-q",*p], check=True); return True
    except Exception: return False
def _apt(*p):
    if not shutil.which("apt"): return False
    try: subprocess.run(["sudo","apt","update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass
    try: subprocess.run(["sudo","apt","install","-y",*p], check=False); return True
    except Exception: return False
def _dnf(*p):
    if not shutil.which("dnf"): return False
    try: subprocess.run(["sudo","dnf","install","-y",*p], check=False); return True
    except Exception: return False
def _pacman(*p):
    if not shutil.which("pacman"): return False
    try: subprocess.run(["sudo","pacman","-Sy","--noconfirm",*p], check=False); return True
    except Exception: return False

def ensure_pydeps():
    try: from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except Exception:
        _pip("cryptography") or _apt("python3-cryptography") or _dnf("python3-cryptography") or _pacman("python-cryptography")
    try: import scapy.all  # noqa
    except Exception:
        _pip("scapy") or _apt("python3-scapy") or _dnf("python3-scapy") or _pacman("python-scapy")

def ensure_sysbins():
    miss=[]
    if not shutil.which("nft"): miss.append("nftables")
    if not os.path.exists("/usr/sbin/sshd"): miss.append("openssh-server")
    if miss: _apt(*miss) or _dnf(*miss) or _pacman(*miss)

def must_root():
    if os.geteuid()!=0: print("[ERREUR] Lancer avec sudo.", file=sys.stderr); sys.exit(1)

# ---------- secrets ----------
def b64_read(raw:str)->bytes:
    tok = raw.strip().split()[0] if raw.strip() else ""
    try: return base64.b64decode(tok, validate=True)
    except Exception: return base64.b64decode(tok)

def load_or_create_master_secret()->bytes:
    os.makedirs(os.path.dirname(MASTER_SECRET_PATH), exist_ok=True)
    if not os.path.exists(MASTER_SECRET_PATH):
        raw=os.urandom(32); open(MASTER_SECRET_PATH,"w").write(base64.b64encode(raw).decode()+"\n")
        os.chmod(MASTER_SECRET_PATH,0o600); LOG("READY", secret=MASTER_SECRET_PATH, created=1)
    else:
        LOG("READY", secret=MASTER_SECRET_PATH, created=0)
    sec=b64_read(open(MASTER_SECRET_PATH).read())
    if len(sec)<16: print("[ERREUR] Secret trop court.", file=sys.stderr); sys.exit(1)
    return sec

def copy_secret_for_user(name:str, content:str):
    sudo_user=os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pw=pwd.getpwnam(sudo_user); home,uid,gid=pw.pw_dir,pw.pw_uid,pw.pw_gid
    except Exception:
        home,uid,gid=os.path.expanduser("~"),None,None
    dst=USER_COPY_FMT.format(home=home, name=name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst,"w").write(content.strip()+"\n"); os.chmod(dst,0o600)
    if uid is not None: os.chown(dst,uid,gid)
    LOG("READY", copy_secret=dst)

# ---------- firewall / nft / sshd ----------
def firewall_open_if_needed():
    if shutil.which("ufw"):
        st=_run("bash","-lc","ufw status | grep -i active || true").stdout
        if "active" in (st or "").lower():
            _run("bash","-lc",f"ufw allow {LURE_PORT}/tcp || true")
            _run("bash","-lc",f"ufw allow {SSH_PORT}/tcp || true")
            LOG("UFW", opened=f"{LURE_PORT},{SSH_PORT}")
    if shutil.which("firewall-cmd"):
        st=_run("firewall-cmd","--state").stdout.strip()
        if st=="running":
            _run("firewall-cmd","--add-port",f"{LURE_PORT}/tcp","--permanent")
            _run("firewall-cmd","--add-port",f"{SSH_PORT}/tcp","--permanent")
            _run("firewall-cmd","--reload"); LOG("FIREWALLD", opened=f"{LURE_PORT},{SSH_PORT}")

def nft_delete_table():
    _run("bash","-lc",f"nft list table inet {NFT_TABLE} >/dev/null 2>&1 && nft delete table inet {NFT_TABLE} || true")

def nft_install_base(ttl:int):
    nft_delete_table()
    conf=f"""
add table inet {NFT_TABLE}
add set   inet {NFT_TABLE} {NFT_SET_ALLOWED} {{ type ipv4_addr; flags timeout; timeout {ttl}s; }}
add chain inet {NFT_TABLE} {NFT_CHAIN_INPUT} {{ type filter hook input priority -150; policy accept; }}
add rule  inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} ip saddr @{NFT_SET_ALLOWED} accept
add rule  inet {NFT_TABLE} {NFT_CHAIN_INPUT} tcp dport {SSH_PORT} drop
"""
    tmp="/tmp/poc5_nft.nft"; open(tmp,"w").write(conf)
    subprocess.run(["nft","-f",tmp], check=False)
    LOG("NFT", table=NFT_TABLE, chain=NFT_CHAIN_INPUT, set=NFT_SET_ALLOWED)

def nft_add_allowed(ip:str, ttl:int):
    _run("bash","-lc",f"nft add element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} timeout {ttl}s }}'")
    ips_autorisees[ip]=time.monotonic()+ttl
    LOG("OPEN", ip=ip, ttl=f"{ttl}s"); jlog("open", ip=ip, ttl=ttl)

def nft_gc():
    now=time.monotonic()
    for ip,exp in list(ips_autorisees.items()):
        if now>exp:
            _run("bash","-lc",f"nft delete element inet {NFT_TABLE} {NFT_SET_ALLOWED} '{{ {ip} }}'")
            ips_autorisees.pop(ip,None)
            LOG("CLOSE", ip=ip); jlog("close", ip=ip)

def ensure_host_keys(): _run("bash","-lc","test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A")
def start_sshd():
    global _sshd
    cfg=f"Port {SSH_PORT}\nListenAddress 0.0.0.0\nUsePAM yes\nPasswordAuthentication yes\nPidFile /tmp/poc5_sshd.pid\nLogLevel QUIET\n"
    path="/tmp/poc5_sshd_config"; open(path,"w").write(cfg)
    _sshd=subprocess.Popen(["/usr/sbin/sshd","-f",path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    LOG("SSHD", listen=f"0.0.0.0:{SSH_PORT}")
def stop_sshd():
    global _sshd
    if _sshd and _sshd.poll() is None:
        _sshd.terminate()
        try:_sshd.wait(2)
        except: _sshd.kill()
        LOG("SSHD", status="stopped")

# ---------- logs ----------
def jlog(event, **fields):
    row={"ts":datetime.utcnow().isoformat()+"Z","event":event}; row.update(fields)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH,"a") as f: f.write(json.dumps(row, ensure_ascii=False)+"\n")
    except Exception: pass

# ---------- helpers seuil / corrélation ----------
def _bits_to_bytes(bits):
    if len(bits)%8: return b""
    out=bytearray()
    for i in range(0,len(bits),8):
        out.append(int("".join(map(str,bits[i:i+8])),2))
    return bytes(out)

def derive_threshold_from_preamble(w):
    hi=[w[i] for i,b in enumerate(PREAMBULE) if b==1]
    lo=[w[i] for i,b in enumerate(PREAMBULE) if b==0]
    if not hi or not lo: m=median(w); return m,m,m,0.0
    mhi,mlo=median(hi),median(lo)
    if mhi<mlo: mhi,mlo=mlo,mhi
    thr=(mhi+mlo)/2.0; return thr,mhi,mlo,abs(mhi-mlo)

def classify_with_threshold(d, thr): return [1 if x>thr else 0 for x in d]

def find_candidates_corr(deltas, max_k=32):
    t=[1,-1,1,-1,1,-1,1,-1]; res=[]; n=len(deltas)
    if n<8: return []
    for i in range(0,n-8):
        w=deltas[i:i+8]; mu=sum(w)/8.0
        score=sum((w[j]-mu)*t[j] for j in range(8)); amp=max(w)-min(w)
        res.append((score*amp,i,amp,score))
    res.sort(key=lambda x:x[0], reverse=True)
    med=median(deltas) if deltas else 0.01; min_amp=max(0.002,0.05*med)
    return [i for _,i,amp,_ in res[:max_k] if amp>min_amp]

# ---------- SPA decrypt ----------
def spa_parse_wire(wire: bytes, aes_key: bytes, hmac_key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        if len(wire) < 1+12+16: return None
        if wire[0] != 0x01:     return None
        nonce = wire[1:13]
        if len(wire) == WIRE_LEN_FIXED:
            ctag = wire[13:]
        elif len(wire) >= WIRE_LEN_LEGACY:
            clen = struct.unpack("!H", wire[13:15])[0]
            ctag = wire[15:15+clen]
        else:
            return None
        pt = AESGCM(aes_key).decrypt(nonce, ctag, None)  # 22B: t(4)|d(2)|mac16
        if len(pt) != 22: return None
        t, d = struct.unpack("!IH", pt[:6]); sig = pt[6:22]
        exp = hmac.new(hmac_key, pt[:6], hashlib.sha256).digest()[:16]
        if sig != exp: return None
        if abs(int(time.time()) - int(t)) > ANTI_REPLAY_S: return None
        return {"timestamp": int(t), "duration": int(d)}
    except Exception:
        return None

# ---------- Canal "win": state-machine ----------
def win_reset(ip):
    win_state[ip]={"stage":"seek","buf":[],"need":0,"nibbles":[]}

def win_push_nibble(ip, nib, aes_key, hmac_key):
    st = win_state.setdefault(ip, {"stage":"seek","buf":[],"need":0,"nibbles":[]})
    if st["stage"]=="seek":
        st["buf"].append(nib)
        if len(st["buf"])>4: st["buf"].pop(0)
        if st["buf"]==WIN_PREAMBLE:
            st["stage"]="len"; st["nibbles"].clear()
    elif st["stage"]=="len":
        st["nibbles"].append(nib)
        if len(st["nibbles"])>=4:
            L=((st["nibbles"][0]<<12)|(st["nibbles"][1]<<8)|(st["nibbles"][2]<<4)|st["nibbles"][3])
            L=min(max(1,L),1024)  # borne de sécurité
            st["need"]=L*2; st["nibbles"].clear(); st["stage"]="data"
    elif st["stage"]=="data":
        st["nibbles"].append(nib)
        if st["need"] and len(st["nibbles"])>=st["need"]:
            b=bytearray()
            for i in range(0,st["need"],2): b.append((st["nibbles"][i]<<4)|st["nibbles"][i+1])
            st["nibbles"].clear(); st["need"]=0; st["stage"]="seek"; st["buf"].clear()
            spa=spa_parse_wire(bytes(b), aes_key, hmac_key)
            if spa:
                ttl=int(spa.get("duration", OPEN_TTL_S)) or OPEN_TTL_S
                nft_add_allowed(ip, ttl)
                return True
    return False

# ---------- Canal "timing" ----------
def try_decode_timing_for_ip(src_ip, deltas, aes_key, hmac_key):
    if len(deltas) < len(PREAMBULE)+8: return False
    cands=find_candidates_corr(deltas)
    if not cands:
        if len(deltas)>2000: deltas[:]=deltas[-1000:]
        return False
    for idx in cands:
        if idx+len(PREAMBULE)>len(deltas): continue
        pre=deltas[idx:idx+len(PREAMBULE)]
        thr,hi,lo,diff=derive_threshold_from_preamble(pre)
        if max(hi,lo) and diff<0.2*max(hi,lo): continue
        need=len(PREAMBULE)+8*WIRE_LEN_FIXED
        if len(deltas)-idx>=need:
            seg=deltas[idx:idx+need]; bits=classify_with_threshold(seg,thr)
            data=_bits_to_bytes(bits[len(PREAMBULE):])
            if data and data[0]==0x01:
                LOG("CAND", ip=src_ip, head=data[:4].hex(), thr=f"{thr:.5f}")
                spa=spa_parse_wire(data, aes_key, hmac_key)
                if spa:
                    deltas.clear(); ttl=int(spa.get("duration", OPEN_TTL_S)) or OPEN_TTL_S
                    nft_add_allowed(src_ip, ttl); return True
        after=classify_with_threshold(deltas[idx+len(PREAMBULE):],thr)
        if len(after)>=16:
            L=int("".join(map(str,after[:16])),2); need=len(PREAMBULE)+16+8*L
            if len(deltas)-idx>=need:
                seg=deltas[idx:idx+need]; bits=classify_with_threshold(seg,thr)
                msg=_bits_to_bytes(bits[len(PREAMBULE)+16:])
                if msg and msg[0]==0x01:
                    LOG("CAND", ip=src_ip, head=msg[:4].hex(), thr=f"{thr:.5f}")
                    spa=spa_parse_wire(msg, aes_key, hmac_key)
                    if spa:
                        deltas.clear(); ttl=int(spa.get("duration", OPEN_TTL_S)) or OPEN_TTL_S
                        nft_add_allowed(src_ip, ttl); return True
    if len(deltas)>2*BITS_FIXED: deltas[:]=deltas[-BITS_FIXED:]
    return False

# ---------- sniff ----------
def pick_ifaces(user_value):
    if user_value: return [i.strip() for i in user_value.split(",") if i.strip()]
    try:
        from scapy.all import get_if_list  # type: ignore
        ifs=set(get_if_list())
    except Exception:
        ifs=set()
    chosen=[]
    if 'lo' in ifs: chosen.append('lo')
    r=_run("bash","-lc","ip route show default | awk '{print $5}' | head -n1")
    dev=(r.stdout or "").strip()
    if dev: chosen.append(dev)
    for cand in ("eth0","ens3","enp0s3","en0"):
        if cand in ifs and cand not in chosen: chosen.append(cand)
    return list(dict.fromkeys(chosen)) or ['lo']

def start_sniffer_thread(iface, aes_key, hmac_key):
    from scapy.all import sniff, TCP, IP  # type: ignore
    LOG("LISTEN", mode="scapy", iface=iface, bpf=f"tcp[13] & 0x12 == 0x02 and dst port {LURE_PORT}")
    def _prn(p):
        try:
            if not p.haslayer(TCP) or not p.haslayer(IP): return
            if p[TCP].dport != LURE_PORT: return
            f=int(p[TCP].flags)
            if (f & 0x02)==0 or (f & 0x10)!=0: return  # SYN sans ACK
            src=p[IP].src
            now=float(p.time)

            # dédup loopback (même sport+seq vu deux fois proche)
            sig=(p[TCP].sport, int(p[TCP].seq))
            last=_recent.get(sig); _recent[sig]=now
            if last is not None and (now-last)<DEDUP_WINDOW: return
            if len(_recent)>5000:
                for k,t0 in list(_recent.items()):
                    if now-t0>2.0: _recent.pop(k,None)

            # Canal timing (stocke deltas quoi qu'il arrive)
            last_t=derniers.get(src); derniers[src]=now
            if last_t is None:
                arrivees.setdefault(src, []); win_reset(src); LOG("PKT", ip=src, first=1); return
            lst=arrivees.setdefault(src, []); lst.append(now-last_t)
            if len(lst)%50==0: LOG("PKT", ip=src, count=len(lst))
            try: try_decode_timing_for_ip(src, lst, aes_key, hmac_key)
            except Exception as e: LOG("DECODE_ERR_TIMING", err=str(e))

            # Canal window : accepte [4096..4111], sinon fallback w&0xF (utile VM)
            w=int(p[TCP].window)
            nib = (w - WIN_BASE) if (WIN_BASE <= w <= WIN_BASE+15) else (w & 0xF)
            if 0 <= nib <= 15:
                try:
                    if win_push_nibble(src, nib, aes_key, hmac_key): pass
                except Exception as e:
                    LOG("DECODE_ERR_WIN", err=str(e)); win_reset(src)

            if len(lst)>4096: arrivees[src]=lst[-1024:]
            nft_gc()
        except Exception as e:
            LOG("SCAPY_CB_ERROR", err=str(e))
    t=threading.Thread(target=lambda: sniff(
            iface=iface,
            filter=f"tcp[13] & 0x12 == 0x02 and dst port {LURE_PORT}",
            prn=_prn, store=False,
            stop_filter=lambda p: stop_evt.is_set()),
        daemon=True)
    t.start(); return t

# ---------- cleanup ----------
def cleanup():
    try: nft_delete_table()
    except Exception: pass
    try: stop_sshd()
    except Exception: pass
    LOG("CLEANUP"); jlog("server_stop")

# ---------- main ----------
def main():
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="Interfaces à sniffer (ex: 'lo' ou 'lo,eth0')")
    args=ap.parse_args()

    LOG("BOOT", text="starting"); must_root(); ensure_pydeps(); ensure_sysbins(); firewall_open_if_needed()

    master=load_or_create_master_secret()
    aes_key=hashlib.sha256(master+b"|AES").digest()
    hmac_key=hashlib.sha256(master+b"|HMAC").digest()
    copy_secret_for_user("secret", base64.b64encode(master).decode())

    ttl=OPEN_TTL_S if OPEN_TTL_S>0 else 24*3600
    nft_install_base(ttl); ensure_host_keys(); start_sshd()
    LOG("READY", server="up", log=LOG_PATH)

    for iface in pick_ifaces(args.iface):
        start_sniffer_thread(iface, aes_key, hmac_key)

    def _sig(_s,_f): stop_evt.set()
    signal.signal(signal.SIGINT,_sig); signal.signal(signal.SIGTERM,_sig)

    try:
        while not stop_evt.is_set(): time.sleep(0.5)
    finally:
        cleanup()

if __name__=="__main__":
    try: main()
    except Exception:
        LOG("FATAL", trace=traceback.format_exc()); cleanup(); sys.exit(1)
