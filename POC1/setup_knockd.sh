#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  Script : setup_knockd.sh
#  Purpose: Configure knockd so that a three-port sequence opens SSH on 2222
#           for thirty seconds. Intended for demonstrations and lab work.
#  Usage  : sudo ./setup_knockd.sh
#  Notes  : This script modifies /etc/knockd.conf and iptables rules.
#           Run it only on a test machine.
# ---------------------------------------------------------------------------

set -e                                       

if [[ $EUID -ne 0 ]]; then                    
    echo "[!] Run this script as root."     
    exit 1                                 
fi

echo "[+] Installing knockd..."               
apt-get update -y >/dev/null               
apt-get install -y knockd >/dev/null       
echo "[+] Writing /etc/knockd.conf..."     
cat >/etc/knockd.conf <<'KNOCKEOF'             
[options]
    UseSyslog

[openSSH]
    sequence      = 8881,7777,9991
    seq_timeout   = 5
    command       = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT
    cmd_timeout   = 30
    tcpflags      = syn

[closeSSH]
    sequence      = 9991,7777,8881
    seq_timeout   = 5
    command       = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 2222 -j ACCEPT
    tcpflags      = syn
KNOCKEOF

echo "[+] Setting default firewall rule: DROP TCP 2222..." 
iptables -D INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || true 
iptables -I INPUT -p tcp --dport 2222 -j DROP               

cleanup() {                                                    
    echo "[+] Cleaning up: removing DROP rule on port 2222." 
    iptables -D INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || true 
}
trap cleanup EXIT                                              

echo "[+] Restarting knockd service..."                 
systemctl enable knockd >/dev/null                        
systemctl restart knockd                        

echo "[+] Checking that knockd is listening..."            
sleep 1                                                
ss -lunpt | grep knockd || echo "[!] knockd not listening!" 
echo "[+] Setup complete. Use the client to knock."     
