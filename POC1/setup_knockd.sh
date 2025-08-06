#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  Script : setup_knockd.sh
#  Purpose: Configure knockd so that a three-port sequence opens SSH on 2222
#           for thirty seconds. Intended for demonstrations and lab work.
#  Usage  : sudo ./setup_knockd.sh
#  Notes  : This script modifies /etc/knockd.conf and iptables rules.
#           Run it only on a test machine.
# ---------------------------------------------------------------------------

set -e                                          # Stop immediately on errors

if [[ $EUID -ne 0 ]]; then                      # Make sure we are root
    echo "[!] Run this script as root."       # Warn the user
    exit 1                                      # Abort if not root
fi

echo "[+] Installing knockd..."               # Install knockd package
apt-get update -y >/dev/null                    # Refresh package index
apt-get install -y knockd >/dev/null            # Install knockd silently

echo "[+] Writing /etc/knockd.conf..."        # Create knockd configuration
cat >/etc/knockd.conf <<'KNOCKEOF'               # Start here-document
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

echo "[+] Setting default firewall rule: DROP TCP 2222..."  # Block 2222 by default
iptables -D INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || true  # Remove old rule if any
iptables -I INPUT -p tcp --dport 2222 -j DROP                    # Insert new DROP rule

cleanup() {                                                      # Function to restore firewall
    echo "[+] Cleaning up: removing DROP rule on port 2222."  # Inform user during cleanup
    iptables -D INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || true  # Remove rule safely
}
trap cleanup EXIT                                                # Register cleanup for script exit

echo "[+] Restarting knockd service..."                        # Restart knockd
systemctl enable knockd >/dev/null                               # Ensure service starts at boot
systemctl restart knockd                                         # Restart service now

echo "[+] Checking that knockd is listening..."                # Verify knockd is running
sleep 1                                                          # Short pause
ss -lunpt | grep knockd || echo "[!] knockd not listening!"   # Display listening socket

echo "[+] Setup complete. Use the client to knock."            # Final message
