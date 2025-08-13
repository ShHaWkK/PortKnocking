#!/usr/bin/env bash
set -euo pipefail

# Détecte le gestionnaire
pm=""
if   command -v apt-get >/dev/null; then pm="apt"
elif command -v dnf >/dev/null;     then pm="dnf"
elif command -v pacman >/dev/null;  then pm="pacman"
elif command -v zypper >/dev/null;  then pm="zypper"
else echo "[!] Aucun gestionnaire pris en charge (apt/dnf/pacman/zypper)."; exit 1; fi

sudo=true
if [[ $EUID -eq 0 ]]; then sudo=""
fi

echo "[i] Gestionnaire: $pm"
case "$pm" in
  apt)
    $sudo apt-get update -y
    $sudo apt-get install -y python3 python3-pip python3-venv nftables openssh-server qrencode libpcap0.8 libpcap0.8-dev
    ;;
  dnf)
    $sudo dnf install -y python3 python3-pip nftables openssh-server qrencode libpcap libpcap-devel
    ;;
  pacman)
    $sudo pacman -Sy --noconfirm python python-pip nftables openssh qrencode libpcap
    ;;
  zypper)
    $sudo zypper --non-interactive install -y python3 python3-pip nftables openssh qrencode libpcap libpcap-devel
    ;;
esac

echo "[i] Pip deps (user): numpy scapy"
python3 -m pip install --user -q numpy scapy

echo "[✓] Dépendances installées."
