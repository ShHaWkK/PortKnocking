#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
autodeps.py — utilitaires d'auto-install "raisonnable" pour tes POC
- Installe les paquets Python manquants (pip).
- Vérifie/installe les binaires système selon le gestionnaire présent (apt/dnf/pacman/zypper).
- Comportement :
  * Si root => installe directement.
  * Si non-root => tente `sudo`, sinon affiche la commande claire à lancer.
- Écrit pour rester lisible le jour de la soutenance (pas de magie noire).
"""

import os, shutil, subprocess, sys

def _run(cmd, check=True, quiet=False):
    res = subprocess.run(cmd, text=True, capture_output=True)
    if not quiet and res.stdout.strip():
        print(res.stdout.rstrip())
    if check and res.returncode != 0:
        if res.stderr.strip():
            print(res.stderr.rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res

def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows/Cygwin: pas notre cible ici

def have_bin(name: str) -> bool:
    return shutil.which(name) is not None

def ensure_pip_packages(pkgs):
    missing = []
    for p in pkgs:
        try:
            __import__(p.split("==")[0].split(">=")[0].split("[")[0])
        except Exception:
            missing.append(p)
    if not missing:
        return True
    print(f"[autodeps] Install pip: {' '.join(missing)}")
    cmd = [sys.executable, "-m", "pip", "install", "-q"] + missing
    try:
        _run(cmd, check=True)
        return True
    except Exception as e:
        print(f"[autodeps] pip a échoué: {e}")
        return False

def _pm_and_cmd():
    # Détecte le gestionnaire et la/les commandes d’install
    if have_bin("apt") or have_bin("apt-get"):
        return "apt", [["apt-get","update","-y"], ["apt-get","install","-y"]]
    if have_bin("dnf"):
        return "dnf", [["dnf","install","-y"]]
    if have_bin("pacman"):
        return "pacman", [["pacman","-Sy","--noconfirm"]]
    if have_bin("zypper"):
        return "zypper", [["zypper","--non-interactive","install","-y"]]
    return None, []

def _sudo_wrap(cmd):
    if _is_root():
        return cmd
    return ["sudo"] + cmd

def ensure_system_packages(wanted_by_pm: dict) -> bool:
    """
    wanted_by_pm: { "apt": ["nftables","openssh-server","qrencode","libpcap0.8","libpcap0.8-dev"],
                    "dnf": ["nftables","openssh-server","qrencode","libpcap","libpcap-devel"],
                    "pacman": ["nftables","openssh","qrencode","libpcap"],
                    "zypper": ["nftables","openssh","qrencode","libpcap","libpcap-devel"] }
    """
    pm, installers = _pm_and_cmd()
    if pm is None:
        print("[autodeps] Aucun gestionnaire détecté (apt/dnf/pacman/zypper).")
        return False
    wanted = wanted_by_pm.get(pm, [])
    if not wanted:
        return True
    print(f"[autodeps] Vérification/installation système via {pm} : {' '.join(wanted)}")
    ok = True
    for i, base in enumerate(installers):
        # Première commande type "update" si présente, puis "install"
        cmd = _sudo_wrap(base + wanted if base[-1].endswith("install") or base[-1].endswith("--noconfirm") else base)
        try:
            _run(cmd, check=True)
        except Exception as e:
            if i == len(installers) - 1:
                print(f"[autodeps] Échec installation {pm}: {e}")
                ok = False
    return ok

def ensure_everything(pip_pkgs=None, sys_pkgs_by_pm=None) -> bool:
    pip_ok = ensure_pip_packages(pip_pkgs or [])
    sys_ok = ensure_system_packages(sys_pkgs_by_pm or {})
    return pip_ok and sys_ok
