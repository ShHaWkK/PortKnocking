#!/usr/bin/env bash
# Prépare l'environnement pour POC2 : ferme par défaut le port de service (SSH ici)
SERVICE_PORT=22

echo "[*] Mise en place : fermeture par défaut du port $SERVICE_PORT"
sudo iptables -I INPUT -p tcp --dport "$SERVICE_PORT" -j DROP

# Création dossiers
mkdir -p poc2_hmac/logs
echo "[*] OK"
