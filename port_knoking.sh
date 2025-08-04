#!/bin/bash

# === Configuration ===
SSH_PORT=2222
KNOCK_PORTS=(10001 10002 10003)
IP=$(ip a show lo | grep inet | awk '{print $2}' | cut -d/ -f1)
DELAY_BETWEEN_KNOCKS=1
TEMP_OPEN_DURATION=10

clear
echo "===== Simulation du port-knocking en local ====="
echo "Adresse IP locale : $IP"
echo ""

# Fermeture du port SSH
echo "Fermeture du port SSH ($SSH_PORT)..."
iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null
iptables -A INPUT -p tcp --dport $SSH_PORT -j DROP
echo "Port $SSH_PORT bloqué."
sleep 1

# Simulation d'une mauvaise séquence
echo ""
echo "Test avec une mauvaise séquence (ordre incorrect)..."
WRONG_ORDER=("${KNOCK_PORTS[2]}" "${KNOCK_PORTS[1]}" "${KNOCK_PORTS[0]}")
for port in "${WRONG_ORDER[@]}"; do
    echo "=> Connexion simulée sur le port $port"
    nc -z 127.0.0.1 $port 2>/dev/null
    sleep $DELAY_BETWEEN_KNOCKS
done

# Vérification du port après mauvaise séquence
echo ""
echo "Test de la connexion SSH sur le port $SSH_PORT après mauvaise séquence..."
nc -z 127.0.0.1 $SSH_PORT && echo "Port ouvert (erreur)" || echo "Port toujours fermé (comportement attendu)"
sleep 2

# Nettoyage éventuel (redondant si déjà bloqué)
iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null

# Simulation de la bonne séquence
echo ""
echo "Test avec la bonne séquence : ${KNOCK_PORTS[*]}"
for port in "${KNOCK_PORTS[@]}"; do
    echo "=> Connexion simulée sur le port $port"
    nc -z 127.0.0.1 $port 2>/dev/null
    sleep $DELAY_BETWEEN_KNOCKS
done

# Ouverture temporaire du port SSH pour l'adresse IP locale
iptables -I INPUT -p tcp -s $IP --dport $SSH_PORT -j ACCEPT
echo "Séquence correcte. Port $SSH_PORT ouvert temporairement pour $IP."
echo "Connexion possible pendant $TEMP_OPEN_DURATION secondes..."
sleep $TEMP_OPEN_DURATION

# Fermeture du port à nouveau
iptables -D INPUT -p tcp -s $IP --dport $SSH_PORT -j ACCEPT
echo "Temps écoulé. Port $SSH_PORT à nouveau fermé."
