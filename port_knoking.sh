#!/bin/bash

# Configuration
PORTS=(10001 10002 10003)         # Séquence de ports attendue
SSH_PORT=2222                     # Port à protéger
IP="127.0.0.1"                    # Adresse IP locale
DELAI_OUVERTURE=10                # Durée d'ouverture en secondes

clear
echo "===== Simulation du port-knocking en local ====="
echo "Adresse IP locale : $IP"
echo ""

# Étape 1 : On bloque le port SSH (2222)
echo "Fermeture du port SSH ($SSH_PORT)..."
iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null
iptables -A INPUT -p tcp --dport $SSH_PORT -j DROP
echo "Port $SSH_PORT bloqué."
echo ""

# Fonction pour envoyer une séquence de knocks
envoyer_knocks() {
    local sequence=("$@")
    for port in "${sequence[@]}"; do
        echo "=> Connexion simulée sur le port $port"
        nc -z $IP $port 2>/dev/null
        sleep 0.5
    done
}

# Fonction pour tester si le port SSH est ouvert
tester_port_ssh() {
    echo ""
    echo "Test de la connexion SSH sur le port $SSH_PORT..."
    if nc -zvw1 $IP $SSH_PORT 2>&1 | grep -q succeeded; then
        echo "✅ Port $SSH_PORT est OUVERT"
    else
        echo "❌ Port $SSH_PORT est FERMÉ"
    fi
    echo ""
}

# Étape 2 : Test avec MAUVAISE séquence
echo "Test avec une mauvaise séquence (ordre incorrect)..."
MAUVAISE_SEQ=("${PORTS[2]}" "${PORTS[1]}" "${PORTS[0]}")
envoyer_knocks "${MAUVAISE_SEQ[@]}"
tester_port_ssh

# Pause
sleep 2

# Étape 3 : Test avec la BONNE séquence
echo "Test avec la bonne séquence (ordre correct)..."
envoyer_knocks "${PORTS[@]}"

echo "Ouverture temporaire du port $SSH_PORT pour $DELAI_OUVERTURE secondes..."
iptables -I INPUT -p tcp --dport $SSH_PORT -s $IP -j ACCEPT

tester_port_ssh

# Attente puis fermeture du port
sleep $DELAI_OUVERTURE
echo "Fermeture automatique du port $SSH_PORT..."
iptables -D INPUT -p tcp --dport $SSH_PORT -s $IP -j ACCEPT
tester_port_ssh

echo "===== Fin du test ====="
