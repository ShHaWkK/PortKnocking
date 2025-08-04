#!/bin/bash

IP=$(hostname -I | awk '{print $1}')
PORT_KNOCK_SEQ=(10001 10002 10003)
SSH_PORT=2222
USER_TEST="kali"

echo "─── Simulation du port-knocking en local ───"
echo "Adresse IP locale : $IP"

#  S'assurer que le port SSH est bien fermé au début
echo -e "\\nFermeture du port SSH ($SSH_PORT)..."
iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null
iptables -A INPUT -p tcp --dport $SSH_PORT -j DROP
echo "Port $SSH_PORT bloqué."

# Test avec une séquence incorrecte
echo -e "\\nTest avec une mauvaise séquence (ordre incorrect)..."
for port in 10003 10002 10001; do
    echo "⇒ Connexion simulée sur le port $port"
    nc -z $IP $port 2>/dev/null
done

echo -e "\\nTest de la connexion SSH sur le port $SSH_PORT après mauvaise séquence..."
timeout 5 bash -c "cat < /dev/null > /dev/tcp/$IP/$SSH_PORT" 2>/dev/null && echo "✗ Port $SSH_PORT est OUVERT (ERREUR)" || echo "✓ Port $SSH_PORT est FERMÉ"

# Test avec la bonne séquence
echo -e "\\nTest avec la bonne séquence (ordre correct)..."
for port in "${PORT_KNOCK_SEQ[@]}"; do
    echo "⇒ Connexion simulée sur le port $port"
    nc -z $IP $port 2>/dev/null
done

echo "Ouverture temporaire du port $SSH_PORT pour 10 secondes..."
iptables -I INPUT -p tcp --dport $SSH_PORT -s $IP -j ACCEPT

# Tester la connexion SSH (réelle)
echo -e "\\nTest de la connexion SSH sur le port $SSH_PORT..."
timeout 5 bash -c "cat < /dev/null > /dev/tcp/$IP/$SSH_PORT" 2>/dev/null && echo "✓ Port $SSH_PORT est OUVERT" || echo "✗ Port $SSH_PORT est FERMÉ"

sleep 10
echo -e "\\nFermeture automatique du port $SSH_PORT..."
iptables -D INPUT -p tcp --dport $SSH_PORT -s $IP -j ACCEPT
echo "✓ Port $SSH_PORT est maintenant FERMÉ."

echo -e "\\n─── Fin du test ───"
