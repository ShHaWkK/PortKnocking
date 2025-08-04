#!/bin/bash

# 1. Configuration
KNOCK_SEQ=(10001 10002 10003)
SSH_PORT=2222
INTERFACE=lo
KNOCK_LOG="/tmp/knock.log"
TIMEOUT=30

echo "═══ Simulation du port-knocking en local ═══"

# 2. Fermer le port 2222 (au cas où)
sudo iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null
echo "═══ Fermeture du port SSH ($SSH_PORT)..."

# 3. Lancer tcpdump pour capter les knocks
echo "═══ Lancement de l'écoute réseau avec tcpdump (10 sec)..."
sudo timeout 10 tcpdump -i $INTERFACE "port ${KNOCK_SEQ[0]} or port ${KNOCK_SEQ[1]} or port ${KNOCK_SEQ[2]}" -nn > "$KNOCK_LOG" 2>/dev/null &

# 4. Attente courte avant knock
sleep 2

# 5. Simuler les knocks avec netcat (client)
echo "═══ Envoi de la séquence de knocks depuis le client... ═══"
for port in "${KNOCK_SEQ[@]}"; do
    nc -z 127.0.0.1 $port
    echo "  ↳ Knock sur le port $port"
    sleep 1
done

# 6. Attente fin de tcpdump
sleep 3

# 7. Analyse du log
echo "═══ Analyse des knocks reçus... ═══"
COUNT=0
for port in "${KNOCK_SEQ[@]}"; do
    if grep "$port" "$KNOCK_LOG" >/dev/null; then
        echo "=== Knock détecté sur $port ==="
        ((COUNT++))
    else
        echo "  [X] Knock manquant sur $port"
    fi
done

# 8. Vérification séquence complète
if [ "$COUNT" -eq "${#KNOCK_SEQ[@]}" ]; then
    echo " === Séquence correcte. Ouverture temporaire du port $SSH_PORT (30 sec)... ==="
    sudo iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT

    echo "Port $SSH_PORT ouvert pour 30 secondes..."
    sleep $TIMEOUT

    echo "Fermeture du port $SSH_PORT après timeout."
    sudo iptables -D INPUT -p tcp --dport $SSH_PORT -j ACCEPT
else
    echo "[X] Séquence incorrecte. Port $SSH_PORT reste fermé."
fi

# 9. Nettoyage
rm -f "$KNOCK_LOG"
