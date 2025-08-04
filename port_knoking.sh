#!/bin/bash

# Port-knocking simple local 
# Auteur : ShHawk
# Objectif : démonstration du mécanisme de port-knocking sans dépendances externes

# Paramètres du port-knocking
KNOCK_SEQ=(10001 10002 10003)   # Séquence à frapper
SSH_PORT=2222                   # Port protégé
LOGFILE="/tmp/iptables_knock.log"
IP=$(hostname -I | awk '{print $1}')   # Adresse IP de l'utilisateur

echo ""
echo "===== Simulation du port-knocking en local ====="
echo "Adresse IP locale : $IP"
echo ""

# Nettoyer les règles de pare-feu et fermer le port SSH
echo "Fermeture du port SSH ($SSH_PORT)..."
sudo iptables -F
sudo iptables -A INPUT -p tcp --dport $SSH_PORT -j DROP

# Activer la journalisation des knocks
echo "Activation de la surveillance via iptables (ports : ${KNOCK_SEQ[*]})..."
for port in "${KNOCK_SEQ[@]}"; do
    sudo iptables -A INPUT -p tcp --dport $port -j LOG --log-prefix "KNOCK_$port "
done

# Envoi de la séquence de knocks depuis le client (en local)
echo ""
echo "Envoi de la séquence de knocks dans le bon ordre..."
for port in "${KNOCK_SEQ[@]}"; do
    echo "↳ Connexion simulée sur le port $port"
    nc -z 127.0.0.1 $port
    sleep 0.5
done

# Attente pour laisser le temps à iptables de journaliser
sleep 1

# Analyse des logs récents pour détecter les knocks
echo ""
echo "Analyse des knocks reçus..."
sudo journalctl -n 100 | grep "KNOCK_" > "$LOGFILE"

ALL_OK=true
for port in "${KNOCK_SEQ[@]}"; do
    if grep -q "KNOCK_$port" "$LOGFILE"; then
        echo "Knock détecté sur le port $port"
    else
        echo "Knock manquant sur le port $port"
        ALL_OK=false
    fi
done

#  Vérification finale et ouverture du port si la séquence est correcte
if [ "$ALL_OK" = true ]; then
    echo ""
    echo "Séquence correcte. Ouverture temporaire du port $SSH_PORT pour l'adresse IP $IP..."
    sudo iptables -I INPUT -s $IP -p tcp --dport $SSH_PORT -j ACCEPT
    sleep 20
    echo "Fermeture du port $SSH_PORT..."
    sudo iptables -D INPUT -s $IP -p tcp --dport $SSH_PORT -j ACCEPT
else
    echo ""
    echo "Séquence incorrecte. Le port $SSH_PORT reste fermé."
fi

# Fin
echo ""
echo "Fin de la simulation."
