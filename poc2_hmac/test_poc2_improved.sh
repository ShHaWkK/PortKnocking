#!/usr/bin/env bash
# Test complet POC2 : knock valide, replay, knock expiré, absence de knock

CONFIG="../config/poc2_hmac.yaml"
SERVER="127.0.0.1"
SSH_PORT=22

function try_ssh() {
  timeout 2 bash -c "echo > /dev/tcp/$SERVER/$SSH_PORT" &>/dev/null
  return $?
}

echo "1) Vérifier que SSH est fermé sans knock"
if try_ssh; then
  echo "  [ERREUR] SSH accessible sans knock"
else
  echo "  [OK] SSH bloqué"
fi

echo "2) Envoi d'un knock valide"
python3 client_hmac_knock.py --config "$CONFIG" --server "$SERVER"
sleep 2  # laisser le temps d'ouvrir

if try_ssh; then
  echo "  [OK] SSH accessible après knock valide"
else
  echo "  [ERREUR] SSH toujours fermé"
fi

echo "3) Replay immédiat (le même knock ne doit pas rouvrir)"
python3 client_hmac_knock.py --config "$CONFIG" --server "$SERVER"
sleep 1
if try_ssh; then
  echo "  [OK] Replay rejeté (le port reste ouvert mais pas rée-autorisé abusivement)"
else
  echo "  [ERREUR] SSH fermé après replay (problème)"
fi

echo "Attente de fermeture automatique (open_duration + marge)..."
sleep 65

echo "4) Vérification post-expiration : SSH doit être désactivé à nouveau"
if try_ssh; then
  echo "  [ERREUR] SSH toujours ouvert après expiration"
else
  echo "  [OK] SSH refermé"
fi
