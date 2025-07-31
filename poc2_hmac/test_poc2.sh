#!/usr/bin/env bash
# test_poc2.sh — tests de base pour POC2 (HMAC knock)

CONFIG="../config/poc2_hmac.yaml"
SERVER="127.0.0.1"
SSH_PORT=22

function try_ssh() {
  timeout 2 bash -c "echo > /dev/tcp/$SERVER/$SSH_PORT" &>/dev/null
  return $?
}

echo "1) Sans knock : SSH doit être fermé"
if try_ssh; then
  echo "  [ERREUR] SSH accessible sans knock"
else
  echo "  [OK] SSH bloqué"
fi

echo "2) Knock valide"
python3 client_hmac.py --config "$CONFIG" --server "$SERVER"
sleep 1
if try_ssh; then
  echo "  [OK] SSH accessible après knock valide"
else
  echo "  [ERREUR] SSH toujours fermé après knock valide"
fi

echo "Attente de fermeture automatique..."
sleep 65  

echo "3) Vérification post-expiration : SSH doit être fermé à nouveau"
if try_ssh; then
  echo "  [ERREUR] SSH toujours ouvert après expiration"
else
  echo "  [OK] SSH fermé comme attendu"
fi

echo "4) Replay (renvoi du même knock) — devrait échouer à rouvrir"
python3 client_hmac.py --config "$CONFIG" --server "$SERVER"
sleep 1
if try_ssh; then
  echo "  [ERREUR] Replay a rouvert SSH (probablement bug)"
else
  echo "  [OK] Replay rejeté"
fi
