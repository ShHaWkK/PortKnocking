# PortKnocking

# Port Knocking Project

## Objectif
Conception et implémentation de mécanismes avancés de contrôle d’ouverture de port réseau (« port knocking ») avec six POCs pertinents, testés et évalués :

1. **UDP** : séquence de frappes UDP ouvrant temporairement un service TCP.
2. **POC2** : knock authentifié par HMAC + timestamp (anti-replay).
3. **SPA** : Single Packet Authorization contenant un secret partagé.
4. **POC14** : preuve de travail (Proof-of-Work) préalable au knock pour durcir contre les abus.
5. **POC30** : challenge-réponse signé RSA garantissant l’authenticité du client.
6. **POC31** : échange Diffie-Hellman X25519 suivi d’un HMAC pour valider le knock.

## Organisation

- `udp/` : démonstration de port-knocking basique via UDP.
- `poc2_hmac/` : implémentation HMAC + timestamp.
- `spa/` : exemple de Single Packet Authorization.
- `poc14_pow/` : port-knocking avec preuve de travail.
- `poc30_rsa/` : challenge-réponse avec signature RSA.
- `poc31_dh/` : échange Diffie-Hellman + HMAC.

## Configuration

Les paramètres sont centralisés dans `config/`.
- `poc2_hmac.yaml` : clé secrète, tolérance du timestamp, port de knock, port à ouvrir.
- `poc14_pow.yaml` : difficulté de preuve de travail, challenge, politique de rejet/temps d’attente.
- `poc30_rsa.yaml` : ports, durée d’ouverture, clés RSA et taille du challenge.
- `poc31_dh.yaml` : challenge partagé, ports et durée d’ouverture.
