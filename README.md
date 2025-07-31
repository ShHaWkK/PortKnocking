# PortKnocking

# Port Knocking Project

## Objectif
Conception et implémentation de mécanismes avancés de contrôle d’ouverture de port réseau (“port knocking”) avec trois POCs pertinents, testés et évalués :
1. **POC2** : Knock authentifié par HMAC + timestamp (anti-replay).  
2. **POC14** : Preuve de travail (Proof-of-Work) préalable au knock pour durcir contre les abus.  
3. **POC20** : Simulation et visualisation des attaques / défenses pour évaluer la robustesse.

## Organisation

## Configuration

Les paramètres sont centralisés dans config/.
- poc2_hmac.yaml : clé secrète, tolérance du timestamp, port de knock, port à ouvrir.
- poc14_pow.yaml : difficulté de preuve de travail, challenge, politique de rejet/temps d’attente.
- simulation.yaml : scénarios, nombres d’essais, délais entre attaques.