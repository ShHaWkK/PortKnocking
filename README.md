# Proof-of-Concept Port Knocking

## Objectif
Ce projet démontre un mécanisme minimal de port knocking en Python.
Un serveur n'ouvre un port sensible qu'après réception d'une séquence
spécifique de paquets TCP SYN.

## Principe de fonctionnement

```
client --> knock 7000 --> knock 8000 --> knock 9000 --> serveur
                                           |
                                           v
                                  iptables ouvre le port 2222
```

Le client envoie une série de requêtes TCP SYN sur des ports prédéfinis.
Si la séquence est correcte, le serveur ajoute temporairement une règle
`iptables` permettant la connexion sur le port protégé.

## Prérequis

- Python ≥ 3.7
- [Scapy](https://scapy.net)
- Droits root (pour sniffer et modifier iptables)

## Installation

```bash
pip3 install scapy
```

## Tests POC5

```bash
# auto-test du décodage
sudo python3 poc5/poc5_server_timing.py --selftest

# client sans émission (aperçu des bits)
sudo python3 poc5/poc5_client_timing.py 127.0.0.1 --dry-run

# boucle locale
sudo python3 poc5/poc5_server_timing.py --iface lo &
sudo python3 poc5/poc5_client_timing.py 127.0.0.1
```

