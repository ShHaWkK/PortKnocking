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
