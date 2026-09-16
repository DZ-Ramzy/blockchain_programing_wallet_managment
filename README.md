# TD02 — Wallet management (BIP 39 / BIP 32)

Programme Python en ligne de commande qui génère et importe une phrase mnémonique (BIP 39)
puis dérive les clés d'un wallet HD (BIP 32), sans librairie Bitcoin.

## Lancer le programme

Prérequis : Python 3.9+

```bash
python3 main.py
```

## Rapport

### Étape 1 — Programme interactif
Menu en boucle : générer une mnémonique, importer une mnémonique, dériver des clés BIP 32, quitter.
