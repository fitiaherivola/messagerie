"""
Module de chiffrement SYMÉTRIQUE AES  —  À COMPLÉTER PAR L'ÉTUDIANT
===================================================================

Objectif : garantir la CONFIDENTIALITÉ des messages avec une clé secrète
partagée (settings.AES_CLE_HEX). Le même secret sert à chiffrer et à déchiffrer.

Bibliothèque conseillée : cryptography
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    https://cryptography.io/en/latest/hazmat/primitives/aead/

Format de sortie imposé (pour que le reste de l'application fonctionne) :
    chiffrer() renvoie une CHAÎNE base64 contenant  nonce (12 octets) + texte chiffré
    dechiffrer() prend cette chaîne et renvoie le texte en clair (str)

Questions à traiter dans le compte rendu :
    - Pourquoi faut-il un nonce/IV différent à chaque message ?
    - Que se passe-t-il si on utilise le mode ECB ? (essayez !)
    - Différence entre AES-CBC et AES-GCM (authentification) ?
    - Quel est le problème de stocker la clé dans settings.py ?
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def chiffrer(texte: str, cle: bytes) -> str:
    """
    Chiffre `texte` avec AES (clé de 16, 24 ou 32 octets).
    Renvoie une chaîne base64 :  base64( nonce || texte_chiffré ).

    Étapes :
        1. générer un nonce aléatoire de 12 octets (os.urandom)
        2. chiffrer texte.encode("utf-8") avec AESGCM(cle).encrypt(nonce, donnees, None)
        3. concaténer nonce + chiffré, encoder en base64, puis .decode("ascii")
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(cle)
    chiffre = aesgcm.encrypt(nonce, texte.encode("utf-8"), None)
    donnees = nonce + chiffre
    return base64.b64encode(donnees).decode("ascii")


def dechiffrer(donnees_b64: str, cle: bytes) -> str:
    """
    Opération inverse de chiffrer().

    Étapes :
        1. décoder la base64
        2. séparer les 12 premiers octets (nonce) du reste (chiffré)
        3. AESGCM(cle).decrypt(nonce, chiffre, None) puis .decode("utf-8")
    """
    donnees = base64.b64decode(donnees_b64)
    nonce = donnees[:12]
    chiffre = donnees[12:]
    aesgcm = AESGCM(cle)
    texte = aesgcm.decrypt(nonce, chiffre, None)
    return texte.decode("utf-8")