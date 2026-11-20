"""
Module de HACHAGE des messages  —  À COMPLÉTER PAR L'ÉTUDIANT
==============================================================

Objectif : garantir l'INTÉGRITÉ des messages.
Lors de l'envoi, on calcule l'empreinte (hash) du message EN CLAIR et on la
stocke en base. Lors de la lecture, on recalcule l'empreinte du message
déchiffré et on la compare à celle stockée : si elles diffèrent, le message
a été altéré (en base, en transit, ou mal déchiffré).

Bibliothèque conseillée : hashlib (standard Python)
    https://docs.python.org/3/library/hashlib.html

Pour aller plus loin :
    - Comparer MD5, SHA-1, SHA-256, SHA-3 (taille de l'empreinte, sécurité)
    - Remplacer le hash simple par un HMAC (module hmac) : quelle différence ?
"""

import hashlib
import hmac

ALGORITHME = "sha256"


def calculer_empreinte(texte: str) -> str:
    """
    Calcule l'empreinte du texte et la renvoie en hexadécimal.

    Exemple attendu (SHA-256) :
        calculer_empreinte("bonjour")
        -> '2cb4b1431b84ec15d35ed83bb927e27e8967d75f4bcd9cc4b25c8d879ae23e18'

    Indices :
        - un hash s'applique sur des OCTETS : pensez à texte.encode("utf-8")
        - hashlib.sha256(...).hexdigest()
    """
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()


def verifier_empreinte(texte: str, empreinte: str) -> bool:
    """
    Renvoie True si l'empreinte du texte correspond à l'empreinte fournie.

    Indice : préférez hmac.compare_digest(a, b) à a == b (pourquoi ?)
    """
    calculee = hashlib.sha256(texte.encode("utf-8")).hexdigest()
    return hmac.compare_digest(calculee, empreinte)