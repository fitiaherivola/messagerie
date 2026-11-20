"""
Module de chiffrement ASYMÉTRIQUE RSA  —  À COMPLÉTER PAR L'ÉTUDIANT
====================================================================

Objectif : chaque utilisateur possède une paire de clés (publique / privée).
L'expéditeur chiffre avec la clé PUBLIQUE du destinataire ; seul le
destinataire, avec sa clé PRIVÉE, peut déchiffrer.

Bibliothèque conseillée : cryptography
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

Format imposé :
    - les clés circulent au format PEM (str)
    - chiffrer() renvoie une chaîne base64, dechiffrer() renvoie du texte (str)
    - remplissage : OAEP avec SHA-256 (MGF1 SHA-256)

Questions à traiter dans le compte rendu :
    - Quelle est la taille maximale d'un message chiffrable avec RSA-2048 + OAEP ?
      (testez avec un long message !)
    - Pourquoi n'utilise-t-on pas RSA « nu » (sans padding) ?
    - Comment combiner RSA et AES pour chiffrer un message de taille quelconque ?
      -> voir le mode HYBRIDE dans chat/crypto/service.py
"""

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generer_paire_cles(taille: int = 2048) -> tuple[str, str]:
    """
    Génère une paire de clés RSA et renvoie (cle_privee_pem, cle_publique_pem).

    Indices :
        - rsa.generate_private_key(public_exponent=65537, key_size=taille)
        - cle_privee.private_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.PKCS8,
              encryption_algorithm=serialization.NoEncryption())
        - cle_privee.public_key().public_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo)
        - .decode("ascii") pour obtenir des str
    """
    cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=taille)
    priv_pem = cle_privee.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = cle_privee.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def chiffrer(donnees: bytes, cle_publique_pem: str) -> str:
    """
    Chiffre des OCTETS avec la clé publique (OAEP/SHA-256), renvoie du base64 (str).

    Remarque : on travaille sur des bytes (et non du str) pour pouvoir
    chiffrer aussi bien un texte (texte.encode()) qu'une clé AES (mode hybride).

    Indice : serialization.load_pem_public_key(cle_publique_pem.encode())
    """
    cle_publique = serialization.load_pem_public_key(cle_publique_pem.encode())
    chiffre = cle_publique.encrypt(
        donnees,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(chiffre).decode("ascii")


def dechiffrer(donnees_b64: str, cle_privee_pem: str) -> bytes:
    """
    Déchiffre avec la clé privée et renvoie les OCTETS en clair.

    Indice : serialization.load_pem_private_key(cle_privee_pem.encode(), password=None)
    """
    from cryptography.hazmat.primitives import hashes

    from cryptography.hazmat.primitives import hashes

    cle_privee = serialization.load_pem_private_key(cle_privee_pem.encode(), password=None)
    chiffre = base64.b64decode(donnees_b64)
    texte = cle_privee.decrypt(
        chiffre,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return texte