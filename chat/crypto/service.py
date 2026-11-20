"""
Couche de liaison entre l'application et les modules cryptographiques.
======================================================================

Ce fichier est DÉJÀ ÉCRIT : il appelle les fonctions de aes.py, rsa.py et
hachage.py. Les étudiants n'ont normalement pas à le modifier, mais doivent
le LIRE pour comprendre comment leurs fonctions sont utilisées.

Algorithmes disponibles à l'envoi :
    AUCUN    : message stocké en clair
    AES      : chiffré avec la clé secrète partagée (settings.AES_CLE_HEX)
    RSA      : chiffré avec la clé publique du destinataire
    HYBRIDE  : une clé AES aléatoire chiffre le message, et cette clé AES
               est elle-même chiffrée en RSA avec la clé publique du destinataire
               (principe utilisé par TLS, PGP, S/MIME...)
"""

import os
from dataclasses import dataclass

from django.conf import settings

from . import aes, hachage, rsa


class CryptoNonImplemente(Exception):
    """Levée quand l'étudiant n'a pas encore écrit la fonction demandée."""


def cle_aes_partagee() -> bytes:
    return bytes.fromhex(settings.AES_CLE_HEX)


# --------------------------------------------------------------------------- #
#  ENVOI
# --------------------------------------------------------------------------- #
def preparer_message(texte: str, algorithme: str, destinataire) -> dict:
    """
    Transforme le texte saisi en champs à enregistrer dans le modèle Message.
    Renvoie un dict {contenu, cle_chiffree, empreinte}.
    """
    # 1) Empreinte du message EN CLAIR (intégrité)
    try:
        empreinte = hachage.calculer_empreinte(texte)
    except NotImplementedError:
        empreinte = ""  # le hachage n'est pas encore fait : on continue sans

    # 2) Chiffrement (confidentialité)
    cle_chiffree = ""
    try:
        if algorithme == "AUCUN":
            contenu = texte

        elif algorithme == "AES":
            contenu = aes.chiffrer(texte, cle_aes_partagee())

        elif algorithme == "RSA":
            cle_pub = _cle_publique(destinataire)
            contenu = rsa.chiffrer(texte.encode("utf-8"), cle_pub)

        elif algorithme == "HYBRIDE":
            cle_pub = _cle_publique(destinataire)
            cle_session = os.urandom(32)  # clé AES-256 à usage unique
            contenu = aes.chiffrer(texte, cle_session)
            cle_chiffree = rsa.chiffrer(cle_session, cle_pub)

        else:
            raise ValueError(f"Algorithme inconnu : {algorithme}")

    except NotImplementedError as e:
        raise CryptoNonImplemente(str(e)) from e

    return {"contenu": contenu, "cle_chiffree": cle_chiffree, "empreinte": empreinte}


# --------------------------------------------------------------------------- #
#  LECTURE
# --------------------------------------------------------------------------- #
@dataclass
class ResultatLecture:
    texte: str          # texte affiché à l'utilisateur
    dechiffre: bool     # le déchiffrement a-t-il réussi ?
    integrite: str      # "OK", "ALTÉRÉ", "NON VÉRIFIÉ"
    erreur: str = ""


def lire_message(message, lecteur) -> ResultatLecture:
    """Déchiffre un Message pour l'utilisateur `lecteur` et vérifie son intégrité."""
    algo = message.algorithme
    try:
        if algo == "AUCUN":
            texte = message.contenu
        elif algo == "AES":
            texte = aes.dechiffrer(message.contenu, cle_aes_partagee())
        elif algo == "RSA":
            texte = rsa.dechiffrer(message.contenu, _cle_privee(lecteur)).decode("utf-8")
        elif algo == "HYBRIDE":
            cle_session = rsa.dechiffrer(message.cle_chiffree, _cle_privee(lecteur))
            texte = aes.dechiffrer(message.contenu, cle_session)
        else:
            raise ValueError(f"Algorithme inconnu : {algo}")
    except NotImplementedError as e:
        return ResultatLecture(message.contenu, False, "NON VÉRIFIÉ", f"Non implémenté : {e}")
    except Exception as e:  # clé incorrecte, données corrompues, etc.
        return ResultatLecture(message.contenu, False, "NON VÉRIFIÉ",
                               f"Échec du déchiffrement ({type(e).__name__}) : {e}")

    # Vérification d'intégrité
    if not message.empreinte:
        integrite = "NON VÉRIFIÉ"
    else:
        try:
            integrite = "OK" if hachage.verifier_empreinte(texte, message.empreinte) else "ALTÉRÉ"
        except NotImplementedError:
            integrite = "NON VÉRIFIÉ"

    return ResultatLecture(texte, True, integrite)


# --------------------------------------------------------------------------- #
#  Gestion des clés RSA des utilisateurs
# --------------------------------------------------------------------------- #
def generer_cles_utilisateur(profil) -> None:
    prive, public = rsa.generer_paire_cles()
    profil.cle_privee = prive
    profil.cle_publique = public
    profil.save()


def _cle_publique(utilisateur) -> str:
    profil = utilisateur.profil
    if not profil.cle_publique:
        raise ValueError(f"{utilisateur.username} n'a pas encore de clé publique RSA "
                         "(il doit la générer depuis la page « Mes clés »).")
    return profil.cle_publique


def _cle_privee(utilisateur) -> str:
    profil = utilisateur.profil
    if not profil.cle_privee:
        raise ValueError("Vous n'avez pas de clé privée RSA.")
    return profil.cle_privee
