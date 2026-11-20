"""
Tests automatiques de la partie cryptographique.

Lancer :   python manage.py test chat
Un test « skipped » signifie que la fonction n'est pas encore implémentée.
Objectif du TP : 0 échec, 0 skip.
"""
import os

from django.contrib.auth.models import User
from django.test import TestCase

from .crypto import aes, hachage, rsa, service
from .models import Message


def _requiert(fonction, *args):
    """Appelle la fonction ; si elle n'est pas implémentée, on saute le test."""
    try:
        return fonction(*args)
    except NotImplementedError as e:
        raise __import__("unittest").SkipTest(str(e))


class TestHachage(TestCase):
    def test_valeur_connue_sha256(self):
        self.assertEqual(
            _requiert(hachage.calculer_empreinte, "bonjour"),
            "2cb4b1431b84ec15d35ed83bb927e27e8967d75f4bcd9cc4b25c8d879ae23e18")

    def test_verification(self):
        e = _requiert(hachage.calculer_empreinte, "Salut ESTI")
        self.assertTrue(_requiert(hachage.verifier_empreinte, "Salut ESTI", e))
        self.assertFalse(_requiert(hachage.verifier_empreinte, "Salut ESTi", e))

    def test_accents(self):
        e = _requiert(hachage.calculer_empreinte, "Élève à l'école")
        self.assertEqual(len(e), 64)


class TestAES(TestCase):
    cle = os.urandom(32)

    def test_aller_retour(self):
        c = _requiert(aes.chiffrer, "Message secret é à ç", self.cle)
        self.assertIsInstance(c, str)
        self.assertNotIn("secret", c)
        self.assertEqual(_requiert(aes.dechiffrer, c, self.cle), "Message secret é à ç")

    def test_nonce_aleatoire(self):
        """Deux chiffrements du même texte doivent donner des résultats différents."""
        c1 = _requiert(aes.chiffrer, "même texte", self.cle)
        c2 = _requiert(aes.chiffrer, "même texte", self.cle)
        self.assertNotEqual(c1, c2)

    def test_mauvaise_cle(self):
        c = _requiert(aes.chiffrer, "texte", self.cle)
        with self.assertRaises(Exception):
            aes.dechiffrer(c, os.urandom(32))


class TestRSA(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.priv, cls.pub = rsa.generer_paire_cles()
        except NotImplementedError:
            cls.priv = cls.pub = None

    def setUp(self):
        if self.priv is None:
            self.skipTest("rsa.generer_paire_cles() n'est pas encore implémentée")

    def test_format_pem(self):
        self.assertIn("BEGIN PUBLIC KEY", self.pub)
        self.assertIn("PRIVATE KEY", self.priv)

    def test_aller_retour(self):
        c = _requiert(rsa.chiffrer, "Bonjour RSA".encode(), self.pub)
        self.assertIsInstance(c, str)
        self.assertEqual(_requiert(rsa.dechiffrer, c, self.priv), b"Bonjour RSA")

    def test_mauvaise_cle(self):
        autre_priv, _ = rsa.generer_paire_cles()
        c = _requiert(rsa.chiffrer, b"secret", self.pub)
        with self.assertRaises(Exception):
            rsa.dechiffrer(c, autre_priv)


class TestIntegrationMessagerie(TestCase):
    """Teste le parcours complet : envoi -> stockage -> lecture."""

    def setUp(self):
        self.alice = User.objects.create_user("alice", password="x")
        self.bob = User.objects.create_user("bob", password="x")

    def _envoyer(self, texte, algo):
        champs = service.preparer_message(texte, algo, self.bob)
        return Message.objects.create(expediteur=self.alice, destinataire=self.bob,
                                      sujet="test", algorithme=algo, **champs)

    def _tester(self, algo):
        if algo in ("RSA", "HYBRIDE"):
            _requiert(service.generer_cles_utilisateur, self.bob.profil)
        try:
            m = self._envoyer("Rendez-vous à 14h", algo)
        except service.CryptoNonImplemente as e:
            self.skipTest(str(e))
        if algo != "AUCUN":
            self.assertNotIn("Rendez-vous", m.contenu, "le contenu stocké doit être chiffré")
        r = service.lire_message(m, self.bob)
        self.assertTrue(r.dechiffre, r.erreur)
        self.assertEqual(r.texte, "Rendez-vous à 14h")
        if m.empreinte:
            self.assertEqual(r.integrite, "OK")

    def test_aucun(self):
        self._tester("AUCUN")

    def test_aes(self):
        self._tester("AES")

    def test_rsa(self):
        self._tester("RSA")

    def test_hybride(self):
        self._tester("HYBRIDE")

    def test_alteration_detectee(self):
        m = self._envoyer("Virement de 100 €", "AUCUN")
        if not m.empreinte:
            self.skipTest("hachage non implémenté")
        m.contenu = "Virement de 900 €"
        m.save()
        self.assertEqual(service.lire_message(m, self.bob).integrite, "ALTÉRÉ")
