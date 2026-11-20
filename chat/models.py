from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class Profil(models.Model):
    
    utilisateur = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                       related_name="profil")
    cle_publique = models.TextField(blank=True)
    cle_privee = models.TextField(blank=True)

    def __str__(self):
        return f"Profil de {self.utilisateur.username}"


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def creer_profil(sender, instance, created, **kwargs):
    if created:
        Profil.objects.create(utilisateur=instance)


class Message(models.Model):
    ALGORITHMES = [
        ("AUCUN", "Aucun (texte en clair)"),
        ("AES", "AES (clé secrète partagée)"),
        ("RSA", "RSA (clé publique du destinataire)"),
        ("HYBRIDE", "Hybride RSA + AES"),
    ]

    expediteur = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                   related_name="messages_envoyes")
    destinataire = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                     related_name="messages_recus")
    sujet = models.CharField(max_length=200)

    # Contenu tel qu'il est STOCKÉ en base : en clair ou chiffré (base64)
    contenu = models.TextField()
    algorithme = models.CharField(max_length=10, choices=ALGORITHMES, default="AUCUN")
    # Mode hybride uniquement : clé AES de session chiffrée en RSA (base64)
    cle_chiffree = models.TextField(blank=True)
    # Empreinte (hash) du message EN CLAIR, en hexadécimal
    empreinte = models.CharField(max_length=128, blank=True)

    date_envoi = models.DateTimeField(auto_now_add=True)
    lu = models.BooleanField(default=False)

    class Meta:
        ordering = ["-date_envoi"]

    def __str__(self):
        return f"{self.expediteur} → {self.destinataire} : {self.sujet}"
