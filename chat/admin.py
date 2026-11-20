from django.contrib import admin

from .models import Message, Profil


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("sujet", "expediteur", "destinataire", "algorithme", "date_envoi", "lu")
    list_filter = ("algorithme", "lu")
    readonly_fields = ("date_envoi",)


@admin.register(Profil)
class ProfilAdmin(admin.ModelAdmin):
    list_display = ("utilisateur",)
