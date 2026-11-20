from django.contrib import messages as flash
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from .crypto import service
from .forms import AlterationForm, MessageForm
from .models import Message


def inscription(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            flash.success(request, "Compte créé. Pensez à générer vos clés RSA.")
            return redirect("chat:mes_cles")
    else:
        form = UserCreationForm()
    return render(request, "registration/inscription.html", {"form": form})


@login_required
def boite_reception(request):
    recus = Message.objects.filter(destinataire=request.user).select_related("expediteur")
    return render(request, "chat/boite.html", {"liste": recus, "titre": "Boîte de réception",
                                               "recus": True})


@login_required
def envoyes(request):
    liste = Message.objects.filter(expediteur=request.user).select_related("destinataire")
    return render(request, "chat/boite.html", {"liste": liste, "titre": "Messages envoyés",
                                               "recus": False})


@login_required
def nouveau_message(request):
    form = MessageForm(request.POST or None, utilisateur=request.user)
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        try:
            champs = service.preparer_message(d["texte"], d["algorithme"], d["destinataire"])
        except service.CryptoNonImplemente as e:
            flash.error(request, f"Algorithme pas encore implémenté : {e}")
        except ValueError as e:
            flash.error(request, str(e))
        else:
            Message.objects.create(expediteur=request.user, destinataire=d["destinataire"],
                                   sujet=d["sujet"], algorithme=d["algorithme"], **champs)
            flash.success(request, "Message envoyé.")
            return redirect("chat:envoyes")
    return render(request, "chat/nouveau.html", {"form": form})


@login_required
def detail_message(request, pk):
    msg = get_object_or_404(Message.objects.filter(
        Q(destinataire=request.user) | Q(expediteur=request.user)), pk=pk)

    if msg.destinataire == request.user:
        if not msg.lu:
            msg.lu = True
            msg.save(update_fields=["lu"])
        resultat = service.lire_message(msg, request.user)
    else:
        # L'expéditeur ne peut pas déchiffrer un message RSA/HYBRIDE
        # (il n'a pas la clé privée du destinataire) : c'est voulu !
        if msg.algorithme in ("RSA", "HYBRIDE"):
            resultat = service.ResultatLecture(
                msg.contenu, False, "NON VÉRIFIÉ",
                "Chiffré pour le destinataire : seul lui peut le lire.")
        else:
            resultat = service.lire_message(msg, request.user)

    return render(request, "chat/detail.html", {"msg": msg, "r": resultat})


@login_required
def alterer_message(request, pk):
    """
    Outil PÉDAGOGIQUE : simule un attaquant ayant accès à la base de données
    et modifiant le contenu stocké. Permet d'observer l'effet sur le
    déchiffrement et sur la vérification d'intégrité.
    """
    msg = get_object_or_404(Message, pk=pk, destinataire=request.user)
    form = AlterationForm(request.POST or None, initial={"contenu": msg.contenu})
    if request.method == "POST" and form.is_valid():
        msg.contenu = form.cleaned_data["contenu"]
        msg.save(update_fields=["contenu"])
        flash.warning(request, "Contenu modifié en base (simulation d'attaque).")
        return redirect("chat:detail", pk=pk)
    return render(request, "chat/alterer.html", {"msg": msg, "form": form})


@login_required
def mes_cles(request):
    profil = request.user.profil
    if request.method == "POST":
        try:
            service.generer_cles_utilisateur(profil)
            flash.success(request, "Nouvelle paire de clés RSA générée.")
        except NotImplementedError as e:
            flash.error(request, f"Pas encore implémenté : {e}")
        return redirect("chat:mes_cles")
    return render(request, "chat/cles.html", {"profil": profil})
