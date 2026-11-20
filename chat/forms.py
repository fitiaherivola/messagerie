from django import forms
from django.contrib.auth import get_user_model

from .models import Message

User = get_user_model()


class MessageForm(forms.Form):
    destinataire = forms.ModelChoiceField(queryset=User.objects.none(), label="Destinataire")
    sujet = forms.CharField(max_length=200)
    texte = forms.CharField(widget=forms.Textarea(attrs={"rows": 6}), label="Message")
    algorithme = forms.ChoiceField(choices=Message.ALGORITHMES, initial="AUCUN",
                                   label="Chiffrement")

    def __init__(self, *args, utilisateur=None, **kwargs):
        super().__init__(*args, **kwargs)
        qs = User.objects.order_by("username")
        if utilisateur is not None:
            qs = qs.exclude(pk=utilisateur.pk)
        self.fields["destinataire"].queryset = qs


class AlterationForm(forms.Form):
    """Permet de modifier le contenu stocké pour simuler une attaque sur l'intégrité."""
    contenu = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}),
                              label="Contenu stocké en base")
