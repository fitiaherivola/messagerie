from django.urls import path

from . import views

app_name = "chat"

urlpatterns = [
    path("", views.boite_reception, name="boite_reception"),
    path("envoyes/", views.envoyes, name="envoyes"),
    path("nouveau/", views.nouveau_message, name="nouveau"),
    path("message/<int:pk>/", views.detail_message, name="detail"),
    path("message/<int:pk>/alterer/", views.alterer_message, name="alterer"),
    path("cles/", views.mes_cles, name="mes_cles"),
]
