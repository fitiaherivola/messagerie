# CryptoMsg — Messagerie Sécurisée Pédagogique

**Auteur : Fabrice RAZAFINDRAIBE — ESTI**

Application Django de messagerie interne permettant d'étudier et d'implémenter les primitives cryptographiques fondamentales : hachage (SHA-256), chiffrement symétrique (AES-GCM), chiffrement asymétrique (RSA-OAEP) et mode hybride (RSA + AES).

---

## 🎯 Objectifs Pédagogiques

| Module | Fichier | Propriété de Sécurité | Notions Clés |
|--------|---------|----------------------|--------------|
| **Hachage** | `chat/crypto/hachage.py` | Intégrité | SHA-256, HMAC, résistance aux collisions |
| **AES-GCM** | `chat/crypto/aes.py` | Confidentialité (symétrique) | Nonce/IV, tag d'authentification, modes de chiffrement |
| **RSA-OAEP** | `chat/crypto/rsa.py` | Confidentialité (asymétrique) | Paire de clés, padding OAEP, limite de taille |
| **Hybride** | `chat/crypto/service.py` | Combinaison | Échange de clé, TLS/PGP pattern |

L'application fonctionne **dès le départ** en mode « Aucun » (texte en clair). Chaque fonction implémentée débloque une nouvelle option de chiffrement.

---

## 🚀 Installation & Démarrage

```bash
# 1. Cloner et entrer dans le projet
cd messagerie_etudiants/messagerie

# 2. Créer l'environnement virtuel
python -m venv venv
# Windows :
venv\Scripts\activate
# Linux/Mac :
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt
# Django>=5.0, cryptography>=42.0

# 4. Base de données
python manage.py migrate

# 5. (Optionnel) Superutilisateur pour /admin
python manage.py createsuperuser

# 6. Lancer le serveur
python manage.py runserver
```

Ouvrir **http://127.0.0.1:8000** — Créer **deux comptes** (ex: `alice` et `bob`, dans deux navigateurs ou une fenêtre privée) et s'envoyer des messages.

---

## 📁 Structure du Projet

```
messagerie/                 # Configuration Django
├── settings.py             # AES_CLE_HEX (clé partagée 32 octets hex)
├── urls.py                 # Routes principales + auth
└── wsgi.py / asgi.py

chat/                       # Application principale
├── models.py               # Profil (clés RSA) + Message (contenu, algo, empreinte)
├── views.py                # Réception, envoi, lecture, clés, altération
├── forms.py                # MessageForm, AlterationForm
├── urls.py                 # Routes chat/
├── tests.py                # Tests unitaires (13 tests)
├── admin.py                # Interface d'administration
├── crypto/                 # Modules cryptographiques
│   ├── __init__.py
│   ├── service.py          # Couche de liaison (DÉJÀ ÉCRIT - à lire !)
│   ├── hachage.py          # SHA-256 — À COMPLÉTER
│   ├── aes.py              # AES-GCM — À COMPLÉTER
│   └── rsa.py              # RSA-OAEP — À COMPLÉTER
├── migrations/
└── templates/
    ├── base.html           # Layout principal (header, flash, main)
    ├── chat/
    │   ├── boite.html      # Liste messages (réception / envoyés)
    │   ├── nouveau.html    # Formulaire envoi + explications algos
    │   ├── detail.html     # Lecture + intégrité + données brutes
    │   ├── cles.html       # Génération/affichage clés RSA
    │   └── alterer.html    # Simulation attaque (modification BDD)
    └── registration/
        ├── login.html
        └── inscription.html
```

---

## 🔧 Explication Détaillée du Code

### 1. `chat/models.py` — Modèles de Données

```python
class Profil(models.Model):
    utilisateur = OneToOneField(User, related_name="profil")
    cle_publique = TextField(blank=True)   # PEM public key
    cle_privee = TextField(blank=True)     # PEM private key (stockée en clair !)
```
- Chaque utilisateur a un `Profil` créé automatiquement via signal `post_save`.
- Les clés RSA sont stockées en **format PEM** (base64 avec en-têtes `-----BEGIN PUBLIC KEY-----`).
- ⚠️ **Faille pédagogique** : clé privée en clair sur le serveur (voir README section Avertissements).

```python
class Message(models.Model):
    ALGORITHMES = [
        ("AUCUN", "Aucun (texte en clair)"),
        ("AES", "AES (clé secrète partagée)"),
        ("RSA", "RSA (clé publique du destinataire)"),
        ("HYBRIDE", "Hybride RSA + AES"),
    ]
    expediteur = ForeignKey(User, related_name="messages_envoyes")
    destinataire = ForeignKey(User, related_name="messages_recus")
    sujet = CharField(max_length=200)
    contenu = TextField()                    # Stocké en base64 (chiffré ou clair)
    algorithme = CharField(choices=ALGORITHMES, default="AUCUN")
    cle_chiffree = TextField(blank=True)     # Hybride seulement : clé AES de session chiffrée en RSA
    empreinte = CharField(max_length=128, blank=True)  # SHA-256 hex du message EN CLAIR
    date_envoi = DateTimeField(auto_now_add=True)
    lu = BooleanField(default=False)
```
- `contenu` : toujours stocké en **base64** (sauf mode AUCUN = texte brut).
- `cle_chiffree` : uniquement pour mode **HYBRIDE** — clé AES-256 aléatoire chiffrée avec la clé publique RSA du destinataire.
- `empreinte` : hash SHA-256 du message **en clair** (avant chiffrement), en hexadécimal (64 caractères).

---

### 2. `chat/crypto/service.py` — Couche de Liaison (⚠️ DÉJÀ ÉCRIT, NE PAS MODIFIER)

Ce fichier **appelle** vos fonctions `hachage.py`, `aes.py`, `rsa.py`. Il faut le **lire** pour comprendre l'interface attendue.

#### Envoi — `preparer_message(texte, algorithme, destinataire) -> dict`
```python
# 1. Empreinte du message EN CLAIR (intégrité)
empreinte = hachage.calculer_empreinte(texte)  # -> str hex

# 2. Chiffrement selon l'algorithme
if algorithme == "AUCUN":
    contenu = texte
elif algorithme == "AES":
    contenu = aes.chiffrer(texte, cle_aes_partagee())  # cle 32 octets depuis settings
elif algorithme == "RSA":
    cle_pub = _cle_publique(destinataire)
    contenu = rsa.chiffrer(texte.encode("utf-8"), cle_pub)
elif algorithme == "HYBRIDE":
    cle_pub = _cle_publique(destinataire)
    cle_session = os.urandom(32)           # Clé AES-256 à usage unique
    contenu = aes.chiffrer(texte, cle_session)
    cle_chiffree = rsa.chiffrer(cle_session, cle_pub)  # Clé AES chiffrée en RSA

return {"contenu": contenu, "cle_chiffree": cle_chiffree, "empreinte": empreinte}
```

#### Lecture — `lire_message(message, lecteur) -> ResultatLecture`
```python
@dataclass
class ResultatLecture:
    texte: str           # Message affiché à l'utilisateur
    dechiffre: bool      # Succès du déchiffrement
    integrite: str       # "OK" | "ALTÉRÉ" | "NON VÉRIFIÉ"
    erreur: str = ""     # Message d'erreur si échec

# Déchiffrement selon l'algorithme stocké
if algo == "AUCUN":      texte = message.contenu
elif algo == "AES":      texte = aes.dechiffrer(message.contenu, cle_aes_partagee())
elif algo == "RSA":      texte = rsa.dechiffrer(message.contenu, _cle_privee(lecteur)).decode()
elif algo == "HYBRIDE":
    cle_session = rsa.dechiffrer(message.cle_chiffree, _cle_privee(lecteur))
    texte = aes.dechiffrer(message.contenu, cle_session)

# Vérification intégrité
if not message.empreinte: integrite = "NON VÉRIFIÉ"
else: integrite = "OK" if hachage.verifier_empreinte(texte, message.empreinte) else "ALTÉRÉ"
```

#### Gestion Clés — `generer_cles_utilisateur(profil)`
```python
prive, public = rsa.generer_paire_cles()  # RSA-2048
profil.cle_privee = prive
profil.cle_publique = public
profil.save()
```

---

### 3. `chat/crypto/hachage.py` — Intégrité (SHA-256)

```python
import hashlib, hmac
ALGORITHME = "sha256"

def calculer_empreinte(texte: str) -> str:
    """Retourne l'empreinte SHA-256 en hexadécimal (64 chars)."""
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()

def verifier_empreinte(texte: str, empreinte: str) -> bool:
    """Compare en temps constant (hmac.compare_digest) pour éviter les attaques par canal latéral."""
    calculee = hashlib.sha256(texte.encode("utf-8")).hexdigest()
    return hmac.compare_digest(calculee, empreinte)
```
- **Pourquoi `hmac.compare_digest` ?** Évite les attaques par timing (comparaison en temps constant).
- **Limite** : hash simple = n'importe qui peut recalculer l'empreinte après modification. Solution : **HMAC** (clé secrète) ou **signature RSA**.

---

### 4. `chat/crypto/aes.py` — Confidentialité Symétrique (AES-GCM)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, os

def chiffrer(texte: str, cle: bytes) -> str:
    """
    AES-GCM (Authenticated Encryption)
    Sortie: base64( nonce(12 octets) || ciphertext || tag )
    """
    nonce = os.urandom(12)                    # 96 bits — JAMAIS réutilisé !
    aesgcm = AESGCM(cle)
    chiffre = aesgcm.encrypt(nonce, texte.encode("utf-8"), None)
    return base64.b64encode(nonce + chiffre).decode("ascii")

def dechiffrer(donnees_b64: str, cle: bytes) -> str:
    donnees = base64.b64decode(donnees_b64)
    nonce = donnees[:12]
    chiffre = donnees[12:]
    aesgcm = AESGCM(cle)
    texte = aesgcm.decrypt(nonce, chiffre, None)  # Lève Exception si tag invalide
    return texte.decode("utf-8")
```

**Points clés :**
- **Nonce 12 octets** aléatoire à chaque message — **critique** pour la sécurité (réutilisation = catastrophe).
- **GCM** = chiffrement + authentification intégrée (tag 16 octets ajouté au ciphertext).
- `AESGCM.decrypt` lève une exception si le tag ne correspond pas → **détection d'altération automatique**.
- Clé partagée `settings.AES_CLE_HEX` (32 octets = AES-256) — **même clé pour tous les utilisateurs** (problème : compromis d'un = compromis de tous).

---

### 5. `chat/crypto/rsa.py` — Confidentialité Asymétrique (RSA-OAEP)

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64

def generer_paire_cles(taille: int = 2048) -> tuple[str, str]:
    cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=taille)
    priv_pem = cle_privee.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # ⚠️ Sans mot de passe !
    ).decode("ascii")
    pub_pem = cle_privee.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    return priv_pem, pub_pem

def chiffrer(donnees: bytes, cle_publique_pem: str) -> str:
    cle_publique = serialization.load_pem_public_key(cle_publique_pem.encode())
    chiffre = cle_publique.encrypt(
        donnees,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(chiffre).decode("ascii")

def dechiffrer(donnees_b64: str, cle_privee_pem: str) -> bytes:
    cle_privee = serialization.load_pem_private_key(cle_privee_pem.encode(), password=None)
    chiffre = base64.b64decode(donnees_b64)
    texte = cle_privee.decrypt(
        chiffre,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return texte  # bytes
```

**Points clés :**
- **OAEP (Optimal Asymmetric Encryption Padding)** avec SHA-256 — **obligatoire** (RSA "nu" = vulnérable).
- **Limite de taille** : RSA-2048 + OAEP SHA-256 ≈ **190 octets** max. Au-delà → erreur. Solution : **mode Hybride**.
- Clé privée stockée **sans chiffrement** (`NoEncryption()`) — ⚠️ faille pédagogique.
- Entrée/sortie en **bytes** pour supporter aussi bien texte que clés AES (mode hybride).

---

### 6. Mode Hybride (dans `service.py`) — Le Meilleur des Deux Mondes

```python
# Côté ENVOI (expéditeur)
cle_session = os.urandom(32)                    # Clé AES-256 aléatoire (usage unique)
contenu = aes.chiffrer(message, cle_session)    # Chiffrement rapide du message (taille illimitée)
cle_chiffree = rsa.chiffrer(cle_session, cle_pub_destinataire)  # Échange de clé sécurisé

# Côté LECTURE (destinataire)
cle_session = rsa.dechiffrer(cle_chiffree, cle_privee_destinataire)  # Seul lui peut
message = aes.dechiffrer(contenu, cle_session)
```

**Schéma :**
```
Expéditeur                              Destinataire
────────────────────────────────────────────────────────────
1. Génère clé AES aléatoire (Ks)    ←──  Clé publique RSA (Kpub)
2. Chiffre message avec Ks (AES)         │
3. Chiffre Ks avec Kpub (RSA)    ──────→ │
4. Envoie : {contenu_AES, Ks_RSA}        │
                                       5. Déchiffre Ks avec Kpriv (RSA)
                                       6. Déchiffre message avec Ks (AES)
```

C'est exactement le principe de **TLS**, **PGP**, **S/MIME**, **Signal** (avec X25519 au lieu de RSA).

---

### 7. `chat/views.py` — Logique Métier

| Vue | URL | Rôle |
|-----|-----|------|
| `inscription` | `/inscription/` | Création compte + login auto → redirige vers génération clés |
| `boite_reception` | `/` | Messages reçus (filtré `destinataire=request.user`) |
| `envoyes` | `/envoyes/` | Messages envoyés (filtré `expediteur=request.user`) |
| `nouveau_message` | `/nouveau/` | Formulaire envoi → appelle `service.preparer_message()` |
| `detail_message` | `/message/<pk>/` | Lecture + déchiffrement + vérification intégrité |
| `alterer_message` | `/message/<pk>/alterer/` | **Outil pédagogique** : modifie `message.contenu` en BDD |
| `mes_cles` | `/cles/` | Génération/affichage paire RSA via `service.generer_cles_utilisateur()` |

**Détail important — `detail_message` :**
```python
if msg.destinataire == request.user:
    # Destinataire : peut déchiffrer (a la clé privée)
    resultat = service.lire_message(msg, request.user)
else:
    # Expéditeur : NE PEUT PAS déchiffrer RSA/HYBRIDE (pas la clé privée du destinataire)
    if msg.algorithme in ("RSA", "HYBRIDE"):
        resultat = ResultatLecture(msg.contenu, False, "NON VÉRIFIÉ",
                                   "Chiffré pour le destinataire : seul lui peut le lire.")
    else:
        resultat = service.lire_message(msg, request.user)
```
→ C'est **volontaire** : l'expéditeur ne peut pas relire ses propres messages RSA/Hybride (confidentialité parfaite).

---

### 8. `chat/forms.py` — Formulaires

```python
class MessageForm(forms.Form):
    destinataire = ModelChoiceField(queryset=User.objects.none())  # Exclut l'utilisateur courant
    sujet = CharField(max_length=200)
    texte = CharField(widget=Textarea(attrs={"rows": 6}))
    algorithme = ChoiceField(choices=Message.ALGORITHMES, initial="AUCUN")

class AlterationForm(forms.Form):
    contenu = CharField(widget=Textarea(attrs={"rows": 4}), label="Contenu stocké en base")
```

---

### 9. `chat/tests.py` — Tests Unitaires (13 tests)

```bash
python manage.py test chat
```
- Au départ : `OK (skipped=13)` — tous les tests sont skip car fonctions `NotImplementedError`.
- Objectif : **`OK` sans aucun test sauté** après implémentation des 3 modules crypto.

Tests couvrent :
- Hachage : empreinte correcte, détection altération, `compare_digest`
- AES : chiffrement/déchiffrement, nonce unique, tag GCM, altération détectée
- RSA : génération clés, chiffrement/déchiffrement, limite taille, régénération clés
- Hybride : message long, round-trip complet

---

## ✅ Vérification de Votre Travail

```bash
# Lancer les tests
python manage.py test chat -v 2

# Résultats attendus après implémentation complète :
# test_calculer_empreinte ... ok
# test_verifier_empreinte ... ok
# test_aes_chiffrer_dechiffrer ... ok
# test_aes_nonce_unique ... ok
# test_aes_alteration_detectee ... ok
# test_rsa_generer_paire_cles ... ok
# test_rsa_chiffrer_dechiffrer ... ok
# test_rsa_limite_taille ... ok
# test_rsa_regenerer_cles ... ok
# test_hybride_long_message ... ok
# ...
# OK (13 tests)
```

---

## 🎓 Travail Demandé (Par Parties)

### Partie 1 — Hachage (`chat/crypto/hachage.py`)
1. Implémenter `calculer_empreinte()` et `verifier_empreinte()`
2. Envoyer un message « Aucun » → intégrité ✔ OK
3. **Simuler une altération** (bouton 🧪) : modifier un mot → intégrité ✘ ALTÉRÉ
4. **Question** : Un attaquant avec accès BDD peut modifier le message **ET** recalculer l'empreinte. Le hachage simple protège-t-il ? Que changerait un **HMAC** ou une **signature RSA** ?

### Partie 2 — AES (`chat/crypto/aes.py`)
1. Implémenter `chiffrer()` et `dechiffrer()` (AES-GCM)
2. Envoyer un message AES → observer le contenu **réellement stocké** (base64)
3. Envoyer **deux fois** le même texte → contenus identiques ? **Non** (nonce aléatoire)
4. **Altérer** un caractère du contenu chiffré → erreur de déchiffrement (tag GCM invalide)
5. **Question** : Tous les utilisateurs partagent `AES_CLE_HEX`. Problème ? Où stocker la clé ?

### Partie 3 — RSA (`chat/crypto/rsa.py`)
1. Implémenter `generer_paire_cles()`, `chiffrer()`, `dechiffrer()`
2. Chaque utilisateur génère ses clés via **Mes clés**
3. Envoyer un message RSA. L'expéditeur peut-il relire ? **Non** (pas la clé privée du destinataire)
4. Message RSA > 300 caractères → **erreur** (limite RSA-2048 + OAEP ≈ 190 octets)
5. Régénérer clés destinataire → relire ancien message → **illisible** (nouvelle clé privée)

### Partie 4 — Hybride (déjà câblé dans `service.py`)
1. Une fois AES + RSA faits → mode **Hybride** fonctionne automatiquement
2. Lire `service.py` et décrire le schéma (dessin attendu dans le compte-rendu)
3. Vérifier qu'un **long message** passe désormais
4. Comparer avec **TLS** / **PGP** (même principe : échange de clé asymétrique + chiffrement symétrique)

---

## 🔬 Bonus (Pour Aller Plus Loin)

- **Signature numérique RSA-PSS** : l'expéditeur signe le message → authentification + non-répudiation
- **HMAC** au lieu de hash simple → intégrité avec clé secrète (résiste à modification + recalcul)
- **Chiffrement clé privée** : `BestAvailableEncryption(password)` + PBKDF2 au stockage
- **ECDH (X25519)** : remplacer RSA par échange de clés à courbes elliptiques (plus court, plus rapide)
- **Perfect Forward Secrecy** : clés de session éphémères (Double Ratchet comme Signal)

---

## ⚠️ Avertissements Pédagogiques (IMPORTANT)

Ce projet est **volontairement simplifié** et **ne doit JAMAIS être utilisé en production** :

| Faille | Explication | Solution Réelle |
|--------|-------------|-----------------|
| `AES_CLE_HEX` en dur dans `settings.py` | Clé partagée, même pour tous, versionnée dans le code | KMS / HSM / rotation de clés / derivation par utilisateur |
| Clés privées RSA **en clair** sur le serveur | N'importe quel admin BDD les lit → déchiffre tout | **E2EE** : clé privée générée et stockée **côté client** (navigateur/app) |
| Bouton « altération » modifie la BDD | Permet à un utilisateur de corrompre les données | Audit logs, WORM storage, signatures |
| Pas d'authentification de l'expéditeur | Personne ne prouve qui a envoyé le message | Signatures numériques / certificats |
| Pas de PFS (Perfect Forward Secrecy) | Compromission clé long terme = tous messages passés lus | Double Ratchet / X3DH (Signal Protocol) |

**Identifier et discuter ces faiblesses fait partie intégrante du TP.**

---

## 📚 Ressources & Documentation

- **hashlib** : https://docs.python.org/3/library/hashlib.html
- **hmac** : https://docs.python.org/3/library/hmac.html
- **cryptography (AES-GCM)** : https://cryptography.io/en/latest/hazmat/primitives/aead/
- **cryptography (RSA)** : https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
- **OAEP expliqué** : https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
- **TLS 1.3** : https://datatracker.ietf.org/doc/html/rfc8446
- **Signal Protocol** : https://signal.org/docs/specifications/doubleratchet/

---

## 📝 Licence

Projet pédagogique — Usage éducatif uniquement.