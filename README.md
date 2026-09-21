# Larivière Live — Portail Streamlit Public Sécurisé

Portail frontal Streamlit public (sécurisé par sas d'authentification) pour la démonstration **Éditions Larivière — IA Partenariats**.

Ce portail agit comme une enveloppe d'exécution sécurisée (100% public-safe) déployable sur Streamlit Community Cloud sans consommer de slot d'application privée.

---

## 1. Architecture de sécurité

```
Navigateur utilisateur
       │
       │ (HTTPS / WebSocket Streamlit)
       ▼
┌────────────────────────────────────────────────────────┐
│ Streamlit Community Cloud (Public App Slot - Illimité) │
│ Dépôt public : cdurand42/Lariviere-Live               │
│                                                        │
│  [ SAS D'AUTHENTIFICATION ]                            │
│  - Demande Username + Mot de passe                     │
│  - Hachage PBKDF2-HMAC-SHA256 (600 000 it, sel 16 o)   │
│  - Comparaison en temps constant (hmac.compare_digest) │
│  - Aucun mot de passe en clair toléré                  │
│  - Session authentifiée + Déconnexion (en-tête discret) │
│  - Fail-closed si credentials absents                  │
│                                                        │
│  [ CHARGEUR DYNAMIQUE SÉCURISÉ ]                       │
│  - Ne télécharge LariviereAI QU'APRÈS authentification │
│  - Appel REST API GitHub (archive compressée)          │
│  - Token transmis UNIQUEMENT en header Authorization   │
│  - AUCUN token dans les URLs, commandes git ou logs    │
│  - Mise en cache locale conteneur (_lariviere_app/)    │
│  - Gestion st.set_page_config unique et sûre           │
│  - Exécution du point d'entrée app.main()              │
└────────────────────────────────────────────────────────┘
       │
       │ HTTPS REST API (Authorization: Bearer <GITHUB_TOKEN>)
       ▼
┌────────────────────────────────────────────────────────┐
│ Dépôt Privé GitHub (cdurand42/lariviere-ai-demo)       │
│  - Code métier propriétaire (scénarios, prompts IA)    │
│  - Modèles et benchmarks (Game Fair, Bol d'Or, etc.)   │
│  - Génération PowerPoint et intégrations d'images      │
└────────────────────────────────────────────────────────┘
```

### Garanties de sécurité :
1. **100% Public-Safe** : Le présent dépôt public ne contient aucun code métier propriétaire, aucun prompt, aucun catalogue commercial, et aucun secret ou donnée sensible.
2. **Sas d'authentification obligatoire** : Aucun accès au code ni requête vers GitHub n'est effectué avant la validation du mot de passe.
3. **Protection stricte du jeton GitHub (PAT)** :
   - `GITHUB_TOKEN` n'est **jamais** passé dans une URL ni dans une commande git CLI.
   - Il est utilisé en mémoire vive dans l'en-tête `Authorization: Bearer <token>` de la requête HTTPS REST API GitHub.
   - Les logs et messages d'erreur masquent automatiquement la valeur du jeton.
4. **Dérivation cryptographique robuste** : PBKDF2-HMAC-SHA256 avec 600 000 itérations et sel aléatoire de 16 octets.
5. **Gestion de session et déconnexion** : Bouton de déconnexion discret dans l'en-tête réinitialisant intégralement la session (sidebar Streamlit masquée).
6. **Optimisation runtime** : L'archive n'est téléchargée qu'une seule fois par cycle de vie de conteneur, évitant tout ralentissement ou dépassement de quota d'API.

---

## 2. Configuration & Secrets

Secrets à renseigner dans les **Advanced Settings > Secrets** de Streamlit Cloud (ou en local dans `.streamlit/secrets.toml`) :

| Variable | Description |
|---|---|
| `LIVE_USERNAME` | Identifiant autorisé pour l'accès (ex. `admin`) |
| `LIVE_PASSWORD_HASH` | Empreinte PBKDF2-HMAC-SHA256 (`pbkdf2_sha256$600000$...`) |
| `GITHUB_TOKEN` | Fine-grained Personal Access Token GitHub (Lecture seule sur le dépôt privé) |
| `GITHUB_REPO` | Dépôt privé (défaut : `cdurand42/lariviere-ai-demo`) |
| `GITHUB_REF` | Branche ou tag à charger (ex. `feat/streamlit-auth-gateway` ou `main`) |
| `GEMINI_API_KEY` | Clé API Google Gemini pour la génération de scénarios |

### Génération du hash PBKDF2 :
Exécuter localement :
```bash
python auth.py
```
Copier l'empreinte générée dans les secrets.

### Création du Personal Access Token (PAT) GitHub :
1. Sur GitHub : **Settings > Developer Settings > Personal access tokens > Fine-grained tokens**.
2. **Repository access** : Sélectionner uniquement `cdurand42/lariviere-ai-demo`.
3. **Permissions** : `Repository permissions` > **Contents** : `Read-only`.
4. Copier le token généré (`github_pat_...`) dans `GITHUB_TOKEN`.

---

## 3. Lancement local

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer les secrets
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Éditer .streamlit/secrets.toml avec vos valeurs

# 3. Lancer les tests unitaires
pytest

# 4. Lancer l'application
streamlit run app.py
```

---

## 4. Déploiement sur Streamlit Community Cloud

1. Déposer ce dépôt public sur GitHub : `cdurand42/Lariviere-Live`.
2. Sur [share.streamlit.io](https://share.streamlit.io/) :
   - **Repository** : `cdurand42/Lariviere-Live`
   - **Branch** : `main` (ou `feat/streamlit-auth-gateway`)
   - **Main file path** : `app.py`
3. Renseigner l'ensemble des secrets requis dans les **Secrets** de l'application.
4. Déployer l'application publique.
5. Une fois le portail public validé, l'application privée existante `cdurand42/lariviere-ai-demo` peut être supprimée de Streamlit Cloud pour libérer le slot d'application privée réservé.
