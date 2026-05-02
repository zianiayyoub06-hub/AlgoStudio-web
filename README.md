# AlgoStudio Web 🧠

> **Environnement d'exécution d'algorithmes en pseudo-code français — version Web**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/Licence-MIT-green)](LICENSE)

---
 🌐 DIRECT WEB 
Try AlgoStudio instantly in your browser:
https://algostudio.onrender.com
THANKS FOR VISITING 

Note

The live version is hosted on Render. If it hasn't been visited recently, the server might be "sleeping." Please allow up to 60 seconds for the first load.
---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| 🖊️ **Éditeur intelligent** | Coloration syntaxique + autocomplete Algo |
| ▶️ **Exécution interactive** | `Lire()` en mode terminal — saisie en direct |
| 🔴 **Error highlighting** | Ligne d'erreur surlignée dans l'éditeur |
| 📑 **Onglets multiples** | Travaillez sur plusieurs algorithmes |
| 📖 **30+ exemples** | Chapitres 1→10 intégrés |
| ⬆️ **Export C / Python** | Génère du code compilable |
| 💾 **Save / Open fichiers** | `.algo` sur le disque local |
| 🔗 **Share link** | Partagez un algo via URL |
| 🌙 **Dark / Light** | Thème selon vos préférences |
| 🔒 **Sécurisé** | 3 couches anti-DDoS, file access bloqué |
| 📊 **Admin Dashboard** | Stats temps réel sur `/admin` |

---

## 🚀 Lancement rapide

```bash
git clone https://github.com/zianiayyoub06-hub/algostudio-web.git
cd algostudio-web
pip install -r requirements.txt
python server.py
# → http://localhost:5000
```

---

## 🌐 Déploiement HTTPS

### Railway (5 min, gratuit, HTTPS auto)
```
railway.app → New Project → Deploy from GitHub → Generate Domain
```

### VPS + Nginx + Let's Encrypt
```bash
gunicorn server:app -w 2 -b 127.0.0.1:8000
# Voir DEPLOIEMENT.md pour les détails
```

### Docker
```bash
docker build -t algostudio .
docker run -p 8000:8000 -e ADMIN_KEY=votre_cle algostudio
```

---

## ⚙️ Variables d'environnement

| Variable | Description |
|----------|-------------|
| `ADMIN_KEY` | Clé d'accès au dashboard `/admin` |
| `PRODUCTION` | Active le ProxyFix (Nginx/Railway) |

---

## 📁 Structure

```
algostudio_web/
├── server.py          ← API Flask sécurisée
├── static/
│   ├── index.html     ← Interface SPA
│   └── admin.html     ← Dashboard admin
└── core/              ← Moteur (lexer/parser/interpreter/codegen)
```

---

## 📄 Licence

MIT — Développé par **ZIANI Ayyoub**
