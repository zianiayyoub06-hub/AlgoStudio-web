# 🚀 AlgoStudio Web — Guide de Déploiement HTTPS

---

## Option A — Railway (le plus simple, gratuit, HTTPS automatique)

> **Durée : 5 minutes. Zéro configuration serveur.**

### 1. Créer un compte
→ https://railway.app (connexion avec GitHub)

### 2. Nouveau projet
```
New Project → Deploy from GitHub repo
```
Poussez d'abord votre code sur GitHub :
```bash
git init
git add .
git commit -m "AlgoStudio Web"
git branch -M main
git remote add origin https://github.com/VOTRE_USER/algostudio-web.git
git push -u origin main
```

### 3. Dans Railway
- Sélectionnez votre dépôt
- Railway détecte automatiquement le `Procfile` ✅
- Cliquez **Deploy**
- Dans **Settings → Domains** → **Generate Domain** → HTTPS automatique ✅

### 4. Variables d'environnement (optionnel)
Dans Railway → Variables :
```
PORT=8000
```

**Résultat :** `https://algostudio-web-xxxx.railway.app`

---

## Option B — Render (alternatif gratuit)

1. → https://render.com → New Web Service
2. Connectez votre dépôt GitHub
3. **Build Command :** `pip install -r requirements.txt`
4. **Start Command :** `gunicorn server:app --workers 2 --bind 0.0.0.0:$PORT --timeout 30`
5. Render génère automatiquement un domaine HTTPS ✅

---

## Option C — VPS Ubuntu (contrôle total)

> Testé sur Ubuntu 22.04 / 24.04. Remplacez `votredomaine.com` partout.

### 1. Préparer le serveur

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip nginx certbot python3-certbot-nginx git
```

### 2. Déployer l'application

```bash
# Créer un utilisateur dédié
sudo useradd -m -s /bin/bash algo
sudo su - algo

# Cloner / uploader le projet
mkdir -p /home/algo/app
cd /home/algo/app
# (uploader algostudio_web/ ici via scp ou git)

pip install -r algostudio_web/requirements.txt
```

### 3. Service systemd (démarrage automatique)

```bash
sudo nano /etc/systemd/system/algostudio.service
```

Contenu :
```ini
[Unit]
Description=AlgoStudio Web
After=network.target

[Service]
User=algo
WorkingDirectory=/home/algo/app/algostudio_web
ExecStart=/home/algo/.local/bin/gunicorn server:app \
    --workers 2 \
    --bind 127.0.0.1:8000 \
    --timeout 30 \
    --max-requests 500 \
    --access-logfile /home/algo/app/access.log \
    --error-logfile /home/algo/app/error.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable algostudio
sudo systemctl start algostudio
sudo systemctl status algostudio  # doit afficher "active (running)"
```

### 4. Nginx + HTTPS (Let's Encrypt)

```bash
# Copier la config Nginx
sudo cp /home/algo/app/algostudio_web/nginx.conf /etc/nginx/sites-available/algostudio
sudo sed -i 's/votredomaine.com/VOTRE_VRAI_DOMAINE/g' /etc/nginx/sites-available/algostudio
sudo ln -s /etc/nginx/sites-available/algostudio /etc/nginx/sites-enabled/
sudo nginx -t   # vérifier la config
sudo systemctl reload nginx
```

```bash
# Obtenir le certificat SSL gratuit
sudo certbot --nginx -d votredomaine.com -d www.votredomaine.com
# Suivez les instructions → choisir "redirect HTTP to HTTPS"
```

```bash
# Renouvellement automatique (certbot le fait déjà via cron)
sudo certbot renew --dry-run  # test
```

### 5. Firewall

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

**Résultat :** `https://votredomaine.com` ✅

---

## Vérifications post-déploiement

```bash
# Test HTTPS
curl -I https://votredomaine.com

# Vérifier les headers de sécurité
curl -I https://votredomaine.com/api/examples

# Test de l'API
curl -X POST https://votredomaine.com/api/run \
  -H "Content-Type: application/json" \
  -d '{"source":"algorithme T;debut ecrire(42);fin.","inputs":[]}'
```

Headers attendus dans la réponse :
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: ...
Strict-Transport-Security: max-age=31536000  ← ajouté par Nginx
```

---

## Mise à jour de l'application

```bash
# Sur VPS
cd /home/algo/app/algostudio_web
git pull  # ou re-upload les fichiers
sudo systemctl restart algostudio
```

---

## Notes de sécurité importantes

- ✅ HTTPS obligatoire (HTTP redirigé automatiquement)
- ✅ TLS 1.2 + 1.3 uniquement
- ✅ HSTS activé (1 an)
- ✅ Rate limiting double couche (Nginx + app)
- ✅ Utilisateur non-root
- ✅ Gunicorn `--max-requests 500` (redémarre les workers pour éviter les fuites mémoire)
- ⚠️  Gardez votre système à jour : `sudo apt upgrade`
- ⚠️  Surveillez les logs : `/home/algo/app/error.log`
