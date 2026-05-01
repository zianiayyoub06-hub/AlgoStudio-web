FROM python:3.11-slim

# Utilisateur non-root pour la sécurité
RUN useradd -m -u 1000 algo
WORKDIR /app

# Dépendances d'abord (cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code de l'application
COPY . .
RUN chown -R algo:algo /app

USER algo

EXPOSE 8000

CMD ["gunicorn", "server:app", \
     "--workers", "2", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "30", \
     "--max-requests", "500", \
     "--max-requests-jitter", "50", \
     "--access-logfile", "-"]
