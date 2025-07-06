# Dockerfile per TVProxy - Server Proxy con Gunicorn

# 1. Usa l'immagine base ufficiale di Python 3.12 slim
FROM python:3.12-slim

# 2. Installa git e certificati SSL (per clonare da GitHub e HTTPS)
RUN apt-get update && apt-get install -y \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 3. Imposta la directory di lavoro
WORKDIR /app

# 4. Copia il codice dell'applicazione
COPY . .

# 6. Aggiorna pip e installa le dipendenze senza cache
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# 7. Espone la porta 7860 per Gunicorn
EXPOSE 7860

# 8. Comando per avviare Gunicorn ottimizzato per proxy server
#    - 4 worker per gestire più clienti
#    - Worker class sync (più stabile per proxy HTTP)
#    - Timeout adeguati per streaming
#    - Logging su stdout/stderr
CMD ["gunicorn", "app:app", \
     "-w", "4", \
     "--worker-class", "sync", \
     "-b", "0.0.0.0:7860", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info"]