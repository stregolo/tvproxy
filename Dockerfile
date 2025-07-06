# Dockerfile per Flask Proxy Server con Gunicorn e logging su stdout/stderr

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

# 4. Clona il repository (o copia il codice direttamente) nella working directory
#    Se vuoi usare il tuo repository remoto, decommenta la riga git clone:
# RUN git clone https://github.com/nzo66/tvproxy .
COPY . .

# 5. Pre-crea le directory necessarie e rendile scrivibili
RUN mkdir -p logs \
    && mkdir -p /tmp \
    && chmod 0777 logs \
    && chmod 0777 /tmp

# 6. Aggiorna pip e installa le dipendenze senza cache
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# 7. Espone la porta 7860 per Flask/Gunicorn
EXPOSE 7860

# Volume per persistenza dei file di sincronizzazione (opzionale)
VOLUME ["/tmp"]

# 8. Comando ottimizzato per avviare Gunicorn con sincronizzazione:
#    - 4 worker gevent per sincronizzazione automatica
#    - connessioni keep-alive
#    - timeout adeguati
#    - logging su stdout/stderr
#    - File di sincronizzazione in /tmp/ (config, client stats, system stats)
CMD ["gunicorn", "app:app", \
     "-w", "4", \
     "--worker-class", "gevent", \
     "--worker-connections", "100", \
     "-b", "0.0.0.0:7860", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
