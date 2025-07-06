# TVProxy - Server Proxy per Streaming TV

Un server proxy leggero e veloce per streaming TV, ottimizzato per DaddyLive, Vavoo e altri servizi IPTV. Configurabile tramite variabili d'ambiente, senza interfaccia web.

## Caratteristiche

- **Proxy intelligente**: Supporto per DaddyLive, Vavoo e altri servizi IPTV
- **Caching avanzato**: Cache per M3U8, segmenti TS e chiavi AES-128
- **Pre-buffering**: Pre-caricamento segmenti per streaming fluido
- **Proxy multipli**: Rotazione automatica tra proxy HTTP/SOCKS5
- **Proxy specifici**: Proxy dedicati per DaddyLive
- **Connessioni persistenti**: Keep-alive per performance ottimali
- **Multi-client**: Gunicorn per gestire più clienti simultaneamente
- **Configurazione via env**: Nessun file di configurazione necessario

## Installazione

### HuggingFace Spaces (Più Semplice)

Il progetto è **già pronto** per HuggingFace Spaces! Basta:

1. **Crea un nuovo Space** (SDK: Docker)
2. **Carica il codice** del repository  
3. **Vai in Settings → Secrets** e aggiungi le variabili proxy:
   ```
   PROXY=socks5://user:pass@proxy.com:1080
   DADDY_PROXY=socks5://daddy-proxy.com:1080
   ```
4. **Fai Factory Rebuild** dopo aver aggiunto le variabili

Il server sarà subito disponibile all'URL del tuo Space!

### Docker (Raccomandato)

```bash
# Clona il repository
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy

# Crea il file .env con le tue configurazioni
cp .env.example .env
# Modifica .env con le tue impostazioni

# Avvia con Docker
docker build -t tvproxy .
docker run -d --name tvproxy -p 7860:7860 --env-file .env tvproxy
```

### Installazione diretta

```bash
# Clona il repository
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy

# Installa dipendenze
pip install -r requirements.txt

# Crea il file .env
cp .env.example .env
# Modifica .env con le tue impostazioni

# Avvia il server
python app.py
```

## Configurazione

Copia `.env.example` in `.env` e configura le variabili:

### Configurazione essenziale

```bash
# Proxy generali (HTTP, HTTPS, SOCKS5)
PROXY=socks5://user:pass@proxy1.com:1080,http://proxy2.com:8080

# Proxy specifici per DaddyLive
DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080

# Domini da non proxy (separati da virgola)
NO_PROXY_DOMAINS=github.com,raw.githubusercontent.com

# Timeout richieste (secondi)
REQUEST_TIMEOUT=30

# Verifica SSL (true/false)
VERIFY_SSL=false
```

### Configurazione avanzata

```bash
# Cache
CACHE_ENABLED=true
CACHE_TTL_M3U8=5
CACHE_TTL_TS=300
CACHE_TTL_KEY=300
CACHE_MAXSIZE_M3U8=200
CACHE_MAXSIZE_TS=1000
CACHE_MAXSIZE_KEY=200

# Pre-buffering
PREBUFFER_ENABLED=true
PREBUFFER_MAX_SEGMENTS=3
PREBUFFER_MAX_SIZE_MB=50
PREBUFFER_MAX_MEMORY_PERCENT=30.0

# Connessioni persistenti
KEEP_ALIVE_TIMEOUT=300
MAX_KEEP_ALIVE_REQUESTS=1000
POOL_CONNECTIONS=20
POOL_MAXSIZE=50
```

### Esempio per server 1GB RAM

```bash
# Configurazione ottimizzata per server con 1GB RAM
CACHE_ENABLED=false
PREBUFFER_MAX_SEGMENTS=2
PREBUFFER_MAX_SIZE_MB=25
POOL_CONNECTIONS=5
POOL_MAXSIZE=10
```

## Utilizzo

### Proxy per liste M3U

```
http://tuo-server:7860/proxy?url=http://esempio.com/lista.m3u
```

### Proxy per singoli canali M3U8

```
http://tuo-server:7860/proxy/m3u?url=http://esempio.com/canale.m3u8
```

### Risoluzione DaddyLive

```
http://tuo-server:7860/proxy/resolve?url=123
```

### Test Vavoo

```
http://tuo-server:7860/proxy/vavoo?url=https://vavoo.to/vavoo-iptv/play/277580225585f503fbfc87
```

## Architettura

### Gunicorn per Multi-Client

Il server usa Gunicorn per gestire più clienti simultaneamente:

- **4 worker** in produzione (2 per HuggingFace Spaces)
- **Worker sync** per stabilità con proxy HTTP
- **Timeout 120s** per streaming
- **Keep-alive** per connessioni persistenti
- **Max requests** per riciclo worker

### Sistema di Cache

- **M3U8 Cache**: Playlist HLS (5s TTL)
- **TS Cache**: Segmenti video (5min TTL)  
- **Key Cache**: Chiavi AES-128 (5min TTL)

### Pre-Buffering

- Pre-carica i prossimi segmenti in background
- Controllo memoria automatico
- Pulizia emergenza se RAM > 90%
- Configurabile per dimensione e numero segmenti

## Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  tvproxy:
    build: .
    ports:
      - "7860:7860"
    env_file:
      - .env
         restart: unless-stopped
```

### HuggingFace Spaces

Il progetto è **già pronto** per HuggingFace Spaces! Include `DockerfileHF` ottimizzato:

1. **Crea un nuovo Space** (SDK: Docker)
2. **Carica il codice** del repository
3. **Vai in Settings → Secrets** e aggiungi le variabili proxy:
   ```
   PROXY=socks5://user:pass@proxy.com:1080
   DADDY_PROXY=socks5://daddy-proxy.com:1080
   ```
4. **Fai Factory Rebuild** dopo aver aggiunto le variabili

**Configurazione ottimizzata per Spaces:**
- 2 worker (limite gratuito)
- Configurazione memoria ridotta
- Logging su stdout/stderr
- Impostazioni di default già ottimizzate

## Logs

I log vengono mostrati solo su console (stdout/stderr):
- Nessun file di log salvato
- Log level INFO
- Output visibile nei log del container/processo

## Supporto

Per problemi o domande, apri una issue su GitHub.
