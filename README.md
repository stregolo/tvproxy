# 🚀 TVProxy - Server Proxy per Streaming TV

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![HuggingFace](https://img.shields.io/badge/HuggingFace-Spaces-yellow.svg)](https://huggingface.co/spaces)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Un server proxy leggero e veloce per streaming TV** 🎬  
> Ottimizzato per DaddyLive, Vavoo e altri servizi IPTV  
> Configurabile tramite variabili d'ambiente, senza interfaccia web

---

## 📚 Indice

- [💾 Configurazione per Server con 1 GB di RAM](#-configurazione-per-server-con-1-gb-di-ram)
- [☁️ Piattaforme di Deploy](#️-piattaforme-di-deploy)
- [💻 Setup Locale](#-setup-locale)
- [🧰 Utilizzo del Proxy](#-utilizzo-del-proxy)
- [🔁 Configurazione Proxy](#-configurazione-proxy-opzionale)
- [🐳 Gestione Docker Rapida](#-gestione-docker-rapida)

---

## ✨ Caratteristiche Principali

| 🎯 **Proxy Intelligente** | 🔄 **Caching Avanzato** | ⚡ **Pre-buffering** |
|---------------------------|-------------------------|---------------------|
| Supporto DaddyLive, Vavoo e IPTV | Cache M3U8, TS e chiavi AES-128 | Pre-caricamento segmenti |

| 🌐 **Proxy Multipli** | 🔒 **Proxy Specifici** | 🚀 **Performance** |
|----------------------|----------------------|-------------------|
| Rotazione automatica HTTP/SOCKS5 | Proxy dedicati DaddyLive | Keep-alive e connessioni persistenti |

---

## 💾 Configurazione per Server con 1 GB di RAM

### 📃 `.env` ottimizzato

```dotenv
# Proxy (opzionale)
PROXY=socks5://user:pass@proxy1.com:1080,http://proxy2.com:8080
DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080

# Ottimizzazioni memoria
REQUEST_TIMEOUT=30
KEEP_ALIVE_TIMEOUT=120
MAX_KEEP_ALIVE_REQUESTS=100
POOL_CONNECTIONS=5
POOL_MAXSIZE=10

# Cache ridotta
CACHE_ENABLED=true
CACHE_TTL_M3U8=2
CACHE_TTL_TS=60
CACHE_TTL_KEY=60
CACHE_MAXSIZE_M3U8=50
CACHE_MAXSIZE_TS=200
CACHE_MAXSIZE_KEY=50

# Pre-buffering ridotto
PREBUFFER_ENABLED=true
PREBUFFER_MAX_SEGMENTS=2
PREBUFFER_MAX_SIZE_MB=25
PREBUFFER_MAX_MEMORY_PERCENT=20.0
PREBUFFER_EMERGENCY_THRESHOLD=90
```

### 🚫 Disattivare la Cache per Streaming Diretto

Se vuoi **disabilitare completamente la cache** (ad esempio per streaming diretto e contenuti sempre aggiornati), puoi farlo aggiungendo questa riga al tuo file `.env`:

```dotenv
CACHE_ENABLED=false
```

---

## ☁️ Piattaforme di Deploy

### ▶️ Render

1. **Projects** → **New → Web Service** → *Public Git Repo*
2. **Repository**: `https://github.com/nzo66/tvproxy` → **Connect**
3. Scegli un nome, **Instance Type** `Free` (o superiore)
4. Aggiungi le variabili proxy nell'area **Environment** (opzionale)
5. **Create Web Service**

### 🤖 HuggingFace Spaces

1. Crea un nuovo **Space** (SDK: *Docker*)
2. Carica `DockerfileHF` come `Dockerfile`
3. Vai in **Settings → Secrets** e aggiungi **solo i proxy**:
   ```
   PROXY=socks5://user:pass@proxy.com:1080
   DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080
   ```
4. **Factory Rebuild** dopo aver aggiunto le variabili

🎉 **Fatto!** Il server è già ottimizzato per HuggingFace Spaces con configurazioni predefinite perfette.

#### **Configurazione Avanzata (Opzionale)**

Se vuoi personalizzare ulteriormente, puoi aggiungere queste variabili nei **Secrets**:

```dotenv
# Proxy (obbligatorio se necessario)
PROXY=socks5://user:pass@proxy.com:1080
DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080

# Configurazioni avanzate (già ottimizzate di default)
CACHE_TTL_M3U8=5
CACHE_MAXSIZE_M3U8=500
CACHE_TTL_TS=600
CACHE_MAXSIZE_TS=8000
POOL_CONNECTIONS=50
POOL_MAXSIZE=300
REQUEST_TIMEOUT=45
NO_PROXY_DOMAINS=github.com
```

**Nota**: Le configurazioni di default sono già ottimizzate per HuggingFace Spaces. Devi configurare solo i proxy se necessario!

---

## 💻 Setup Locale

### 🐳 Docker

```bash
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
docker build -t tvproxy .

docker run -d -p 7860:7860 \
  -e PROXY=socks5://user:pass@proxy.com:1080 \
  -e DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080 \
  --name tvproxy tvproxy
```

### 🐧 Termux (Android)

```bash
pkg update && pkg upgrade
pkg install git python nano -y

git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
pip install -r requirements.txt

echo "PROXY=socks5://user:pass@proxy.com:1080" > .env
echo "DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080" >> .env

gunicorn app:app -w 4 --worker-class gevent -b 0.0.0.0:7860
```

### 🐍 Python

```bash
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
pip install -r requirements.txt

echo "PROXY=socks5://user:pass@proxy.com:1080" > .env
echo "DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080" >> .env

gunicorn app:app -w 4 --worker-class gevent --worker-connections 100 \
        -b 0.0.0.0:7860 --timeout 120 --keep-alive 5 \
        --max-requests 1000 --max-requests-jitter 100
```

---

## 🧰 Utilizzo del Proxy

Sostituisci `<server-ip>` con l'indirizzo del tuo server.

### 💡 Liste M3U

```
http://<server-ip>:7860/proxy?url=<URL_LISTA_M3U>
```

### 📺 Flussi M3U8 con headers

```
http://<server-ip>:7860/proxy/m3u?url=<URL_FLUSSO_M3U8>&h_<HEADER>=<VALORE>
```

**Esempio:**
```
.../proxy/m3u?url=https://example.com/stream.m3u8&h_user-agent=VLC/3.0.20&h_referer=https://example.com/
```

### 🔍 Risoluzione DaddyLive 2025

```
http://<server-ip>:7860/proxy/resolve?url=<URL_DADDYLIVE>
```

### 🔑 Chiavi AES-128

```
http://<server-ip>:7860/proxy/key?url=<URL_CHIAVE>&h_<HEADER>=<VALORE>
```

### 🧪 Test Vavoo

```
http://<server-ip>:7860/proxy/vavoo?url=https://vavoo.to/vavoo-iptv/play/277580225585f503fbfc87
```

---

## 🔁 Configurazione Proxy (Opzionale)

### 📋 Tipi di Proxy

| Variabile          | Descrizione                                                  | Esempio                                   |
|--------------------|--------------------------------------------------------------|-------------------------------------------|
| `PROXY`            | **Proxy generali** - Usato per TUTTI i servizi (Vavoo, IPTV, ecc.) | `socks5://user:pass@host:port,...`        |
| `DADDY_PROXY`      | **Proxy specifici** - Usato SOLO per DaddyLive              | `socks5://user:pass@host:port,...`        |
| `NO_PROXY_DOMAINS` | Domini da escludere dal proxy, separati da virgola           | `github.com,vavoo.to`                     |

### 🎯 Come Funziona

- **`PROXY`**: Proxy universale per tutti i servizi (Vavoo, IPTV, download, ecc.)
- **`DADDY_PROXY`**: Proxy dedicato solo per i domini DaddyLive
- **Priorità**: Se entrambi sono configurati, DaddyLive userà `DADDY_PROXY`, tutto il resto userà `PROXY`

### 📝 Esempio `.env`

```dotenv
# Proxy generali per tutti i servizi
PROXY=socks5://user:pass@host1:1080,http://user:pass@host2:8080

# Proxy specifici solo per DaddyLive
DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080

# Domini esclusi dal proxy
NO_PROXY_DOMAINS=github.com,vavoo.to
```

**Risultato:**
- ✅ **DaddyLive** → usa `DADDY_PROXY`
- ✅ **Vavoo, IPTV, altri** → usano `PROXY`
- ✅ **github.com, vavoo.to** → connessione diretta (no proxy)

---

## 🐳 Gestione Docker Rapida

```bash
docker logs -f tvproxy      # log in tempo reale
docker stop tvproxy         # ferma il container
docker start tvproxy        # avvia il container
docker rm -f tvproxy        # rimuovi il container
```

---

## ⚙️ Configurazione Avanzata

### 🔧 Configurazione Essenziale

```bash
# Proxy generali (HTTP, HTTPS, SOCKS5)
PROXY=socks5://user:pass@proxy1.com:1080,http://proxy2.com:8080

# Proxy specifici per DaddyLive
DADDY_PROXY=socks5://user:pass@daddy-proxy.com:1080

# Domini da non proxy
NO_PROXY_DOMAINS=github.com,raw.githubusercontent.com

# Timeout e SSL
REQUEST_TIMEOUT=30
VERIFY_SSL=false
```

### ⚡ Configurazione Avanzata

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
PREBUFFER_CLEANUP_INTERVAL=300
PREBUFFER_EMERGENCY_THRESHOLD=99.9

# Connessioni
KEEP_ALIVE_TIMEOUT=300
MAX_KEEP_ALIVE_REQUESTS=1000
POOL_CONNECTIONS=20
POOL_MAXSIZE=50
```

---

## 🏗️ Architettura

### 🔄 Gunicorn Multi-Client

| **Worker** | **Timeout** | **Keep-alive** | **Max Requests** |
|------------|-------------|----------------|------------------|
| 4 (prod) / 2 (HF) | 120s | ✅ | Riciclo automatico |

### 💾 Sistema di Cache

| **Tipo** | **TTL** | **Descrizione** |
|----------|---------|-----------------|
| M3U8 | 5s | Playlist HLS |
| TS | 5min | Segmenti video |
| Key | 5min | Chiavi AES-128 |

### ⚡ Pre-Buffering

- ✅ Pre-carica segmenti in background
- 🧠 Controllo memoria automatico
- 🚨 Pulizia emergenza (RAM > 90%)
- ⚙️ Configurabile dimensione e numero

---

## ✅ Caratteristiche Principali

- Supporto automatico `.m3u` / `.m3u8`
- Headers personalizzati (`Authorization`, `Referer`, ...)
- Aggira restrizioni geografiche
- Compatibile con qualsiasi player IPTV
- Totalmente dockerizzato
- Cache intelligente M3U8 / TS / AES
- Pre-buffering per streaming fluido
- Risoluzione Vavoo integrata
- Supporto DaddyLive 2025

---

## 📝 Logs

I log vengono mostrati solo su console (stdout/stderr):
- ❌ Nessun file di log salvato
- 📊 Log level INFO
- 👀 Output visibile nei log del container/processo

---

## 🤝 Supporto

Per problemi o domande, apri una issue su GitHub.

---

<div align="center">

**⭐ Se questo progetto ti è utile, lascia una stella! ⭐**

> 🎉 **Enjoy the Stream!**  
> Goditi i tuoi flussi preferiti ovunque, senza restrizioni, con controllo completo e monitoraggio avanzato.

</div>
****
