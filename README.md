# tvproxy 📺

Un server proxy avanzato e dockerizzato basato su **Flask** e **Requests**, progettato per superare restrizioni e accedere a flussi M3U/M3U8 senza interruzioni con funzionalità avanzate di monitoraggio e ottimizzazione.

- 📥 **Scarica e modifica** flussi `.m3u` e `.m3u8` al volo
- 🔁 **Proxa i segmenti** `.ts` mantenendo header personalizzati
- 🚫 **Supera restrizioni** comuni come `Referer`, `User-Agent`, ecc.
- 🐳 **Facilmente dockerizzabile** su qualsiasi macchina, server o piattaforma cloud
- 🧪 **Dashboard web completa** per amministrazione e monitoraggio in tempo reale
- ⚡ **Sistema di pre-buffering** per eliminare il buffering durante lo streaming
- 🌟 **Proxy DaddyLive dedicati** con gestione separata e blacklist automatica
- 🔍 **Risoluzione Vavoo** integrata per link Vavoo.to
- 📊 **WebSocket real-time** per statistiche live e aggiornamenti istantanei
- 🛡️ **Sistema di blacklist** intelligente per proxy con errori 429
- 🔧 **Configurazione dinamica** senza riavvio del server

---

## 📚 Indice

- [Configurazione Autenticazione](#-configurazione-autenticazione-obbligatoria)
- [Configurazione per Server con 1 GB di RAM](#-configurazione-per-server-con-ram-limitata-1-gb)
- [Piattaforme di Deploy](#️-piattaforme-di-deploy)
- [Setup Locale](#-setup-locale)
- [Dashboard di Amministrazione](#️-dashboard-di-amministrazione)
- [Utilizzo del Proxy](#-utilizzo-del-proxy)
- [Configurazione Proxy](#-configurazione-proxy-opzionale)
- [Proxy DaddyLive Dedicati](#-proxy-daddylive-dedicati)
- [Sistema di Pre-Buffering](#-sistema-di-pre-buffering)
- [Risoluzione Vavoo](#-risoluzione-vavoo)
- [Gestione Docker](#-gestione-docker-rapida)
- [Caratteristiche Principali](#-caratteristiche-principali)

---

## 🔐 Configurazione Autenticazione (OBBLIGATORIA)

### Variabili d'Ambiente di Sicurezza

| Variabile        | Descrizione                                                         | Obbligatoria | Default       |
|------------------|---------------------------------------------------------------------|--------------|---------------|
| `ADMIN_PASSWORD` | Password per accedere alla dashboard di amministrazione            | **SÌ**       | `password123` |
| `SECRET_KEY`     | Chiave segreta per le sessioni Flask (deve essere univoca e sicura) | **SÌ**       | Nessuna       |

> ⚠️  **IMPORTANTE**: Solo `ADMIN_PASSWORD` e `SECRET_KEY` devono essere impostati come variabili d'ambiente.  
> 🔧 **Tutte le altre configurazioni** (proxy, cache, pre-buffering, timeout, ecc.) devono essere gestite dal **pannello web** di amministrazione.  
> 🚫 **Le variabili d'ambiente `PROXY` e `DADDY_PROXY` non sono più utilizzate** - i proxy vengono configurati solo tramite il pannello web.  
> 🔑 Usa un valore univoco per `SECRET_KEY`, ad esempio generato con:  
> `openssl rand -hex 32`  
> oppure:  
> `python -c 'import secrets; print(secrets.token_hex(32))'`

---

### 🐳 Esempio Docker

```bash
docker run -d -p 7860:7860 \
  -e ADMIN_PASSWORD=tua_password_sicura \
  -e SECRET_KEY=1f4d8e9a6c57bd2eec914d93cfb7a3efb9ae67f2643125c89cc3c50e75c4d4c3 \
  --name tvproxy tvproxy
```

---

### 📦 Esempio `.env` (Termux / Python)

```dotenv
# SOLO queste due variabili sono necessarie
ADMIN_PASSWORD=tua_password_sicura
SECRET_KEY=1f4d8e9a6c57bd2eec914d93cfb7a3efb9ae67f2643125c89cc3c50e75c4d4c3
```

---

## 💾 Configurazione per Server con RAM Limitata (1 GB)

### 📃 Configurazione Ottimizzata

Per server con RAM limitata, configura le seguenti impostazioni dal pannello web di amministrazione:

#### Ottimizzazioni Memoria
- **REQUEST_TIMEOUT**: 30
- **KEEP_ALIVE_TIMEOUT**: 120
- **MAX_KEEP_ALIVE_REQUESTS**: 100
- **POOL_CONNECTIONS**: 5
- **POOL_MAXSIZE**: 10

#### Cache Ridotta
- **CACHE_TTL_M3U8**: 2
- **CACHE_TTL_TS**: 60
- **CACHE_TTL_KEY**: 60
- **CACHE_MAXSIZE_M3U8**: 50
- **CACHE_MAXSIZE_TS**: 200
- **CACHE_MAXSIZE_KEY**: 50

#### Pre-buffering Ridotto
- **PREBUFFER_ENABLED**: true
- **PREBUFFER_MAX_SEGMENTS**: 2
- **PREBUFFER_MAX_SIZE_MB**: 20
- **PREBUFFER_MAX_MEMORY_PERCENT**: 15

---

## 🚫 Disattivare la Cache per Streaming Diretto

Se vuoi **disabilitare completamente la cache** (ad esempio per streaming diretto e contenuti sempre aggiornati), puoi farlo dal pannello web di amministrazione:

1. Accedi alla dashboard: `http://<server-ip>:7860/login`
2. Vai su **Config** → **Configurazione**
3. Imposta **CACHE_ENABLED** su `false`
4. Salva la configurazione

La cache verrà disabilitata immediatamente senza bisogno di riavviare il server.

---

## ☁️ Piattaforme di Deploy

### ▶️ Render

1. Projects → **New → Web Service** → *Public Git Repo*.
2. Repository: `https://github.com/nzo66/tvproxy` → **Connect**.
3. Scegli un nome, **Instance Type** `Free` (o superiore).
4. Aggiungi le variabili `ADMIN_PASSWORD` e `SECRET_KEY` nell'area **Environment**.
6. **Create Web Service**.

### 🤖 HuggingFace Spaces

1. Crea un nuovo **Space** (SDK: *Docker*).
2. Carica `DockerfileHF` come `Dockerfile`.
3. Vai in **Settings → Secrets** e aggiungi `ADMIN_PASSWORD` e `SECRET_KEY`.
4. **OBBLIGATORIO**: Configura `DADDY PROXY` dal pannello web per servizi DaddyLive (SOCKS5 non supportato su HF).
6. Dopo ogni modifica alle variabili fai **Factory Rebuild**.

**⚠️ IMPORTANTE: Configurazione HuggingFace**
- La configurazione viene salvata **in memoria** e non persiste dopo il riavvio
- Per configurazione permanente, usa i **Secrets di HuggingFace** (solo `ADMIN_PASSWORD` e `SECRET_KEY`)
- **Tutte le altre configurazioni** (proxy, cache, timeout, ecc.) vengono gestite solo dal pannello web
- Il pannello web mostra un avviso quando rileva l'ambiente HuggingFace
- Usa il pulsante **"Stato Config"** per verificare lo stato della configurazione

#### **Configurazione Ottimizzata per HuggingFace**

Per **HuggingFace Spaces**, è **OBBLIGATORIO** utilizzare questa configurazione ottimizzata. Aggiungi le seguenti variabili nei **Secrets** del tuo Space:

```dotenv
# OBBLIGATORIO
ADMIN_PASSWORD=tua_password_sicura
SECRET_KEY=chiave_segreta_generata
```

**Configurazione dal Pannello Web**
Dopo il deploy, accedi alla dashboard e configura le seguenti impostazioni ottimizzate per HuggingFace:

**Proxy DaddyLive (OBBLIGATORIO per HuggingFace)**
- Usa solo proxy HTTP/HTTPS (SOCKS5 non supportato su HF)
- Configura dal pannello web: **Config** → **Configurazione** → **Proxy DaddyLive**

**⚠️ IMPORTANTE**: Tutte le configurazioni tecniche (proxy, cache, timeout, pool, pre-buffering) vengono gestite **solo tramite il pannello web**.

**Cache Ottimizzata**
- **CACHE_TTL_M3U8**: 5
- **CACHE_MAXSIZE_M3U8**: 500
- **CACHE_TTL_TS**: 600
- **CACHE_MAXSIZE_TS**: 8000
- **CACHE_TTL_KEY**: 600
- **CACHE_MAXSIZE_KEY**: 1000

**Pool di Connessioni Potenziato**
- **POOL_CONNECTIONS**: 50
- **POOL_MAXSIZE**: 300
- **MAX_KEEP_ALIVE_REQUESTS**: 5000
- **KEEP_ALIVE_TIMEOUT**: 900
- **REQUEST_TIMEOUT**: 45

**Pre-buffering ottimizzato**
- **PREBUFFER_EMERGENCY_THRESHOLD**: 99.9
- **PREBUFFER_MAX_SEGMENTS**: 5
- **PREBUFFER_MAX_SIZE_MB**: 200
- **PREBUFFER_MAX_MEMORY_PERCENT**: 30

**Domini senza proxy**
- **NO_PROXY_DOMAINS**: github.com,raw.githubusercontent.com

**Perché questa configurazione?**
- **DADDY_PROXY Obbligatorio**: HuggingFace richiede proxy HTTP/HTTPS per servizi DaddyLive
- **Cache Ottimizzata**: Valori più elevati per gestire meglio i flussi video frequenti
- **Pool di Connessioni Potenziato**: Gestisce più connessioni simultanee nell'ambiente cloud
- **Timeout Bilanciati**: Equilibrio tra stabilità e performance per connessioni di lunga durata
- **Pre-buffering Intelligente**: Riduce il buffering durante lo streaming

> ⚠️ **IMPORTANTE**: Su HuggingFace Spaces, i proxy SOCKS5 non sono supportati. Usa solo proxy HTTP/HTTPS per `DADDY_PROXY`.

### 🔧 Risoluzione Problemi

**Problema: "Configurazione persa dopo riavvio"**
- **Causa**: La cache in memoria viene cancellata al riavvio
- **Soluzione**: Esporta la configurazione e importala dopo il riavvio

---

## 💻 Setup Locale

### 🐳 Docker

```bash
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
docker build -t tvproxy .

docker run -d -p 7860:7860 \
  -e ADMIN_PASSWORD=tua_password_sicura \
  -e SECRET_KEY=chiave_segreta_generata \
  --name tvproxy tvproxy
```

**🐳 Docker con Sincronizzazione (Raccomandato)**
```bash
# Usa il volume per persistenza dei file di sincronizzazione
docker run -d -p 7860:7860 \
  -e ADMIN_PASSWORD=tua_password_sicura \
  -e SECRET_KEY=chiave_segreta_generata \
  -v tvproxy_sync:/tmp \
  --name tvproxy tvproxy
```

**🐳 Docker per HuggingFace**
```bash
# Usa DockerfileHF per HuggingFace Spaces
docker build -f DockerfileHF -t tvproxy-hf .
```

**🐳 Docker Compose (Raccomandato)**
```bash
# Modifica le credenziali in docker-compose.yml
nano docker-compose.yml

# Avvia con docker-compose
docker-compose up -d

# Visualizza i log
docker-compose logs -f

# Ferma il servizio
docker-compose down
```

### 🐧 Termux (Android)

```bash
pkg update && pkg upgrade
pkg install git python nano -y

git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
pip install -r requirements.txt

# SOLO queste due variabili sono necessarie
echo "ADMIN_PASSWORD=tua_password_sicura" > .env
echo "SECRET_KEY=chiave_segreta_generata" >> .env

gunicorn app:app -w 4 --worker-class gevent -b 0.0.0.0:7860
```

### 🐍 Python

```bash
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
pip install -r requirements.txt

# SOLO queste due variabili sono necessarie
echo "ADMIN_PASSWORD=tua_password_sicura" > .env
echo "SECRET_KEY=chiave_segreta_generata" >> .env

gunicorn app:app -w 4 --worker-class gevent --worker-connections 100 \
        -b 0.0.0.0:7860 --timeout 120 --keep-alive 5 \
        --max-requests 1000 --max-requests-jitter 100
```

---

## 🎛️ Dashboard di Amministrazione

- **🏠 Home**: `http://<server-ip>:7860/`
- **🔐 Login**: `http://<server-ip>:7860/login`
- **📊 Dashboard**: `http://<server-ip>:7860/dashboard`
- **⚙️ Config**: `http://<server-ip>:7860/admin/config`
- **📝 Log**: `http://<server-ip>:7860/admin/logs`
- **👥 Client**: `http://<server-ip>:7860/admin/clients`
- **📈 API Stats**: `http://<server-ip>:7860/stats`

### 🆕 Nuove Funzionalità Dashboard

- **📊 Statistiche Real-time**: WebSocket per aggiornamenti istantanei
- **🛡️ Gestione Proxy**: Monitoraggio blacklist e stato proxy
- **⚡ Pre-buffering**: Controllo e configurazione del sistema di pre-buffering
- **💾 Gestione Memoria**: Monitoraggio RAM e pulizia automatica
- **👥 Tracking Client**: Statistiche sui client connessi e loro utilizzo
- **🔧 Configurazione Dinamica**: Modifica impostazioni senza riavvio
- **🔑 Debug Sessioni**: Monitoraggio sincronizzazione sessioni tra workers

---

## 🧰 Utilizzo del Proxy

Sostituisci `<server-ip>` con l'indirizzo del tuo server.

### 💡 Liste M3U

```
http://<server-ip>/proxy?url=<URL_LISTA_M3U>
```

### 📺 Flussi M3U8 con headers

```
http://<server-ip>/proxy/m3u?url=<URL_FLUSSO_M3U8>&h_<HEADER>=<VALORE>
```

Esempio:
```
.../proxy/m3u?url=https://example.com/stream.m3u8&h_user-agent=VLC/3.0.20&h_referer=https://example.com/
```

### 🔍 Risoluzione DaddyLive 2025

```
http://<server-ip>/proxy/resolve?url=<URL_DADDYLIVE>
```

### 🌟 Risoluzione Vavoo

```
http://<server-ip>/proxy/vavoo?url=<URL_VAVOO>
```

Esempio:
```
.../proxy/vavoo?url=https://vavoo.to/vavoo-iptv/play/277580225585f503fbfc87
```

### ⚡ Pre-buffering Manuale

```
http://<server-ip>/proxy/prebuffer?m3u8_url=<URL_M3U8>&stream_id=<ID_STREAM>
```

### 🔑 Chiavi AES-128

```
http://<server-ip>/proxy/key?url=<URL_CHIAVE>&h_<HEADER>=<VALORE>
```

---

## 🔁 Configurazione Proxy (Opzionale)

> ⚠️ **IMPORTANTE**: La configurazione dei proxy deve essere fatta dal **pannello web** di amministrazione (`/admin/config`), NON tramite variabili d'ambiente.

### Proxy Supportati

| Tipo        | Descrizione                                                  | Esempio                                   |
|-------------|--------------------------------------------------------------|-------------------------------------------|
| **SOCKS5**  | Proxy SOCKS5 con riconoscimento automatico                   | `socks5://user:pass@host:port`            |
| **HTTP**    | Proxy HTTP con riconoscimento automatico                     | `http://user:pass@host:port`              |
| **HTTPS**   | Proxy HTTPS con riconoscimento automatico                    | `https://user:pass@host:port`             |

### 🌟 Proxy DaddyLive Dedicati

Il sistema supporta proxy dedicati per servizi DaddyLive, configurati separatamente dai proxy generali.

**Riconoscimento Automatico**: Il sistema rileva automaticamente il tipo di proxy (SOCKS5, HTTP, HTTPS) e normalizza gli URL.

### Configurazione dal Pannello Web

1. Accedi alla dashboard: `http://<server-ip>:7860/login`
2. Vai su **Config** → **Configurazione**
3. Inserisci i proxy nei campi:
   - **Proxy Generali**: Per tutte le richieste
   - **Proxy DaddyLive**: Solo per servizi DaddyLive
   - **Domini senza proxy**: Domini da escludere dal proxy

### Formati Supportati

```
# Proxy singoli
socks5://user:pass@host:port
http://user:pass@host:port
https://user:pass@host:port

# Proxy multipli (separati da virgola)
socks5://proxy1:1080,http://proxy2:8080,https://proxy3:8443

# Senza autenticazione
socks5://host:port
http://host:port
```

---

## 🌟 Proxy DaddyLive Dedicati

### Come Funziona

Il sistema utilizza proxy dedicati per i servizi DaddyLive, identificati automaticamente da:

- **Domini**: `newkso.ru` (qualsiasi sottodominio)
- **Path**: URL che contengono `/stream-` nel percorso
- **Fallback**: Se i proxy DaddyLive non sono disponibili, usa i proxy normali

### Vantaggi

- **🎯 Ottimizzazione**: Proxy dedicati per servizi specifici
- **🛡️ Blacklist Separata**: Gestione errori 429 indipendente
- **📊 Statistiche Dedicati**: Monitoraggio separato per proxy DaddyLive
- **🔄 Fallback Automatico**: Passaggio ai proxy normali se necessario

### Configurazione

I proxy DaddyLive dedicati vengono configurati dal pannello web di amministrazione nella sezione **Config** → **Configurazione**.

---

## ⚡ Sistema di Pre-Buffering

### Caratteristiche

- **🚀 Pre-scarica**: I segmenti successivi vengono scaricati in background
- **💾 Gestione Memoria**: Controllo automatico dell'uso RAM
- **🔄 Pulizia Automatica**: Rimozione buffer inattivi
- **⚙️ Configurabile**: Parametri personalizzabili dall'interfaccia web

### Configurazione

Il sistema di pre-buffering viene configurato dal pannello web di amministrazione nella sezione **Config** → **Configurazione**.

### Endpoint di Gestione

- **📊 Stato**: `/admin/prebuffer/status`
- **🧹 Pulizia**: `/admin/prebuffer/clear`
- **🧪 Test**: `/admin/prebuffer/test`
- **💾 Memoria**: `/admin/memory/status`

---

## 🔍 Risoluzione Vavoo

### Supporto Integrato

Il sistema include risoluzione automatica per link Vavoo:

- **🔗 Pattern Supportati**:
  - `https://vavoo.to/vavoo-iptv/play/[ID]`
  - `https://vavoo.to/play/[ID]`

- **🎯 Endpoint Dedicato**: `/proxy/vavoo?url=<URL_VAVOO>`

### Esempio

```
http://<server-ip>/proxy/vavoo?url=https://vavoo.to/vavoo-iptv/play/277580225585f503fbfc87
```

### Caratteristiche

- **🔄 Retry Automatico**: Tentativi multipli per errori temporanei
- **🛡️ Gestione Errori**: Fallback all'URL originale in caso di errore
- **📊 Logging Dettagliato**: Tracciamento completo del processo di risoluzione

---

## 🛡️ Sistema di Blacklist Proxy

### Gestione Errori 429

- **⏰ Blacklist Temporanea**: 5 minuti per errori 429
- **🔒 Blacklist Permanente**: 1 ora dopo 5 errori consecutivi
- **🔄 Pulizia Automatica**: Rimozione automatica dei proxy scaduti
- **📊 Statistiche Separate**: Conteggi distinti per proxy normali e DaddyLive

### Configurazione

I domini da escludere dal proxy vengono configurati dal pannello web di amministrazione nella sezione **Config** → **Configurazione**.

---

## 🐳 Gestione Docker Rapida

```bash
docker logs -f tvproxy      # log in tempo reale
docker stop tvproxy         # ferma il container
docker start tvproxy        # avvia il container
docker rm -f tvproxy        # rimuovi il container
```

---

## ✅ Caratteristiche Principali

### 🔧 Funzionalità Core
- ✅ Supporto automatico `.m3u` / `.m3u8`
- ✅ Headers personalizzati (`Authorization`, `Referer`, ...)
- ✅ Aggira restrizioni geografiche
- ✅ Compatibile con qualsiasi player IPTV
- ✅ Totalmente dockerizzato

### 🎛️ Dashboard Avanzata
- ✅ Dashboard web completa con statistiche, log, configurazioni
- ✅ Autenticazione sicura + whitelist IP
- ✅ Monitoraggio RAM / rete in tempo reale
- ✅ Cache intelligente M3U8 / TS / AES
- ✅ Configurazioni dinamiche **senza riavvio**

### 🌟 Nuove Funzionalità
- ✅ **Proxy DaddyLive dedicati** con gestione separata
- ✅ **Sistema di pre-buffering** per eliminare il buffering
- ✅ **Risoluzione Vavoo** integrata
- ✅ **WebSocket real-time** per statistiche live
- ✅ **Sistema di blacklist** intelligente per proxy
- ✅ **Tracking client** con statistiche dettagliate
- ✅ **Gestione memoria** avanzata con pulizia automatica
- ✅ **Retry logic** per errori temporanei
- ✅ **Riconoscimento automatico** tipo proxy (SOCKS5, HTTP, HTTPS)
- ✅ **Statistiche IP** (IPv4, IPv6, hostname) separate per tipo proxy

---

## 🎉 Enjoy the Stream!

> Goditi i tuoi flussi preferiti ovunque, senza restrizioni, con controllo completo e monitoraggio avanzato. Il sistema ora include funzionalità enterprise per gestione proxy avanzata, pre-buffering intelligente e risoluzione automatica di servizi popolari.
