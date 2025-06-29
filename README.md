# 📺 tvproxy

Un server proxy leggero e dockerizzato basato su **Flask** e **Requests**, progettato per superare restrizioni e accedere a flussi M3U/M3U8 senza interruzioni.

- 📥 **Scarica e modifica** flussi `.m3u` e `.m3u8` al volo.  
- 🔁 **Proxa i segmenti** `.ts` mantenendo header personalizzati.  
- 🚫 **Supera restrizioni** comuni come `Referer`, `User-Agent`, ecc.  
- 🐳 **Facilmente dockerizzabile** su qualsiasi macchina, server o piattaforma cloud.  
- 🧰 **Dashboard web completa** per amministrazione e monitoraggio in tempo reale.

---

## 📚 Indice

- Configurazione Autenticazione  
- Configurazione per Server con 1 GB di RAM  
- Piattaforme di Deploy  
  - Render  
  - HuggingFace  
- Setup Locale  
  - Docker  
  - Termux (Android)  
  - Python  
- Dashboard di Amministrazione  
- Utilizzo del Proxy  
- Configurazione Proxy  
- Gestione Docker

---

## 🔐 Configurazione Autenticazione (OBBLIGATORIA)

### Variabili d'Ambiente di Sicurezza

| Variabile        | Descrizione                                                        | Obbligatoria | Default       |
|------------------|--------------------------------------------------------------------|--------------|---------------|
| `ADMIN_PASSWORD` | Password per accedere alla dashboard di amministrazione           | **SÌ**       | `password123` |
| `ADMIN_USERNAME` | Username per l'accesso (configurabile dalla web UI)               | No           | `admin`       |
| `SECRET_KEY`     | Chiave segreta per le sessioni Flask (configurabile dalla web UI) | No           | Auto-generata |
| `ALLOWED_IPS`    | Lista di IP autorizzati separati da virgola                       | No           | Tutti gli IP  |

> ⚠️  **Minimo necessario**: impostare `ADMIN_PASSWORD`.

```bash
# Esempio Docker
docker run -d -p 7860:7860 -e ADMIN_PASSWORD="tua_password_sicura" --name tvproxy tvproxy

# Esempio .env (Termux/Python)
echo "ADMIN_PASSWORD=tua_password_sicura" > .env
```

---

## 💾 Configurazione per Server con RAM Limitata (1 GB)

### 📋 `.env` ottimizzato

```dotenv
# OBBLIGATORIO
ADMIN_PASSWORD="tua_password_sicura"

# Ottimizzazioni memoria 
REQUEST_TIMEOUT=15
KEEP_ALIVE_TIMEOUT=120
MAX_KEEP_ALIVE_REQUESTS=100
POOL_CONNECTIONS=5
POOL_MAXSIZE=10

# Cache ridotta
CACHE_TTL_M3U8=3
CACHE_TTL_TS=60
CACHE_TTL_KEY=60
CACHE_MAXSIZE_M3U8=50
CACHE_MAXSIZE_TS=200
CACHE_MAXSIZE_KEY=50
```

---

## ☁️ Piattaforme di Deploy

### ▶️ Render

1. Projects → **New → Web Service** → *Public Git Repo*.  
2. Repository: `https://github.com/nzo66/tvproxy` → **Connect**.  
3. Scegli un nome, **Instance Type** `Free` (o superiore).  
4. Aggiungi la variabile `ADMIN_PASSWORD` in **Environment**.  
5. (Opzionale) Aggiungi `SOCKS5_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`.  
6. **Create Web Service**.

### 🧠 HuggingFace Spaces

1. Crea un nuovo **Space** (SDK: *Docker*).  
2. Carica `DockerfileHF` come `Dockerfile`.  
3. Vai in **Settings → Secrets** e aggiungi `ADMIN_PASSWORD`.  
4. (Opzionale) Aggiungi `HTTP_PROXY` + `HTTPS_PROXY` (SOCKS5 non supportato).  
5. Dopo ogni modifica alle variabili fai **Factory Rebuild**.

---

## 💻 Setup Locale

### 🐳 Docker

```bash
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
docker build -t tvproxy .

docker run -d -p 7860:7860 -e ADMIN_PASSWORD="tua_password_sicura" --name tvproxy tvproxy
```

### 📱 Termux (Android)

```bash
pkg update && pkg upgrade
pkg install git python nano -y

git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
pip install -r requirements.txt

echo "ADMIN_PASSWORD=tua_password_sicura" > .env

gunicorn app:app -w 4 --worker-class gevent -b 0.0.0.0:7860
```

### 🐍 Python

```bash
git clone https://github.com/nzo66/tvproxy.git
cd tvproxy
pip install -r requirements.txt

echo "ADMIN_PASSWORD=tua_password_sicura" > .env

gunicorn app:app -w 4 --worker-class gevent --worker-connections 100 \
        -b 0.0.0.0:7860 --timeout 120 --keep-alive 5 \
        --max-requests 1000 --max-requests-jitter 100
```

---

## 🧰 Dashboard di Amministrazione

- 🏠 Home: `http://<server-ip>:7860/`  
- 🔐 Login: `http://<server-ip>:7860/login`  
- 📊 Dashboard: `http://<server-ip>:7860/dashboard`  
- ⚙️ Config: `http://<server-ip>:7860/admin/config`  
- 📜 Log: `http://<server-ip>:7860/admin/logs`  
- 📈 API Stats: `http://<server-ip>:7860/stats`

Modifiche **senza riavvio** dal pannello web!

---

## 📡 Utilizzo del Proxy

Sostituisci `<server-ip>` con l'indirizzo del tuo server.

### 💡 Liste M3U

```
http://<server-ip>:7860/proxy?url=<URL_LISTA_M3U>
```

### 📺 Flussi M3U8 con headers

```
http://<server-ip>:7860/proxy/m3u?url=<URL_FLUSSO_M3U8>&h_<HEADER>=<VALORE>
```
Esempio:
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

---

## 🔧 Configurazione Proxy (Opzionale)

| Variabile      | Descrizione                                              | Esempio                                   |
|----------------|----------------------------------------------------------|-------------------------------------------|
| `SOCKS5_PROXY` | Uno o più proxy SOCKS5, separati da virgola              | `socks5://user:pass@host:port,...`        |
| `HTTP_PROXY`   | Proxy HTTP (usare in coppia con `HTTPS_PROXY`)           | `http://user:pass@host:port,...`          |
| `HTTPS_PROXY`  | Proxy HTTPS (di solito uguale a `HTTP_PROXY`)            | `http://user:pass@host:port,...`          |

Esempio `.env`:

```dotenv
ADMIN_PASSWORD="tua_password_sicura"
# SOCKS5_PROXY="socks5://user:pass@host1:1080"
# HTTP_PROXY="http://user:pass@host:8080"
# HTTPS_PROXY="http://user:pass@host:8080"
```

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

- Supporto automatico `.m3u` / `.m3u8`
- Headers personalizzati (`Authorization`, `Referer`, ...)
- Aggira restrizioni geografiche
- Compatibile con qualsiasi player IPTV
- Totalmente dockerizzato
- Dashboard web completa con statistiche, log, configurazioni
- Autenticazione sicura + whitelist IP
- Monitoraggio RAM / rete in tempo reale
- Cache intelligente M3U8 / TS / AES
- Configurazioni dinamiche **senza riavvio**

---

## 🎉 Enjoy the Stream!

> Goditi i tuoi flussi preferiti ovunque, senza restrizioni, con controllo completo e monitoraggio avanzato.