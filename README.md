# tvproxy 📺

Un server proxy leggero e dockerizzato basato su **Flask** e **Requests**, progettato per superare restrizioni e accedere a flussi M3U/M3U8 senza interruzioni.

- 📥 **Scarica e modifica** flussi `.m3u` e `.m3u8` al volo.
- 🔁 **Proxa i segmenti** `.ts` mantenendo header personalizzati.
- 🚫 **Supera restrizioni** comuni come `Referer`, `User-Agent`, ecc.
- 🐳 **Facilmente dockerizzabile** su qualsiasi macchina, server o piattaforma cloud.

---

## 📚 Indice

- Piattaforme di Deploy
  - Render
  - HuggingFace
- Setup Locale
  - Docker
  - Termux (Android)
  - Python
- Utilizzo del Proxy
- Gestione Docker

---

## ☁️ Piattaforme di Deploy

### ▶️ Deploy su Render

1.  Vai su **Projects → New → Web Service → Public Git Repo**.
2.  Inserisci l'URL del repository: `https://github.com/nzo66/tvproxy` e clicca **Connect**.
3.  Scegli un nome a piacere per il servizio.
4.  Imposta **Instance Type** su `Free` (o un'opzione a pagamento per prestazioni migliori).
5.  Clicca su **Create Web Service**.

### 🤗 Deploy su HuggingFace

1.  Crea un nuovo **Space**.
2.  Scegli un nome, seleziona **Docker** come SDK e lascia la visibilità su **Public**.
3.  Vai su **Files** → `⋮` → **Upload file** e carica il file `DockerfileHF` dal repository, rinominandolo in **Dockerfile**.
4.  **Configura le variabili d'ambiente per la porta:**
    *   Vai su **Settings** del tuo Space.
    *   Nella sezione **Secrets**, aggiungi un nuovo secret.
    *   **Name:** `PORT`
    *   **Value:** `7860`
5.  Una volta completato il deploy, vai su `⋮` → **Embed this Space** per ottenere il **Direct URL**.

> 🔄 **Nota:** Se aggiorni il valore del proxy, ricorda di fare un "Factory Rebuild" dallo Space per applicare le modifiche.
> 🔄 **Nota:** Se aggiorni il Dockerfile o le variabili d'ambiente, ricorda di fare un "Factory Rebuild" dallo Space per applicare le modifiche.

---

## 💻 Setup Locale

### 🐳 Docker (Locale o Server)

#### Costruzione e Avvio

1.  **Clona il repository e costruisci l'immagine Docker:**
    ```bash
    git clone https://github.com/nzo66/tvproxy.git
    cd tvproxy
    docker build -t tvproxy .
    ```

2.  **Avvia il container:**

    ```bash
    docker run -d -p 7860:7860 --name tvproxy tvproxy
    ```

### 🐧 Termux (Dispositivi Android)

1.  **Installa i pacchetti necessari:**
    ```bash
    pkg update && pkg upgrade
    pkg install git python nano -y
    ```

2.  **Clona il repository e installa le dipendenze:**
    ```bash
    git clone https://github.com/nzo66/tvproxy.git
    cd tvproxy
    pip install -r requirements.txt
    ```

3.  **Avvia il server con Gunicorn:**
    ```bash
    gunicorn app:app -w 4 --worker-class gevent -b 0.0.0.0:7860
    ```
    > 👉 **Consiglio:** Per un avvio più robusto, puoi usare i parametri aggiuntivi:
    > ```bash
    > gunicorn app:app -w 4 --worker-class gevent --worker-connections 100 -b 0.0.0.0:7860 --timeout 120 --keep-alive 5 --max-requests 1000 --max-requests-jitter 100
    > ```

### 🐍 Python (Locale)

1.  **Clona il repository:**
    ```bash
    git clone https://github.com/nzo66/tvproxy.git
    cd tvproxy
    ```

2.  **Installa le dipendenze:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Avvia il server con Gunicorn:**
    ```bash
    gunicorn app:app -w 4 --worker-class gevent --worker-connections 100 -b 0.0.0.0:7860 --timeout 120 --keep-alive 5 --max-requests 1000 --max-requests-jitter 100
    ```

---

## 🛠️ Come Utilizzare

Sostituisci `<server-ip>` con l'IP o l'hostname del tuo server e `<URL_...>` con gli URL che vuoi proxare.

### 📡 Endpoint 1: Proxy per Liste M3U Complete

Ideale per proxare un'intera lista M3U, garantendo compatibilità con vari formati (es. Vavoo, Daddylive).

**Formato URL:**
```text
http://<server-ip>:7860/proxy?url=<URL_LISTA_M3U>
```

### 📺 Endpoint 2: Proxy per Singoli Flussi M3U8 (con Headers)

Specifico per proxare un singolo flusso `.m3u8`, con la possibilità di aggiungere headers HTTP personalizzati per superare protezioni specifiche.

**Formato URL Base:**
```text
http://<server-ip>:7860/proxy/m3u?url=<URL_FLUSSO_M3U8>
```

**Aggiungere Headers Personalizzati (Opzionale):**
Per aggiungere headers, accodali all'URL usando il prefisso `&h_`.

**Formato:**
```text
&h_<NOME_HEADER>=<VALORE_HEADER>
```

**Esempio completo con Headers:**
```text
http://<server-ip>:7860/proxy/m3u?url=https://example.com/stream.m3u8&h_user-agent=VLC/3.0.20&h_referer=https://example.com/
```

> ⚠️ **Attenzione:** Se i valori degli header contengono caratteri speciali, assicurati che siano correttamente **URL-encoded**.

---

## 🐳 Gestione Docker

-   **Visualizza i log:** `docker logs -f tvproxy`
-   **Ferma il container:** `docker stop tvproxy`
-   **Avvia il container:** `docker start tvproxy`
-   **Rimuovi il container:** `docker rm -f tvproxy`

---

## ✅ Caratteristiche Principali

-   ✅ Supporto automatico per `.m3u` e `.m3u8`.
-   ✅ Inoltro di headers HTTP personalizzati (`Authorization`, `Referer`, etc.).
-   ✅ Superamento di restrizioni geografiche o di accesso.
-   ✅ Compatibilità con qualsiasi player IPTV.
-   ✅ Totalmente dockerizzato e pronto per il deploy.
-   ✅ Avviabile anche direttamente con Python.

---

## 🎉 Enjoy the Stream!

> Ora puoi guardare i tuoi flussi preferiti ovunque, senza restrizioni.
