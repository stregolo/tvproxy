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
- Configurazione Proxy
- Gestione Docker

---

## ☁️ Piattaforme di Deploy

### ▶️ Deploy su Render

1.  Vai su **Projects → New → Web Service → Public Git Repo**.
2.  Inserisci l'URL del repository: `https://github.com/nzo66/tvproxy` e clicca **Connect**.
3.  Scegli un nome a piacere per il servizio.
4.  Imposta **Instance Type** su `Free` (o un'opzione a pagamento per prestazioni migliori).
5.  **(Opzionale) Configura le variabili d'ambiente per i proxy:**
    *   Nella sezione **Environment**, aggiungi una o più variabili.
    *   **Per proxy SOCKS5:**
        *   **Key:** `SOCKS5_PROXY`
        *   **Value:** `socks5://user:pass@host:port`
    *   **Per proxy HTTP/HTTPS:**
        *   **Key 1:** `HTTP_PROXY`
        *   **Value 1:** `http://user:pass@host:port`
        *   **Key 2:** `HTTPS_PROXY`
        *   **Value 2:** `http://user:pass@host:port`
    *   **Nota:** Puoi inserire più proxy (dello stesso tipo) separandoli da una virgola. Lo script ne sceglierà uno a caso per ogni richiesta.
    *   Per maggiori dettagli, consulta la sezione Configurazione Proxy.
6.  Clicca su **Create Web Service**.

### 🤗 Deploy su HuggingFace

1.  Crea un nuovo **Space**.
2.  Scegli un nome, seleziona **Docker** come SDK e lascia la visibilità su **Public**.
3.  Vai su **Files** → `⋮` → **Upload file** e carica il file `DockerfileHF` dal repository, rinominandolo in **Dockerfile**.
4.  **Configura le variabili d'ambiente per la porta:**
    *   Vai su **Settings** del tuo Space.
    *   Nella sezione **Secrets**, aggiungi un nuovo secret.
5.  **(Opzionale) Configura un proxy HTTP/HTTPS:**
    *   HuggingFace Spaces **non supporta proxy SOCKS5**, ma puoi usare proxy HTTP/HTTPS.
    *   Nella sezione **Secrets**, aggiungi i seguenti secret (devono essere usati entrambi):
    *   **Secret 1:**
        *   **Name:** `HTTP_PROXY`
        *   **Value:** `http://user:pass@host:port,http://user:pass@host:port`
    *   **Secret 2:**
        *   **Name:** `HTTPS_PROXY`
        *   **Value:** `http://user:pass@host:port,http://user:pass@host:port`
    *   **Nota:** Entrambe le variabili devono puntare allo stesso URL del proxy HTTP.
6.  Una volta completato il deploy, vai su `⋮` → **Embed this Space** per ottenere il **Direct URL**.

> 🔄 **Nota:** Se aggiorni il valore del proxy o altre variabili, ricorda di fare un "Factory Rebuild" dallo Space per applicare le modifiche.

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

    *   **Senza proxy:**
        ```bash
        docker run -d -p 7860:7860 --name tvproxy tvproxy
        ```

    *   **Con un proxy SOCKS5:**
        ```bash
        docker run -d -p 7860:7860 -e SOCKS5_PROXY="socks5://proxy1,socks5://proxy2" --name tvproxy tvproxy
        ```
    *   **Con un proxy HTTP/HTTPS:**
        ```bash
        docker run -d -p 7860:7860 -e HTTP_PROXY="http://proxy.example.com:8080,http://user:pass@host:port" -e HTTPS_PROXY="http://proxy.example.com:8080,http://user:pass@host:port" --name tvproxy tvproxy
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

3.  **(Opzionale) Configura un proxy tramite file `.env`:**
    ```bash
    # Crea e apri il file .env con l'editor nano
    nano .env
    ```
    Incolla la configurazione nel file. Puoi usare proxy SOCKS5 o HTTP/HTTPS. Salva con `Ctrl+X`, poi `Y` e `Invio`.
    ```dotenv
    # Scegli solo un tipo di proxy (SOCKS5 o HTTP/HTTPS).
    # Rimuovi il commento (#) dalle righe che vuoi usare.

    # --- Proxy SOCKS5 (uno o più, separati da virgola) ---
    # SOCKS5_PROXY="socks5://user:pass@host1:port,socks5://host2:port"

    # --- Proxy HTTP/HTTPS (devono essere specificati entrambi) ---
    # HTTP_PROXY="http://user:pass@host:port,http://user:pass@host:port"
    # HTTPS_PROXY="http://user:pass@host:port,http://user:pass@host:port"
    ```

4.  **Avvia il server con Gunicorn:**
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

3.  **(Opzionale) Configura un proxy tramite file `.env`:**
    Crea un file `.env` nella cartella principale e aggiungi la configurazione del proxy. Lo script lo caricherà automaticamente.
    ```bash
    # Esempio: crea e modifica il file con nano
    nano .env
    ```
    **Contenuto del file `.env`:**
    ```dotenv
    # Scegli solo un tipo di proxy (SOCKS5 o HTTP/HTTPS).
    # Rimuovi il commento (#) dalle righe che vuoi usare.

    # --- Proxy SOCKS5 (uno o più, separati da virgola) ---
    # SOCKS5_PROXY="socks5://user:pass@host1:port,socks5://host2:port"

    # --- Proxy HTTP/HTTPS (devono essere specificati entrambi) ---
    # HTTP_PROXY="http://user:pass@host:port,http://user:pass@host:port"
    # HTTPS_PROXY="http://user:pass@host:port,http://user:pass@host:port"
    ```

4.  **Avvia il server con Gunicorn:**
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

## 🔒 Configurazione Proxy

L'uso dei proxy è **completamente opzionale**. Se non viene specificato alcun proxy, tutte le richieste verranno effettuate direttamente dal server. Configurali solo se hai bisogno di superare blocchi geografici o restrizioni di rete.

Lo script supporta proxy **SOCKS5**, **HTTP** e **HTTPS** tramite variabili d'ambiente o un file `.env`.

### Variabili d'Ambiente

| Variabile            | Descrizione                                                                                              | Esempio                                                    |
| -------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------         |
| `SOCKS5_PROXY`       | Uno o più proxy SOCKS5, separati da virgola.                                                             | `socks5://user:pass@host:port,socks5://host2:port`         |
| `HTTP_PROXY`         | L'URL del proxy HTTP. Da usare in coppia con `HTTPS_PROXY`.                                              | `http://user:pass@host:port,http://host:port`              |
| `HTTPS_PROXY`        | L'URL del proxy per le richieste HTTPS. Di solito è lo stesso di `HTTP_PROXY`.                            | `http://user:pass@host:port,http://host:port`             |

### Esempio di file `.env` (per uso locale)

Crea un file `.env` nella directory principale del progetto per configurare facilmente i proxy durante lo sviluppo locale. Lo script caricherà automaticamente le variabili.

```dotenv
# Scegli solo un tipo di proxy (SOCKS5 o HTTP/HTTPS).
# Rimuovi il commento (#) dalle righe che vuoi usare.

# --- Proxy SOCKS5 ---
# Puoi specificare uno o più proxy, separati da virgola.
# SOCKS5_PROXY="socks5://user:pass@host1:port,socks5://host2:port"

# --- Proxy HTTP/HTTPS ---
# Devi specificare entrambe le variabili con lo stesso valore.
# HTTP_PROXY="http://user:pass@host:port,http://host:port"
# HTTPS_PROXY="http://user:pass@host:port,http://host:port"
```

---

## 🔐 Proxy Consigliato per Streaming

### 🌍 [proxy-cheap](https://www.proxy-cheap.com/) — HTTP & SOCKS5 Static Datacenter Dedicati

> ⚠️ **Importante:** HuggingFace supporta solo proxy **HTTP**  
> ✅ Ideale per: Streaming, scraping, AI requests, automazioni

---

🎁 **Usa il codice coupon:** `NZO66`  
💸 **Ottieni il 10% di sconto prima del pagamento!**

---

🔧 Affidabile, veloce, anonimo — Perfetto per chi cerca stabilità nei proxy dedicati.

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
