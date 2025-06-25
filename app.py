from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback
import json
import base64
from urllib.parse import quote_plus
import os
import random
import time
from cachetools import TTLCache, LRUCache
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

# --- Configurazione Generale ---
# Permette di disabilitare la verifica dei certificati SSL.
# Impostare la variabile d'ambiente VERIFY_SSL a "False" o "0" per disabilitare.
# ATTENZIONE: Disabilitare la verifica SSL può esporre a rischi di sicurezza (es. attacchi man-in-the-middle).
# Usare questa opzione solo se si è consapevoli dei rischi o se è necessario per operare dietro un proxy con ispezione SSL.
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("ATTENZIONE: La verifica del certificato SSL è DISABILITATA. Questo potrebbe esporre a rischi di sicurezza.")
    # Sopprime gli avvisi di richiesta non sicura solo se la verifica è disabilitata
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Timeout per le richieste HTTP in secondi.
# Può essere sovrascritto con la variabile d'ambiente REQUEST_TIMEOUT.
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 15))
print(f"Timeout per le richieste impostato a {REQUEST_TIMEOUT} secondi.")

# --- Configurazione Proxy ---
PROXY_LIST = []

def setup_proxies():
    """Carica la lista di proxy SOCKS5, HTTP e HTTPS dalle variabili d'ambiente."""
    global PROXY_LIST
    proxies_found = []

    # Carica proxy SOCKS5 (supporta lista separata da virgole)
    socks_proxy_list_str = os.environ.get('SOCKS5_PROXY')
    if socks_proxy_list_str:
        raw_socks_list = [p.strip() for p in socks_proxy_list_str.split(',') if p.strip()]
        if raw_socks_list:
            print(f"Trovati {len(raw_socks_list)} proxy SOCKS5. Verranno usati a rotazione.")
            for proxy in raw_socks_list:
                # Riconosce e converte automaticamente a socks5h per la risoluzione DNS remota
                final_proxy_url = proxy
                if proxy.startswith('socks5://'):
                    final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                    print(f"Proxy SOCKS5 convertito per garantire la risoluzione DNS remota")
                elif not proxy.startswith('socks5h://'):
                    print(f"ATTENZIONE: L'URL del proxy SOCKS5 non è un formato SOCKS5 valido (es. socks5:// o socks5h://). Potrebbe non funzionare.")
                proxies_found.append(final_proxy_url)
            print("Assicurati di aver installato la dipendenza per SOCKS: 'pip install PySocks'")

    # Carica proxy HTTP
    http_proxy = os.environ.get('HTTP_PROXY')
    if http_proxy:
        print(f"Trovato HTTP_PROXY")
        proxies_found.append(http_proxy)

    # Carica proxy HTTPS
    https_proxy = os.environ.get('HTTPS_PROXY')
    if https_proxy:
        print(f"Trovato HTTPS_PROXY")
        # Evita duplicati se HTTP_PROXY e HTTPS_PROXY sono uguali
        if https_proxy not in proxies_found:
            proxies_found.append(https_proxy)

    PROXY_LIST = proxies_found

    if PROXY_LIST:
        print(f"Totale di {len(PROXY_LIST)} proxy configurati. Verranno usati a rotazione per ogni richiesta.")
    else:
        print("Nessun proxy (SOCKS5, HTTP, HTTPS) configurato.")

def get_proxy_for_url(url):
    """
    Seleziona un proxy casuale dalla lista, ma lo salta per i domini GitHub.
    Restituisce il dizionario proxy formattato per la libreria requests, o None.
    """
    if not PROXY_LIST:
        return None

    # Controlla se l'URL è un dominio GitHub per saltare il proxy
    try:
        parsed_url = urlparse(url)
        if 'github.com' in parsed_url.netloc:
            print(f"Richiesta a GitHub rilevata ({url}), il proxy verrà saltato.")
            return None
    except Exception:
        # In caso di URL non valido, procedi comunque (potrebbe essere un frammento)
        pass

    chosen_proxy = random.choice(PROXY_LIST)
    return {'http': chosen_proxy, 'https': chosen_proxy}

setup_proxies()

# --- Configurazione Cache ---
M3U8_CACHE = TTLCache(maxsize=200, ttl=5)
TS_CACHE = LRUCache(maxsize=1000)
KEY_CACHE = LRUCache(maxsize=200)

# --- Dynamic DaddyLive URL Fetcher ---
DADDYLIVE_BASE_URL = None
LAST_FETCH_TIME = 0
FETCH_INTERVAL = 3600  # 1 hour in seconds

def get_daddylive_base_url():
    """Fetches and caches the dynamic base URL for DaddyLive."""
    global DADDYLIVE_BASE_URL, LAST_FETCH_TIME
    current_time = time.time()
    
    # Return cached URL if it's not expired
    if DADDYLIVE_BASE_URL and (current_time - LAST_FETCH_TIME < FETCH_INTERVAL):
        return DADDYLIVE_BASE_URL

    try:
        print("Fetching dynamic DaddyLive base URL from GitHub...")
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        response = requests.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
            proxies=get_proxy_for_url(github_url),
            verify=VERIFY_SSL
        )
        response.raise_for_status()
        content = response.text
        match = re.search(r'src\s*=\s*"([^"]*)"', content)
        if match:
            base_url = match.group(1)
            if not base_url.endswith('/'):
                base_url += '/'
            DADDYLIVE_BASE_URL = base_url
            LAST_FETCH_TIME = current_time
            print(f"Dynamic DaddyLive base URL updated to: {DADDYLIVE_BASE_URL}")
            return DADDYLIVE_BASE_URL
    except requests.RequestException as e:
        print(f"Error fetching dynamic DaddyLive URL: {e}. Using fallback.")
    
    # Fallback in case of any error
    DADDYLIVE_BASE_URL = "https://daddylive.sx/"
    print(f"Using fallback DaddyLive URL: {DADDYLIVE_BASE_URL}")
    return DADDYLIVE_BASE_URL

get_daddylive_base_url()  # Fetch on startup

def detect_m3u_type(content):
    """Rileva se è un M3U (lista IPTV) o un M3U8 (flusso HLS)"""
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def replace_key_uri(line, headers_query):
    """Sostituisce l'URI della chiave AES-128 con il proxy"""
    match = re.search(r'URI="([^"]+)"', line)
    if match:
        key_url = match.group(1)
        proxied_key_url = f"/proxy/key?url={quote(key_url)}&{headers_query}"
        return line.replace(key_url, proxied_key_url)
    return line

def extract_channel_id(url):
    """Estrae l'ID del canale da vari formati URL"""

    # Pattern per /premium.../mono.m3u8
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        return match_premium.group(1)

    # Pattern unificato per /watch/, /stream/, /cast/, /player/
    # Esempio: /watch/stream-12345.php
    match_player = re.search(r'/(?:watch|stream|cast|player)/stream-(\d+)\.php', url)
    if match_player:
        return match_player.group(1)

    return None

def process_daddylive_url(url):
    """Converte URL vecchi in formati compatibili con DaddyLive 2025"""
    daddy_base_url = get_daddylive_base_url()
    daddy_domain = urlparse(daddy_base_url).netloc

    # Converti premium URLs in formato watch
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        channel_id = match_premium.group(1)
        new_url = f"{daddy_base_url}watch/stream-{channel_id}.php"
        print(f"URL processato da {url} a {new_url}")
        return new_url

    # Se è già un URL DaddyLive moderno (con watch, stream, cast, player), usalo direttamente
    if daddy_domain in url and any(p in url for p in ['/watch/', '/stream/', '/cast/', '/player/']):
        return url

    # Se contiene solo numeri, crea URL watch
    if url.isdigit():
        return f"{daddy_base_url}watch/stream-{url}.php"

    return url

def resolve_m3u8_link(url, headers=None):
    """
    Risolve URL DaddyLive. Se l'URL non è per DaddyLive,
    pulisce semplicemente gli header incorporati e lo restituisce.
    """
    if not url:
        print("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    # Fa una copia degli header per evitare di modificare l'originale
    current_headers = headers.copy() if headers else {}
    
    # Estrazione header incorporati nell'URL
    clean_url = url
    extracted_headers = {}
    if '&h_' in url or '%26h_' in url:
        print("Rilevati parametri header nell'URL - Estrazione in corso...")
        temp_url = url
        # Gestione speciale per vavoo che a volte usa %26 invece di &
        if 'vavoo.to' in temp_url.lower() and '%26' in temp_url:
             temp_url = temp_url.replace('%26', '&')
        
        # Gestione generica per URL con doppio encoding
        if '%26h_' in temp_url:
            temp_url = unquote(unquote(temp_url))

        url_parts = temp_url.split('&h_', 1)
        clean_url = url_parts[0]
        header_params = '&h_' + url_parts[1]
        
        for param in header_params.split('&'):
            if param.startswith('h_'):
                try:
                    key_value = param[2:].split('=', 1)
                    if len(key_value) == 2:
                        key = unquote(key_value[0]).replace('_', '-')
                        value = unquote(key_value[1])
                        extracted_headers[key] = value
                except Exception as e:
                    print(f"Errore nell'estrazione dell'header {param}: {e}")

    # --- Inizia la logica di risoluzione specifica per DaddyLive ---
    print(f"Tentativo di risoluzione URL (DaddyLive): {clean_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    # Header specifici per la risoluzione DaddyLive
    daddylive_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': daddy_base_url,
        'Origin': daddy_origin
    }
    # Uniamo gli header: quelli di daddylive hanno la precedenza per la risoluzione
    final_headers_for_resolving = {**current_headers, **daddylive_headers}

    try:
        # Ottieni URL base dinamico
        print("Ottengo URL base dinamico...")
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        main_url_req = requests.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
            proxies=get_proxy_for_url(github_url),
            verify=VERIFY_SSL
        )
        main_url_req.raise_for_status()
        main_url = main_url_req.text
        baseurl = re.findall('src = "([^"]*)', main_url)[0]
        print(f"URL base ottenuto: {baseurl}")

        # Estrai ID del canale dall'URL pulito
        channel_id = extract_channel_id(clean_url)
        if not channel_id:
            print(f"Impossibile estrarre ID canale da {clean_url}")
            # Fallback: restituisce l'URL pulito
            return {"resolved_url": clean_url, "headers": current_headers}

        print(f"ID canale estratto: {channel_id}")

        # Costruisci URL del stream (identico a addon.py)
        stream_url = f"{baseurl}stream/stream-{channel_id}.php"
        print(f"URL stream costruito: {stream_url}")

        # Aggiorna header con baseurl corretto
        final_headers_for_resolving['Referer'] = baseurl + '/'
        final_headers_for_resolving['Origin'] = baseurl

        # PASSO 1: Richiesta alla pagina stream per cercare Player 2
        print(f"Passo 1: Richiesta a {stream_url}")
        response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(stream_url), verify=VERIFY_SSL)
        response.raise_for_status()

        # Cerca link Player 2 (metodo esatto da addon.py)
        iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*<\/button>', response.text)
        if not iframes:
            print("Nessun link Player 2 trovato")
            return {"resolved_url": clean_url, "headers": current_headers}

        print(f"Passo 2: Trovato link Player 2: {iframes[0]}")

        # PASSO 2: Segui il link Player 2
        url2 = iframes[0]
        url2 = baseurl + url2
        url2 = url2.replace('//cast', '/cast')  # Fix da addon.py

        # Aggiorna header
        final_headers_for_resolving['Referer'] = url2
        final_headers_for_resolving['Origin'] = url2

        print(f"Passo 3: Richiesta a Player 2: {url2}")
        response = requests.get(url2, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(url2), verify=VERIFY_SSL)
        response.raise_for_status()

        # PASSO 3: Cerca iframe nella risposta Player 2
        iframes = re.findall(r'iframe src="([^"]*)', response.text)
        if not iframes:
            print("Nessun iframe trovato nella pagina Player 2")
            return {"resolved_url": clean_url, "headers": current_headers}

        iframe_url = iframes[0]
        print(f"Passo 4: Trovato iframe: {iframe_url}")

        # PASSO 4: Accedi all'iframe
        print(f"Passo 5: Richiesta iframe: {iframe_url}")
        response = requests.get(iframe_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(iframe_url), verify=VERIFY_SSL)
        response.raise_for_status()

        iframe_content = response.text

        # PASSO 5: Estrai parametri dall'iframe (metodo esatto addon.py)
        try:
            channel_key = re.findall(r'(?s) channelKey = \"([^"]*)', iframe_content)[0]

            # Estrai e decodifica parametri base64
            auth_ts_b64 = re.findall(r'(?s)c = atob\("([^"]*)', iframe_content)[0]
            auth_ts = base64.b64decode(auth_ts_b64).decode('utf-8')

            auth_rnd_b64 = re.findall(r'(?s)d = atob\("([^"]*)', iframe_content)[0]
            auth_rnd = base64.b64decode(auth_rnd_b64).decode('utf-8')

            auth_sig_b64 = re.findall(r'(?s)e = atob\("([^"]*)', iframe_content)[0]
            auth_sig = base64.b64decode(auth_sig_b64).decode('utf-8')
            auth_sig = quote_plus(auth_sig)

            auth_host_b64 = re.findall(r'(?s)a = atob\("([^"]*)', iframe_content)[0]
            auth_host = base64.b64decode(auth_host_b64).decode('utf-8')

            auth_php_b64 = re.findall(r'(?s)b = atob\("([^"]*)', iframe_content)[0]
            auth_php = base64.b64decode(auth_php_b64).decode('utf-8')

            print(f"Parametri estratti: channel_key={channel_key}")

        except (IndexError, Exception) as e:
            print(f"Errore estrazione parametri: {e}")
            return {"resolved_url": clean_url, "headers": current_headers}

        # PASSO 6: Richiesta di autenticazione
        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
        print(f"Passo 6: Autenticazione: {auth_url}")

        auth_response = requests.get(auth_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(auth_url), verify=VERIFY_SSL)
        auth_response.raise_for_status()

        # PASSO 7: Estrai host e server lookup
        host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]

        # PASSO 8: Server lookup per ottenere server_key
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        print(f"Passo 7: Server lookup: {server_lookup_url}")

        lookup_response = requests.get(server_lookup_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(server_lookup_url), verify=VERIFY_SSL)
        lookup_response.raise_for_status()
        server_data = lookup_response.json()
        server_key = server_data['server_key']

        print(f"Server key ottenuto: {server_key}")

        # PASSO 9: Costruisci URL M3U8 finale SENZA parametri proxy
        referer_raw = f'https://{urlparse(iframe_url).netloc}'

        # URL base M3U8 PULITO (senza parametri proxy)
        clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'

        print(f"URL M3U8 pulito costruito: {clean_m3u8_url}")

        # Header corretti per il fetch
        final_headers_for_fetch = {
            'User-Agent': final_headers_for_resolving.get('User-Agent'),
            'Referer': referer_raw,
            'Origin': referer_raw
        }

        return {
            "resolved_url": clean_m3u8_url,  # URL PULITO senza parametri proxy
            "headers": final_headers_for_fetch # Header corretti
        }

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ProxyError) as e:
        print(f"ERRORE DI TIMEOUT O PROXY DURANTE LA RISOLUZIONE: {e}")
        print("Questo problema è spesso legato a un proxy SOCKS5 lento, non funzionante o bloccato.")
        print("CONSIGLI: Controlla che i tuoi proxy siano attivi. Prova ad aumentare il timeout impostando la variabile d'ambiente 'REQUEST_TIMEOUT' (es. a 20 o 30 secondi).")
        return {"resolved_url": clean_url, "headers": current_headers}
    except Exception as e:
        print(f"Errore durante la risoluzione: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # Fallback: restituisce l'URL pulito originale
        return {"resolved_url": clean_url, "headers": current_headers}

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto DaddyLive 2025 e caching"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    # Crea una chiave univoca per la cache basata sull'URL e sugli header
    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"

    # Controlla se la risposta è già in cache
    if cache_key in M3U8_CACHE:
        print(f"Cache HIT per M3U8: {m3u_url}")
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl")
    print(f"Cache MISS per M3U8: {m3u_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    # Header di default aggiornati per DaddyLive 2025
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": daddy_base_url,
        "Origin": daddy_origin
    }

    # Estrai gli header dalla richiesta, sovrascrivendo i default
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    # Processa URL con nuova logica DaddyLive 2025
    processed_url = process_daddylive_url(m3u_url)

    try:
        print(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        print(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        # CORREZIONE: Verifica che sia un M3U8 valido (senza parametri proxy)
        if not resolved_url.endswith('.m3u8'):
            print(f"URL risolto non è un M3U8: {resolved_url}")
            return "Errore: Impossibile ottenere un M3U8 valido dal canale", 500

        # Fetchare il contenuto M3U8 effettivo dall'URL pulito
        print(f"Fetching M3U8 content from clean URL: {resolved_url}")
        print(f"Using headers: {current_headers_for_proxy}")

        m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, allow_redirects=True, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(resolved_url), verify=VERIFY_SSL)
        m3u_response.raise_for_status()

        m3u_content = m3u_response.text
        final_url = m3u_response.url

        # Processa il contenuto M3U8
        file_type = detect_m3u_type(m3u_content)
        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl")

        # Processa contenuto M3U8
        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        # Prepara la query degli header per segmenti/chiavi proxati
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in current_headers_for_proxy.items()])

        modified_m3u8 = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-KEY") and 'URI="' in line:
                line = replace_key_uri(line, headers_query)
            elif line and not line.startswith("#"):
                segment_url = urljoin(base_url, line)
                line = f"/proxy/ts?url={quote(segment_url)}&{headers_query}"
            modified_m3u8.append(line)

        modified_m3u8_content = "\n".join(modified_m3u8)

        # Salva il contenuto modificato nella cache prima di restituirlo
        M3U8_CACHE[cache_key] = modified_m3u8_content

        return Response(modified_m3u8_content, content_type="application/vnd.apple.mpegurl")

    except requests.RequestException as e:
        print(f"Errore durante il download o la risoluzione del file: {str(e)}")
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        print(f"Errore generico nella funzione proxy_m3u: {str(e)}")
        return f"Errore generico durante l'elaborazione: {str(e)}", 500


@app.route('/proxy/resolve')
def proxy_resolve():
    """Proxy per risolvere e restituire un URL M3U8 con metodo DaddyLive 2025"""
    url = request.args.get('url', '').strip()
    if not url:
        return "Errore: Parametro 'url' mancante", 400

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    # AGGIUNTA: Header di default identici a /proxy/m3u
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": daddy_base_url,
        "Origin": daddy_origin
    }

    # Estrai gli header dalla richiesta, sovrascrivendo i default
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    try:
        processed_url = process_daddylive_url(url)
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL", 500

        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in result["headers"].items()])
        return Response(
            f"#EXTM3U\n"
            f"#EXTINF:-1,Canale Risolto\n"
            f"/proxy/m3u?url={quote(result['resolved_url'])}&{headers_query}",
            content_type="application/vnd.apple.mpegurl"
        )

    except Exception as e:
        return f"Errore durante la risoluzione dell'URL: {str(e)}", 500


@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con headers personalizzati e caching"""
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    # Controlla se il segmento è in cache
    if ts_url in TS_CACHE:
        print(f"Cache HIT per TS: {ts_url}")
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")
    print(f"Cache MISS per TS: {ts_url}")

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(ts_url), verify=VERIFY_SSL)
        response.raise_for_status()

        # Definiamo un generatore per inviare i dati in streaming al client
        # e contemporaneamente costruire il contenuto per la cache.
        def generate_and_cache():
            content_parts = []
            try:
                # Itera sui chunk della risposta
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: # Filtra i keep-alive chunk
                        content_parts.append(chunk)
                        yield chunk
            finally:
                # Una volta che lo streaming al client è completo, salviamo il segmento nella cache.
                ts_content = b"".join(content_parts)
                if ts_content:
                    TS_CACHE[ts_url] = ts_content
                    print(f"Segmento TS cachato ({len(ts_content)} bytes) per: {ts_url}")

        return Response(generate_and_cache(), content_type="video/mp2t")

    except requests.RequestException as e:
        return f"Errore durante il download del segmento TS: {str(e)}", 500
        
@app.route('/proxy')
def proxy():
    """Proxy per liste M3U che aggiunge automaticamente /proxy/m3u?url= con IP prima dei link"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    try:
        server_ip = request.host
        proxy_for_request = get_proxy_for_url(m3u_url)
        response = requests.get(m3u_url, timeout=REQUEST_TIMEOUT, proxies=proxy_for_request, verify=VERIFY_SSL)
        response.raise_for_status()
        m3u_content = response.text
        
        modified_lines = []
        # This list will accumulate header parameters for the *next* stream URL
        current_stream_headers_params = [] 

        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith('#EXTHTTP:'):
                try:
                    json_str = line.split(':', 1)[1].strip()
                    headers_dict = json.loads(json_str)
                    for key, value in headers_dict.items():
                        encoded_key = quote(quote(key))
                        encoded_value = quote(quote(str(value)))
                        current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                except Exception as e:
                    print(f"ERROR: Errore nel parsing di #EXTHTTP '{line}': {e}")
                modified_lines.append(line)
            
            elif line.startswith('#EXTVLCOPT:'):
                try:
                    options_str = line.split(':', 1)[1].strip()
                    # Split by comma, then iterate through key=value pairs
                    for opt_pair in options_str.split(','):
                        opt_pair = opt_pair.strip()
                        if '=' in opt_pair:
                            key, value = opt_pair.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"') # Remove potential quotes
                            
                            header_key = None
                            if key.lower() == 'http-user-agent':
                                header_key = 'User-Agent'
                            elif key.lower() == 'http-referer':
                                header_key = 'Referer'
                            elif key.lower() == 'http-cookie':
                                header_key = 'Cookie'
                            elif key.lower() == 'http-header': # For generic http-header option
                                # This handles cases like http-header=X-Custom: Value
                                full_header_value = value
                                if ':' in full_header_value:
                                    header_name, header_val = full_header_value.split(':', 1)
                                    header_key = header_name.strip()
                                    value = header_val.strip()
                                else:
                                    print(f"WARNING: Malformed http-header option in EXTVLCOPT: {opt_pair}")
                                    continue # Skip malformed header
                            
                            if header_key:
                                encoded_key = quote(quote(header_key))
                                encoded_value = quote(quote(value))
                                current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                            
                except Exception as e:
                    print(f"ERROR: Errore nel parsing di #EXTVLCOPT '{line}': {e}")
                modified_lines.append(line) # Keep the original EXTVLCOPT line in the output
            elif line and not line.startswith('#'):
                if 'pluto.tv' in line.lower():
                    modified_lines.append(line)
                else:
                    encoded_line = quote(line, safe='')
                    # Construct the headers query string from accumulated parameters
                    headers_query_string = ""
                    if current_stream_headers_params:
                        headers_query_string = "%26" + "%26".join(current_stream_headers_params)
                    
                    modified_line = f"http://{server_ip}/proxy/m3u?url={encoded_line}{headers_query_string}"
                    modified_lines.append(modified_line)
                
                # Reset headers for the next stream URL
                current_stream_headers_params = [] 
            else:
                modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)
        parsed_m3u_url = urlparse(m3u_url)
        original_filename = os.path.basename(parsed_m3u_url.path)
        
        return Response(modified_content, content_type="application/vnd.apple.mpegurl", headers={'Content-Disposition': f'attachment; filename="{original_filename}"'})
        
    except requests.RequestException as e:
        proxy_used = proxy_for_request['http'] if proxy_for_request else "Nessuno"
        print(f"ERRORE: Fallito il download di '{m3u_url}' usando il proxy. Dettagli: {e}")
        return f"Errore durante il download della lista M3U: {str(e)}", 500
    except Exception as e:
        return f"Errore generico: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Proxy per la chiave AES-128 con headers personalizzati e caching"""
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

    # Controlla se la chiave è in cache
    if key_url in KEY_CACHE:
        print(f"Cache HIT per KEY: {key_url}")
        return Response(KEY_CACHE[key_url], content_type="application/octet-stream")
    print(f"Cache MISS per KEY: {key_url}")

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(key_url, headers=headers, allow_redirects=True, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(key_url), verify=VERIFY_SSL)
        response.raise_for_status()
        key_content = response.content

        # Salva la chiave nella cache
        KEY_CACHE[key_url] = key_content
        return Response(key_content, content_type="application/octet-stream")

    except requests.RequestException as e:
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

@app.route('/')
def index():
    """Pagina principale che mostra un messaggio di benvenuto"""
    base_url = get_daddylive_base_url()
    return f"Proxy ONLINE"

if __name__ == '__main__':
    # Usa la porta 7860 di default, ma permetti di sovrascriverla con la variabile d'ambiente PORT
    port = int(os.environ.get("PORT", 7860))
    print(f"Proxy ONLINE - In ascolto su porta {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
