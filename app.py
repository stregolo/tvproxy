from flask import Flask, request, Response, jsonify, render_template_string, session, redirect, url_for
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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import psutil
from threading import Thread, Lock
import weakref
import hashlib
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

load_dotenv()

# --- Configurazione Autenticazione ---
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password123')
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '').split(',') if os.environ.get('ALLOWED_IPS') else []

def check_auth(username, password):
    """Verifica le credenziali di accesso"""
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def check_ip_allowed():
    """Verifica se l'IP è nella lista degli IP consentiti"""
    if not ALLOWED_IPS or ALLOWED_IPS == ['']:
        return True
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    return client_ip in ALLOWED_IPS

def login_required(f):
    """Decorator per richiedere il login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_ip_allowed():
            return "Accesso negato: IP non autorizzato", 403
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Configurazione Generale ---
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("ATTENZIONE: La verifica del certificato SSL è DISABILITATA. Questo potrebbe esporre a rischi di sicurezza.")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Timeout aumentato per gestire meglio i segmenti TS di grandi dimensioni
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))
print(f"Timeout per le richieste impostato a {REQUEST_TIMEOUT} secondi.")

# Configurazioni Keep-Alive
KEEP_ALIVE_TIMEOUT = int(os.environ.get('KEEP_ALIVE_TIMEOUT', 300))  # 5 minuti
MAX_KEEP_ALIVE_REQUESTS = int(os.environ.get('MAX_KEEP_ALIVE_REQUESTS', 1000))
POOL_CONNECTIONS = int(os.environ.get('POOL_CONNECTIONS', 20))
POOL_MAXSIZE = int(os.environ.get('POOL_MAXSIZE', 50))

print(f"Keep-Alive configurato: timeout={KEEP_ALIVE_TIMEOUT}s, max_requests={MAX_KEEP_ALIVE_REQUESTS}")

# --- Variabili globali per monitoraggio sistema ---
system_stats = {
    'ram_usage': 0,
    'ram_used_gb': 0,
    'ram_total_gb': 0,
    'network_sent': 0,
    'network_recv': 0,
    'bandwidth_usage': 0
}

# Pool globale di sessioni per connessioni persistenti
SESSION_POOL = {}
SESSION_LOCK = Lock()

def get_system_stats():
    """Ottiene le statistiche di sistema in tempo reale"""
    global system_stats
    
    # Memoria RAM
    memory = psutil.virtual_memory()
    system_stats['ram_usage'] = memory.percent
    system_stats['ram_used_gb'] = memory.used / (1024**3)  # GB
    system_stats['ram_total_gb'] = memory.total / (1024**3)  # GB
    
    # Utilizzo di rete
    net_io = psutil.net_io_counters()
    system_stats['network_sent'] = net_io.bytes_sent / (1024**2)  # MB
    system_stats['network_recv'] = net_io.bytes_recv / (1024**2)  # MB
    
    return system_stats

def monitor_bandwidth():
    """Monitora la banda di rete in background"""
    global system_stats
    prev_sent = 0
    prev_recv = 0
    
    while True:
        try:
            net_io = psutil.net_io_counters()
            current_sent = net_io.bytes_sent
            current_recv = net_io.bytes_recv
            
            if prev_sent > 0 and prev_recv > 0:
                # Calcola la banda utilizzata nell'ultimo secondo (in MB/s)
                sent_per_sec = (current_sent - prev_sent) / (1024 * 1024)  # Convertito in MB/s
                recv_per_sec = (current_recv - prev_recv) / (1024 * 1024)  # Convertito in MB/s
                system_stats['bandwidth_usage'] = sent_per_sec + recv_per_sec
            
            prev_sent = current_sent
            prev_recv = current_recv
        except Exception as e:
            print(f"Errore nel monitoraggio banda: {e}")
        
        time.sleep(1)

def connection_manager():
    """Thread per gestire le connessioni persistenti"""
    while True:
        try:
            time.sleep(300)  # Controlla ogni 5 minuti
            
            # Statistiche connessioni
            with SESSION_LOCK:
                active_sessions = len(SESSION_POOL)
                print(f"Sessioni attive nel pool: {active_sessions}")
                
                # Pulizia periodica delle sessioni inattive
                if active_sessions > 10:  # Se troppe sessioni, pulisci
                    cleanup_sessions()
                    
        except Exception as e:
            print(f"Errore nel connection manager: {e}")

def cleanup_sessions():
    """Pulisce le sessioni inattive dal pool"""
    global SESSION_POOL, SESSION_LOCK
    
    with SESSION_LOCK:
        for key, session in list(SESSION_POOL.items()):
            try:
                session.close()
            except:
                pass
        SESSION_POOL.clear()
        print("Pool di sessioni pulito")

# Avvia i thread di monitoraggio
bandwidth_thread = Thread(target=monitor_bandwidth, daemon=True)
bandwidth_thread.start()

connection_thread = Thread(target=connection_manager, daemon=True)
connection_thread.start()

# --- Configurazione Proxy ---
PROXY_LIST = []

def setup_proxies():
    """Carica la lista di proxy SOCKS5, HTTP e HTTPS dalle variabili d'ambiente."""
    global PROXY_LIST
    proxies_found = []

    socks_proxy_list_str = os.environ.get('SOCKS5_PROXY')
    if socks_proxy_list_str:
        raw_socks_list = [p.strip() for p in socks_proxy_list_str.split(',') if p.strip()]
        if raw_socks_list:
            print(f"Trovati {len(raw_socks_list)} proxy SOCKS5. Verranno usati a rotazione.")
            for proxy in raw_socks_list:
                final_proxy_url = proxy
                if proxy.startswith('socks5://'):
                    final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                    print(f"Proxy SOCKS5 convertito per garantire la risoluzione DNS remota")
                elif not proxy.startswith('socks5h://'):
                    print(f"ATTENZIONE: L'URL del proxy SOCKS5 non è un formato SOCKS5 valido (es. socks5:// o socks5h://). Potrebbe non funzionare.")
                proxies_found.append(final_proxy_url)
            print("Assicurati di aver installato la dipendenza per SOCKS: 'pip install PySocks'")

    http_proxy_list_str = os.environ.get('HTTP_PROXY')
    if http_proxy_list_str:
        http_proxies = [p.strip() for p in http_proxy_list_str.split(',') if p.strip()]
        if http_proxies:
            print(f"Trovati {len(http_proxies)} proxy HTTP. Verranno usati a rotazione.")
            proxies_found.extend(http_proxies)

    https_proxy_list_str = os.environ.get('HTTPS_PROXY')
    if https_proxy_list_str:
        https_proxies = [p.strip() for p in https_proxy_list_str.split(',') if p.strip()]
        if https_proxies:
            print(f"Trovati {len(https_proxies)} proxy HTTPS. Verranno usati a rotazione.")
            proxies_found.extend(https_proxies)

    PROXY_LIST = proxies_found

    if PROXY_LIST:
        print(f"Totale di {len(PROXY_LIST)} proxy configurati. Verranno usati a rotazione per ogni richiesta.")
    else:
        print("Nessun proxy (SOCKS5, HTTP, HTTPS) configurato.")

def get_proxy_for_url(url):
    """Seleziona un proxy casuale dalla lista, ma lo salta per i domini GitHub."""
    if not PROXY_LIST:
        return None

    try:
        parsed_url = urlparse(url)
        if 'github.com' in parsed_url.netloc:
            return None
    except Exception:
        pass

    chosen_proxy = random.choice(PROXY_LIST)
    return {'http': chosen_proxy, 'https': chosen_proxy}

def create_robust_session():
    """Crea una sessione con configurazione robusta e keep-alive per connessioni persistenti."""
    session = requests.Session()
    
    # Configurazione Keep-Alive
    session.headers.update({
        'Connection': 'keep-alive',
        'Keep-Alive': f'timeout={KEEP_ALIVE_TIMEOUT}, max={MAX_KEEP_ALIVE_REQUESTS}'
    })
    
    retry_strategy = Retry(
        total=3,
        read=2,
        connect=2,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=POOL_CONNECTIONS,
        pool_maxsize=POOL_MAXSIZE,
        pool_block=False
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def get_persistent_session(proxy_url=None):
    """Ottiene una sessione persistente dal pool o ne crea una nuova"""
    global SESSION_POOL, SESSION_LOCK
    
    # Usa proxy_url come chiave, o 'default' se non c'è proxy
    pool_key = proxy_url if proxy_url else 'default'
    
    with SESSION_LOCK:
        if pool_key not in SESSION_POOL:
            session = create_robust_session()
            
            # Configura proxy se fornito
            if proxy_url:
                session.proxies.update({'http': proxy_url, 'https': proxy_url})
            
            SESSION_POOL[pool_key] = session
            print(f"Nuova sessione persistente creata per: {pool_key}")
        
        return SESSION_POOL[pool_key]

def make_persistent_request(url, headers=None, timeout=None, proxy_url=None, **kwargs):
    """Effettua una richiesta usando connessioni persistenti"""
    session = get_persistent_session(proxy_url)
    
    # Headers per keep-alive
    request_headers = {
        'Connection': 'keep-alive',
        'Keep-Alive': f'timeout={KEEP_ALIVE_TIMEOUT}, max={MAX_KEEP_ALIVE_REQUESTS}'
    }
    
    if headers:
        request_headers.update(headers)
    
    try:
        response = session.get(
            url, 
            headers=request_headers, 
            timeout=timeout or REQUEST_TIMEOUT,
            verify=VERIFY_SSL,
            **kwargs
        )
        return response
    except Exception as e:
        print(f"Errore nella richiesta persistente: {e}")
        # In caso di errore, rimuovi la sessione dal pool
        with SESSION_LOCK:
            if proxy_url in SESSION_POOL:
                del SESSION_POOL[proxy_url]
        raise

def get_dynamic_timeout(url, base_timeout=REQUEST_TIMEOUT):
    """Calcola timeout dinamico basato sul tipo di risorsa."""
    if '.ts' in url.lower():
        return base_timeout * 2  # Timeout doppio per segmenti TS
    elif '.m3u8' in url.lower():
        return base_timeout * 1.5  # Timeout aumentato per playlist
    else:
        return base_timeout

setup_proxies()

# --- Configurazione Cache ---
M3U8_CACHE = TTLCache(maxsize=200, ttl=5)
TS_CACHE = TTLCache(maxsize=1000, ttl=300) 
KEY_CACHE = TTLCache(maxsize=200, ttl=300)

# --- Dynamic DaddyLive URL Fetcher ---
DADDYLIVE_BASE_URL = None
LAST_FETCH_TIME = 0
FETCH_INTERVAL = 3600

def get_daddylive_base_url():
    """Fetches and caches the dynamic base URL for DaddyLive."""
    global DADDYLIVE_BASE_URL, LAST_FETCH_TIME
    current_time = time.time()
    
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
    
    DADDYLIVE_BASE_URL = "https://daddylive.sx/"
    print(f"Using fallback DaddyLive URL: {DADDYLIVE_BASE_URL}")
    return DADDYLIVE_BASE_URL

get_daddylive_base_url()

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
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        return match_premium.group(1)

    match_player = re.search(r'/(?:watch|stream|cast|player)/stream-(\d+)\.php', url)
    if match_player:
        return match_player.group(1)

    return None

def process_daddylive_url(url):
    """Converte URL vecchi in formati compatibili con DaddyLive 2025"""
    daddy_base_url = get_daddylive_base_url()
    daddy_domain = urlparse(daddy_base_url).netloc

    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        channel_id = match_premium.group(1)
        new_url = f"{daddy_base_url}watch/stream-{channel_id}.php"
        print(f"URL processato da {url} a {new_url}")
        return new_url

    if daddy_domain in url and any(p in url for p in ['/watch/', '/stream/', '/cast/', '/player/']):
        return url

    if url.isdigit():
        return f"{daddy_base_url}watch/stream-{url}.php"

    return url

def resolve_m3u8_link(url, headers=None):
    """Risolve URL DaddyLive con gestione avanzata degli errori di timeout."""
    if not url:
        print("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    current_headers = headers.copy() if headers else {}
    
    clean_url = url
    extracted_headers = {}
    if '&h_' in url or '%26h_' in url:
        print("Rilevati parametri header nell'URL - Estrazione in corso...")
        temp_url = url
        if 'vavoo.to' in temp_url.lower() and '%26' in temp_url:
             temp_url = temp_url.replace('%26', '&')
        
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

    print(f"Tentativo di risoluzione URL (DaddyLive): {clean_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    daddylive_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': daddy_base_url,
        'Origin': daddy_origin
    }
    final_headers_for_resolving = {**current_headers, **daddylive_headers}

    try:
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
        baseurl = re.findall('(?s)src = "([^"]*)', main_url)[0]
        print(f"URL base ottenuto: {baseurl}")

        channel_id = extract_channel_id(clean_url)
        if not channel_id:
            print(f"Impossibile estrarre ID canale da {clean_url}")
            return {"resolved_url": clean_url, "headers": current_headers}

        print(f"ID canale estratto: {channel_id}")

        stream_url = f"{baseurl}stream/stream-{channel_id}.php"
        print(f"URL stream costruito: {stream_url}")

        final_headers_for_resolving['Referer'] = baseurl + '/'
        final_headers_for_resolving['Origin'] = baseurl

        print(f"Passo 1: Richiesta a {stream_url}")
        response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(stream_url), verify=VERIFY_SSL)
        response.raise_for_status()

        iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*</button>', response.text)
        if not iframes:
            print("Nessun link Player 2 trovato")
            return {"resolved_url": clean_url, "headers": current_headers}

        print(f"Passo 2: Trovato link Player 2: {iframes[0]}")

        url2 = iframes[0]
        url2 = baseurl + url2
        url2 = url2.replace('//cast', '/cast')

        final_headers_for_resolving['Referer'] = url2
        final_headers_for_resolving['Origin'] = url2

        print(f"Passo 3: Richiesta a Player 2: {url2}")
        response = requests.get(url2, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(url2), verify=VERIFY_SSL)
        response.raise_for_status()

        iframes = re.findall(r'iframe src="([^"]*)', response.text)
        if not iframes:
            print("Nessun iframe trovato nella pagina Player 2")
            return {"resolved_url": clean_url, "headers": current_headers}

        iframe_url = iframes[0]
        print(f"Passo 4: Trovato iframe: {iframe_url}")

        print(f"Passo 5: Richiesta iframe: {iframe_url}")
        response = requests.get(iframe_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(iframe_url), verify=VERIFY_SSL)
        response.raise_for_status()

        iframe_content = response.text

        try:
            channel_key = re.findall(r'(?s) channelKey = \"([^"]*)', iframe_content)[0]

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

        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
        print(f"Passo 6: Autenticazione: {auth_url}")

        auth_response = requests.get(auth_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(auth_url), verify=VERIFY_SSL)
        auth_response.raise_for_status()

        host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]

        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        print(f"Passo 7: Server lookup: {server_lookup_url}")

        lookup_response = requests.get(server_lookup_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(server_lookup_url), verify=VERIFY_SSL)
        lookup_response.raise_for_status()
        server_data = lookup_response.json()
        server_key = server_data['server_key']

        print(f"Server key ottenuto: {server_key}")

        referer_raw = f'https://{urlparse(iframe_url).netloc}'

        clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'

        print(f"URL M3U8 pulito costruito: {clean_m3u8_url}")

        final_headers_for_fetch = {
            'User-Agent': final_headers_for_resolving.get('User-Agent'),
            'Referer': referer_raw,
            'Origin': referer_raw
        }

        return {
            "resolved_url": clean_m3u8_url,
            "headers": final_headers_for_fetch
        }

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ProxyError) as e:
        print(f"ERRORE DI TIMEOUT O PROXY DURANTE LA RISOLUZIONE: {e}")
        print("Questo problema è spesso legato a un proxy SOCKS5 lento, non funzionante o bloccato.")
        print("CONSIGLI: Controlla che i tuoi proxy siano attivi. Prova ad aumentare il timeout impostando la variabile d'ambiente 'REQUEST_TIMEOUT' (es. a 20 o 30 secondi).")
        return {"resolved_url": clean_url, "headers": current_headers}
    except requests.exceptions.ConnectionError as e:
        if "Read timed out" in str(e):
            print(f"Read timeout durante la risoluzione per {clean_url}")
            return {"resolved_url": clean_url, "headers": current_headers}
        else:
            print(f"Errore di connessione durante la risoluzione: {e}")
            return {"resolved_url": clean_url, "headers": current_headers}
    except requests.exceptions.ReadTimeout as e:
        print(f"Read timeout esplicito per {clean_url}")
        return {"resolved_url": clean_url, "headers": current_headers}
    except Exception as e:
        print(f"Errore durante la risoluzione: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {"resolved_url": clean_url, "headers": current_headers}

# --- Template HTML ---

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - Proxy Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h1 {
            color: #333;
            margin: 0;
            font-size: 28px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
        }
        .error {
            color: #e74c3c;
            text-align: center;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🚀 Proxy Dashboard</h1>
            <p>Accedi per continuare</p>
        </div>
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn-login">Accedi</button>
        </form>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Dashboard - Amministrazione</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="10">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f8f9fa;
            color: #333;
        }
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .navbar h1 {
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .navbar .nav-links {
            display: flex;
            gap: 20px;
        }
        .navbar a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            transition: background 0.3s;
        }
        .navbar a:hover {
            background: rgba(255,255,255,0.2);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .status-banner {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(40,167,69,0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }
        .stat-header {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }
        .stat-icon {
            font-size: 24px;
            margin-right: 10px;
        }
        .stat-title {
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #667eea;
            margin: 10px 0;
        }
        .stat-subtitle {
            color: #666;
            font-size: 14px;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 15px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.5s ease;
            border-radius: 4px;
        }
        .endpoints-section {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            margin-top: 30px;
        }
        .endpoints-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .endpoint-card {
            padding: 20px;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            transition: all 0.3s;
        }
        .endpoint-card:hover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        .endpoint-card h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 14px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>🚀 Proxy Dashboard</h1>
        <div class="nav-links">
            <a href="/admin">⚙️ Admin</a>
            <a href="/stats">📊 API</a>
            <a href="/logout">🚪 Logout</a>
        </div>
    </nav>

    <div class="refresh-indicator">
        🔄 Auto-refresh: 10s
    </div>

    <div class="container">
        <div class="status-banner">
            <h2>✅ Sistema Operativo</h2>
            <p><strong>Base URL DaddyLive:</strong> {{ daddy_base_url }}</p>
            <p><strong>Proxy Configurati:</strong> {{ proxy_count }} | <strong>Sessioni Attive:</strong> {{ session_count }}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">💾</span>
                    <span class="stat-title">Utilizzo RAM</span>
                </div>
                <div class="stat-value">{{ "%.1f"|format(stats.ram_usage) }}%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{ stats.ram_usage }}%"></div>
                </div>
                <div class="stat-subtitle">{{ "%.2f"|format(stats.ram_used_gb) }} GB / {{ "%.2f"|format(stats.ram_total_gb) }} GB</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">🌐</span>
                    <span class="stat-title">Banda di Rete</span>
                </div>
                <div class="stat-value">{{ "%.2f"|format(stats.bandwidth_usage) }}</div>
                <div class="stat-subtitle">MB/s - Utilizzo corrente</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">📤</span>
                    <span class="stat-title">Dati Inviati</span>
                </div>
                <div class="stat-value">{{ "%.1f"|format(stats.network_sent) }}</div>
                <div class="stat-subtitle">MB - Totale dalla partenza</div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-icon">📥</span>
                    <span class="stat-title">Dati Ricevuti</span>
                </div>
                <div class="stat-value">{{ "%.1f"|format(stats.network_recv) }}</div>
                <div class="stat-subtitle">MB - Totale dalla partenza</div>
            </div>
        </div>

        <div class="endpoints-section">
            <h3>🔗 Endpoints Disponibili</h3>
            <div class="endpoints-grid">
                <div class="endpoint-card">
                    <h4>/proxy</h4>
                    <p>Proxy per liste M3U con header personalizzati</p>
                </div>
                <div class="endpoint-card">
                    <h4>/proxy/m3u</h4>
                    <p>Proxy per file M3U8 con risoluzione DaddyLive</p>
                </div>
                <div class="endpoint-card">
                    <h4>/proxy/resolve</h4>
                    <p>Risoluzione diretta URL DaddyLive</p>
                </div>
                <div class="endpoint-card">
                    <h4>/proxy/ts</h4>
                    <p>Proxy per segmenti TS con caching</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Pannello Amministrazione</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f8f9fa;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
            text-align: center;
        }
        .admin-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
        }
        .admin-card {
            padding: 25px;
            border: 2px solid #e9ecef;
            border-radius: 12px;
            text-align: center;
        }
        .admin-card h3 {
            color: #667eea;
            margin-bottom: 15px;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 30px;
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚙️ Pannello di Amministrazione</h1>
        
        <div class="admin-grid">
            <div class="admin-card">
                <h3>📊 Monitoraggio Sistema</h3>
                <p>Visualizza statistiche dettagliate del sistema</p>
                <a href="/dashboard" class="btn">Vai alla Dashboard</a>
            </div>
            
            <div class="admin-card">
                <h3>🔧 Configurazioni</h3>
                <p>Gestisci le impostazioni del proxy</p>
                <button class="btn" onclick="alert('Funzionalità in sviluppo')">Configura</button>
            </div>
            
            <div class="admin-card">
                <h3>📝 Log Sistema</h3>
                <p>Visualizza i log delle attività</p>
                <button class="btn" onclick="alert('Funzionalità in sviluppo')">Visualizza Log</button>
            </div>
            
            <div class="admin-card">
                <h3>🔄 Gestione Cache</h3>
                <p>Pulisci e gestisci la cache</p>
                <button class="btn" onclick="clearCache()">Pulisci Cache</button>
            </div>
        </div>
        
        <a href="/dashboard" class="back-link">← Torna alla Dashboard</a>
    </div>
    
    <script>
        function clearCache() {
            if(confirm('Sei sicuro di voler pulire la cache?')) {
                fetch('/admin/clear-cache', {method: 'POST'})
                    .then(() => alert('Cache pulita con successo!'))
                    .catch(() => alert('Errore durante la pulizia della cache'));
            }
        }
    </script>
</body>
</html>
"""

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Server - Benvenuto</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            color: white;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
            text-align: center;
        }
        .hero {
            margin-bottom: 50px;
        }
        .hero h1 {
            font-size: 48px;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .hero p {
            font-size: 20px;
            opacity: 0.9;
            margin-bottom: 30px;
        }
        .status-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 20px;
            margin: 30px 0;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .stats-mini {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-mini {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        .stat-mini h3 {
            margin: 0 0 10px 0;
            font-size: 24px;
        }
        .stat-mini p {
            margin: 0;
            opacity: 0.8;
        }
        .cta-buttons {
            margin: 40px 0;
        }
        .btn {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 15px 30px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50px;
            text-decoration: none;
            margin: 10px;
            display: inline-block;
            transition: all 0.3s;
            backdrop-filter: blur(10px);
        }
        .btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        .footer {
            margin-top: 50px;
            opacity: 0.7;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>🚀 Proxy Server</h1>
            <p>Sistema di proxy avanzato per streaming e contenuti multimediali</p>
        </div>
        
        <div class="status-card">
            <h2>✅ Sistema Operativo</h2>
            <p><strong>Base URL:</strong> {{ base_url }}</p>
            <p><strong>Sessioni Attive:</strong> {{ session_count }}</p>
        </div>
        
        <div class="stats-mini">
            <div class="stat-mini">
                <h3>{{ "%.1f"|format(stats.ram_usage) }}%</h3>
                <p>Utilizzo RAM</p>
            </div>
            <div class="stat-mini">
                <h3>{{ "%.2f"|format(stats.bandwidth_usage) }}</h3>
                <p>MB/s Banda</p>
            </div>
            <div class="stat-mini">
                <h3>{{ "%.1f"|format(stats.network_sent) }}</h3>
                <p>MB Inviati</p>
            </div>
            <div class="stat-mini">
                <h3>{{ "%.1f"|format(stats.network_recv) }}</h3>
                <p>MB Ricevuti</p>
            </div>
        </div>
        
        <div class="cta-buttons">
            <a href="/login" class="btn">🔐 Accedi alla Dashboard</a>
            <a href="/stats" class="btn">📊 API Statistiche</a>
        </div>
        
        <div class="footer">
            <p>Proxy Server v2.0 - Sistema di monitoraggio avanzato</p>
        </div>
    </div>
</body>
</html>
"""

# --- Route di Autenticazione ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Pagina di login"""
    if not check_ip_allowed():
        return "Accesso negato: IP non autorizzato", 403
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_auth(username, password):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Credenziali non valide'
            return render_template_string(LOGIN_TEMPLATE, error=error)
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard avanzata con statistiche di sistema"""
    stats = get_system_stats()
    daddy_base_url = get_daddylive_base_url()
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                stats=stats, 
                                daddy_base_url=daddy_base_url,
                                session_count=len(SESSION_POOL),
                                proxy_count=len(PROXY_LIST))

@app.route('/admin')
@login_required
def admin_panel():
    """Pannello di amministrazione"""
    return render_template_string(ADMIN_TEMPLATE)

@app.route('/admin/clear-cache', methods=['POST'])
@login_required
def clear_cache():
    """Pulisce tutte le cache"""
    M3U8_CACHE.clear()
    TS_CACHE.clear()
    KEY_CACHE.clear()
    cleanup_sessions()
    return jsonify({"status": "success", "message": "Cache pulita con successo"})

@app.route('/stats')
def get_stats():
    """Endpoint per ottenere le statistiche di sistema"""
    stats = get_system_stats()
    return jsonify(stats)

@app.route('/')
def index():
    """Pagina principale migliorata"""
    stats = get_system_stats()
    base_url = get_daddylive_base_url()
    
    return render_template_string(INDEX_TEMPLATE, 
                                stats=stats, 
                                base_url=base_url,
                                session_count=len(SESSION_POOL))

# --- Route Proxy (tutte le route proxy esistenti rimangono identiche) ---

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto DaddyLive 2025 e caching"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"

    if cache_key in M3U8_CACHE:
        print(f"Cache HIT per M3U8: {m3u_url}")
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl")
    print(f"Cache MISS per M3U8: {m3u_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": daddy_base_url,
        "Origin": daddy_origin
    }

    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    processed_url = process_daddylive_url(m3u_url)

    try:
        print(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        print(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        if not resolved_url.endswith('.m3u8'):
            print(f"URL risolto non è un M3U8: {resolved_url}")
            return "Errore: Impossibile ottenere un M3U8 valido dal canale", 500

        print(f"Fetching M3U8 content from clean URL: {resolved_url}")
        print(f"Using headers: {current_headers_for_proxy}")

        timeout = get_dynamic_timeout(resolved_url)
        proxy_config = get_proxy_for_url(resolved_url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        m3u_response = make_persistent_request(
            resolved_url,
            headers=current_headers_for_proxy,
            timeout=timeout,
            proxy_url=proxy_key,
            allow_redirects=True
        )
        m3u_response.raise_for_status()

        m3u_content = m3u_response.text
        final_url = m3u_response.url

        file_type = detect_m3u_type(m3u_content)
        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl")

        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

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

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": daddy_base_url,
        "Origin": daddy_origin
    }

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
    """Proxy per segmenti .TS con connessioni persistenti, headers personalizzati e caching"""
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    if ts_url in TS_CACHE:
        print(f"Cache HIT per TS: {ts_url}")
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")
    print(f"Cache MISS per TS: {ts_url}")

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    proxy_config = get_proxy_for_url(ts_url)
    proxy_key = proxy_config['http'] if proxy_config else None
    
    ts_timeout = get_dynamic_timeout(ts_url)
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            response = make_persistent_request(
                ts_url,
                headers=headers,
                timeout=ts_timeout,
                proxy_url=proxy_key,
                stream=True,
                allow_redirects=True
            )
            response.raise_for_status()

            def generate_and_cache():
                content_parts = []
                try:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            content_parts.append(chunk)
                            yield chunk
                except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                    if "Read timed out" in str(e) or "timed out" in str(e).lower():
                        print(f"Timeout durante il download del segmento TS (tentativo {attempt + 1}): {ts_url}")
                        return
                    raise
                finally:
                    ts_content = b"".join(content_parts)
                    if ts_content and len(ts_content) > 1024:
                        TS_CACHE[ts_url] = ts_content
                        print(f"Segmento TS cachato ({len(ts_content)} bytes) per: {ts_url}")

            return Response(generate_and_cache(), content_type="video/mp2t")

        except requests.exceptions.ConnectionError as e:
            if "Read timed out" in str(e) or "timed out" in str(e).lower():
                print(f"Timeout del segmento TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
                if attempt == max_retries - 1:
                    return f"Errore: Timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
                time.sleep(2 ** attempt)
                continue
            else:
                return f"Errore di connessione per il segmento TS: {str(e)}", 500
        except requests.exceptions.ReadTimeout as e:
            print(f"Read timeout esplicito per il segmento TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
            if attempt == max_retries - 1:
                return f"Errore: Read timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
            time.sleep(2 ** attempt)
            continue
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
        proxy_config = get_proxy_for_url(m3u_url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            m3u_url,
            timeout=REQUEST_TIMEOUT,
            proxy_url=proxy_key
        )
        response.raise_for_status()
        m3u_content = response.text
        
        modified_lines = []
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
                    for opt_pair in options_str.split(','):
                        opt_pair = opt_pair.strip()
                        if '=' in opt_pair:
                            key, value = opt_pair.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')
                            
                            header_key = None
                            if key.lower() == 'http-user-agent':
                                header_key = 'User-Agent'
                            elif key.lower() == 'http-referer':
                                header_key = 'Referer'
                            elif key.lower() == 'http-cookie':
                                header_key = 'Cookie'
                            elif key.lower() == 'http-header':
                                full_header_value = value
                                if ':' in full_header_value:
                                    header_name, header_val = full_header_value.split(':', 1)
                                    header_key = header_name.strip()
                                    value = header_val.strip()
                                else:
                                    print(f"WARNING: Malformed http-header option in EXTVLCOPT: {opt_pair}")
                                    continue
                            
                            if header_key:
                                encoded_key = quote(quote(header_key))
                                encoded_value = quote(quote(value))
                                current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                            
                except Exception as e:
                    print(f"ERROR: Errore nel parsing di #EXTVLCOPT '{line}': {e}")
                modified_lines.append(line)
            elif line and not line.startswith('#'):
                if 'pluto.tv' in line.lower():
                    modified_lines.append(line)
                else:
                    encoded_line = quote(line, safe='')
                    headers_query_string = ""
                    if current_stream_headers_params:
                        headers_query_string = "%26" + "%26".join(current_stream_headers_params)
                    
                    modified_line = f"http://{server_ip}/proxy/m3u?url={encoded_line}{headers_query_string}"
                    modified_lines.append(modified_line)
                
                current_stream_headers_params = [] 
            else:
                modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)
        parsed_m3u_url = urlparse(m3u_url)
        original_filename = os.path.basename(parsed_m3u_url.path)
        
        return Response(modified_content, content_type="application/vnd.apple.mpegurl", headers={'Content-Disposition': f'attachment; filename="{original_filename}"'})
        
    except requests.RequestException as e:
        print(f"ERRORE: Fallito il download di '{m3u_url}'.")
        return f"Errore durante il download della lista M3U: {str(e)}", 500
    except Exception as e:
        return f"Errore generico: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Proxy per la chiave AES-128 con headers personalizzati e caching"""
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

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
        proxy_config = get_proxy_for_url(key_url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            key_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            proxy_url=proxy_key,
            allow_redirects=True
        )
        response.raise_for_status()
        key_content = response.content

        KEY_CACHE[key_url] = key_content
        return Response(key_content, content_type="application/octet-stream")

    except requests.RequestException as e:
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    print(f"Proxy ONLINE - In ascolto su porta {port}")
    print(f"Admin Username: {ADMIN_USERNAME}")
    print(f"Admin Password: {ADMIN_PASSWORD}")
    if ALLOWED_IPS:
        print(f"IP consentiti: {ALLOWED_IPS}")
    app.run(host="0.0.0.0", port=port, debug=False)
