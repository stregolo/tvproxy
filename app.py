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
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import subprocess
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Pool di thread per gestire test simultanei (se non esiste già)
if 'executor' not in globals():
    executor = ThreadPoolExecutor(max_workers=10)

# Dizionario thread-safe per tracciare i test attivi (se non esiste già)
if 'active_tests' not in globals():
    active_tests = {}
    active_tests_lock = threading.Lock()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

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

# --- Setup Logging System ---
def setup_logging():
    """Configura il sistema di logging"""
    os.makedirs('logs', exist_ok=True)
    
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # Handler per file con rotazione
    file_handler = RotatingFileHandler(
        'logs/proxy.log', 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Handler per console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Configura il logger principale
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)

setup_logging()

# --- Configurazione Manager ---
class ConfigManager:
    def __init__(self):
        self.config_file = 'proxy_config.json'
        self.default_config = {
            'SOCKS5_PROXY': '',
            'HTTP_PROXY': '',
            'HTTPS_PROXY': '',
            'REQUEST_TIMEOUT': 30,
            'VERIFY_SSL': False,
            'KEEP_ALIVE_TIMEOUT': 300,
            'MAX_KEEP_ALIVE_REQUESTS': 1000,
            'POOL_CONNECTIONS': 20,
            'POOL_MAXSIZE': 50,
            'CACHE_TTL_M3U8': 5,
            'CACHE_TTL_TS': 300,
            'CACHE_TTL_KEY': 300,
            'CACHE_MAXSIZE_M3U8': 200,
            'CACHE_MAXSIZE_TS': 1000,
            'CACHE_MAXSIZE_KEY': 200,
            'ALLOWED_IPS': '',
            'ADMIN_USERNAME': 'admin',
            'ADMIN_PASSWORD': 'password123'
        }
        
    def load_config(self):
        """Carica la configurazione dal file JSON"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                app.logger.error(f"Errore nel caricamento della configurazione: {e}")
        return self.default_config.copy()
    
    def save_config(self, config):
        """Salva la configurazione nel file JSON"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            app.logger.error(f"Errore nel salvataggio della configurazione: {e}")
            return False
    
    def apply_config_to_app(self, config):
        """Applica la configurazione all'app Flask"""
        for key, value in config.items():
            if hasattr(app, 'config'):
                app.config[key] = value
            os.environ[key] = str(value)
        return True

config_manager = ConfigManager()

# --- Log Manager ---
class LogManager:
    def __init__(self):
        self.log_file = 'logs/proxy.log'
        
    def get_log_files(self):
        """Ottiene la lista dei file di log disponibili"""
        log_files = []
        logs_dir = 'logs'
        
        if os.path.exists(logs_dir):
            for filename in os.listdir(logs_dir):
                if filename.endswith('.log'):
                    filepath = os.path.join(logs_dir, filename)
                    stat = os.stat(filepath)
                    log_files.append({
                        'name': filename,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        
        return sorted(log_files, key=lambda x: x['modified'], reverse=True)
    
    def read_log_file(self, filename, lines=100):
        """Legge le ultime righe di un file di log"""
        filepath = os.path.join('logs', filename)
        
        if not os.path.exists(filepath):
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if lines else all_lines
        except Exception as e:
            return [f"Errore nella lettura del file: {str(e)}"]
    
    def stream_log_file(self, filename):
        """Stream in tempo reale di un file di log"""
        filepath = os.path.join('logs', filename)
        
        def generate():
            if not os.path.exists(filepath):
                yield f"data: {json.dumps({'error': 'File non trovato'})}\n\n"
                return
            
            # Leggi le ultime 50 righe per iniziare
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines[-50:]:
                    yield f"data: {json.dumps({'line': line.strip(), 'timestamp': time.time()})}\n\n"
            
            # Monitora il file per nuove righe
            f = open(filepath, 'r', encoding='utf-8')
            f.seek(0, 2)  # Vai alla fine del file
            
            while True:
                line = f.readline()
                if line:
                    yield f"data: {json.dumps({'line': line.strip(), 'timestamp': time.time()})}\n\n"
                else:
                    time.sleep(0.1)
        
        return generate()

log_manager = LogManager()

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
            app.logger.error(f"Errore nel monitoraggio banda: {e}")
        
        time.sleep(1)

def connection_manager():
    """Thread per gestire le connessioni persistenti"""
    while True:
        try:
            time.sleep(300)  # Controlla ogni 5 minuti
            
            # Statistiche connessioni
            with SESSION_LOCK:
                active_sessions = len(SESSION_POOL)
                app.logger.info(f"Sessioni attive nel pool: {active_sessions}")
                
                # Pulizia periodica delle sessioni inattive
                if active_sessions > 10:  # Se troppe sessioni, pulisci
                    cleanup_sessions()
                    
        except Exception as e:
            app.logger.error(f"Errore nel connection manager: {e}")

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
        app.logger.info("Pool di sessioni pulito")

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
            app.logger.info(f"Trovati {len(raw_socks_list)} proxy SOCKS5. Verranno usati a rotazione.")
            for proxy in raw_socks_list:
                final_proxy_url = proxy
                if proxy.startswith('socks5://'):
                    final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                    app.logger.info(f"Proxy SOCKS5 convertito per garantire la risoluzione DNS remota")
                elif not proxy.startswith('socks5h://'):
                    app.logger.warning(f"ATTENZIONE: L'URL del proxy SOCKS5 non è un formato SOCKS5 valido (es. socks5:// o socks5h://). Potrebbe non funzionare.")
                proxies_found.append(final_proxy_url)
            app.logger.info("Assicurati di aver installato la dipendenza per SOCKS: 'pip install PySocks'")

    http_proxy_list_str = os.environ.get('HTTP_PROXY')
    if http_proxy_list_str:
        http_proxies = [p.strip() for p in http_proxy_list_str.split(',') if p.strip()]
        if http_proxies:
            app.logger.info(f"Trovati {len(http_proxies)} proxy HTTP. Verranno usati a rotazione.")
            proxies_found.extend(http_proxies)

    https_proxy_list_str = os.environ.get('HTTPS_PROXY')
    if https_proxy_list_str:
        https_proxies = [p.strip() for p in https_proxy_list_str.split(',') if p.strip()]
        if https_proxies:
            app.logger.info(f"Trovati {len(https_proxies)} proxy HTTPS. Verranno usati a rotazione.")
            proxies_found.extend(https_proxies)

    PROXY_LIST = proxies_found

    if PROXY_LIST:
        app.logger.info(f"Totale di {len(PROXY_LIST)} proxy configurati. Verranno usati a rotazione per ogni richiesta.")
    else:
        app.logger.info("Nessun proxy (SOCKS5, HTTP, HTTPS) configurato.")

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
            app.logger.info(f"Nuova sessione persistente creata per: {pool_key}")
        
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
        app.logger.error(f"Errore nella richiesta persistente: {e}")
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
        app.logger.info("Fetching dynamic DaddyLive base URL from GitHub...")
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
            app.logger.info(f"Dynamic DaddyLive base URL updated to: {DADDYLIVE_BASE_URL}")
            return DADDYLIVE_BASE_URL
    except requests.RequestException as e:
        app.logger.error(f"Error fetching dynamic DaddyLive URL: {e}. Using fallback.")
    
    DADDYLIVE_BASE_URL = "https://daddylive.sx/"
    app.logger.info(f"Using fallback DaddyLive URL: {DADDYLIVE_BASE_URL}")
    return DADDYLIVE_BASE_URL

get_daddylive_base_url()

# [Mantieni tutte le funzioni esistenti per il processing DaddyLive...]
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
        app.logger.info(f"URL processato da {url} a {new_url}")
        return new_url

    if daddy_domain in url and any(p in url for p in ['/watch/', '/stream/', '/cast/', '/player/']):
        return url

    if url.isdigit():
        return f"{daddy_base_url}watch/stream-{url}.php"

    return url

def resolve_m3u8_link(url, headers=None):
    """Risolve URL DaddyLive con gestione avanzata degli errori di timeout."""
    if not url:
        app.logger.error("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    current_headers = headers.copy() if headers else {}
    
    clean_url = url
    extracted_headers = {}
    if '&h_' in url or '%26h_' in url:
        app.logger.info("Rilevati parametri header nell'URL - Estrazione in corso...")
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
                    app.logger.error(f"Errore nell'estrazione dell'header {param}: {e}")

    # **AGGIUNTA: Controllo per URL Vavoo.to DOPO l'estrazione degli header**
    if 'vavoo.to' in clean_url.lower():
        app.logger.info(f"URL Vavoo.to rilevato, passaggio diretto: {clean_url}")
        final_headers = {**current_headers, **extracted_headers}
        return {
            "resolved_url": clean_url,
            "headers": final_headers
        }

    # Continua con la logica DaddyLive per altri URL...
    app.logger.info(f"Tentativo di risoluzione URL (DaddyLive): {clean_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    daddylive_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': daddy_base_url,
        'Origin': daddy_origin
    }
    final_headers_for_resolving = {**current_headers, **daddylive_headers}

    try:
        app.logger.info("Ottengo URL base dinamico...")
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
        app.logger.info(f"URL base ottenuto: {baseurl}")

        channel_id = extract_channel_id(clean_url)
        if not channel_id:
            app.logger.error(f"Impossibile estrarre ID canale da {clean_url}")
            return {"resolved_url": clean_url, "headers": current_headers}

        app.logger.info(f"ID canale estratto: {channel_id}")

        stream_url = f"{baseurl}stream/stream-{channel_id}.php"
        app.logger.info(f"URL stream costruito: {stream_url}")

        final_headers_for_resolving['Referer'] = baseurl + '/'
        final_headers_for_resolving['Origin'] = baseurl

        app.logger.info(f"Passo 1: Richiesta a {stream_url}")
        response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(stream_url), verify=VERIFY_SSL)
        response.raise_for_status()

        iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*</button>', response.text)
        if not iframes:
            app.logger.error("Nessun link Player 2 trovato")
            return {"resolved_url": clean_url, "headers": current_headers}

        app.logger.info(f"Passo 2: Trovato link Player 2: {iframes[0]}")

        url2 = iframes[0]
        url2 = baseurl + url2
        url2 = url2.replace('//cast', '/cast')

        final_headers_for_resolving['Referer'] = url2
        final_headers_for_resolving['Origin'] = url2

        app.logger.info(f"Passo 3: Richiesta a Player 2: {url2}")
        response = requests.get(url2, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(url2), verify=VERIFY_SSL)
        response.raise_for_status()

        iframes = re.findall(r'iframe src="([^"]*)', response.text)
        if not iframes:
            app.logger.error("Nessun iframe trovato nella pagina Player 2")
            return {"resolved_url": clean_url, "headers": current_headers}

        iframe_url = iframes[0]
        app.logger.info(f"Passo 4: Trovato iframe: {iframe_url}")

        app.logger.info(f"Passo 5: Richiesta iframe: {iframe_url}")
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

            app.logger.info(f"Parametri estratti: channel_key={channel_key}")

        except (IndexError, Exception) as e:
            app.logger.error(f"Errore estrazione parametri: {e}")
            return {"resolved_url": clean_url, "headers": current_headers}

        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
        app.logger.info(f"Passo 6: Autenticazione: {auth_url}")

        auth_response = requests.get(auth_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(auth_url), verify=VERIFY_SSL)
        auth_response.raise_for_status()

        host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]

        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        app.logger.info(f"Passo 7: Server lookup: {server_lookup_url}")

        lookup_response = requests.get(server_lookup_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(server_lookup_url), verify=VERIFY_SSL)
        lookup_response.raise_for_status()
        server_data = lookup_response.json()
        server_key = server_data['server_key']

        app.logger.info(f"Server key ottenuto: {server_key}")

        referer_raw = f'https://{urlparse(iframe_url).netloc}'

        clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'

        app.logger.info(f"URL M3U8 pulito costruito: {clean_m3u8_url}")

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
        app.logger.error(f"ERRORE DI TIMEOUT O PROXY DURANTE LA RISOLUZIONE: {e}")
        app.logger.error("Questo problema è spesso legato a un proxy SOCKS5 lento, non funzionante o bloccato.")
        app.logger.error("CONSIGLI: Controlla che i tuoi proxy siano attivi. Prova ad aumentare il timeout impostando la variabile d'ambiente 'REQUEST_TIMEOUT' (es. a 20 o 30 secondi).")
        return {"resolved_url": clean_url, "headers": current_headers}
    except requests.exceptions.ConnectionError as e:
        if "Read timed out" in str(e):
            app.logger.error(f"Read timeout durante la risoluzione per {clean_url}")
            return {"resolved_url": clean_url, "headers": current_headers}
        else:
            app.logger.error(f"Errore di connessione durante la risoluzione: {e}")
            return {"resolved_url": clean_url, "headers": current_headers}
    except requests.exceptions.ReadTimeout as e:
        app.logger.error(f"Read timeout esplicito per {clean_url}")
        return {"resolved_url": clean_url, "headers": current_headers}
    except Exception as e:
        app.logger.error(f"Errore durante la risoluzione: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return {"resolved_url": clean_url, "headers": current_headers}

# --- Template HTML ---

LOGIN_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Login - Proxy Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
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
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
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

DASHBOARD_TEMPLATE = r"""
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
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
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
            <a href="/admin/config">⚙️ Configurazioni</a>
            <a href="/admin/logs">📝 Log</a>
            <a href="/admin">🏠 Admin</a>
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

ADMIN_TEMPLATE = r"""
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
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
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
        .navbar {
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: -20px -20px 20px -20px;
        }
        .navbar h1 {
            font-size: 24px;
            margin: 0;
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
    </style>
</head>
<body>
    <div class="navbar">
        <h1>⚙️ Pannello di Amministrazione</h1>
        <div class="nav-links">
            <a href="/dashboard">📊 Dashboard</a>
            <a href="/logout">🚪 Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="admin-grid">
            <div class="admin-card">
                <h3>📊 Monitoraggio Sistema</h3>
                <p>Visualizza statistiche dettagliate del sistema in tempo reale</p>
                <a href="/dashboard" class="btn">Vai alla Dashboard</a>
            </div>
            
            <div class="admin-card">
                <h3>🔧 Configurazioni</h3>
                <p>Gestisci le impostazioni del proxy, timeout, cache e sicurezza</p>
                <a href="/admin/config" class="btn">Configura Sistema</a>
            </div>
            
            <div class="admin-card">
                <h3>📝 Log Sistema</h3>
                <p>Visualizza i log delle attività in tempo reale con streaming</p>
                <a href="/admin/logs" class="btn">Visualizza Log</a>
            </div>
            
            <div class="admin-card">
                <h3>🔄 Gestione Cache</h3>
                <p>Pulisci e gestisci la cache del sistema</p>
                <button class="btn" onclick="clearCache()">Pulisci Cache</button>
            </div>
            
            <div class="admin-card">
                <h3>📈 API Statistiche</h3>
                <p>Accesso alle API JSON per integrazioni esterne</p>
                <a href="/stats" class="btn">API Endpoint</a>
            </div>
            
            <div class="admin-card">
                <h3>🛡️ Sicurezza</h3>
                <p>Gestione IP consentiti e credenziali di accesso</p>
                <a href="/admin/config#security" class="btn">Impostazioni Sicurezza</a>
            </div>
        </div>
    </div>
    
    <script>
        function clearCache() {
            if(confirm('Sei sicuro di voler pulire la cache del sistema?')) {
                fetch('/admin/clear-cache', {method: 'POST'})
                    .then(response => response.json())
                    .then(data => {
                        alert(data.message);
                    })
                    .catch(() => alert('Errore durante la pulizia della cache'));
            }
        }
    </script>
</body>
</html>
"""

CONFIG_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Gestione Configurazioni - Proxy</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f8f9fa;
            margin: 0;
            padding: 0;
        }
        .navbar {
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .navbar h1 {
            font-size: 24px;
            margin: 0;
        }
        .navbar .nav-links a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            transition: background 0.3s;
            margin-left: 10px;
        }
        .navbar .nav-links a:hover {
            background: rgba(255,255,255,0.2);
        }
        .container {
            max-width: 1000px;
            margin: 20px auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #333;
        }
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
            box-sizing: border-box;
        }
        .form-group input:focus, .form-group textarea:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        .form-group small {
            color: #666;
            font-size: 12px;
            margin-top: 5px;
            display: block;
        }
        .config-section {
            margin-bottom: 40px;
            padding: 25px;
            border: 1px solid #e1e5e9;
            border-radius: 10px;
            background: #f8f9ff;
        }
        .config-section h3 {
            margin: 0 0 20px 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .btn {
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            margin-right: 10px;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .btn-secondary {
            background: #6c757d;
        }
        .alert {
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
            display: none;
        }
        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .alert-error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .row {
            display: flex;
            gap: 20px;
        }
        .col {
            flex: 1;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>⚙️ Gestione Configurazioni Proxy</h1>
        <div class="nav-links">
            <a href="/admin">← Admin</a>
            <a href="/dashboard">📊 Dashboard</a>
            <a href="/logout">🚪 Logout</a>
        </div>
    </nav>
    
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <form id="configForm">
            <!-- Sezione Proxy -->
            <div class="config-section">
                <h3>🌐 Configurazioni Proxy</h3>
                <div class="form-group">
                    <label for="socks5_proxy">Proxy SOCKS5:</label>
                    <textarea id="socks5_proxy" name="SOCKS5_PROXY" rows="3" placeholder="socks5://user:pass@proxy1:1080,socks5://user:pass@proxy2:1080">{{ config.SOCKS5_PROXY }}</textarea>
                    <small>Lista di proxy SOCKS5 separati da virgola</small>
                </div>
                <div class="row">
                    <div class="col">
                        <div class="form-group">
                            <label for="http_proxy">Proxy HTTP:</label>
                            <textarea id="http_proxy" name="HTTP_PROXY" rows="2" placeholder="http://proxy1:8080,http://proxy2:8080">{{ config.HTTP_PROXY }}</textarea>
                        </div>
                    </div>
                    <div class="col">
                        <div class="form-group">
                            <label for="https_proxy">Proxy HTTPS:</label>
                            <textarea id="https_proxy" name="HTTPS_PROXY" rows="2" placeholder="https://proxy1:8080,https://proxy2:8080">{{ config.HTTPS_PROXY }}</textarea>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sezione Timeouts -->
            <div class="config-section">
                <h3>⏱️ Configurazioni Timeout</h3>
                <div class="row">
                    <div class="col">
                        <div class="form-group">
                            <label for="request_timeout">Request Timeout (secondi):</label>
                            <input type="number" id="request_timeout" name="REQUEST_TIMEOUT" value="{{ config.REQUEST_TIMEOUT }}" min="5" max="300">
                            <small>Timeout per le richieste HTTP</small>
                        </div>
                    </div>
                    <div class="col">
                        <div class="form-group">
                            <label for="keep_alive_timeout">Keep-Alive Timeout (secondi):</label>
                            <input type="number" id="keep_alive_timeout" name="KEEP_ALIVE_TIMEOUT" value="{{ config.KEEP_ALIVE_TIMEOUT }}" min="60" max="3600">
                            <small>Timeout per connessioni persistenti</small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sezione Cache -->
            <div class="config-section">
                <h3>💾 Configurazioni Cache</h3>
                <div class="row">
                    <div class="col">
                        <div class="form-group">
                            <label for="cache_ttl_m3u8">TTL Cache M3U8 (secondi):</label>
                            <input type="number" id="cache_ttl_m3u8" name="CACHE_TTL_M3U8" value="{{ config.CACHE_TTL_M3U8 }}" min="1" max="300">
                        </div>
                        <div class="form-group">
                            <label for="cache_maxsize_m3u8">Max Size Cache M3U8:</label>
                            <input type="number" id="cache_maxsize_m3u8" name="CACHE_MAXSIZE_M3U8" value="{{ config.CACHE_MAXSIZE_M3U8 }}" min="10" max="1000">
                        </div>
                    </div>
                    <div class="col">
                        <div class="form-group">
                            <label for="cache_ttl_ts">TTL Cache TS (secondi):</label>
                            <input type="number" id="cache_ttl_ts" name="CACHE_TTL_TS" value="{{ config.CACHE_TTL_TS }}" min="60" max="3600">
                        </div>
                        <div class="form-group">
                            <label for="cache_maxsize_ts">Max Size Cache TS:</label>
                            <input type="number" id="cache_maxsize_ts" name="CACHE_MAXSIZE_TS" value="{{ config.CACHE_MAXSIZE_TS }}" min="100" max="5000">
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sezione Sicurezza -->
            <div class="config-section" id="security">
                <h3>🔒 Configurazioni Sicurezza</h3>
                <div class="row">
                    <div class="col">
                        <div class="form-group">
                            <label for="admin_username">Username Admin:</label>
                            <input type="text" id="admin_username" name="ADMIN_USERNAME" value="{{ config.ADMIN_USERNAME }}">
                        </div>
                        <div class="form-group">
                            <label for="verify_ssl">Verifica SSL:</label>
                            <select id="verify_ssl" name="VERIFY_SSL">
                                <option value="true" {% if config.VERIFY_SSL %}selected{% endif %}>Abilitato</option>
                                <option value="false" {% if not config.VERIFY_SSL %}selected{% endif %}>Disabilitato</option>
                            </select>
                        </div>
                    </div>
                    <div class="col">
                        <div class="form-group">
                            <label for="admin_password">Password Admin:</label>
                            <input type="password" id="admin_password" name="ADMIN_PASSWORD" value="{{ config.ADMIN_PASSWORD }}">
                        </div>
                        <div class="form-group">
                            <label for="allowed_ips">IP Consentiti:</label>
                            <input type="text" id="allowed_ips" name="ALLOWED_IPS" value="{{ config.ALLOWED_IPS }}" placeholder="192.168.1.100,10.0.0.1">
                            <small>Lista di IP separati da virgola (lascia vuoto per tutti)</small>
                        </div>
                    </div>
                </div>
            </div>

            <div style="margin-top: 30px;">
                <button type="submit" class="btn">💾 Salva Configurazioni</button>
                <button type="button" class="btn btn-secondary" onclick="resetForm()">🔄 Ripristina Default</button>
                <button type="button" class="btn btn-secondary" onclick="testConnection()">🔍 Test Connessioni</button>
            </div>
        </form>
    </div>

    <script>
        document.getElementById('configForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const config = {};
            
            for (let [key, value] of formData.entries()) {
                if (key === 'VERIFY_SSL') {
                    config[key] = value === 'true';
                } else if (['REQUEST_TIMEOUT', 'KEEP_ALIVE_TIMEOUT', 'CACHE_TTL_M3U8', 'CACHE_TTL_TS', 'CACHE_MAXSIZE_M3U8', 'CACHE_MAXSIZE_TS'].includes(key)) {
                    config[key] = parseInt(value);
                } else {
                    config[key] = value;
                }
            }
            
            fetch('/admin/config/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                showAlert(data.message, data.status === 'success' ? 'success' : 'error');
                if (data.status === 'success') {
                    setTimeout(() => location.reload(), 2000);
                }
            })
            .catch(error => {
                showAlert('Errore nel salvataggio della configurazione', 'error');
                console.error('Error:', error);
            });
        });
        
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.textContent = message;
            alert.className = 'alert alert-' + type;
            alert.style.display = 'block';
            
            setTimeout(() => {
                alert.style.display = 'none';
            }, 5000);
        }
        
        function resetForm() {
            if (confirm('Sei sicuro di voler ripristinare le configurazioni di default?')) {
                fetch('/admin/config/reset', {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    showAlert(data.message, data.status === 'success' ? 'success' : 'error');
                    if (data.status === 'success') {
                        setTimeout(() => location.reload(), 2000);
                    }
                });
            }
        }
        
        function testConnection() {
            const testBtn = event.target;
            const originalText = testBtn.textContent;
            
            // Chiedi all'utente se vuole il test avanzato
            const useAdvanced = confirm('Vuoi usare il test parallelo avanzato?\n\n• Sì: Test parallelo con risultati in tempo reale\n• No: Test semplice tradizionale');
            
            if (useAdvanced) {
                testConnectionAdvanced(testBtn, originalText);
            } else {
                testConnectionSimple(testBtn, originalText);
            }
        }
        
        function testConnectionSimple(testBtn, originalText) {
            testBtn.textContent = '🔍 Test in corso...';
            testBtn.disabled = true;
            
            fetch('/admin/config/test', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                showAlert(data.message, data.status === 'success' ? 'success' : 'error');
            })
            .catch(error => {
                showAlert('Errore nel test delle connessioni', 'error');
            })
            .finally(() => {
                testBtn.textContent = originalText;
                testBtn.disabled = false;
            });
        }
        
        function testConnectionAdvanced(testBtn, originalText) {
            testBtn.textContent = '⚡ Test Parallelo...';
            testBtn.disabled = true;
            
            // Crea l'area dei risultati se non esiste
            let resultsArea = document.getElementById('test-results-area');
            if (!resultsArea) {
                resultsArea = document.createElement('div');
                resultsArea.id = 'test-results-area';
                resultsArea.innerHTML = `
                    <div style="margin-top: 20px; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #007bff;">
                        <h4>🔍 Risultati Test Connessioni in Tempo Reale</h4>
                        <div id="test-progress" style="margin: 10px 0;">
                            <div style="background: #e9ecef; height: 8px; border-radius: 4px; overflow: hidden;">
                                <div id="test-progress-bar" style="background: #007bff; height: 100%; width: 0%; transition: width 0.3s;"></div>
                            </div>
                            <small id="test-status">Preparazione test...</small>
                        </div>
                        <div style="display: flex; gap: 15px; margin-top: 15px;">
                            <div style="flex: 1;">
                                <h5 style="color: #28a745; margin: 0 0 10px 0;">✅ Funzionanti (<span id="working-count">0</span>)</h5>
                                <div id="working-list" style="max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px;"></div>
                            </div>
                            <div style="flex: 1;">
                                <h5 style="color: #dc3545; margin: 0 0 10px 0;">❌ Non Funzionanti (<span id="failed-count">0</span>)</h5>
                                <div id="failed-list" style="max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px;"></div>
                            </div>
                        </div>
                        <div style="margin-top: 15px;">
                            <button id="stop-test-btn" onclick="stopConfigTest()" style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">⏹️ Stop Test</button>
                            <button id="download-results-btn" onclick="downloadConfigResults()" disabled style="background: #28a745; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-left: 10px;">📥 Scarica Funzionanti</button>
                        </div>
                    </div>
                `;
                document.querySelector('.container').appendChild(resultsArea);
            }
            
            // Reset UI
            document.getElementById('working-list').innerHTML = '';
            document.getElementById('failed-list').innerHTML = '';
            document.getElementById('working-count').textContent = '0';
            document.getElementById('failed-count').textContent = '0';
            document.getElementById('test-progress-bar').style.width = '0%';
            document.getElementById('test-status').textContent = 'Avvio test parallelo...';
            document.getElementById('stop-test-btn').disabled = false;
            document.getElementById('download-results-btn').disabled = true;
            
            let workingCount = 0;
            let failedCount = 0;
            let totalCount = 0;
            let completedCount = 0;
            
            // Avvia test streaming
            const eventSource = new EventSource('/admin/config/test', {
                headers: {
                    'Accept': 'text/event-stream'
                }
            });
            
            window.configTestEventSource = eventSource;
            
            eventSource.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    
                    if (data.status === 'INFO') {
                        document.getElementById('test-status').textContent = data.message;
                        // Estrai il numero totale se presente
                        const match = data.message.match(/(\\d+) proxy/);
                        if (match) {
                            totalCount = parseInt(match[1]);
                        }
                    } else if (data.status === 'SUCCESS') {
                        workingCount++;
                        completedCount++;
                        
                        const workingList = document.getElementById('working-list');
                        const item = document.createElement('div');
                        item.style.cssText = 'padding: 3px; border-bottom: 1px solid #ddd; color: #28a745;';
                        item.innerHTML = `✅ ${data.proxy} <small style="color: #666;">(${data.protocol_used})</small>`;
                        workingList.appendChild(item);
                        
                        document.getElementById('working-count').textContent = workingCount;
                        document.getElementById('download-results-btn').disabled = false;
                        
                        updateTestProgress();
                        
                    } else if (data.status === 'FAIL') {
                        failedCount++;
                        completedCount++;
                        
                        const failedList = document.getElementById('failed-list');
                        const item = document.createElement('div');
                        item.style.cssText = 'padding: 3px; border-bottom: 1px solid #ddd; color: #dc3545;';
                        item.innerHTML = `❌ ${data.proxy} <small style="color: #666;">${data.details}</small>`;
                        failedList.appendChild(item);
                        
                        document.getElementById('failed-count').textContent = failedCount;
                        
                        updateTestProgress();
                        
                    } else if (data.status === 'COMPLETED') {
                        document.getElementById('test-status').textContent = '✅ Test completato!';
                        document.getElementById('stop-test-btn').disabled = true;
                        testBtn.textContent = originalText;
                        testBtn.disabled = false;
                        eventSource.close();
                        
                    } else if (data.status === 'ERROR') {
                        showAlert(`Errore durante il test: ${data.message}`, 'error');
                        testBtn.textContent = originalText;
                        testBtn.disabled = false;
                        eventSource.close();
                    }
                    
                } catch (e) {
                    console.error('Errore parsing risultato test:', e);
                }
            };
            
            eventSource.onerror = function(event) {
                console.error('Errore EventSource:', event);
                showAlert('Errore di connessione durante il test', 'error');
                testBtn.textContent = originalText;
                testBtn.disabled = false;
                eventSource.close();
            };
            
            function updateTestProgress() {
                if (totalCount > 0) {
                    const percentage = (completedCount / totalCount) * 100;
                    document.getElementById('test-progress-bar').style.width = percentage + '%';
                    document.getElementById('test-status').textContent = 
                        `Test in corso: ${completedCount}/${totalCount} (${workingCount} ✅, ${failedCount} ❌)`;
                }
            }
        }
        
        function stopConfigTest() {
            if (window.configTestEventSource) {
                window.configTestEventSource.close();
                document.getElementById('test-status').textContent = '⏹️ Test interrotto';
                document.getElementById('stop-test-btn').disabled = true;
                // Riabilita il pulsante principale
                const testBtn = document.querySelector('button[onclick="testConnection()"]');
                if (testBtn) {
                    testBtn.textContent = '🔍 Test Connessioni';
                    testBtn.disabled = false;
                }
            }
        }
        
        function downloadConfigResults() {
            const workingItems = document.querySelectorAll('#working-list div');
            const proxies = Array.from(workingItems).map(item => {
                const text = item.textContent;
                return text.substring(2, text.indexOf(' (')); // Rimuovi ✅ e la parte del protocollo
            }).join('\n');
            
            if (proxies) {
                const blob = new Blob([proxies], {type: 'text/plain'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'proxy_configurazioni_funzionanti.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }
        }

LOG_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Sistema Log - Proxy</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 0;
        }
        .navbar {
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .navbar h1 {
            font-size: 24px;
            margin: 0;
        }
        .navbar .nav-links a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            transition: background 0.3s;
            margin-left: 10px;
        }
        .navbar .nav-links a:hover {
            background: rgba(255,255,255,0.2);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #252526;
            border-radius: 0;
            box-shadow: 0 5px 20px rgba(0,0,0,0.3);
            overflow: hidden;
            height: calc(100vh - 80px);
            display: flex;
            flex-direction: column;
        }
        .header {
            background: #2d2d30;
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: rgba(255,255,255,0.3);
        }
        .btn.active {
            background: rgba(255,255,255,0.4);
        }
        .log-selector {
            background: #2d2d30;
            padding: 15px;
            border-bottom: 1px solid #3e3e42;
        }
        .log-selector select {
            background: #3c3c3c;
            color: #d4d4d4;
            border: 1px solid #5a5a5a;
            padding: 8px 12px;
            border-radius: 5px;
            margin-right: 10px;
        }
        .log-info {
            background: #2d2d30;
            padding: 10px 15px;
            border-bottom: 1px solid #3e3e42;
            font-size: 12px;
            color: #858585;
        }
        .log-container {
            flex: 1;
            overflow-y: auto;
            background: #1e1e1e;
            padding: 15px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 12px;
            line-height: 1.4;
        }
        .log-line {
            margin-bottom: 2px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .log-line.info {
            color: #4fc3f7;
        }
        .log-line.warning {
            color: #ffb74d;
        }
        .log-line.error {
            color: #f44336;
        }
        .log-line.debug {
            color: #81c784;
        }
        .log-line:hover {
            background: #2d2d30;
        }
        .stats {
            display: flex;
            gap: 20px;
            color: #858585;
            font-size: 11px;
        }
        .auto-scroll {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 25px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        .filter-controls {
            background: #2d2d30;
            padding: 10px 15px;
            border-bottom: 1px solid #3e3e42;
            display: flex;
            gap: 10px;
            align-items: center;
            font-size: 12px;
        }
        .filter-controls input, .filter-controls select {
            background: #3c3c3c;
            color: #d4d4d4;
            border: 1px solid #5a5a5a;
            padding: 5px 10px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>📝 Sistema Log</h1>
        <div class="nav-links">
            <a href="/admin">← Admin</a>
            <a href="/dashboard">📊 Dashboard</a>
            <a href="/logout">🚪 Logout</a>
        </div>
    </nav>
    
    <div class="container">
        <div class="header">
            <h2>Log in Tempo Reale</h2>
            <div class="controls">
                <button class="btn" id="pauseBtn" onclick="toggleStream()">⏸️ Pausa</button>
                <button class="btn" onclick="clearLogs()">🗑️ Pulisci</button>
                <button class="btn" onclick="downloadLog()">💾 Download</button>
                <div class="stats">
                    <span>Righe: <span id="lineCount">0</span></span>
                    <span>Ultimo aggiornamento: <span id="lastUpdate">-</span></span>
                </div>
            </div>
        </div>
        
        <div class="log-selector">
            <label for="logFile">File di Log:</label>
            <select id="logFile" onchange="changeLogFile()">
                {% for log_file in log_files %}
                <option value="{{ log_file.name }}" {% if loop.first %}selected{% endif %}>
                    {{ log_file.name }} ({{ "%.1f"|format(log_file.size/1024) }} KB - {{ log_file.modified }})
                </option>
                {% endfor %}
            </select>
            
            <label for="logLevel">Livello:</label>
            <select id="logLevel" onchange="filterLogs()">
                <option value="">Tutti</option>
                <option value="DEBUG">Debug</option>
                <option value="INFO">Info</option>
                <option value="WARNING">Warning</option>
                <option value="ERROR">Error</option>
            </select>
        </div>
        
        <div class="filter-controls">
            <label>Filtro testo:</label>
            <input type="text" id="textFilter" placeholder="Cerca nei log..." onkeyup="filterLogs()">
            <label>Max righe:</label>
            <input type="number" id="maxLines" value="1000" min="100" max="10000" onchange="filterLogs()">
        </div>
        
        <div class="log-info">
            <span id="logInfo">Connessione al log in corso...</span>
        </div>
        
        <div class="log-container" id="logContainer">
            <!-- I log appariranno qui -->
        </div>
    </div>
    
    <button class="auto-scroll" id="autoScrollBtn" onclick="toggleAutoScroll()">📜 Auto-scroll</button>

    <script>
        let eventSource = null;
        let isPaused = false;
        let autoScroll = true;
        let lineCount = 0;
        let allLogs = [];
        
        function initLogStream() {
            const selectedFile = document.getElementById('logFile').value;
            
            if (eventSource) {
                eventSource.close();
            }
            
            eventSource = new EventSource(`/admin/logs/stream/${selectedFile}`);
            
            eventSource.onmessage = function(event) {
                if (!isPaused) {
                    const data = JSON.parse(event.data);
                    if (data.line) {
                        addLogLine(data.line, data.timestamp);
                    }
                }
            };
            
            eventSource.onerror = function(event) {
                document.getElementById('logInfo').textContent = 'Errore di connessione al log stream';
            };
            
            document.getElementById('logInfo').textContent = `Streaming log: ${selectedFile}`;
        }
        
        function addLogLine(line, timestamp) {
            allLogs.push({line, timestamp});
            lineCount++;
            
            // Mantieni solo le ultime N righe
            const maxLines = parseInt(document.getElementById('maxLines').value);
            if (allLogs.length > maxLines) {
                allLogs = allLogs.slice(-maxLines);
            }
            
            filterLogs();
            updateStats();
        }
        
        function filterLogs() {
            const levelFilter = document.getElementById('logLevel').value;
            const textFilter = document.getElementById('textFilter').value.toLowerCase();
            const container = document.getElementById('logContainer');
            
            let filteredLogs = allLogs;
            
            if (levelFilter) {
                filteredLogs = filteredLogs.filter(log => log.line.includes(levelFilter));
            }
            
            if (textFilter) {
                filteredLogs = filteredLogs.filter(log => log.line.toLowerCase().includes(textFilter));
            }
            
            container.innerHTML = '';
            
            filteredLogs.forEach(log => {
                const div = document.createElement('div');
                div.className = 'log-line ' + getLogLevel(log.line);
                div.textContent = log.line;
                container.appendChild(div);
            });
            
            if (autoScroll) {
                container.scrollTop = container.scrollHeight;
            }
        }
        
        function getLogLevel(line) {
            if (line.includes('ERROR')) return 'error';
            if (line.includes('WARNING')) return 'warning';
            if (line.includes('DEBUG')) return 'debug';
            if (line.includes('INFO')) return 'info';
            return '';
        }
        
        function updateStats() {
            document.getElementById('lineCount').textContent = lineCount;
            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        }
        
        function toggleStream() {
            isPaused = !isPaused;
            const btn = document.getElementById('pauseBtn');
            btn.textContent = isPaused ? '▶️ Riprendi' : '⏸️ Pausa';
            btn.classList.toggle('active', isPaused);
        }
        
        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            const btn = document.getElementById('autoScrollBtn');
            btn.textContent = autoScroll ? '📜 Auto-scroll' : '📜 Scroll OFF';
            btn.classList.toggle('active', !autoScroll);
        }
        
        function changeLogFile() {
            allLogs = [];
            lineCount = 0;
            document.getElementById('logContainer').innerHTML = '';
            initLogStream();
        }
        
        function clearLogs() {
            if (confirm('Sei sicuro di voler pulire i log visualizzati?')) {
                allLogs = [];
                lineCount = 0;
                document.getElementById('logContainer').innerHTML = '';
                updateStats();
            }
        }
        
        function downloadLog() {
            const selectedFile = document.getElementById('logFile').value;
            window.open(`/admin/logs/download/${selectedFile}`, '_blank');
        }
        
        // Inizializza al caricamento della pagina
        document.addEventListener('DOMContentLoaded', function() {
            initLogStream();
        });
        
        // Pulisci la connessione quando si chiude la pagina
        window.addEventListener('beforeunload', function() {
            if (eventSource) {
                eventSource.close();
            }
        });
    </script>
</body>
</html>
"""

INDEX_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Server - Benvenuto</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, rgb(102, 126, 234) 0%, rgb(118, 75, 162) 100%);
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
        app.logger.warning(f"Tentativo di accesso da IP non autorizzato: {request.remote_addr}")
        return "Accesso negato: IP non autorizzato", 403
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_auth(username, password):
            session['logged_in'] = True
            session['username'] = username
            app.logger.info(f"Login riuscito per utente: {username}")
            return redirect(url_for('dashboard'))
        else:
            app.logger.warning(f"Tentativo di login fallito per utente: {username}")
            error = 'Credenziali non valide'
            return render_template_string(LOGIN_TEMPLATE, error=error)
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'unknown')
    session.pop('logged_in', None)
    session.pop('username', None)
    app.logger.info(f"Logout per utente: {username}")
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

@app.route('/admin/config')
@login_required
def admin_config():
    """Pagina di gestione configurazioni"""
    config = config_manager.load_config()
    return render_template_string(CONFIG_TEMPLATE, config=config)

@app.route('/admin/config/save', methods=['POST'])
@login_required
def save_config():
    """Salva la configurazione"""
    try:
        new_config = request.get_json()
        
        # Valida la configurazione
        if not isinstance(new_config, dict):
            return jsonify({"status": "error", "message": "Configurazione non valida"})
        
        # Salva la configurazione
        if config_manager.save_config(new_config):
            # Applica la configurazione all'app
            config_manager.apply_config_to_app(new_config)
            
            # Riavvia i proxy se necessario
            setup_proxies()
            
            app.logger.info(f"Configurazione aggiornata dall'utente {session.get('username', 'unknown')}")
            return jsonify({"status": "success", "message": "Configurazione salvata con successo! Riavvia l'applicazione per applicare tutte le modifiche."})
        else:
            return jsonify({"status": "error", "message": "Errore nel salvataggio della configurazione"})
            
    except Exception as e:
        app.logger.error(f"Errore nel salvataggio configurazione: {e}")
        return jsonify({"status": "error", "message": f"Errore: {str(e)}"})

@app.route('/admin/config/reset', methods=['POST'])
@login_required
def reset_config():
    """Ripristina la configurazione di default"""
    try:
        default_config = config_manager.default_config.copy()
        if config_manager.save_config(default_config):
            config_manager.apply_config_to_app(default_config)
            app.logger.info("Configurazione ripristinata ai valori di default")
            return jsonify({"status": "success", "message": "Configurazione ripristinata ai valori di default"})
        else:
            return jsonify({"status": "error", "message": "Errore nel ripristino della configurazione"})
    except Exception as e:
        app.logger.error(f"Errore nel ripristino configurazione: {e}")
        return jsonify({"status": "error", "message": f"Errore: {str(e)}"})

@app.route('/admin/config/test', methods=['POST'])
@login_required
def test_config():
    """Testa le configurazioni proxy con sistema parallelo avanzato"""
    try:
        config = config_manager.load_config()
        
        # Controlla se è una richiesta per streaming
        if request.headers.get('Accept') == 'text/event-stream':
            return test_config_stream(config)
        
        # Altrimenti usa il test semplice (per compatibilità)
        return test_config_simple(config)
            
    except Exception as e:
        app.logger.error(f"Errore nel test configurazioni: {e}")
        return jsonify({"status": "error", "message": f"Errore nel test: {str(e)}"})

def test_config_simple(config):
    """Test semplice per compatibilità"""
    results = []
    
    # Test basic per SOCKS5
    if config.get('SOCKS5_PROXY'):
        proxies = [p.strip() for p in config['SOCKS5_PROXY'].split(',') if p.strip()]
        for proxy in proxies[:3]:
            try:
                response = requests.get('https://httpbin.org/ip', 
                                      proxies={'http': proxy, 'https': proxy}, 
                                      timeout=10)
                if response.status_code == 200:
                    results.append(f"✅ SOCKS5 {proxy}: OK")
                else:
                    results.append(f"❌ SOCKS5 {proxy}: Status {response.status_code}")
            except Exception as e:
                results.append(f"❌ SOCKS5 {proxy}: {str(e)}")
    
    # Test basic per HTTP
    if config.get('HTTP_PROXY'):
        proxies = [p.strip() for p in config['HTTP_PROXY'].split(',') if p.strip()]
        for proxy in proxies[:2]:
            try:
                response = requests.get('http://httpbin.org/ip', 
                                      proxies={'http': proxy}, 
                                      timeout=10)
                if response.status_code == 200:
                    results.append(f"✅ HTTP {proxy}: OK")
                else:
                    results.append(f"❌ HTTP {proxy}: Status {response.status_code}")
            except Exception as e:
                results.append(f"❌ HTTP {proxy}: {str(e)}")
    
    app.logger.info("Test configurazioni semplice eseguito")
    message = "Test completato:\n" + "\n".join(results)
    return jsonify({"status": "success", "message": message})

def test_config_stream(config):
    """Test avanzato con streaming per configurazioni proxy"""
    session_id = str(uuid.uuid4())
    
    # Raccogli tutti i proxy dalle configurazioni
    all_proxies = []
    
    if config.get('SOCKS5_PROXY'):
        socks_proxies = [p.strip() for p in config['SOCKS5_PROXY'].split(',') if p.strip()]
        all_proxies.extend(socks_proxies)
    
    if config.get('HTTP_PROXY'):
        http_proxies = [p.strip() for p in config['HTTP_PROXY'].split(',') if p.strip()]
        all_proxies.extend(http_proxies)
        
    if config.get('HTTPS_PROXY'):
        https_proxies = [p.strip() for p in config['HTTPS_PROXY'].split(',') if p.strip()]
        all_proxies.extend(https_proxies)
    
    if not all_proxies:
        def no_proxies():
            yield f"data: {json.dumps({'status': 'INFO', 'message': 'Nessun proxy configurato da testare'})}\n\n"
        return Response(no_proxies(), mimetype='text/event-stream')
    
    # Registra il test attivo
    with active_tests_lock:
        active_tests[session_id] = {
            'running': True,
            'start_time': datetime.now(),
            'total_proxies': len(all_proxies),
            'completed_count': 0,
            'max_workers': min(len(all_proxies), 10)  # Max 10 worker per i test di configurazione
        }
    
    def generate_config_test_results():
        try:
            max_workers = min(10, len(all_proxies))  # Limitato a 10 per i test di configurazione
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Invia tutti i proxy per il testing parallelo
                future_to_proxy = {
                    executor.submit(test_config_single_proxy, proxy, session_id): proxy 
                    for proxy in all_proxies
                }
                
                yield f"data: {json.dumps({'status': 'INFO', 'message': f'Avvio test di {len(all_proxies)} proxy con {max_workers} thread...'})}\n\n"
                
                for future in as_completed(future_to_proxy):
                    # Controlla se il test è stato fermato
                    with active_tests_lock:
                        if session_id not in active_tests or not active_tests[session_id]['running']:
                            for f in future_to_proxy:
                                f.cancel()
                            break
                    
                    result = future.result()
                    if result and result['status'] != 'STOPPED':
                        # Aggiorna il contatore
                        with active_tests_lock:
                            if session_id in active_tests:
                                active_tests[session_id]['completed_count'] += 1
                        
                        yield f"data: {json.dumps(result)}\n\n"
                        
        except Exception as e:
            yield f"data: {json.dumps({'status': 'ERROR', 'message': f'Errore durante il test: {str(e)}'})}\n\n"
        finally:
            # Pulisci sempre il test attivo
            with active_tests_lock:
                if session_id in active_tests:
                    active_tests[session_id]['running'] = False
                    del active_tests[session_id]
            
            yield f"data: {json.dumps({'status': 'COMPLETED', 'message': 'Test delle configurazioni completato'})}\n\n"
    
    return Response(generate_config_test_results(), mimetype='text/event-stream')

def test_config_single_proxy(proxy_line, session_id):
    """Test di un singolo proxy per le configurazioni"""
    try:
        # Controlla se il test è stato fermato
        with active_tests_lock:
            if session_id not in active_tests or not active_tests[session_id]['running']:
                return {'status': 'STOPPED', 'details': 'Test fermato', 'is_protocol_error': False}

        # Determina il tipo di proxy
        if proxy_line.startswith(('socks5h://', 'socks5://')):
            proxy_type = 'socks5'
            address_for_curl = proxy_line.split('//', 1)[1] if '//' in proxy_line else proxy_line
        elif proxy_line.startswith(('http://', 'https://')):
            proxy_type = 'http'
            address_for_curl = proxy_line
        else:
            # Prova come HTTP per default
            proxy_type = 'http'
            address_for_curl = proxy_line

        # Test con httpbin.org
        if proxy_type == 'socks5':
            cmd = ['curl', '-k', '--max-time', '10', '--silent', '--show-error', 
                   '--connect-timeout', '7', '--socks5-hostname', address_for_curl, 
                   'https://httpbin.org/ip']
        else:
            cmd = ['curl', '-k', '--max-time', '10', '--silent', '--show-error', 
                   '--connect-timeout', '7', '--proxy', address_for_curl, 
                   'https://httpbin.org/ip']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        # Controlla di nuovo se fermato
        with active_tests_lock:
            if session_id not in active_tests or not active_tests[session_id]['running']:
                return {'status': 'STOPPED', 'details': 'Test fermato', 'is_protocol_error': False}
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                # Verifica che la risposta sia JSON valido
                import json
                json.loads(result.stdout)
                return {
                    'status': 'SUCCESS',
                    'proxy': proxy_line,
                    'proxy_to_save': proxy_line,
                    'protocol_used': proxy_type.upper(),
                    'details': 'Connessione riuscita'
                }
            except:
                return {
                    'status': 'FAIL',
                    'proxy': proxy_line,
                    'details': 'Risposta non valida',
                    'is_protocol_error': False
                }
        else:
            return {
                'status': 'FAIL',
                'proxy': proxy_line,
                'details': f'Errore: {result.stderr.strip() if result.stderr else "Timeout o connessione fallita"}',
                'is_protocol_error': False
            }
            
    except subprocess.TimeoutExpired:
        return {
            'status': 'FAIL',
            'proxy': proxy_line,
            'details': 'Timeout durante il test',
            'is_protocol_error': False
        }
    except Exception as e:
        return {
            'status': 'FAIL',
            'proxy': proxy_line,
            'details': f'Errore: {str(e)}',
            'is_protocol_error': False
        }
        
@app.route('/admin/logs')
@login_required
def admin_logs():
    """Pagina di visualizzazione log"""
    log_files = log_manager.get_log_files()
    return render_template_string(LOG_TEMPLATE, log_files=log_files)

@app.route('/admin/logs/stream/<filename>')
@login_required
def stream_logs(filename):
    """Stream in tempo reale dei log"""
    return Response(
        log_manager.stream_log_file(filename),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*'
        }
    )

@app.route('/admin/logs/download/<filename>')
@login_required
def download_log(filename):
    """Download di un file di log"""
    try:
        filepath = os.path.join('logs', filename)
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return Response(
                content,
                mimetype='text/plain',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}'
                }
            )
        else:
            return "File non trovato", 404
    except Exception as e:
        app.logger.error(f"Errore nel download log {filename}: {e}")
        return f"Errore nel download: {str(e)}", 500

@app.route('/admin/clear-cache', methods=['POST'])
@login_required
def clear_cache():
    """Pulisce tutte le cache"""
    M3U8_CACHE.clear()
    TS_CACHE.clear()
    KEY_CACHE.clear()
    cleanup_sessions()
    app.logger.info(f"Cache pulita dall'utente {session.get('username', 'unknown')}")
    return jsonify({"status": "success", "message": "Cache pulita con successo"})

@app.route('/stats')
def get_stats():
    """Endpoint per ottenere le statistiche di sistema"""
    stats = get_system_stats()
    stats['daddy_base_url'] = get_daddylive_base_url()
    stats['session_count'] = len(SESSION_POOL)
    stats['proxy_count'] = len(PROXY_LIST)
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

# --- Route Proxy (mantieni tutte le route proxy esistenti) ---

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto DaddyLive 2025 e caching"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"

    if cache_key in M3U8_CACHE:
        app.logger.info(f"Cache HIT per M3U8: {m3u_url}")
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl")
    app.logger.info(f"Cache MISS per M3U8: {m3u_url}")

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
        app.logger.info(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        app.logger.info(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        if not resolved_url.endswith('.m3u8'):
            app.logger.error(f"URL risolto non è un M3U8: {resolved_url}")
            return "Errore: Impossibile ottenere un M3U8 valido dal canale", 500

        app.logger.info(f"Fetching M3U8 content from clean URL: {resolved_url}")

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
        app.logger.error(f"Errore durante il download o la risoluzione del file: {str(e)}")
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        app.logger.error(f"Errore generico nella funzione proxy_m3u: {str(e)}")
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
        app.logger.error(f"Errore durante la risoluzione dell'URL: {str(e)}")
        return f"Errore durante la risoluzione dell'URL: {str(e)}", 500

@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con connessioni persistenti, headers personalizzati e caching"""
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    if ts_url in TS_CACHE:
        app.logger.info(f"Cache HIT per TS: {ts_url}")
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")
    app.logger.info(f"Cache MISS per TS: {ts_url}")

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
                        app.logger.warning(f"Timeout durante il download del segmento TS (tentativo {attempt + 1}): {ts_url}")
                        return
                    raise
                finally:
                    ts_content = b"".join(content_parts)
                    if ts_content and len(ts_content) > 1024:
                        TS_CACHE[ts_url] = ts_content
                        app.logger.info(f"Segmento TS cachato ({len(ts_content)} bytes) per: {ts_url}")

            return Response(generate_and_cache(), content_type="video/mp2t")

        except requests.exceptions.ConnectionError as e:
            if "Read timed out" in str(e) or "timed out" in str(e).lower():
                app.logger.warning(f"Timeout del segmento TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
                if attempt == max_retries - 1:
                    return f"Errore: Timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
                time.sleep(2 ** attempt)
                continue
            else:
                app.logger.error(f"Errore di connessione per il segmento TS: {str(e)}")
                return f"Errore di connessione per il segmento TS: {str(e)}", 500
        except requests.exceptions.ReadTimeout as e:
            app.logger.warning(f"Read timeout esplicito per il segmento TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
            if attempt == max_retries - 1:
                return f"Errore: Read timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
            time.sleep(2 ** attempt)
            continue
        except requests.RequestException as e:
            app.logger.error(f"Errore durante il download del segmento TS: {str(e)}")
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
                    app.logger.error(f"Errore nel parsing di #EXTHTTP '{line}': {e}")
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
                                    app.logger.warning(f"Malformed http-header option in EXTVLCOPT: {opt_pair}")
                                    continue
                            
                            if header_key:
                                encoded_key = quote(quote(header_key))
                                encoded_value = quote(quote(value))
                                current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                            
                except Exception as e:
                    app.logger.error(f"Errore nel parsing di #EXTVLCOPT '{line}': {e}")
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
        app.logger.error(f"Fallito il download di '{m3u_url}': {e}")
        return f"Errore durante il download della lista M3U: {str(e)}", 500
    except Exception as e:
        app.logger.error(f"Errore generico nel proxy M3U: {e}")
        return f"Errore generico: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Proxy per la chiave AES-128 con headers personalizzati e caching"""
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

    if key_url in KEY_CACHE:
        app.logger.info(f"Cache HIT per KEY: {key_url}")
        return Response(KEY_CACHE[key_url], content_type="application/octet-stream")
    app.logger.info(f"Cache MISS per KEY: {key_url}")

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
        app.logger.error(f"Errore durante il download della chiave AES-128: {str(e)}")
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

# --- Inizializzazione dell'app ---

# Carica e applica la configurazione salvata al startup
saved_config = config_manager.load_config()
config_manager.apply_config_to_app(saved_config)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    
    # Log di avvio
    app.logger.info("="*50)
    app.logger.info("🚀 PROXY SERVER AVVIATO")
    app.logger.info("="*50)
    app.logger.info(f"Porta: {port}")
    app.logger.info(f"Admin Username: {ADMIN_USERNAME}")
    app.logger.info(f"Admin Password: {ADMIN_PASSWORD}")
    app.logger.info(f"Proxy configurati: {len(PROXY_LIST)}")
    if ALLOWED_IPS:
        app.logger.info(f"IP consentiti: {ALLOWED_IPS}")
    else:
        app.logger.info("Accesso consentito da tutti gli IP")
    app.logger.info("="*50)
    
    app.run(host="0.0.0.0", port=port, debug=False)
