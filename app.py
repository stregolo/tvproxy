from flask import Flask, request, Response, jsonify, session, redirect, url_for
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
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
load_dotenv()

# --- Configurazione Autenticazione ---
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

def requires_auth(f):
    """Decorator per richiedere autenticazione"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Pagina di login per la dashboard"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('advanced_dashboard'))
        else:
            error = 'Credenziali non valide'
            return render_login_page(error)
    
    return render_login_page()

def render_login_page(error=None):
    """Renderizza la pagina di login"""
    login_html = f"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Proxy Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
        }}
        
        .login-header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        
        .login-header h1 {{
            color: #333;
            font-size: 2rem;
            margin-bottom: 10px;
        }}
        
        .login-header p {{
            color: #666;
            font-size: 1rem;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }}
        
        .form-control {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }}
        
        .form-control:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        
        .btn-login {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
        }}
        
        .btn-login:hover {{
            transform: translateY(-2px);
        }}
        
        .error-message {{
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            border: 1px solid #fcc;
        }}
        
        .info-box {{
            background: #e8f4f8;
            color: #2c5aa0;
            padding: 15px;
            border-radius: 6px;
            margin-top: 20px;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🚀 Proxy Dashboard</h1>
            <p>Accedi per continuare</p>
        </div>
        
        {"<div class='error-message'>" + error + "</div>" if error else ""}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" class="form-control" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" class="form-control" required>
            </div>
            
            <button type="submit" class="btn-login">Accedi</button>
        </form>
        
        <div class="info-box">
            <strong>Credenziali predefinite:</strong><br>
            Username: admin<br>
            Password: admin123<br><br>
            <small>Cambia le credenziali impostando le variabili d'ambiente ADMIN_USERNAME e ADMIN_PASSWORD</small>
        </div>
    </div>
</body>
</html>
    """
    return login_html

@app.route('/logout')
def logout():
    """Logout dall'applicazione"""
    session.pop('authenticated', None)
    return redirect(url_for('login'))

# --- Configurazione Generale ---
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("ATTENZIONE: La verifica del certificato SSL è DISABILITATA. Questo potrebbe esporre a rischi di sicurezza.")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))
print(f"Timeout per le richieste impostato a {REQUEST_TIMEOUT} secondi.")

# Configurazioni Keep-Alive
KEEP_ALIVE_TIMEOUT = int(os.environ.get('KEEP_ALIVE_TIMEOUT', 300))
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

# Strutture dati per analytics
analytics_data = {
    'requests_per_endpoint': defaultdict(int),
    'response_times': defaultdict(list),
    'proxy_stats': defaultdict(lambda: {'success': 0, 'failure': 0}),
    'hourly_requests': defaultdict(int),
    'error_log': deque(maxlen=1000),
    'recent_requests': deque(maxlen=500)
}

analytics_lock = threading.Lock()

# Configurazione dinamica (rimossa sezione security/whitelist)
app_config = {
    'proxies': [],
    'cache_settings': {
        'm3u8_ttl': 5,
        'ts_ttl': 300
    }
}

def mask_proxy_ip(proxy_url):
    """Maschera l'IP del proxy per privacy"""
    if not proxy_url:
        return None
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(proxy_url)
        if parsed.hostname:
            # Mostra solo i primi 2 ottetti dell'IP
            ip_parts = parsed.hostname.split('.')
            if len(ip_parts) == 4:
                masked_ip = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx"
                return f"{parsed.scheme}://{masked_ip}:{parsed.port}"
        return "proxy-***"
    except:
        return "proxy-***"

def track_request(endpoint, response_time, proxy_used=None, success=True, error=None):
    """Traccia le metriche delle richieste"""
    with analytics_lock:
        current_hour = datetime.now().strftime('%Y-%m-%d %H:00')
        
        analytics_data['requests_per_endpoint'][endpoint] += 1
        analytics_data['response_times'][endpoint].append(response_time)
        analytics_data['hourly_requests'][current_hour] += 1
        
        # Mantieni solo le ultime 1000 richieste per endpoint
        if len(analytics_data['response_times'][endpoint]) > 1000:
            analytics_data['response_times'][endpoint] = analytics_data['response_times'][endpoint][-500:]
        
        if proxy_used:
            # Maschera l'IP del proxy per privacy
            masked_proxy = mask_proxy_ip(proxy_used)
            if success:
                analytics_data['proxy_stats'][masked_proxy]['success'] += 1
            else:
                analytics_data['proxy_stats'][masked_proxy]['failure'] += 1
        
        if error:
            analytics_data['error_log'].append({
                'timestamp': datetime.now().isoformat(),
                'endpoint': endpoint,
                'error': str(error),
                'proxy': mask_proxy_ip(proxy_used) if proxy_used else None
            })
        
        analytics_data['recent_requests'].append({
            'timestamp': datetime.now().isoformat(),
            'endpoint': endpoint,
            'response_time': response_time,
            'success': success
        })

def get_system_stats():
    """Ottiene le statistiche di sistema in tempo reale"""
    global system_stats
    # Memoria RAM
    memory = psutil.virtual_memory()
    system_stats['ram_usage'] = memory.percent
    system_stats['ram_used_gb'] = memory.used / (1024**3)
    system_stats['ram_total_gb'] = memory.total / (1024**3)
    
    # Utilizzo di rete
    net_io = psutil.net_io_counters()
    system_stats['network_sent'] = net_io.bytes_sent / (1024**2)
    system_stats['network_recv'] = net_io.bytes_recv / (1024**2)
    
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
                sent_per_sec = (current_sent - prev_sent) / (1024 * 1024)
                recv_per_sec = (current_recv - prev_recv) / (1024 * 1024)
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
            time.sleep(300)
            with SESSION_LOCK:
                active_sessions = len(SESSION_POOL)
                print(f"Sessioni attive nel pool: {active_sessions}")
                
                if active_sessions > 10:
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
    
    pool_key = proxy_url if proxy_url else 'default'
    
    with SESSION_LOCK:
        if pool_key not in SESSION_POOL:
            session = create_robust_session()
            if proxy_url:
                session.proxies.update({'http': proxy_url, 'https': proxy_url})
            SESSION_POOL[pool_key] = session
            print(f"Nuova sessione persistente creata per: {mask_proxy_ip(pool_key)}")
        
        return SESSION_POOL[pool_key]

def make_persistent_request(url, headers=None, timeout=None, proxy_url=None, **kwargs):
    """Effettua una richiesta usando connessioni persistenti"""
    session = get_persistent_session(proxy_url)
    
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
        with SESSION_LOCK:
            if proxy_url in SESSION_POOL:
                del SESSION_POOL[proxy_url]
        raise

def get_dynamic_timeout(url, base_timeout=REQUEST_TIMEOUT):
    """Calcola timeout dinamico basato sul tipo di risorsa."""
    if '.ts' in url.lower():
        return base_timeout * 2
    elif '.m3u8' in url.lower():
        return base_timeout * 1.5
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
        
        iframes = re.findall(r']*href="([^"]+)"[^>]*>\s*]*>\s*Player\s*2\s*<\/button>', response.text)
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

# --- ENDPOINT PROXY PRINCIPALI ---

@app.route('/proxy')
def proxy_generic():
    """Endpoint generico per proxy di URL"""
    start_time = time.time()
    endpoint = '/proxy'
    proxy_used = None
    
    try:
        url = request.args.get('url')
        if not url:
            return "Parametro 'url' mancante", 400
        
        # Estrai headers personalizzati
        headers = {}
        for key, value in request.args.items():
            if key.startswith('h_'):
                header_name = key[2:].replace('_', '-')
                headers[header_name] = value
        
        # Headers predefiniti
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        headers.update(default_headers)
        
        proxy_config = get_proxy_for_url(url)
        proxy_used = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            url,
            headers=headers,
            proxy_url=proxy_used
        )
        
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, True)
        
        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )
        
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, False, e)
        return f"Errore: {str(e)}", 500

@app.route('/proxy/m3u')
def proxy_m3u():
    """Endpoint specializzato per file M3U8 con cache"""
    start_time = time.time()
    endpoint = '/proxy/m3u'
    proxy_used = None
    
    try:
        url = request.args.get('url')
        if not url:
            return "Parametro 'url' mancante", 400
        
        # Check cache prima
        if url in M3U8_CACHE:
            response_time = (time.time() - start_time) * 1000
            track_request(endpoint, response_time, None, True)
            return Response(M3U8_CACHE[url], content_type="application/vnd.apple.mpegurl")
        
        # Estrai headers personalizzati
        headers = {}
        for key, value in request.args.items():
            if key.startswith('h_'):
                header_name = key[2:].replace('_', '-')
                headers[header_name] = value
        
        # Risolvi URL se è un link DaddyLive
        resolved_data = resolve_m3u8_link(url, headers)
        resolved_url = resolved_data["resolved_url"]
        resolved_headers = resolved_data["headers"]
        
        if not resolved_url:
            return "Impossibile risolvere l'URL", 400
        
        proxy_config = get_proxy_for_url(resolved_url)
        proxy_used = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            resolved_url,
            headers=resolved_headers,
            proxy_url=proxy_used
        )
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
        
        content = response.text
        
        # Modifica il contenuto M3U8 per proxare i segmenti
        modified_content = ""
        headers_query = "&".join([f"h_{k.replace('-', '_')}={quote(v)}" for k, v in resolved_headers.items()])
        
        for line in content.split('\n'):
            if line.strip() and not line.startswith('#'):
                # È un URL di segmento
                if line.startswith('http'):
                    segment_url = line.strip()
                else:
                    # URL relativo
                    base_url = '/'.join(resolved_url.split('/')[:-1])
                    segment_url = urljoin(base_url + '/', line.strip())
                
                # Determina il tipo di segmento
                if '.ts' in segment_url.lower():
                    proxied_url = f"/proxy/ts?url={quote(segment_url)}&{headers_query}"
                elif '.m3u8' in segment_url.lower():
                    proxied_url = f"/proxy/m3u?url={quote(segment_url)}&{headers_query}"
                else:
                    proxied_url = f"/proxy?url={quote(segment_url)}&{headers_query}"
                
                modified_content += proxied_url + '\n'
            elif line.startswith('#EXT-X-KEY'):
                # Gestisci le chiavi AES-128
                modified_content += replace_key_uri(line, headers_query) + '\n'
            else:
                modified_content += line + '\n'
        
        # Salva in cache
        M3U8_CACHE[url] = modified_content
        
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, True)
        
        return Response(modified_content, content_type="application/vnd.apple.mpegurl")
        
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, False, e)
        return f"Errore: {str(e)}", 500

@app.route('/proxy/ts')
def proxy_ts():
    """Endpoint specializzato per segmenti TS con cache"""
    start_time = time.time()
    endpoint = '/proxy/ts'
    proxy_used = None
    
    try:
        url = request.args.get('url')
        if not url:
            return "Parametro 'url' mancante", 400
        
        # Check cache prima
        if url in TS_CACHE:
            response_time = (time.time() - start_time) * 1000
            track_request(endpoint, response_time, None, True)
            return Response(TS_CACHE[url], content_type="video/mp2t")
        
        # Estrai headers personalizzati
        headers = {}
        for key, value in request.args.items():
            if key.startswith('h_'):
                header_name = key[2:].replace('_', '-')
                headers[header_name] = value
        
        proxy_config = get_proxy_for_url(url)
        proxy_used = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            url,
            headers=headers,
            timeout=get_dynamic_timeout(url),
            proxy_url=proxy_used
        )
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
        
        content = response.content
        
        # Salva in cache
        TS_CACHE[url] = content
        
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, True)
        
        return Response(content, content_type="video/mp2t")
        
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, False, e)
        return f"Errore: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Endpoint per chiavi di decrittazione AES-128"""
    start_time = time.time()
    endpoint = '/proxy/key'
    proxy_used = None
    
    try:
        url = request.args.get('url')
        if not url:
            return "Parametro 'url' mancante", 400
        
        # Check cache prima
        if url in KEY_CACHE:
            response_time = (time.time() - start_time) * 1000
            track_request(endpoint, response_time, None, True)
            return Response(KEY_CACHE[url], content_type="application/octet-stream")
        
        # Estrai headers personalizzati
        headers = {}
        for key, value in request.args.items():
            if key.startswith('h_'):
                header_name = key[2:].replace('_', '-')
                headers[header_name] = value
        
        proxy_config = get_proxy_for_url(url)
        proxy_used = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            url,
            headers=headers,
            proxy_url=proxy_used
        )
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
        
        content = response.content
        
        # Salva in cache
        KEY_CACHE[url] = content
        
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, True)
        
        return Response(content, content_type="application/octet-stream")
        
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, proxy_used, False, e)
        return f"Errore: {str(e)}", 500

@app.route('/proxy/resolve')
def proxy_resolve():
    """Endpoint per risolvere URL DaddyLive"""
    start_time = time.time()
    endpoint = '/proxy/resolve'
    
    try:
        url = request.args.get('url')
        if not url:
            return "Parametro 'url' mancante", 400
        
        # Processa l'URL
        processed_url = process_daddylive_url(url)
        
        # Risolvi l'URL
        resolved_data = resolve_m3u8_link(processed_url)
        
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, None, True)
        
        return jsonify({
            'original_url': url,
            'processed_url': processed_url,
            'resolved_url': resolved_data['resolved_url'],
            'headers': resolved_data['headers']
        })
        
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        track_request(endpoint, response_time, None, False, e)
        return jsonify({'error': str(e)}), 500

# --- API ENDPOINTS (con autenticazione per quelli sensibili) ---

@app.route('/api/analytics')
@requires_auth
def get_analytics():
    """API per ottenere dati analytics"""
    with analytics_lock:
        # Calcola metriche aggregate
        avg_response_times = {}
        for endpoint, times in analytics_data['response_times'].items():
            if times:
                avg_response_times[endpoint] = sum(times) / len(times)
        
        # Prepara dati per grafici (ultime 24 ore)
        now = datetime.now()
        hourly_data = []
        for i in range(24):
            hour = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H:00')
            hourly_data.append({
                'hour': hour,
                'requests': analytics_data['hourly_requests'].get(hour, 0)
            })
        
        return jsonify({
            'requests_per_endpoint': dict(analytics_data['requests_per_endpoint']),
            'avg_response_times': avg_response_times,
            'proxy_stats': dict(analytics_data['proxy_stats']),
            'hourly_requests': list(reversed(hourly_data)),
            'recent_errors': list(analytics_data['error_log'])[-50:],
            'recent_requests': list(analytics_data['recent_requests'])[-100:]
        })

@app.route('/api/proxies', methods=['GET', 'POST'])
@requires_auth
def manage_proxies():
    """Gestione dinamica dei proxy"""
    if request.method == 'GET':
        # Restituisce lista proxy con IP mascherati
        masked_proxies = []
        for i, proxy in enumerate(PROXY_LIST):
            masked_proxies.append({
                'id': str(i),
                'masked_url': mask_proxy_ip(proxy),
                'status': 'active'  # Qui potresti implementare un check reale
            })
        return jsonify({'proxies': masked_proxies})
    
    elif request.method == 'POST':
        data = request.get_json()
        proxy_url = data.get('proxy_url')
        
        if not proxy_url:
            return jsonify({'success': False, 'error': 'URL proxy mancante'})
        
        # Valida formato proxy
        if not any(proxy_url.startswith(proto) for proto in ['http://', 'https://', 'socks5://', 'socks5h://']):
            return jsonify({'success': False, 'error': 'Formato proxy non valido'})
        
        PROXY_LIST.append(proxy_url)
        return jsonify({'success': True})

@app.route('/api/proxies/<proxy_id>', methods=['DELETE'])
@requires_auth
def delete_proxy(proxy_id):
    """Rimuove un proxy dalla lista"""
    try:
        index = int(proxy_id)
        if 0 <= index < len(PROXY_LIST):
            PROXY_LIST.pop(index)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Proxy non trovato'})
    except (ValueError, IndexError):
        return jsonify({'success': False, 'error': 'ID proxy non valido'})

@app.route('/api/test-url', methods=['POST'])
@requires_auth
def test_url():
    """Testa un URL M3U/M3U8"""
    data = request.get_json()
    url = data.get('url')
    headers = data.get('headers', {})
    
    if not url:
        return jsonify({'success': False, 'error': 'URL mancante'})
    
    start_time = time.time()
    try:
        proxy_config = get_proxy_for_url(url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            url,
            headers=headers,
            timeout=10,
            proxy_url=proxy_key
        )
        
        response_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'success': True,
            'response_time': round(response_time, 2),
            'status_code': response.status_code,
            'content_type': response.headers.get('Content-Type', 'unknown'),
            'content_length': len(response.content)
        })
        
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return jsonify({
            'success': False,
            'error': str(e),
            'response_time': round(response_time, 2)
        })

@app.route('/api/cache/clear', methods=['POST'])
@requires_auth
def clear_cache():
    """Pulisce tutte le cache"""
    try:
        M3U8_CACHE.clear()
        TS_CACHE.clear()
        KEY_CACHE.clear()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/config/export')
@requires_auth
def export_config():
    """Esporta la configurazione corrente"""
    config = {
        'proxies': [mask_proxy_ip(proxy) for proxy in PROXY_LIST],
        'cache_settings': app_config['cache_settings'],
        'export_date': datetime.now().isoformat()
    }
    
    response = Response(
        json.dumps(config, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=proxy-config.json'}
    )
    return response

@app.route('/api/config/cache', methods=['POST'])
@requires_auth
def update_cache_config():
    """Aggiorna configurazione cache"""
    data = request.get_json()
    
    try:
        app_config['cache_settings']['m3u8_ttl'] = data.get('m3u8_ttl', 5)
        app_config['cache_settings']['ts_ttl'] = data.get('ts_ttl', 300)
        
        # Ricrea le cache con nuovi TTL
        global M3U8_CACHE, TS_CACHE
        M3U8_CACHE = TTLCache(maxsize=200, ttl=app_config['cache_settings']['m3u8_ttl'])
        TS_CACHE = TTLCache(maxsize=1000, ttl=app_config['cache_settings']['ts_ttl'])
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/stats')
def get_stats():
    """Endpoint per ottenere le statistiche di sistema (pubblico)"""
    stats = get_system_stats()
    return jsonify(stats)

@app.route('/dashboard')
@requires_auth
def advanced_dashboard():
    """Dashboard avanzato con tutte le funzionalità (protetto da autenticazione)"""
    stats = get_system_stats()
    daddy_base_url = get_daddylive_base_url()
    
    dashboard_html = f"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Dashboard Avanzato</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-color: #ffffff;
            --text-color: #333333;
            --card-bg: #f8f9fa;
            --border-color: #dee2e6;
            --primary-color: #007bff;
            --success-color: #28a745;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
        }}
        
        [data-theme="dark"] {{
            --bg-color: #1a1a1a;
            --text-color: #ffffff;
            --card-bg: #2d2d2d;
            --border-color: #404040;
            --primary-color: #0d6efd;
            --success-color: #198754;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            transition: all 0.3s ease;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .header h1 {{
            color: var(--primary-color);
            font-size: 2.5rem;
            font-weight: 300;
        }}
        
        .controls {{
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}
        
        .btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }}
        
        .btn-primary {{
            background-color: var(--primary-color);
            color: white;
        }}
        
        .btn-secondary {{
            background-color: var(--card-bg);
            color: var(--text-color);
            border: 1px solid var(--border-color);
        }}
        
        .btn-danger {{
            background-color: var(--danger-color);
            color: white;
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        
        .toggle-switch {{
            position: relative;
            display: inline-block;
            width: 60px;
            height: 34px;
        }}
        
        .toggle-switch input {{
            opacity: 0;
            width: 0;
            height: 0;
        }}
        
        .slider {{
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 34px;
        }}
        
        .slider:before {{
            position: absolute;
            content: "";
            height: 26px;
            width: 26px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }}
        
        input:checked + .slider {{
            background-color: var(--primary-color);
        }}
        
        input:checked + .slider:before {{
            transform: translateX(26px);
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }}
        
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .card-title {{
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--primary-color);
        }}
        
        .metric {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .metric:last-child {{
            border-bottom: none;
        }}
        
        .metric-value {{
            font-weight: 600;
            font-size: 1.1rem;
        }}
        
        .status-indicator {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }}
        
        .status-online {{
            background-color: var(--success-color);
        }}
        
        .status-offline {{
            background-color: var(--danger-color);
        }}
        
        .status-warning {{
            background-color: var(--warning-color);
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            margin-top: 20px;
        }}
        
        .tabs {{
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }}
        
        .tab {{
            padding: 12px 24px;
            cursor: pointer;
            border: none;
            background: none;
            color: var(--text-color);
            font-size: 14px;
            transition: all 0.3s ease;
        }}
        
        .tab.active {{
            border-bottom: 2px solid var(--primary-color);
            color: var(--primary-color);
            font-weight: 600;
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .log-container {{
            background: #1e1e1e;
            color: #00ff00;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
        
        .test-form {{
            display: grid;
            gap: 15px;
        }}
        
        .form-group {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}
        
        .form-control {{
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-color);
            color: var(--text-color);
            font-size: 14px;
        }}
        
        .form-control:focus {{
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
        }}
        
        .notification {{
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }}
        
        .notification.show {{
            transform: translateX(0);
        }}
        
        .notification.success {{
            background-color: var(--success-color);
        }}
        
        .notification.error {{
            background-color: var(--danger-color);
        }}
        
        .notification.warning {{
            background-color: var(--warning-color);
        }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background-color: var(--border-color);
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .progress-fill {{
            height: 100%;
            background-color: var(--primary-color);
            transition: width 0.3s ease;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header {{
                flex-direction: column;
                text-align: center;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
            
            .grid {{
                grid-template-columns: 1fr;
            }}
            
            .controls {{
                justify-content: center;
            }}
        }}
        
        .proxy-list {{
            max-height: 200px;
            overflow-y: auto;
        }}
        
        .proxy-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .proxy-item:last-child {{
            border-bottom: none;
        }}
        
        .config-section {{
            margin-bottom: 30px;
        }}
        
        .config-section h3 {{
            color: var(--primary-color);
            margin-bottom: 15px;
            font-size: 1.3rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Proxy Dashboard Avanzato</h1>
            <div class="controls">
                <label class="toggle-switch">
                    <input type="checkbox" id="autoRefresh" checked>
                    <span class="slider"></span>
                </label>
                <span>Auto Refresh</span>
                
                <label class="toggle-switch">
                    <input type="checkbox" id="darkMode">
                    <span class="slider"></span>
                </label>
                <span>Modalità Scura</span>
                
                <button class="btn btn-primary" onclick="exportConfig()">📥 Export Config</button>
                <button class="btn btn-secondary" onclick="clearCache()">🗑️ Pulisci Cache</button>
                <a href="/logout" class="btn btn-danger">🚪 Logout</a>
            </div>
        </div>
        
        <div class="grid">
            <!-- Status Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">📊 Status Sistema</h3>
                    <span class="status-indicator status-online"></span>
                </div>
                <div class="metric">
                    <span>Base URL DaddyLive</span>
                    <span class="metric-value">{daddy_base_url}</span>
                </div>
                <div class="metric">
                    <span>Sessioni Attive</span>
                    <span class="metric-value">{len(SESSION_POOL)}</span>
                </div>
                <div class="metric">
                    <span>Proxy Configurati</span>
                    <span class="metric-value" id="proxyCount">{len(PROXY_LIST)}</span>
                </div>
            </div>
            
            <!-- RAM Usage Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">💾 Utilizzo RAM</h3>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {stats['ram_usage']:.1f}%"></div>
                </div>
                <div class="metric">
                    <span>Utilizzo</span>
                    <span class="metric-value">{stats['ram_usage']:.1f}%</span>
                </div>
                <div class="metric">
                    <span>Usata / Totale</span>
                    <span class="metric-value">{stats['ram_used_gb']:.2f} GB / {stats['ram_total_gb']:.2f} GB</span>
                </div>
            </div>
            
            <!-- Network Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">🌐 Rete</h3>
                </div>
                <div class="metric">
                    <span>Banda Corrente</span>
                    <span class="metric-value">{stats['bandwidth_usage']:.2f} MB/s</span>
                </div>
                <div class="metric">
                    <span>Dati Inviati</span>
                    <span class="metric-value">{stats['network_sent']:.1f} MB</span>
                </div>
                <div class="metric">
                    <span>Dati Ricevuti</span>
                    <span class="metric-value">{stats['network_recv']:.1f} MB</span>
                </div>
            </div>
            
            <!-- Performance Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">⚡ Performance</h3>
                </div>
                <div class="metric">
                    <span>Cache Hit Rate</span>
                    <span class="metric-value" id="cacheHitRate">-</span>
                </div>
                <div class="metric">
                    <span>Tempo Risposta Medio</span>
                    <span class="metric-value" id="avgResponseTime">-</span>
                </div>
                <div class="metric">
                    <span>Richieste/Min</span>
                    <span class="metric-value" id="requestsPerMin">-</span>
                </div>
            </div>
        </div>
        
        <!-- Charts Section -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📈 Analytics</h3>
            </div>
            <div class="tabs">
                <button class="tab active" onclick="showTab('requests')">Richieste</button>
                <button class="tab" onclick="showTab('performance')">Performance</button>
                <button class="tab" onclick="showTab('proxies')">Proxy</button>
                <button class="tab" onclick="showTab('errors')">Errori</button>
            </div>
            
            <div id="requests" class="tab-content active">
                <div class="chart-container">
                    <canvas id="requestsChart"></canvas>
                </div>
            </div>
            
            <div id="performance" class="tab-content">
                <div class="chart-container">
                    <canvas id="performanceChart"></canvas>
                </div>
            </div>
            
            <div id="proxies" class="tab-content">
                <div class="chart-container">
                    <canvas id="proxiesChart"></canvas>
                </div>
            </div>
            
            <div id="errors" class="tab-content">
                <div class="chart-container">
                    <canvas id="errorsChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Tools Section -->
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">🔧 Test URL</h3>
                </div>
                <div class="test-form">
                    <div class="form-group">
                        <label>URL da testare:</label>
                        <input type="text" class="form-control" id="testUrl" placeholder="Inserisci URL M3U/M3U8">
                    </div>
                    <div class="form-group">
                        <label>Headers personalizzati (JSON):</label>
                        <textarea class="form-control" id="testHeaders" rows="3" placeholder='{{"User-Agent": "Custom Agent"}}'></textarea>
                    </div>
                    <button class="btn btn-primary" onclick="testUrl()">🧪 Testa URL</button>
                    <div id="testResult" style="margin-top: 15px;"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">📝 Log in Tempo Reale</h3>
                </div>
                <div class="log-container" id="realTimeLog">
                    Caricamento log...
                </div>
            </div>
        </div>
        
        <!-- Configuration Section -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">⚙️ Configurazione</h3>
            </div>
            
            <div class="config-section">
                <h3>Proxy Management</h3>
                <div class="form-group">
                    <label>Aggiungi Proxy SOCKS5/HTTP:</label>
                    <div style="display: flex; gap: 10px;">
                        <input type="text" class="form-control" id="newProxy" placeholder="socks5://user:pass@xxx.xxx.xxx.xxx:1080">
                        <button class="btn btn-primary" onclick="addProxy()">Aggiungi</button>
                    </div>
                </div>
                
                <div class="proxy-list" id="proxyList">
                    <!-- Lista proxy verrà popolata dinamicamente -->
                </div>
            </div>
            
            <div class="config-section">
                <h3>Impostazioni Cache</h3>
                <div class="form-group">
                    <label>TTL M3U8 Cache (secondi):</label>
                    <input type="number" class="form-control" id="m3u8TTL" value="5">
                </div>
                <div class="form-group">
                    <label>TTL TS Cache (secondi):</label>
                    <input type="number" class="form-control" id="tsTTL" value="300">
                </div>
                <button class="btn btn-primary" onclick="updateCacheSettings()">Aggiorna Impostazioni</button>
            </div>
        </div>
    </div>
    
    <!-- Notification Container -->
    <div id="notification" class="notification"></div>
    
    <script>
        // Variabili globali
        let autoRefreshEnabled = true;
        let refreshInterval;
        let charts = {{}};
        
        // Inizializzazione
        document.addEventListener('DOMContentLoaded', function() {{
            initializeCharts();
            loadProxyList();
            startAutoRefresh();
            setupEventListeners();
        }});
        
        function setupEventListeners() {{
            // Auto refresh toggle
            document.getElementById('autoRefresh').addEventListener('change', function() {{
                autoRefreshEnabled = this.checked;
                if (autoRefreshEnabled) {{
                    startAutoRefresh();
                }} else {{
                    clearInterval(refreshInterval);
                }}
            }});
            
            // Dark mode toggle
            document.getElementById('darkMode').addEventListener('change', function() {{
                document.documentElement.setAttribute('data-theme', this.checked ? 'dark' : 'light');
                localStorage.setItem('darkMode', this.checked);
            }});
            
            // Carica preferenza dark mode
            const savedDarkMode = localStorage.getItem('darkMode') === 'true';
            document.getElementById('darkMode').checked = savedDarkMode;
            if (savedDarkMode) {{
                document.documentElement.setAttribute('data-theme', 'dark');
            }}
        }}
        
        function startAutoRefresh() {{
            refreshInterval = setInterval(updateDashboard, 5000);
        }}
        
        function updateDashboard() {{
            if (!autoRefreshEnabled) return;
            
            fetch('/api/analytics')
                .then(response => {{
                    if (response.status === 302) {{
                        // Redirect to login if session expired
                        window.location.href = '/login';
                        return;
                    }}
                    return response.json();
                }})
                .then(data => {{
                    if (data) {{
                        updateMetrics(data);
                        updateCharts(data);
                        updateLogs(data.recent_requests);
                    }}
                }})
                .catch(error => {{
                    console.error('Errore aggiornamento dashboard:', error);
                    showNotification('Errore aggiornamento dati', 'error');
                }});
        }}
        
        function updateMetrics(data) {{
            // Aggiorna metriche performance
            const totalRequests = Object.values(data.requests_per_endpoint).reduce((a, b) => a + b, 0);
            const avgResponseTime = Object.values(data.avg_response_times).reduce((a, b) => a + b, 0) / Object.keys(data.avg_response_times).length || 0;
            
            document.getElementById('avgResponseTime').textContent = avgResponseTime.toFixed(2) + ' ms';
            document.getElementById('requestsPerMin').textContent = Math.round(totalRequests / 60);
            
            // Calcola cache hit rate (simulato)
            const cacheHitRate = Math.random() * 30 + 70; // Simulazione
            document.getElementById('cacheHitRate').textContent = cacheHitRate.toFixed(1) + '%';
        }}
        
        function initializeCharts() {{
            // Grafico richieste
            const requestsCtx = document.getElementById('requestsChart').getContext('2d');
            charts.requests = new Chart(requestsCtx, {{
                type: 'line',
                data: {{
                    labels: [],
                    datasets: [{{
                        label: 'Richieste per Ora',
                        data: [],
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.1)',
                        tension: 0.4
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
            
            // Grafico performance
            const performanceCtx = document.getElementById('performanceChart').getContext('2d');
            charts.performance = new Chart(performanceCtx, {{
                type: 'bar',
                data: {{
                    labels: [],
                    datasets: [{{
                        label: 'Tempo Risposta Medio (ms)',
                        data: [],
                        backgroundColor: 'rgba(54, 162, 235, 0.8)'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false
                }}
            }});
            
            // Grafico proxy
            const proxiesCtx = document.getElementById('proxiesChart').getContext('2d');
            charts.proxies = new Chart(proxiesCtx, {{
                type: 'doughnut',
                data: {{
                    labels: [],
                    datasets: [{{
                        data: [],
                        backgroundColor: [
                            '#FF6384',
                            '#36A2EB',
                            '#FFCE56',
                            '#4BC0C0',
                            '#9966FF'
                        ]
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false
                }}
            }});
            
            // Grafico errori
            const errorsCtx = document.getElementById('errorsChart').getContext('2d');
            charts.errors = new Chart(errorsCtx, {{
                type: 'line',
                data: {{
                    labels: [],
                    datasets: [{{
                        label: 'Errori per Ora',
                        data: [],
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        tension: 0.4
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false
                }}
            }});
        }}
        
        function updateCharts(data) {{
            // Aggiorna grafico richieste
            if (data.hourly_requests) {{
                const hours = data.hourly_requests.map(item => item.hour.split(' ')[1]);
                const requests = data.hourly_requests.map(item => item.requests);
                
                charts.requests.data.labels = hours;
                charts.requests.data.datasets[0].data = requests;
                charts.requests.update();
            }}
            
            // Aggiorna grafico performance
            if (data.avg_response_times) {{
                const endpoints = Object.keys(data.avg_response_times);
                const times = Object.values(data.avg_response_times);
                
                charts.performance.data.labels = endpoints;
                charts.performance.data.datasets[0].data = times;
                charts.performance.update();
            }}
            
            // Aggiorna grafico proxy
            if (data.proxy_stats) {{
                const proxyLabels = Object.keys(data.proxy_stats);
                const proxyData = proxyLabels.map(proxy => 
                    data.proxy_stats[proxy].success + data.proxy_stats[proxy].failure
                );
                
                charts.proxies.data.labels = proxyLabels;
                charts.proxies.data.datasets[0].data = proxyData;
                charts.proxies.update();
            }}
        }}
        
        function updateLogs(recentRequests) {{
            const logContainer = document.getElementById('realTimeLog');
            const logs = recentRequests.slice(-20).map(req => 
                `[${{req.timestamp.split('T')[1].split('.')[0]}}] ${{req.endpoint}} - ${{req.response_time.toFixed(2)}}ms ${{req.success ? '✓' : '✗'}}`
            ).join('\\n');
            
            logContainer.textContent = logs;
            logContainer.scrollTop = logContainer.scrollHeight;
        }}
        
        function showTab(tabName) {{
            // Nascondi tutti i tab content
            document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.remove('active');
            }});
            
            // Rimuovi active da tutti i tab
            document.querySelectorAll('.tab').forEach(tab => {{
                tab.classList.remove('active');
            }});
            
            // Mostra il tab selezionato
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
        
        function testUrl() {{
            const url = document.getElementById('testUrl').value;
            const headers = document.getElementById('testHeaders').value;
            const resultDiv = document.getElementById('testResult');
            
            if (!url) {{
                showNotification('Inserisci un URL da testare', 'warning');
                return;
            }}
            
            resultDiv.innerHTML = '<div style="color: orange;">⏳ Testing...</div>';
            
            const testData = {{
                url: url,
                headers: headers ? JSON.parse(headers) : {{}}
            }};
            
            fetch('/api/test-url', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify(testData)
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    resultDiv.innerHTML = `
                        <div style="color: green;">✅ Test completato con successo</div>
                        <div>Tempo di risposta: ${{data.response_time}}ms</div>
                        <div>Tipo contenuto: ${{data.content_type}}</div>
                    `;
                }} else {{
                    resultDiv.innerHTML = `<div style="color: red;">❌ Test fallito: ${{data.error}}</div>`;
                }}
            }})
            .catch(error => {{
                resultDiv.innerHTML = `<div style="color: red;">❌ Errore: ${{error.message}}</div>`;
            }});
        }}
        
        function loadProxyList() {{
            fetch('/api/proxies')
                .then(response => response.json())
                .then(data => {{
                    const proxyList = document.getElementById('proxyList');
                    proxyList.innerHTML = data.proxies.map(proxy => `
                        <div class="proxy-item">
                            <span>${{proxy.masked_url}}</span>
                            <div>
                                <span class="status-indicator ${{proxy.status === 'active' ? 'status-online' : 'status-offline'}}"></span>
                                <button class="btn btn-secondary" onclick="removeProxy('${{proxy.id}}')">Rimuovi</button>
                            </div>
                        </div>
                    `).join('');
                    
                    document.getElementById('proxyCount').textContent = data.proxies.length;
                }});
        }}
        
        function addProxy() {{
            const proxyUrl = document.getElementById('newProxy').value;
            if (!proxyUrl) {{
                showNotification('Inserisci un URL proxy valido', 'warning');
                return;
            }}
            
            fetch('/api/proxies', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{ proxy_url: proxyUrl }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    showNotification('Proxy aggiunto con successo', 'success');
                    document.getElementById('newProxy').value = '';
                    loadProxyList();
                }} else {{
                    showNotification('Errore aggiunta proxy: ' + data.error, 'error');
                }}
            }});
        }}
        
        function removeProxy(proxyId) {{
            fetch(`/api/proxies/${{proxyId}}`, {{
                method: 'DELETE'
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    showNotification('Proxy rimosso con successo', 'success');
                    loadProxyList();
                }} else {{
                    showNotification('Errore rimozione proxy: ' + data.error, 'error');
                }}
            }});
        }}
        
        function clearCache() {{
            fetch('/api/cache/clear', {{ method: 'POST' }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        showNotification('Cache pulita con successo', 'success');
                    }} else {{
                        showNotification('Errore pulizia cache: ' + data.error, 'error');
                    }}
                }});
        }}
        
        function exportConfig() {{
            fetch('/api/config/export')
                .then(response => response.blob())
                .then(blob => {{
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'proxy-config-' + new Date().toISOString().split('T')[0] + '.json';
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    showNotification('Configurazione esportata', 'success');
                }});
        }}
        
        function updateCacheSettings() {{
            const m3u8TTL = document.getElementById('m3u8TTL').value;
            const tsTTL = document.getElementById('tsTTL').value;
            
            fetch('/api/config/cache', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{
                    m3u8_ttl: parseInt(m3u8TTL),
                    ts_ttl: parseInt(tsTTL)
                }})
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    showNotification('Impostazioni cache aggiornate', 'success');
                }} else {{
                    showNotification('Errore aggiornamento cache: ' + data.error, 'error');
                }}
            }});
        }}
        
        function showNotification(message, type = 'success') {{
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = `notification ${{type}} show`;
            
            setTimeout(() => {{
                notification.classList.remove('show');
            }}, 3000);
        }}
        
        // Avvia aggiornamento iniziale
        updateDashboard();
    </script>
</body>
</html>
    """
    
    return dashboard_html

# --- HOME PAGE ---
@app.route('/')
def home():
    """Pagina principale con informazioni di base"""
    stats = get_system_stats()
    base_url = get_daddylive_base_url()
    
    home_html = f"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Server IPTV</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: white;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .hero {{
            text-align: center;
            margin-bottom: 60px;
        }}
        
        .hero h1 {{
            font-size: 3.5rem;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .hero p {{
            font-size: 1.3rem;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto;
        }}
        
        .status-card {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 40px;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .status-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-item {{
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 8px;
            color: #FFD700;
        }}
        
        .stat-label {{
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        
        .endpoints {{
            background: rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 40px;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .endpoints h2 {{
            margin-bottom: 20px;
            color: #FFD700;
        }}
        
        .endpoint-item {{
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #FFD700;
        }}
        
        .endpoint-url {{
            font-family: 'Courier New', monospace;
            color: #E0E0E0;
            margin-bottom: 5px;
        }}
        
        .endpoint-desc {{
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        
        .action-buttons {{
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }}
        
        .btn {{
            padding: 15px 30px;
            border: none;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            cursor: pointer;
        }}
        
        .btn-primary {{
            background: #FFD700;
            color: #333;
        }}
        
        .btn-secondary {{
            background: rgba(255,255,255,0.2);
            color: white;
            border: 2px solid rgba(255,255,255,0.3);
        }}
        
        .btn:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }}
        
        @media (max-width: 768px) {{
            .hero h1 {{
                font-size: 2.5rem;
            }}
            
            .container {{
                padding: 20px 10px;
            }}
            
            .action-buttons {{
                flex-direction: column;
                align-items: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>🚀 Proxy Server ONLINE</h1>
            <p>Server proxy per streaming IPTV con dashboard avanzata e monitoraggio in tempo reale</p>
        </div>
        
        <div class="status-card">
            <h2>📊 Statistiche Sistema</h2>
            <div class="status-grid">
                <div class="stat-item">
                    <div class="stat-value">🟢</div>
                    <div class="stat-label">Status: ONLINE</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{stats['ram_usage']:.1f}%</div>
                    <div class="stat-label">RAM Utilizzata</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{stats['bandwidth_usage']:.2f}</div>
                    <div class="stat-label">MB/s Banda</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{len(SESSION_POOL)}</div>
                    <div class="stat-label">Connessioni Attive</div>
                </div>
            </div>
            
            <div style="text-align: center; opacity: 0.8;">
                <p><strong>Base URL DaddyLive:</strong> {base_url}</p>
                <p><strong>RAM:</strong> {stats['ram_used_gb']:.2f} GB / {stats['ram_total_gb']:.2f} GB</p>
                <p><strong>Dati di Rete:</strong> ↑{stats['network_sent']:.1f} MB ↓{stats['network_recv']:.1f} MB</p>
            </div>
        </div>
        
        <div class="endpoints">
            <h2>🔗 Endpoints Disponibili</h2>
            
            <div class="endpoint-item">
                <div class="endpoint-url">/proxy - Proxy per liste M3U</div>
                <div class="endpoint-desc">Esempio: /proxy?url=https://example.com/playlist.m3u</div>
            </div>
            
            <div class="endpoint-item">
                <div class="endpoint-url">/proxy/m3u - Proxy per file M3U8</div>
                <div class="endpoint-desc">Esempio: /proxy/m3u?url=https://example.com/stream.m3u8</div>
            </div>
            
            <div class="endpoint-item">
                <div class="endpoint-url">/proxy/resolve - Risoluzione URL DaddyLive</div>
                <div class="endpoint-desc">Esempio: /proxy/resolve?url=123</div>
            </div>
            
            <div class="endpoint-item">
                <div class="endpoint-url">/stats - API JSON delle statistiche</div>
                <div class="endpoint-desc">Ritorna JSON con metriche di sistema</div>
            </div>
        </div>
        
        <div class="action-buttons">
            <a href="/dashboard" class="btn btn-primary">📈 Dashboard Completo</a>
            <a href="/stats" class="btn btn-secondary">📊 API JSON</a>
        </div>
    </div>
</body>
</html>
    """
    
    return home_html

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    print(f"🚀 Proxy Server ONLINE - In ascolto su porta {port}")
    print(f"📈 Dashboard protetta disponibile su: http://localhost:{port}/dashboard")
    print(f"📊 API Stats disponibile su: http://localhost:{port}/stats")
    print(f"🔐 Login disponibile su: http://localhost:{port}/login")
    app.run(host="0.0.0.0", port=port, debug=False)
