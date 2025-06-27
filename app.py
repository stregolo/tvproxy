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
from collections import defaultdict, deque

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

load_dotenv()

# --- Configurazione Generale ---
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("ATTENZIONE: La verifica del certificato SSL è DISABILITATA. Questo potrebbe esporre a rischi di sicurezza.")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))
KEEP_ALIVE_TIMEOUT = int(os.environ.get('KEEP_ALIVE_TIMEOUT', 300))
MAX_KEEP_ALIVE_REQUESTS = int(os.environ.get('MAX_KEEP_ALIVE_REQUESTS', 1000))
POOL_CONNECTIONS = int(os.environ.get('POOL_CONNECTIONS', 20))
POOL_MAXSIZE = int(os.environ.get('POOL_MAXSIZE', 50))

system_stats = {
    'ram_usage': 0,
    'ram_used_gb': 0,
    'ram_total_gb': 0,
    'cpu_usage': 0,
    'network_sent': 0,
    'network_recv': 0,
    'bandwidth_usage': 0
}

SESSION_POOL = {}
SESSION_LOCK = Lock()

# --- Monitoraggio Avanzato ---
REQUEST_STATS = defaultdict(lambda: {"count": 0, "total_time": 0.0, "avg_time": 0.0})
REQUEST_LOG = deque(maxlen=100)
PROXY_STATUS = defaultdict(lambda: {"success": 0, "fail": 0, "last_error": ""})
DADDYLIVE_HISTORY = deque(maxlen=50)
REQUEST_STATS_LOCK = Lock()

def monitor_endpoint(endpoint_name):
    def decorator(func):
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                elapsed = time.time() - start
                with REQUEST_STATS_LOCK:
                    stats = REQUEST_STATS[endpoint_name]
                    stats["count"] += 1
                    stats["total_time"] += elapsed
                    stats["avg_time"] = stats["total_time"] / stats["count"]
                    REQUEST_LOG.appendleft({
                        "endpoint": endpoint_name,
                        "timestamp": time.strftime("%H:%M:%S"),
                        "success": success,
                        "elapsed": round(elapsed, 3),
                        "ip": request.remote_addr
                    })
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

def update_proxy_status(proxy_url, success, error_msg=""):
    if not proxy_url:
        return
    status = PROXY_STATUS[proxy_url]
    if success:
        status["success"] += 1
    else:
        status["fail"] += 1
        status["last_error"] = error_msg

def get_system_stats():
    global system_stats
    memory = psutil.virtual_memory()
    system_stats['ram_usage'] = memory.percent
    system_stats['ram_used_gb'] = memory.used / (1024**3)
    system_stats['ram_total_gb'] = memory.total / (1024**3)
    system_stats['cpu_usage'] = psutil.cpu_percent(interval=0.1)
    net_io = psutil.net_io_counters()
    system_stats['network_sent'] = net_io.bytes_sent / (1024**2)
    system_stats['network_recv'] = net_io.bytes_recv / (1024**2)
    return system_stats

def monitor_bandwidth():
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
    global SESSION_POOL, SESSION_LOCK
    with SESSION_LOCK:
        for key, session in list(SESSION_POOL.items()):
            try:
                session.close()
            except:
                pass
        SESSION_POOL.clear()
        print("Pool di sessioni pulito")

Thread(target=monitor_bandwidth, daemon=True).start()
Thread(target=connection_manager, daemon=True).start()

# --- Configurazione Proxy ---
PROXY_LIST = []

def setup_proxies():
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
    global SESSION_POOL, SESSION_LOCK
    pool_key = proxy_url if proxy_url else 'default'
    with SESSION_LOCK:
        if pool_key not in SESSION_POOL:
            session = create_robust_session()
            if proxy_url:
                session.proxies.update({'http': proxy_url, 'https': proxy_url})
            SESSION_POOL[pool_key] = session
            print(f"Nuova sessione persistente creata per: {pool_key}")
        return SESSION_POOL[pool_key]

def make_persistent_request(url, headers=None, timeout=None, proxy_url=None, **kwargs):
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
        update_proxy_status(proxy_url, True)
        return response
    except Exception as e:
        update_proxy_status(proxy_url, False, str(e))
        with SESSION_LOCK:
            if proxy_url in SESSION_POOL:
                del SESSION_POOL[proxy_url]
        raise

def get_dynamic_timeout(url, base_timeout=REQUEST_TIMEOUT):
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
    global DADDYLIVE_BASE_URL, LAST_FETCH_TIME
    current_time = time.time()
    if DADDYLIVE_BASE_URL and (current_time - LAST_FETCH_TIME < FETCH_INTERVAL):
        return DADDYLIVE_BASE_URL
    try:
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
            return DADDYLIVE_BASE_URL
    except requests.RequestException as e:
        print(f"Error fetching dynamic DaddyLive URL: {e}. Using fallback.")
    DADDYLIVE_BASE_URL = "https://daddylive.sx/"
    return DADDYLIVE_BASE_URL

get_daddylive_base_url()

def detect_m3u_type(content):
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def replace_key_uri(line, headers_query):
    match = re.search(r'URI="([^"]+)"', line)
    if match:
        key_url = match.group(1)
        proxied_key_url = f"/proxy/key?url={quote(key_url)}&{headers_query}"
        return line.replace(key_url, proxied_key_url)
    return line

def extract_channel_id(url):
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        return match_premium.group(1)
    match_player = re.search(r'/(?:watch|stream|cast|player)/stream-(\d+)\.php', url)
    if match_player:
        return match_player.group(1)
    return None

def process_daddylive_url(url):
    daddy_base_url = get_daddylive_base_url()
    daddy_domain = urlparse(daddy_base_url).netloc
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        channel_id = match_premium.group(1)
        new_url = f"{daddy_base_url}watch/stream-{channel_id}.php"
        return new_url
    if daddy_domain in url and any(p in url for p in ['/watch/', '/stream/', '/cast/', '/player/']):
        return url
    if url.isdigit():
        return f"{daddy_base_url}watch/stream-{url}.php"
    return url

def resolve_m3u8_link(url, headers=None):
    if not url:
        return {"resolved_url": None, "headers": {}}
    current_headers = headers.copy() if headers else {}
    clean_url = url
    extracted_headers = {}
    if '&h_' in url or '%26h_' in url:
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
    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc
    daddylive_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': daddy_base_url,
        'Origin': daddy_origin
    }
    final_headers_for_resolving = {**current_headers, **daddylive_headers}
    try:
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
        channel_id = extract_channel_id(clean_url)
        if not channel_id:
            return {"resolved_url": clean_url, "headers": current_headers}
        stream_url = f"{baseurl}stream/stream-{channel_id}.php"
        final_headers_for_resolving['Referer'] = baseurl + '/'
        final_headers_for_resolving['Origin'] = baseurl
        response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(stream_url), verify=VERIFY_SSL)
        response.raise_for_status()
        iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*<\/button>', response.text)
        if not iframes:
            return {"resolved_url": clean_url, "headers": current_headers}
        url2 = iframes[0]
        url2 = baseurl + url2
        url2 = url2.replace('//cast', '/cast')
        final_headers_for_resolving['Referer'] = url2
        final_headers_for_resolving['Origin'] = url2
        response = requests.get(url2, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(url2), verify=VERIFY_SSL)
        response.raise_for_status()
        iframes = re.findall(r'iframe src="([^"]*)', response.text)
        if not iframes:
            return {"resolved_url": clean_url, "headers": current_headers}
        iframe_url = iframes[0]
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
        except (IndexError, Exception) as e:
            return {"resolved_url": clean_url, "headers": current_headers}
        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
        auth_response = requests.get(auth_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(auth_url), verify=VERIFY_SSL)
        auth_response.raise_for_status()
        host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        lookup_response = requests.get(server_lookup_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(server_lookup_url), verify=VERIFY_SSL)
        lookup_response.raise_for_status()
        server_data = lookup_response.json()
        server_key = server_data['server_key']
        referer_raw = f'https://{urlparse(iframe_url).netloc}'
        clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'
        final_headers_for_fetch = {
            'User-Agent': final_headers_for_resolving.get('User-Agent'),
            'Referer': referer_raw,
            'Origin': referer_raw
        }
        # Log cronologia DaddyLive
        with REQUEST_STATS_LOCK:
            DADDYLIVE_HISTORY.appendleft({
                "channel_id": channel_id,
                "resolved_url": clean_m3u8_url,
                "timestamp": time.strftime("%H:%M:%S")
            })
        return {
            "resolved_url": clean_m3u8_url,
            "headers": final_headers_for_fetch
        }
    except Exception as e:
        return {"resolved_url": clean_url, "headers": current_headers}

@app.route('/api/stats')
def api_stats():
    with REQUEST_STATS_LOCK:
        return jsonify({
            "request_stats": dict(REQUEST_STATS),
            "proxy_status": {k: v for k, v in PROXY_STATUS.items()},
            "recent_requests": list(REQUEST_LOG),
            "daddylive_history": list(DADDYLIVE_HISTORY),
            "system_stats": get_system_stats()
        })

@app.route('/dashboard')
def dashboard():
    stats = get_system_stats()
    daddy_base_url = get_daddylive_base_url()
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Proxy Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; color: #222; }}
            .dark {{ background: #181818; color: #eee; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .stat-title {{ font-size: 18px; font-weight: bold; color: #333; margin-bottom: 10px; }}
            .stat-value {{ font-size: 24px; color: #007bff; }}
            .status {{ padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; margin: 20px 0; }}
            .progress-bar {{ width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; overflow: hidden; }}
            .progress-fill {{ height: 100%; background-color: #007bff; transition: width 0.3s ease; }}
            .connection-stats {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
            .log-table, .log-table th, .log-table td {{ border: 1px solid #ccc; border-collapse: collapse; padding: 4px; font-size: 13px; }}
            .log-table th {{ background: #eee; }}
            .proxy-table td {{ font-size: 12px; }}
            @media (max-width: 600px) {{
                .stats-grid {{ grid-template-columns: 1fr; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <button onclick="document.body.classList.toggle('dark')">🌙/☀️</button>
            <h1>🚀 Proxy Monitoring Dashboard</h1>
            <div class="status">
                <strong>Status:</strong> Proxy ONLINE - Base URL: {daddy_base_url}
            </div>
            <div class="connection-stats">
                <strong>Connessioni Persistenti:</strong> {len(SESSION_POOL)} sessioni attive nel pool
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-title">💾 RAM</div>
                    <div class="stat-value" id="ram_usage">{stats['ram_usage']:.1f}%</div>
                    <div class="progress-bar"><div class="progress-fill" id="ram_bar" style="width: {stats['ram_usage']}%"></div></div>
                    <small>{stats['ram_used_gb']:.2f} GB / {stats['ram_total_gb']:.2f} GB</small>
                </div>
                <div class="stat-card">
                    <div class="stat-title">🌐 Banda</div>
                    <div class="stat-value" id="bw">{stats['bandwidth_usage']:.2f} MB/s</div>
                    <small>CPU: <span id="cpu">{stats.get('cpu_usage', 0):.1f}%</span></small>
                </div>
                <div class="stat-card">
                    <div class="stat-title">📤 Inviati</div>
                    <div class="stat-value" id="sent">{stats['network_sent']:.1f} MB</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">📥 Ricevuti</div>
                    <div class="stat-value" id="recv">{stats['network_recv']:.1f} MB</div>
                </div>
            </div>
            <h3>🔗 Endpoints:</h3>
            <ul>
                <li><a href="/proxy?url=URL_M3U">/proxy</a> - Proxy per liste M3U</li>
                <li><a href="/proxy/m3u?url=URL_M3U8">/proxy/m3u</a> - Proxy per file M3U8</li>
                <li><a href="/proxy/resolve?url=URL">/proxy/resolve</a> - Risoluzione URL DaddyLive</li>
                <li><a href="/stats">/stats</a> - API JSON delle statistiche</li>
            </ul>
            <h3>📈 Statistiche Richieste</h3>
            <canvas id="reqChart" height="80"></canvas>
            <h3>📝 Ultime Richieste</h3>
            <table class="log-table" id="logTable"><thead><tr><th>Orario</th><th>Endpoint</th><th>Successo</th><th>Tempo (s)</th><th>IP</th></tr></thead><tbody></tbody></table>
            <h3>🛡️ Stato Proxy</h3>
            <table class="log-table proxy-table" id="proxyTable"><thead><tr><th>Proxy</th><th>Successi</th><th>Fallimenti</th><th>Ultimo errore</th></tr></thead><tbody></tbody></table>
            <h3>🕓 Cronologia Risoluzioni DaddyLive</h3>
            <table class="log-table" id="daddyTable"><thead><tr><th>Orario</th><th>Channel</th><th>URL Risolto</th></tr></thead><tbody></tbody></table>
            <h3>🔬 Testa un URL M3U/M3U8</h3>
            <form id="test-form"><input type="text" name="url" placeholder="Testa un URL" required><button>Testa</button></form>
            <div id="test-result"></div>
        </div>
        <script>
        let autoRefresh = true;
        async function fetchStats() {{
            const res = await fetch('/api/stats');
            const data = await res.json();
            document.getElementById('ram_usage').innerText = data.system_stats.ram_usage.toFixed(1) + "%";
            document.getElementById('ram_bar').style.width = data.system_stats.ram_usage + "%";
            document.getElementById('bw').innerText = data.system_stats.bandwidth_usage.toFixed(2) + " MB/s";
            document.getElementById('cpu').innerText = data.system_stats.cpu_usage.toFixed(1) + "%";
            document.getElementById('sent').innerText = data.system_stats.network_sent.toFixed(1) + " MB";
            document.getElementById('recv').innerText = data.system_stats.network_recv.toFixed(1) + " MB";
            // Chart
            let ctx = document.getElementById('reqChart').getContext('2d');
            let labels = Object.keys(data.request_stats);
            let counts = labels.map(l => data.request_stats[l].count);
            if(window.reqChart) window.reqChart.destroy();
            window.reqChart = new Chart(ctx, {{
                type: 'bar',
                data: {{ labels: labels, datasets: [{{ label: 'Richieste', data: counts, backgroundColor: '#007bff' }}] }},
                options: {{ plugins: {{ legend: {{ display: false }} }} }}
            }});
            // Log Table
            let logRows = data.recent_requests.map(r => `<tr><td>${{r.timestamp}}</td><td>${{r.endpoint}}</td><td>${{r.success ? "✅" : "❌"}}</td><td>${{r.elapsed}}</td><td>${{r.ip}}</td></tr>`).join('');
            document.getElementById('logTable').querySelector('tbody').innerHTML = logRows;
            // Proxy Table (maschera IP)
            let proxyRows = Object.entries(data.proxy_status).map(([k,v]) => {{
                let proxyLabel = k.replace(/:\/\/.*@/, '://***:***@').replace(/:\/\/([^:/]+):?(\d+)?/, '://[hidden]:[port]');
                return `<tr><td>${{proxyLabel}}</td><td>${{v.success}}</td><td>${{v.fail}}</td><td>${{v.last_error}}</td></tr>`;
            }}).join('');
            document.getElementById('proxyTable').querySelector('tbody').innerHTML = proxyRows;
            // DaddyLive Table
            let daddyRows = data.daddylive_history.map(r => `<tr><td>${{r.timestamp}}</td><td>${{r.channel_id}}</td><td>${{r.resolved_url}}</td></tr>`).join('');
            document.getElementById('daddyTable').querySelector('tbody').innerHTML = daddyRows;
        }}
        setInterval(() => {{ if(autoRefresh) fetchStats(); }}, 5000);
        fetchStats();
        document.getElementById('test-form').onsubmit = async function(e) {{
            e.preventDefault();
            let url = this.url.value;
            let res = await fetch('/proxy/resolve?url=' + encodeURIComponent(url));
            document.getElementById('test-result').innerText = await res.text();
        }};
        </script>
    </body>
    </html>
    """

@app.route('/stats')
def get_stats():
    stats = get_system_stats()
    return jsonify(stats)

@app.route('/proxy/m3u')
@monitor_endpoint("proxy_m3u")
def proxy_m3u():
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400
    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"
    if cache_key in M3U8_CACHE:
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl")
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
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500
        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]
        if not resolved_url.endswith('.m3u8'):
            return "Errore: Impossibile ottenere un M3U8 valido dal canale", 500
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
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        return f"Errore generico durante l'elaborazione: {str(e)}", 500

@app.route('/proxy/resolve')
@monitor_endpoint("proxy_resolve")
def proxy_resolve():
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
@monitor_endpoint("proxy_ts")
def proxy_ts():
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400
    if ts_url in TS_CACHE:
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")
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
                    return
                finally:
                    ts_content = b"".join(content_parts)
                    if ts_content and len(ts_content) > 1024:
                        TS_CACHE[ts_url] = ts_content
            return Response(generate_and_cache(), content_type="video/mp2t")
        except requests.exceptions.ConnectionError as e:
            if "Read timed out" in str(e) or "timed out" in str(e).lower():
                if attempt == max_retries - 1:
                    return f"Errore: Timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
                time.sleep(2 ** attempt)
                continue
            else:
                return f"Errore di connessione per il segmento TS: {str(e)}", 500
        except requests.exceptions.ReadTimeout as e:
            if attempt == max_retries - 1:
                return f"Errore: Read timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
            time.sleep(2 ** attempt)
            continue
        except requests.RequestException as e:
            return f"Errore durante il download del segmento TS: {str(e)}", 500

@app.route('/proxy')
@monitor_endpoint("proxy")
def proxy():
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
        return f"Errore durante il download della lista M3U: {str(e)}", 500
    except Exception as e:
        return f"Errore generico: {str(e)}", 500

@app.route('/proxy/key')
@monitor_endpoint("proxy_key")
def proxy_key():
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400
    if key_url in KEY_CACHE:
        return Response(KEY_CACHE[key_url], content_type="application/octet-stream")
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

@app.route('/')
def index():
    stats = get_system_stats()
    base_url = get_daddylive_base_url()
    return f"""
    <h1>🚀 Proxy ONLINE</h1>
    <p><strong>Base URL DaddyLive:</strong> {base_url}</p>
    <h2>📊 Statistiche Sistema</h2>
    <ul>
        <li><strong>RAM:</strong> {stats['ram_usage']:.1f}% ({stats['ram_used_gb']:.2f} GB / {stats['ram_total_gb']:.2f} GB)</li>
        <li><strong>CPU:</strong> {stats.get('cpu_usage', 0):.1f}%</li>
        <li><strong>Banda:</strong> {stats['bandwidth_usage']:.2f} MB/s</li>
        <li><strong>Dati Inviati:</strong> {stats['network_sent']:.1f} MB</li>
        <li><strong>Dati Ricevuti:</strong> {stats['network_recv']:.1f} MB</li>
        <li><strong>Connessioni Persistenti:</strong> {len(SESSION_POOL)} sessioni attive</li>
    </ul>
    <p><a href="/dashboard">📈 Dashboard Completo</a> | <a href="/stats">📊 API JSON</a></p>
    """

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    print(f"Proxy ONLINE - In ascolto su porta {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
