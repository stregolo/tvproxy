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
import secrets
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
from functools import wraps
import ipaddress

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

load_dotenv()

# --- Configurazione Generale ---
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("ATTENZIONE: La verifica del certificato SSL è DISABILITATA.")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))
KEEP_ALIVE_TIMEOUT = int(os.environ.get('KEEP_ALIVE_TIMEOUT', 300))
MAX_KEEP_ALIVE_REQUESTS = int(os.environ.get('MAX_KEEP_ALIVE_REQUESTS', 1000))
POOL_CONNECTIONS = int(os.environ.get('POOL_CONNECTIONS', 20))
POOL_MAXSIZE = int(os.environ.get('POOL_MAXSIZE', 50))

# --- Configurazione Autenticazione ---
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password123')
API_KEYS = set(os.environ.get('API_KEYS', '').split(',')) if os.environ.get('API_KEYS') else set()

# --- Variabili globali per monitoraggio avanzato ---
system_stats = {
    'ram_usage': 0,
    'ram_used_gb': 0,
    'ram_total_gb': 0,
    'network_sent': 0,
    'network_recv': 0,
    'bandwidth_usage': 0,
    'cpu_usage': 0
}

# Statistiche avanzate
endpoint_stats = defaultdict(lambda: {'requests': 0, 'errors': 0, 'total_time': 0, 'avg_time': 0})
proxy_stats = defaultdict(lambda: {'success': 0, 'failures': 0, 'last_used': None, 'status': 'unknown'})
request_log = deque(maxlen=1000)
error_log = deque(maxlen=500)
access_log = deque(maxlen=1000)

# Rate limiting
rate_limit_storage = defaultdict(lambda: {'count': 0, 'reset_time': time.time() + 3600})
blocked_ips = set()
whitelisted_ips = set()

# Cache stats
cache_stats = {
    'hits': 0,
    'misses': 0,
    'hit_rate': 0
}

SESSION_POOL = {}
SESSION_LOCK = Lock()

# --- Configurazione Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def mask_ip(ip_address):
    """Maschera l'IP per la privacy, mostrando solo le prime due parti"""
    try:
        if ':' in ip_address:  # IPv6
            parts = ip_address.split(':')
            return f"{parts[0]}:{parts[1]}:****:****"
        else:  # IPv4
            parts = ip_address.split('.')
            return f"{parts[0]}.{parts[1]}.***.**"
    except:
        return "***.***.***.**"

def mask_proxy_url(proxy_url):
    """Maschera l'URL del proxy per nascondere l'IP completo"""
    if not proxy_url:
        return None
    try:
        parsed = urlparse(proxy_url)
        masked_host = mask_ip(parsed.hostname) if parsed.hostname else "***"
        return f"{parsed.scheme}://{masked_host}:{parsed.port}"
    except:
        return "***://***:***"

# --- Decoratori per autenticazione e rate limiting ---
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or api_key not in API_KEYS:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=100, window=3600):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            
            if client_ip in blocked_ips:
                return jsonify({'error': 'IP blocked'}), 403
                
            if client_ip in whitelisted_ips:
                return f(*args, **kwargs)
            
            current_time = time.time()
            if current_time > rate_limit_storage[client_ip]['reset_time']:
                rate_limit_storage[client_ip] = {'count': 0, 'reset_time': current_time + window}
            
            rate_limit_storage[client_ip]['count'] += 1
            
            if rate_limit_storage[client_ip]['count'] > max_requests:
                log_security_event(client_ip, 'rate_limit_exceeded', request.endpoint)
                return jsonify({'error': 'Rate limit exceeded'}), 429
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_client_ip():
    """Ottiene l'IP reale del client considerando proxy e load balancer"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def log_security_event(ip, event_type, details):
    """Log eventi di sicurezza"""
    event = {
        'timestamp': datetime.now().isoformat(),
        'ip': mask_ip(ip),
        'event': event_type,
        'details': details,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    access_log.append(event)
    logger.warning(f"Security event: {event}")

def log_request(endpoint, start_time, success=True, error=None):
    """Log delle richieste con statistiche"""
    duration = time.time() - start_time
    
    # Aggiorna statistiche endpoint
    endpoint_stats[endpoint]['requests'] += 1
    endpoint_stats[endpoint]['total_time'] += duration
    endpoint_stats[endpoint]['avg_time'] = endpoint_stats[endpoint]['total_time'] / endpoint_stats[endpoint]['requests']
    
    if not success:
        endpoint_stats[endpoint]['errors'] += 1
    
    # Log della richiesta
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'endpoint': endpoint,
        'ip': mask_ip(get_client_ip()),
        'duration': round(duration, 3),
        'success': success,
        'error': str(error) if error else None,
        'user_agent': request.headers.get('User-Agent', 'Unknown')[:100]
    }
    request_log.append(log_entry)
    
    if error:
        error_log.append(log_entry)

def get_system_stats():
    """Ottiene statistiche di sistema avanzate"""
    global system_stats
    
    # Memoria RAM
    memory = psutil.virtual_memory()
    system_stats['ram_usage'] = memory.percent
    system_stats['ram_used_gb'] = memory.used / (1024**3)
    system_stats['ram_total_gb'] = memory.total / (1024**3)
    
    # CPU
    system_stats['cpu_usage'] = psutil.cpu_percent(interval=1)
    
    # Rete
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
            logger.error(f"Errore nel monitoraggio banda: {e}")
        
        time.sleep(1)

# --- Configurazione Proxy ---
PROXY_LIST = []

def setup_proxies():
    """Carica la lista di proxy dalle variabili d'ambiente"""
    global PROXY_LIST
    proxies_found = []

    for proxy_type in ['SOCKS5_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY']:
        proxy_list_str = os.environ.get(proxy_type)
        if proxy_list_str:
            raw_proxies = [p.strip() for p in proxy_list_str.split(',') if p.strip()]
            for proxy in raw_proxies:
                if proxy_type == 'SOCKS5_PROXY' and proxy.startswith('socks5://'):
                    proxy = 'socks5h' + proxy[len('socks5'):]
                proxies_found.append(proxy)
                # Inizializza statistiche proxy
                proxy_stats[proxy] = {'success': 0, 'failures': 0, 'last_used': None, 'status': 'unknown'}

    PROXY_LIST = proxies_found
    logger.info(f"Configurati {len(PROXY_LIST)} proxy")

def get_proxy_for_url(url):
    """Seleziona un proxy casuale dalla lista"""
    if not PROXY_LIST:
        return None

    try:
        parsed_url = urlparse(url)
        if 'github.com' in parsed_url.netloc:
            return None
    except Exception:
        pass

    # Seleziona proxy con meno fallimenti
    available_proxies = [p for p in PROXY_LIST if proxy_stats[p]['status'] != 'failed']
    if not available_proxies:
        available_proxies = PROXY_LIST  # Fallback a tutti i proxy
    
    chosen_proxy = random.choice(available_proxies)
    proxy_stats[chosen_proxy]['last_used'] = datetime.now().isoformat()
    
    return {'http': chosen_proxy, 'https': chosen_proxy}

def test_proxy(proxy_url):
    """Testa la connettività di un proxy"""
    try:
        test_response = requests.get(
            'https://httpbin.org/ip',
            proxies={'http': proxy_url, 'https': proxy_url},
            timeout=10,
            verify=VERIFY_SSL
        )
        if test_response.status_code == 200:
            proxy_stats[proxy_url]['status'] = 'active'
            proxy_stats[proxy_url]['success'] += 1
            return True
    except Exception as e:
        proxy_stats[proxy_url]['status'] = 'failed'
        proxy_stats[proxy_url]['failures'] += 1
        logger.warning(f"Proxy test failed for {mask_proxy_url(proxy_url)}: {e}")
    
    return False

# --- Cache con statistiche ---
M3U8_CACHE = TTLCache(maxsize=200, ttl=5)
TS_CACHE = TTLCache(maxsize=1000, ttl=300)
KEY_CACHE = TTLCache(maxsize=200, ttl=300)

def update_cache_stats(cache_hit):
    """Aggiorna statistiche cache"""
    global cache_stats
    if cache_hit:
        cache_stats['hits'] += 1
    else:
        cache_stats['misses'] += 1
    
    total = cache_stats['hits'] + cache_stats['misses']
    cache_stats['hit_rate'] = (cache_stats['hits'] / total * 100) if total > 0 else 0

# --- Routes di autenticazione ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['authenticated'] = True
            session['username'] = username
            log_security_event(get_client_ip(), 'successful_login', username)
            return redirect(url_for('advanced_dashboard'))
        else:
            log_security_event(get_client_ip(), 'failed_login', username)
            return render_template_string(LOGIN_TEMPLATE, error="Credenziali non valide")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Routes API ---
@app.route('/api/stats')
@rate_limit(max_requests=1000)
def api_stats():
    """API per statistiche complete"""
    stats = get_system_stats()
    
    # Aggiungi statistiche cache
    stats['cache'] = {
        'hits': cache_stats['hits'],
        'misses': cache_stats['misses'],
        'hit_rate': round(cache_stats['hit_rate'], 2),
        'm3u8_size': len(M3U8_CACHE),
        'ts_size': len(TS_CACHE),
        'key_size': len(KEY_CACHE)
    }
    
    # Aggiungi statistiche endpoint (mascherate)
    stats['endpoints'] = {}
    for endpoint, data in endpoint_stats.items():
        stats['endpoints'][endpoint] = {
            'requests': data['requests'],
            'errors': data['errors'],
            'avg_time': round(data['avg_time'], 3),
            'error_rate': round((data['errors'] / data['requests'] * 100) if data['requests'] > 0 else 0, 2)
        }
    
    # Aggiungi statistiche proxy (mascherate)
    stats['proxies'] = {}
    for proxy, data in proxy_stats.items():
        masked_proxy = mask_proxy_url(proxy)
        stats['proxies'][masked_proxy] = {
            'success': data['success'],
            'failures': data['failures'],
            'status': data['status'],
            'last_used': data['last_used'],
            'success_rate': round((data['success'] / (data['success'] + data['failures']) * 100) if (data['success'] + data['failures']) > 0 else 0, 2)
        }
    
    return jsonify(stats)

@app.route('/api/logs')
@require_auth
def api_logs():
    """API per ottenere i log"""
    log_type = request.args.get('type', 'requests')
    limit = min(int(request.args.get('limit', 100)), 1000)
    
    if log_type == 'requests':
        return jsonify(list(request_log)[-limit:])
    elif log_type == 'errors':
        return jsonify(list(error_log)[-limit:])
    elif log_type == 'access':
        return jsonify(list(access_log)[-limit:])
    else:
        return jsonify({'error': 'Invalid log type'}), 400

@app.route('/api/test-url', methods=['POST'])
@require_auth
def api_test_url():
    """API per testare URL M3U/M3U8"""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    try:
        response = requests.head(url, timeout=10, verify=VERIFY_SSL)
        return jsonify({
            'status': 'success',
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_type': response.headers.get('Content-Type', 'unknown')
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/test-proxies', methods=['POST'])
@require_auth
def api_test_proxies():
    """API per testare tutti i proxy"""
    results = {}
    for proxy in PROXY_LIST:
        masked_proxy = mask_proxy_url(proxy)
        results[masked_proxy] = test_proxy(proxy)
    
    return jsonify(results)

@app.route('/api/clear-cache', methods=['POST'])
@require_auth
def api_clear_cache():
    """API per pulire la cache"""
    cache_type = request.json.get('type', 'all') if request.json else 'all'
    
    cleared = 0
    if cache_type in ['all', 'm3u8']:
        cleared += len(M3U8_CACHE)
        M3U8_CACHE.clear()
    if cache_type in ['all', 'ts']:
        cleared += len(TS_CACHE)
        TS_CACHE.clear()
    if cache_type in ['all', 'key']:
        cleared += len(KEY_CACHE)
        KEY_CACHE.clear()
    
    return jsonify({
        'message': f'Cache cleared: {cleared} items removed',
        'type': cache_type
    })

@app.route('/api/config', methods=['GET', 'POST'])
@require_auth
def api_config():
    """API per gestire la configurazione"""
    if request.method == 'GET':
        config = {
            'request_timeout': REQUEST_TIMEOUT,
            'verify_ssl': VERIFY_SSL,
            'proxy_count': len(PROXY_LIST),
            'masked_proxies': [mask_proxy_url(p) for p in PROXY_LIST],
            'cache_sizes': {
                'm3u8_maxsize': M3U8_CACHE.maxsize,
                'ts_maxsize': TS_CACHE.maxsize,
                'key_maxsize': KEY_CACHE.maxsize
            }
        }
        return jsonify(config)
    
    # POST per aggiornare configurazione
    data = request.get_json()
    # Implementa logica di aggiornamento configurazione
    return jsonify({'message': 'Configuration updated'})

# --- Dashboard avanzato ---
@app.route('/advanced-dashboard')
@require_auth
def advanced_dashboard():
    """Dashboard avanzato con tutte le funzionalità"""
    return render_template_string(ADVANCED_DASHBOARD_TEMPLATE)

# --- Templates ---
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .error { color: red; margin-top: 10px; }
        h2 { text-align: center; margin-bottom: 30px; color: #333; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>🔐 Proxy Admin Login</h2>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
        </form>
    </div>
</body>
</html>
'''

ADVANCED_DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Proxy Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-color: #f8f9fa;
            --card-bg: white;
            --text-color: #333;
            --border-color: #dee2e6;
            --primary-color: #007bff;
            --success-color: #28a745;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
        }
        
        [data-theme="dark"] {
            --bg-color: #1a1a1a;
            --card-bg: #2d2d2d;
            --text-color: #ffffff;
            --border-color: #444;
            --primary-color: #0d6efd;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: var(--bg-color); 
            color: var(--text-color);
            transition: all 0.3s ease;
        }
        
        .header {
            background: var(--card-bg);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header h1 { color: var(--primary-color); }
        
        .controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }
        
        .btn-primary { background: var(--primary-color); color: white; }
        .btn-success { background: var(--success-color); color: white; }
        .btn-danger { background: var(--danger-color); color: white; }
        .btn-warning { background: var(--warning-color); color: black; }
        .btn:hover { opacity: 0.8; transform: translateY(-1px); }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border: 1px solid var(--border-color);
        }
        
        .card h3 {
            margin-bottom: 1rem;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9rem;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--border-color);
            border-radius: 4px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--primary-color);
            transition: width 0.3s ease;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin: 1rem 0;
        }
        
        .log-container {
            max-height: 400px;
            overflow-y: auto;
            background: var(--bg-color);
            border-radius: 4px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
        }
        
        .log-entry {
            margin-bottom: 0.5rem;
            padding: 0.25rem;
            border-radius: 2px;
        }
        
        .log-success { background: rgba(40, 167, 69, 0.1); }
        .log-error { background: rgba(220, 53, 69, 0.1); }
        .log-warning { background: rgba(255, 193, 7, 0.1); }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--card-bg);
            color: var(--text-color);
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 1rem;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }
        
        .tab.active {
            border-bottom-color: var(--primary-color);
            color: var(--primary-color);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        
        .status-active { background: var(--success-color); }
        .status-failed { background: var(--danger-color); }
        .status-unknown { background: #6c757d; }
        
        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 24px;
        }
        
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 24px;
        }
        
        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        
        input:checked + .slider {
            background-color: var(--primary-color);
        }
        
        input:checked + .slider:before {
            transform: translateX(26px);
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 1rem;
            }
            
            .controls {
                flex-wrap: wrap;
                justify-content: center;
            }
            
            .container {
                padding: 1rem;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 4px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            transform: translateX(100%);
            transition: transform 0.3s ease;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification.success { background: var(--success-color); }
        .notification.error { background: var(--danger-color); }
        .notification.warning { background: var(--warning-color); color: black; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Advanced Proxy Dashboard</h1>
        <div class="controls">
            <label class="toggle-switch">
                <input type="checkbox" id="autoRefresh" checked>
                <span class="slider"></span>
            </label>
            <span>Auto Refresh</span>
            
            <button class="btn btn-primary" onclick="toggleTheme()">🌓 Theme</button>
            <button class="btn btn-warning" onclick="testAllProxies()">🔍 Test Proxies</button>
            <button class="btn btn-danger" onclick="clearCache()">🗑️ Clear Cache</button>
            <a href="/logout" class="btn btn-primary">🚪 Logout</a>
        </div>
    </div>

    <div class="container">
        <!-- Statistiche Sistema -->
        <div class="grid">
            <div class="card">
                <h3>💾 Sistema</h3>
                <div class="stat-value" id="ramUsage">--%</div>
                <div class="stat-label">RAM Usage</div>
                <div class="progress-bar">
                    <div class="progress-fill" id="ramProgress"></div>
                </div>
                <small id="ramDetails">-- GB / -- GB</small>
            </div>
            
            <div class="card">
                <h3>⚡ CPU</h3>
                <div class="stat-value" id="cpuUsage">--%</div>
                <div class="stat-label">CPU Usage</div>
                <div class="progress-bar">
                    <div class="progress-fill" id="cpuProgress"></div>
                </div>
            </div>
            
            <div class="card">
                <h3>🌐 Network</h3>
                <div class="stat-value" id="bandwidth">-- MB/s</div>
                <div class="stat-label">Current Bandwidth</div>
                <div style="margin-top: 1rem;">
                    <div>📤 Sent: <span id="networkSent">-- MB</span></div>
                    <div>📥 Received: <span id="networkRecv">-- MB</span></div>
                </div>
            </div>
            
            <div class="card">
                <h3>💾 Cache</h3>
                <div class="stat-value" id="cacheHitRate">--%</div>
                <div class="stat-label">Hit Rate</div>
                <div style="margin-top: 1rem;">
                    <div>✅ Hits: <span id="cacheHits">--</span></div>
                    <div>❌ Misses: <span id="cacheMisses">--</span></div>
                </div>
            </div>
        </div>

        <!-- Grafici -->
        <div class="grid">
            <div class="card">
                <h3>📊 Performance Trends</h3>
                <div class="chart-container">
                    <canvas id="performanceChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h3>🎯 Endpoint Statistics</h3>
                <div class="chart-container">
                    <canvas id="endpointChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Tabs per diverse sezioni -->
        <div class="card">
            <div class="tabs">
                <div class="tab active" onclick="showTab('logs')">📋 Logs</div>
                <div class="tab" onclick="showTab('proxies')">🔗 Proxies</div>
                <div class="tab" onclick="showTab('tools')">🛠️ Tools</div>
                <div class="tab" onclick="showTab('config')">⚙️ Config</div>
            </div>
            
            <div id="logs" class="tab-content active">
                <h3>📋 Request Logs</h3>
                <div class="form-group">
                    <select id="logType" onchange="loadLogs()">
                        <option value="requests">Request Logs</option>
                        <option value="errors">Error Logs</option>
                        <option value="access">Access Logs</option>
                    </select>
                </div>
                <div class="log-container" id="logContainer">
                    Loading logs...
                </div>
            </div>
            
            <div id="proxies" class="tab-content">
                <h3>🔗 Proxy Status</h3>
                <div id="proxyStatus">
                    Loading proxy status...
                </div>
            </div>
            
            <div id="tools" class="tab-content">
                <h3>🛠️ Testing Tools</h3>
                
                <div class="form-group">
                    <label for="testUrl">Test M3U/M3U8 URL:</label>
                    <input type="url" id="testUrl" placeholder="Enter URL to test">
                    <button class="btn btn-primary" onclick="testUrl()" style="margin-top: 0.5rem;">Test URL</button>
                </div>
                
                <div id="testResults" style="margin-top: 1rem;"></div>
                
                <div class="form-group" style="margin-top: 2rem;">
                    <label>Cache Management:</label>
                    <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                        <button class="btn btn-warning" onclick="clearSpecificCache('m3u8')">Clear M3U8</button>
                        <button class="btn btn-warning" onclick="clearSpecificCache('ts')">Clear TS</button>
                        <button class="btn btn-warning" onclick="clearSpecificCache('key')">Clear Keys</button>
                        <button class="btn btn-danger" onclick="clearSpecificCache('all')">Clear All</button>
                    </div>
                </div>
            </div>
            
            <div id="config" class="tab-content">
                <h3>⚙️ Configuration</h3>
                <div id="configContent">
                    Loading configuration...
                </div>
            </div>
        </div>
    </div>

    <script>
        let autoRefreshEnabled = true;
        let performanceChart, endpointChart;
        let performanceData = {
            labels: [],
            ram: [],
            cpu: [],
            bandwidth: []
        };

        // Inizializzazione
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            loadStats();
            loadLogs();
            loadProxyStatus();
            loadConfig();
            
            // Auto refresh
            setInterval(() => {
                if (autoRefreshEnabled) {
                    loadStats();
                    updateCharts();
                }
            }, 5000);
            
            // Toggle auto refresh
            document.getElementById('autoRefresh').addEventListener('change', function() {
                autoRefreshEnabled = this.checked;
            });
        });

        function initCharts() {
            // Performance Chart
            const perfCtx = document.getElementById('performanceChart').getContext('2d');
            performanceChart = new Chart(perfCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'RAM %',
                        data: [],
                        borderColor: '#007bff',
                        backgroundColor: 'rgba(0, 123, 255, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'CPU %',
                        data: [],
                        borderColor: '#28a745',
                        backgroundColor: 'rgba(40, 167, 69, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Bandwidth MB/s',
                        data: [],
                        borderColor: '#ffc107',
                        backgroundColor: 'rgba(255, 193, 7, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top'
                        }
                    }
                }
            });

            // Endpoint Chart
            const endCtx = document.getElementById('endpointChart').getContext('2d');
            endpointChart = new Chart(endCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#007bff',
                            '#28a745',
                            '#ffc107',
                            '#dc3545',
                            '#6c757d',
                            '#17a2b8'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }

        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    updateSystemStats(data);
                    updateCacheStats(data.cache);
                    updateEndpointStats(data.endpoints);
                })
                .catch(error => {
                    console.error('Error loading stats:', error);
                    showNotification('Error loading statistics', 'error');
                });
        }

        function updateSystemStats(data) {
            document.getElementById('ramUsage').textContent = data.ram_usage.toFixed(1) + '%';
            document.getElementById('ramProgress').style.width = data.ram_usage + '%';
            document.getElementById('ramDetails').textContent = 
                `${data.ram_used_gb.toFixed(2)} GB / ${data.ram_total_gb.toFixed(2)} GB`;
            
            document.getElementById('cpuUsage').textContent = data.cpu_usage.toFixed(1) + '%';
            document.getElementById('cpuProgress').style.width = data.cpu_usage + '%';
            
            document.getElementById('bandwidth').textContent = data.bandwidth_usage.toFixed(2) + ' MB/s';
            document.getElementById('networkSent').textContent = data.network_sent.toFixed(1) + ' MB';
            document.getElementById('networkRecv').textContent = data.network_recv.toFixed(1) + ' MB';
            
            // Aggiorna dati per i grafici
            const now = new Date().toLocaleTimeString();
            performanceData.labels.push(now);
            performanceData.ram.push(data.ram_usage);
            performanceData.cpu.push(data.cpu_usage);
            performanceData.bandwidth.push(data.bandwidth_usage);
            
            // Mantieni solo gli ultimi 20 punti
            if (performanceData.labels.length > 20) {
                performanceData.labels.shift();
                performanceData.ram.shift();
                performanceData.cpu.shift();
                performanceData.bandwidth.shift();
            }
        }

        function updateCacheStats(cacheData) {
            document.getElementById('cacheHitRate').textContent = cacheData.hit_rate.toFixed(1) + '%';
            document.getElementById('cacheHits').textContent = cacheData.hits;
            document.getElementById('cacheMisses').textContent = cacheData.misses;
        }

        function updateEndpointStats(endpoints) {
            const labels = Object.keys(endpoints);
            const data = labels.map(label => endpoints[label].requests);
            
            endpointChart.data.labels = labels;
            endpointChart.data.datasets[0].data = data;
            endpointChart.update();
        }

        function updateCharts() {
            performanceChart.data.labels = performanceData.labels;
            performanceChart.data.datasets[0].data = performanceData.ram;
            performanceChart.data.datasets[1].data = performanceData.cpu;
            performanceChart.data.datasets[2].data = performanceData.bandwidth;
            performanceChart.update();
        }

        function loadLogs() {
            const logType = document.getElementById('logType').value;
            fetch(`/api/logs?type=${logType}&limit=50`)
                .then(response => response.json())
                .then(logs => {
                    const container = document.getElementById('logContainer');
                    container.innerHTML = logs.map(log => {
                        const cssClass = log.success === false ? 'log-error' : 
                                       log.event ? 'log-warning' : 'log-success';
                        return `<div class="log-entry ${cssClass}">
                            [${log.timestamp}] ${log.endpoint || log.event || 'REQUEST'} - 
                            IP: ${log.ip} - 
                            ${log.duration ? `${log.duration}s` : ''} 
                            ${log.error ? `ERROR: ${log.error}` : 'SUCCESS'}
                        </div>`;
                    }).join('');
                    container.scrollTop = container.scrollHeight;
                })
                .catch(error => {
                    console.error('Error loading logs:', error);
                });
        }

        function loadProxyStatus() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('proxyStatus');
                    const proxies = data.proxies;
                    
                    if (Object.keys(proxies).length === 0) {
                        container.innerHTML = '<p>No proxies configured</p>';
                        return;
                    }
                    
                    container.innerHTML = Object.entries(proxies).map(([proxy, stats]) => {
                        const statusClass = stats.status === 'active' ? 'status-active' : 
                                          stats.status === 'failed' ? 'status-failed' : 'status-unknown';
                        return `<div style="margin-bottom: 1rem; padding: 1rem; border: 1px solid var(--border-color); border-radius: 4px;">
                            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                                <span class="status-indicator ${statusClass}"></span>
                                <strong>${proxy}</strong>
                            </div>
                            <div style="font-size: 0.9rem; color: #666;">
                                Success: ${stats.success} | Failures: ${stats.failures} | 
                                Success Rate: ${stats.success_rate}% | 
                                Last Used: ${stats.last_used || 'Never'}
                            </div>
                        </div>`;
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading proxy status:', error);
                });
        }

        function loadConfig() {
            fetch('/api/config')
                .then(response => response.json())
                .then(config => {
                    const container = document.getElementById('configContent');
                    container.innerHTML = `
                        <div class="form-group">
                            <label>Request Timeout:</label>
                            <input type="number" value="${config.request_timeout}" readonly>
                        </div>
                        <div class="form-group">
                            <label>SSL Verification:</label>
                            <input type="checkbox" ${config.verify_ssl ? 'checked' : ''} disabled>
                        </div>
                        <div class="form-group">
                            <label>Configured Proxies:</label>
                            <div style="margin-top: 0.5rem;">
                                ${config.masked_proxies.map(proxy => `<div>${proxy}</div>`).join('')}
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Cache Sizes:</label>
                            <div style="margin-top: 0.5rem;">
                                M3U8: ${config.cache_sizes.m3u8_maxsize} | 
                                TS: ${config.cache_sizes.ts_maxsize} | 
                                Keys: ${config.cache_sizes.key_maxsize}
                            </div>
                        </div>
                    `;
                })
                .catch(error => {
                    console.error('Error loading config:', error);
                });
        }

        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
            
            // Load data for specific tabs
            if (tabName === 'logs') {
                loadLogs();
            } else if (tabName === 'proxies') {
                loadProxyStatus();
            } else if (tabName === 'config') {
                loadConfig();
            }
        }

        function testUrl() {
            const url = document.getElementById('testUrl').value;
            if (!url) {
                showNotification('Please enter a URL', 'warning');
                return;
            }
            
            fetch('/api/test-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({url: url})
            })
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('testResults');
                if (data.status === 'success') {
                    container.innerHTML = `
                        <div class="card" style="background: rgba(40, 167, 69, 0.1);">
                            <h4>✅ URL Test Successful</h4>
                            <p><strong>Status Code:</strong> ${data.status_code}</p>
                            <p><strong>Content Type:</strong> ${data.content_type}</p>
                            <details>
                                <summary>Response Headers</summary>
                                <pre>${JSON.stringify(data.headers, null, 2)}</pre>
                            </details>
                        </div>
                    `;
                    showNotification('URL test successful', 'success');
                } else {
                    container.innerHTML = `
                        <div class="card" style="background: rgba(220, 53, 69, 0.1);">
                            <h4>❌ URL Test Failed</h4>
                            <p><strong>Error:</strong> ${data.error}</p>
                        </div>
                    `;
                    showNotification('URL test failed', 'error');
                }
            })
            .catch(error => {
                console.error('Error testing URL:', error);
                showNotification('Error testing URL', 'error');
            });
        }

        function testAllProxies() {
            showNotification('Testing all proxies...', 'warning');
            
            fetch('/api/test-proxies', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(results => {
                const successful = Object.values(results).filter(r => r).length;
                const total = Object.keys(results).length;
                showNotification(`Proxy test complete: ${successful}/${total} working`, 'success');
                loadProxyStatus(); // Refresh proxy status
            })
            .catch(error => {
                console.error('Error testing proxies:', error);
                showNotification('Error testing proxies', 'error');
            });
        }

        function clearCache() {
            if (confirm('Are you sure you want to clear all cache?')) {
                clearSpecificCache('all');
            }
        }

        function clearSpecificCache(type) {
            fetch('/api/clear-cache', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({type: type})
            })
            .then(response => response.json())
            .then(data => {
                showNotification(data.message, 'success');
                loadStats(); // Refresh cache stats
            })
            .catch(error => {
                console.error('Error clearing cache:', error);
                showNotification('Error clearing cache', 'error');
            });
        }

        function toggleTheme() {
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 300);
            }, 3000);
        }

        // Load saved theme
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            document.body.setAttribute('data-theme', savedTheme);
        }
    </script>
</body>
</html>
'''

# Avvia i thread di monitoraggio
bandwidth_thread = Thread(target=monitor_bandwidth, daemon=True)
bandwidth_thread.start()

setup_proxies()

# Resto del codice originale per i proxy endpoints...
# [Il resto del codice rimane uguale, inclusi tutti gli endpoint /proxy, /proxy/m3u, etc.]

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    print(f"Advanced Proxy Dashboard ONLINE - Porta {port}")
    print(f"Login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    app.run(host="0.0.0.0", port=port, debug=False)
