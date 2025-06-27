import os
import re
import time
import random
import requests
import threading
from urllib.parse import urljoin, urlparse, unquote, parse_qs, quote
from flask import Flask, request, Response, jsonify, render_template_string
from cachetools import TTLCache
import psutil
import gc
from collections import defaultdict
import urllib3
import warnings
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disabilita i warning SSL di urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

app = Flask(__name__)

# Configurazione
VERIFY_SSL = False

# Cache ottimizzate - aumentate per migliori prestazioni
M3U8_CACHE = TTLCache(maxsize=200, ttl=5)    # Aumentata da 50 a 200, ridotto TTL da 10 a 5
TS_CACHE = TTLCache(maxsize=1000, ttl=300)   # Aumentata da 200 a 1000, TTL da 60 a 300
KEY_CACHE = TTLCache(maxsize=200, ttl=300)   # Aumentata da 50 a 200, TTL da 120 a 300

# Sistema di cache condivisa e monitoraggio
ACTIVE_DOWNLOADS = {}
download_locks = defaultdict(threading.Lock)

def get_memory_usage():
    """Restituisce l'uso di memoria in MB"""
    try:
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    except:
        return 0

def cleanup_if_needed():
    """Pulisce la memoria se necessario"""
    memory_mb = get_memory_usage()
    if memory_mb > 1200:  # Aumentata soglia da 800MB a 1200MB
        print(f"⚠️ Memoria alta: {memory_mb:.1f}MB - Pulizia in corso...")
        # Pulisci solo la cache TS (più pesante)
        TS_CACHE.clear()
        gc.collect()
        new_memory = get_memory_usage()
        print(f"Memoria dopo pulizia: {new_memory:.1f}MB")

def setup_proxy_from_env():
    """Configura proxy dalle variabili d'ambiente con supporto completo"""
    proxy_config = {}
    
    # Proxy HTTP
    http_proxy = (os.environ.get('HTTP_PROXY') or 
                  os.environ.get('http_proxy'))
    
    # Proxy HTTPS  
    https_proxy = (os.environ.get('HTTPS_PROXY') or 
                   os.environ.get('https_proxy'))
    
    # Proxy SOCKS
    socks_proxy = (os.environ.get('SOCKS_PROXY') or 
                   os.environ.get('socks_proxy'))
    
    # Lista di proxy multipli (separati da virgola)
    proxy_list = os.environ.get('PROXY_LIST')
    
    if proxy_list:
        # Supporto per lista di proxy
        proxies = [p.strip() for p in proxy_list.split(',')]
        selected_proxy = random.choice(proxies)
        proxy_config['http'] = selected_proxy
        proxy_config['https'] = selected_proxy
        print(f"Proxy selezionato dalla lista: {selected_proxy}")
    elif socks_proxy:
        # SOCKS proxy per entrambi HTTP e HTTPS
        proxy_config['http'] = socks_proxy
        proxy_config['https'] = socks_proxy
        print(f"SOCKS proxy configurato: {socks_proxy}")
    else:
        # Proxy separati per HTTP e HTTPS
        if http_proxy:
            proxy_config['http'] = http_proxy
        if https_proxy:
            proxy_config['https'] = https_proxy
        if proxy_config:
            print(f"Proxy configurati: {proxy_config}")
    
    # NO_PROXY per escludere domini
    no_proxy = os.environ.get('NO_PROXY') or os.environ.get('no_proxy')
    if no_proxy:
        print(f"Domini esclusi dal proxy: {no_proxy}")
    
    return proxy_config if proxy_config else None

# Inizializza proxy all'avvio
PROXY_CONFIG = setup_proxy_from_env()

@app.before_request
def before_request():
    """Pulizia periodica della memoria"""
    if random.random() < 0.05:  # 5% delle richieste
        cleanup_if_needed()

def get_proxy_for_url(url):
    """Seleziona proxy ma lo salta per domini GitHub"""
    if not PROXY_CONFIG:
        return None
    
    try:
        parsed_url = urlparse(url)
        if 'github.com' in parsed_url.netloc:
            return None
    except Exception:
        pass
    
    return PROXY_CONFIG

def create_robust_session():
    """Crea una sessione con configurazione robusta per gestire timeout e retry"""
    session = requests.Session()
    
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
        pool_connections=10,
        pool_maxsize=20
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # User-Agent fisso invece di casuale
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    # Configura proxy se disponibili
    if PROXY_CONFIG:
        session.proxies.update(PROXY_CONFIG)
    
    return session

def get_dynamic_timeout(url, base_timeout=30):
    """Timeout dinamico basato sul tipo di risorsa - aumentati"""
    if '.ts' in url.lower():
        return base_timeout * 2  # 60 secondi invece di 15
    elif '.m3u8' in url.lower():
        return base_timeout * 1.5  # 45 secondi invece di 10
    else:
        return base_timeout

def extract_channel_id(url):
    """Estrae un identificativo del canale dall'URL per il monitoraggio"""
    if not url:
        return None
    
    # Estrai identificativo da diversi pattern URL
    patterns = [
        r'/([^/]+)\.m3u8',
        r'channel[=/]([^&/]+)',
        r'id[=/]([^&/]+)',
        r'/([^/]+)/playlist',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Fallback: usa dominio + path
    parsed = urlparse(url)
    return f"{parsed.netloc}{parsed.path}".replace('/', '_')

def detect_m3u_type(content):
    """Rileva il tipo di playlist M3U8"""
    if '#EXT-X-STREAM-INF' in content:
        return "master"
    elif '#EXTINF' in content:
        return "m3u8"
    else:
        return "unknown"

def preload_next_segments(m3u8_content, base_url, headers):
    """Precarica i primi 2 segmenti in background per ridurre latenza"""
    def background_preload():
        lines = m3u8_content.splitlines()
        segments_to_preload = []
        
        for line in lines:
            if line.strip() and not line.startswith('#'):
                segment_url = urljoin(base_url, line.strip())
                segments_to_preload.append(segment_url)
                
                # Precarica solo i primi 2 segmenti
                if len(segments_to_preload) >= 2:
                    break
        
        for segment_url in segments_to_preload:
            if segment_url not in TS_CACHE:
                try:
                    session = create_robust_session()
                    response = session.get(
                        segment_url, 
                        headers=headers, 
                        timeout=10,
                        proxies=get_proxy_for_url(segment_url),
                        verify=VERIFY_SSL
                    )
                    if response.status_code == 200:
                        content = response.content
                        if len(content) < 6 * 1024 * 1024:  # Aumentato da 3MB a 6MB
                            TS_CACHE[segment_url] = content
                            print(f"Segmento precaricato: {len(content)} bytes")
                except:
                    pass  # Ignora errori di precaricamento
    
    # Avvia precaricamento in background solo se cache non piena
    if len(TS_CACHE) < 800:  # Aumentato da 150 a 800
        threading.Thread(target=background_preload, daemon=True).start()

@app.route('/')
def home():
    """Homepage con informazioni di sistema"""
    memory_mb = get_memory_usage()
    cache_stats = {
        'M3U8_CACHE': f"{len(M3U8_CACHE)}/{M3U8_CACHE.maxsize}",
        'TS_CACHE': f"{len(TS_CACHE)}/{TS_CACHE.maxsize}",
        'KEY_CACHE': f"{len(KEY_CACHE)}/{KEY_CACHE.maxsize}",
    }
    
    # Nasconde lo stato del proxy
    proxy_status = "Nascosto"
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>M3U8 Proxy Server</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .status { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .cache-info { background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
            h1 { color: #333; }
            .endpoint { background: #f8f8f8; padding: 10px; margin: 10px 0; border-left: 4px solid #007cba; }
            .example { background: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 4px solid #28a745; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎬 M3U8 Proxy Server Ottimizzato</h1>
            <div class="status">
                <strong>✅ Server Attivo</strong><br>
                Memoria utilizzata: {{ memory_mb }}MB<br>
                Proxy: {{ proxy_status }}<br>
                Timestamp: {{ timestamp }}
            </div>
            
            <div class="cache-info">
                <strong>📊 Statistiche Cache:</strong><br>
                {% for cache_name, cache_stat in cache_stats.items() %}
                    {{ cache_name }}: {{ cache_stat }}<br>
                {% endfor %}
            </div>
            
            <h2>📡 Endpoints Disponibili</h2>
            <div class="endpoint">
                <strong>GET /proxy/m3u</strong><br>
                Proxy per playlist M3U8 con cache condivisa<br>
                Parametri: url, h_* (headers personalizzati)
            </div>
            <div class="example">
                Esempio: /proxy/m3u?url=https://example.com/playlist.m3u8&h_User_Agent=MyApp&h_Referer=https://site.com
            </div>
            
            <div class="endpoint">
                <strong>GET /proxy/ts</strong><br>
                Proxy per segmenti TS con cache condivisa e ottimizzazione memoria<br>
                Parametri: url, h_* (headers personalizzati)
            </div>
            <div class="example">
                Esempio: /proxy/ts?url=https://example.com/segment001.ts&h_Authorization=Bearer token123
            </div>
            
            <div class="endpoint">
                <strong>GET /proxy/key</strong><br>
                Proxy per chiavi di decrittazione AES-128<br>
                Parametri: url, h_* (headers personalizzati)
            </div>
            
            <div class="endpoint">
                <strong>GET /proxy</strong><br>
                Proxy per liste M3U che aggiunge automaticamente proxy agli URL<br>
                Parametri: url
            </div>
            
            <h2>🔧 Endpoints di Gestione</h2>
            <div class="endpoint">
                <strong>GET /status</strong><br>
                Informazioni dettagliate su memoria e cache (JSON)
            </div>
            
            <div class="endpoint">
                <strong>GET /clear-cache</strong><br>
                Pulisce manualmente tutte le cache
            </div>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(html, 
                                memory_mb=f"{memory_mb:.1f}",
                                cache_stats=cache_stats,
                                proxy_status=proxy_status,
                                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per playlist M3U8 con gestione ottimizzata"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    # Controlla cache M3U8
    if m3u_url in M3U8_CACHE:
        print(f"Cache HIT per M3U8: {m3u_url}")
        return Response(M3U8_CACHE[m3u_url], content_type="application/vnd.apple.mpegurl")

    print(f"Cache MISS per M3U8: {m3u_url}")

    # Estrai headers personalizzati
    current_headers_for_proxy = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    m3u_timeout = get_dynamic_timeout(m3u_url)
    max_retries = 3  # Riportato da 2 a 3

    for attempt in range(max_retries):
        try:
            session = create_robust_session()
            response = session.get(
                m3u_url, 
                headers=current_headers_for_proxy, 
                timeout=m3u_timeout,
                proxies=get_proxy_for_url(m3u_url),
                verify=VERIFY_SSL
            )
            response.raise_for_status()

            m3u_content = response.text
            file_type = detect_m3u_type(m3u_content)
            
            # Avvia precaricamento per playlist M3U8
            if file_type == "m3u8":
                base_url = m3u_url.rsplit('/', 1)[0] + '/'
                preload_next_segments(m3u_content, base_url, current_headers_for_proxy)

            # Processa il contenuto M3U8
            base_url = m3u_url.rsplit('/', 1)[0] + '/'
            processed_content = process_m3u_content(m3u_content, base_url, current_headers_for_proxy)

            # Cache il risultato
            M3U8_CACHE[m3u_url] = processed_content
            print(f"M3U8 cachato: {len(processed_content)} caratteri")

            return Response(processed_content, content_type="application/vnd.apple.mpegurl")

        except requests.exceptions.ConnectionError as e:
            if "timed out" in str(e).lower() and attempt < max_retries - 1:
                print(f"Timeout M3U8 (tentativo {attempt + 1}/{max_retries}): {m3u_url}")
                time.sleep(2 ** attempt)  # Backoff esponenziale
                continue
            return f"Errore di connessione: {str(e)}", 500
        except requests.exceptions.ReadTimeout as e:
            if attempt < max_retries - 1:
                print(f"Read timeout M3U8 (tentativo {attempt + 1}/{max_retries}): {m3u_url}")
                time.sleep(2 ** attempt)  # Backoff esponenziale
                continue
            return f"Errore timeout: {str(e)}", 504
        except requests.RequestException as e:
            return f"Errore download M3U8: {str(e)}", 500

def process_m3u_content(content, base_url, headers):
    """Processa il contenuto M3U8 sostituendo gli URL relativi"""
    lines = content.splitlines()
    processed_lines = []
    
    for line in lines:
        if line.strip() and not line.startswith('#'):
            # URL del segmento o playlist
            if line.startswith('http'):
                segment_url = line.strip()
            else:
                segment_url = urljoin(base_url, line.strip())
            
            # Determina il tipo di proxy necessario
            if segment_url.endswith('.ts'):
                proxy_url = f"/proxy/ts?url={quote(segment_url)}"
            elif segment_url.endswith('.m3u8'):
                proxy_url = f"/proxy/m3u?url={quote(segment_url)}"
            else:
                proxy_url = f"/proxy/ts?url={quote(segment_url)}"  # Default a TS
            
            # Aggiungi headers se presenti
            for header_name, header_value in headers.items():
                encoded_name = f"h_{header_name.replace('-', '_')}"
                proxy_url += f"&{encoded_name}={quote(header_value)}"
            
            processed_lines.append(proxy_url)
        elif line.startswith('#EXT-X-KEY:'):
            # Gestisci le chiavi di decrittazione
            processed_line = process_key_line(line, base_url, headers)
            processed_lines.append(processed_line)
        else:
            processed_lines.append(line)
    
    return '\n'.join(processed_lines)

def process_key_line(line, base_url, headers):
    """Processa le linee #EXT-X-KEY sostituendo gli URL delle chiavi"""
    if 'URI=' in line:
        # Estrai l'URL della chiave
        uri_match = re.search(r'URI="([^"]+)"', line)
        if uri_match:
            key_url = uri_match.group(1)
            if not key_url.startswith('http'):
                key_url = urljoin(base_url, key_url)
            
            # Crea URL proxy per la chiave
            proxy_key_url = f"/proxy/key?url={quote(key_url)}"
            
            # Aggiungi headers
            for header_name, header_value in headers.items():
                encoded_name = f"h_{header_name.replace('-', '_')}"
                proxy_key_url += f"&{encoded_name}={quote(header_value)}"
            
            # Sostituisci l'URL nella linea
            line = re.sub(r'URI="[^"]+"', f'URI="{proxy_key_url}"', line)
    
    return line

@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con cache condivisa e gestione memoria ottimizzata"""
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    # Cache condivisa - controlla prima del download
    if ts_url in TS_CACHE:
        print(f"Cache HIT condivisa per TS: {ts_url}")
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")

    # Evita download multipli dello stesso segmento
    with download_locks[ts_url]:
        # Ricontrolla cache dopo aver acquisito il lock
        if ts_url in TS_CACHE:
            return Response(TS_CACHE[ts_url], content_type="video/mp2t")
        
        print(f"Cache MISS per TS: {ts_url} - Download per tutti gli utenti")

        headers = {
            unquote(key[2:]).replace("_", "-"): unquote(value).strip()
            for key, value in request.args.items()
            if key.lower().startswith("h_")
        }

        ts_timeout = get_dynamic_timeout(ts_url)
        max_retries = 3  # Riportato da 2 a 3
        
        for attempt in range(max_retries):
            try:
                session = create_robust_session()
                response = session.get(
                    ts_url, 
                    headers=headers, 
                    timeout=ts_timeout,
                    proxies=get_proxy_for_url(ts_url),
                    verify=VERIFY_SSL
                )
                response.raise_for_status()

                content = response.content
                
                # Cache segmenti più grandi
                if len(content) < 6 * 1024 * 1024:  # Aumentato da 3MB a 6MB
                    TS_CACHE[ts_url] = content
                    print(f"Segmento cachato per tutti gli utenti: {len(content)} bytes")
                else:
                    print(f"Segmento troppo grande per cache: {len(content)} bytes")
                
                return Response(content, content_type="video/mp2t")

            except requests.exceptions.ConnectionError as e:
                if "timed out" in str(e).lower() and attempt < max_retries - 1:
                    print(f"Timeout TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
                    time.sleep(2 ** attempt)  # Backoff esponenziale
                    continue
                return f"Errore di connessione: {str(e)}", 500
            except requests.exceptions.ReadTimeout as e:
                if attempt < max_retries - 1:
                    print(f"Read timeout TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
                    time.sleep(2 ** attempt)  # Backoff esponenziale
                    continue
                return f"Errore timeout: {str(e)}", 504
            except requests.RequestException as e:
                return f"Errore download TS: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Proxy per chiavi di decrittazione"""
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante", 400

    # Controlla cache
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
        session = create_robust_session()
        response = session.get(
            key_url, 
            headers=headers, 
            timeout=get_dynamic_timeout(key_url),
            proxies=get_proxy_for_url(key_url),
            verify=VERIFY_SSL
        )
        response.raise_for_status()

        key_content = response.content
        KEY_CACHE[key_url] = key_content
        print(f"Chiave cachata: {len(key_content)} bytes")

        return Response(key_content, content_type="application/octet-stream")

    except requests.RequestException as e:
        return f"Errore download chiave: {str(e)}", 500

@app.route('/proxy')
def proxy():
    """Proxy per liste M3U che aggiunge automaticamente /proxy/m3u?url= con IP prima dei link"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    try:
        server_ip = request.host
        session = create_robust_session()
        response = session.get(
            m3u_url, 
            timeout=get_dynamic_timeout(m3u_url),
            proxies=get_proxy_for_url(m3u_url),
            verify=VERIFY_SSL
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

@app.route('/status')
def status():
    """Endpoint per monitorare lo stato del server"""
    memory_mb = get_memory_usage()
    
    status_info = {
        "status": "active",
        "memory_mb": round(memory_mb, 1),
        "cache_stats": {
            "m3u8_cache": f"{len(M3U8_CACHE)}/{M3U8_CACHE.maxsize}",
            "ts_cache": f"{len(TS_CACHE)}/{TS_CACHE.maxsize}",
            "key_cache": f"{len(KEY_CACHE)}/{KEY_CACHE.maxsize}"
        },
        "cache_ttl": {
            "m3u8_ttl": M3U8_CACHE.ttl,
            "ts_ttl": TS_CACHE.ttl,
            "key_ttl": KEY_CACHE.ttl
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return jsonify(status_info)

@app.route('/clear-cache')
def clear_cache():
    """Endpoint per pulire manualmente le cache"""
    M3U8_CACHE.clear()
    TS_CACHE.clear()
    KEY_CACHE.clear()
    gc.collect()
    
    return jsonify({
        "status": "success",
        "message": "Cache pulite",
        "memory_after_mb": round(get_memory_usage(), 1)
    })

if __name__ == '__main__':
    print("🚀 Avvio M3U8 Proxy Server ottimizzato...")
    print(f"💾 Configurazione cache:")
    print(f"   - M3U8: {M3U8_CACHE.maxsize} elementi, TTL {M3U8_CACHE.ttl}s")
    print(f"   - TS: {TS_CACHE.maxsize} elementi, TTL {TS_CACHE.ttl}s")
    print(f"   - KEY: {KEY_CACHE.maxsize} elementi, TTL {KEY_CACHE.ttl}s")
    print(f"🔧 Memoria iniziale: {get_memory_usage():.1f}MB")
    
    if PROXY_CONFIG:
        print(f"🌐 Proxy configurato: {PROXY_CONFIG}")
    else:
        print("🌐 Nessun proxy configurato (connessione diretta)")
    
    app.run(host='0.0.0.0', port=7860, debug=False, threaded=True)
