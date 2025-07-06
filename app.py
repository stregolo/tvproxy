from flask import Flask, request, Response, jsonify, render_template, session, redirect, url_for
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
import subprocess
import concurrent.futures
from flask_socketio import SocketIO, emit
import threading
from datetime import datetime, timedelta
import math
import ipaddress

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=60, ping_interval=25, max_http_buffer_size=100000000)
app.permanent_session_lifetime = timedelta(minutes=5)

load_dotenv()

# --- Variabili globali ---
PROXY_LIST = []
DADDY_PROXY_LIST = []  # Proxy dedicati per DaddyLive
SESSION_POOL = {}
PROXY_BLACKLIST = {}
DADDY_PROXY_BLACKLIST = {}  # Blacklist separata per proxy DaddyLive
system_stats = {}
DADDYLIVE_BASE_URL = None
LAST_FETCH_TIME = 0
FETCH_INTERVAL = 3600

# --- Funzioni di utilità ---
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
    
    # Statistiche pre-buffer
    try:
        with pre_buffer_manager.pre_buffer_lock:
            total_segments = sum(len(segments) for segments in pre_buffer_manager.pre_buffer.values())
            total_size = sum(
                sum(len(content) for content in segments.values())
                for segments in pre_buffer_manager.pre_buffer.values()
            )
            system_stats['prebuffer_streams'] = len(pre_buffer_manager.pre_buffer)
            system_stats['prebuffer_segments'] = total_segments
            system_stats['prebuffer_size_mb'] = round(total_size / (1024 * 1024), 2)
            system_stats['prebuffer_threads'] = len(pre_buffer_manager.pre_buffer_threads)
    except Exception as e:
        app.logger.error(f"Errore nel calcolo statistiche pre-buffer: {e}")
        system_stats['prebuffer_streams'] = 0
        system_stats['prebuffer_segments'] = 0
        system_stats['prebuffer_size_mb'] = 0
        system_stats['prebuffer_threads'] = 0
    
    return system_stats

def get_daddylive_base_url():
    """Fetches and caches the dynamic base URL for DaddyLive."""
    global DADDYLIVE_BASE_URL, LAST_FETCH_TIME
    current_time = time.time()
    
    if DADDYLIVE_BASE_URL and (current_time - LAST_FETCH_TIME < FETCH_INTERVAL):
        return DADDYLIVE_BASE_URL

    try:
        app.logger.info("Fetching dynamic DaddyLive base URL from GitHub...")
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        
        # Always use direct connection for GitHub to avoid proxy rate limiting (429 errors)
        session = requests.Session()
        session.trust_env = False  # Ignore environment proxy variables
        main_url_req = session.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL
        )
        main_url_req.raise_for_status()
        content = main_url_req.text
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

# --- Classe VavooResolver per gestire i link Vavoo ---
class VavooResolver:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MediaHubMX/2'
        })
        # Assicurati che la sessione non erediti proxy dalle variabili d'ambiente
        self.session.trust_env = False
    
    def getAuthSignature(self):
        """Funzione che replica esattamente quella dell'addon utils.py"""
        headers = {
            "user-agent": "okhttp/4.11.0",
            "accept": "application/json", 
            "content-type": "application/json; charset=utf-8",
            "content-length": "1106",
            "accept-encoding": "gzip"
        }
        data = {
            "token": "tosFwQCJMS8qrW_AjLoHPQ41646J5dRNha6ZWHnijoYQQQoADQoXYSo7ki7O5-CsgN4CH0uRk6EEoJ0728ar9scCRQW3ZkbfrPfeCXW2VgopSW2FWDqPOoVYIuVPAOnXCZ5g",
            "reason": "app-blur",
            "locale": "de",
            "theme": "dark",
            "metadata": {
                "device": {
                    "type": "Handset",
                    "brand": "google",
                    "model": "Nexus",
                    "name": "21081111RG",
                    "uniqueId": "d10e5d99ab665233"
                },
                "os": {
                    "name": "android",
                    "version": "7.1.2",
                    "abis": ["arm64-v8a", "armeabi-v7a", "armeabi"],
                    "host": "android"
                },
                "app": {
                    "platform": "android",
                    "version": "3.1.20",
                    "buildId": "289515000",
                    "engine": "hbc85",
                    "signatures": ["6e8a975e3cbf07d5de823a760d4c2547f86c1403105020adee5de67ac510999e"],
                    "installer": "app.revanced.manager.flutter"
                },
                "version": {
                    "package": "tv.vavoo.app",
                    "binary": "3.1.20",
                    "js": "3.1.20"
                }
            },
            "appFocusTime": 0,
            "playerActive": False,
            "playDuration": 0,
            "devMode": False,
            "hasAddon": True,
            "castConnected": False,
            "package": "tv.vavoo.app",
            "version": "3.1.20",
            "process": "app",
            "firstAppStart": 1743962904623,
            "lastAppStart": 1743962904623,
            "ipLocation": "",
            "adblockEnabled": True,
            "proxy": {
                "supported": ["ss", "openvpn"],
                "engine": "ss", 
                "ssVersion": 1,
                "enabled": True,
                "autoServer": True,
                "id": "pl-waw"
            },
            "iap": {
                "supported": False
            }
        }
        try:
            # Usa il sistema di proxy configurato
            proxy_config = get_proxy_for_url("https://www.vavoo.tv/api/app/ping", original_url="https://vavoo.to")
            proxy_key = proxy_config['http'] if proxy_config else None
            
            # Usa make_persistent_request per sfruttare il sistema di proxy
            resp = make_persistent_request(
                "https://www.vavoo.tv/api/app/ping",
                headers=headers,
                timeout=10,
                proxy_url=proxy_key,
                method='POST',
                json=data
            )
            resp.raise_for_status()
            return resp.json().get("addonSig")
        except Exception as e:
            app.logger.error(f"Errore nel recupero della signature Vavoo: {e}")
            return None

    def resolve_vavoo_link(self, link, verbose=False):
        """
        Risolve un link Vavoo usando solo il metodo principale (streammode=1)
        """
        if not "vavoo.to" in link:
            if verbose:
                app.logger.info("Il link non è un link Vavoo")
            return None
            
        # Solo metodo principale per il proxy
        signature = self.getAuthSignature()
        if not signature:
            app.logger.error("Impossibile ottenere la signature Vavoo")
            return None
            
        headers = {
            "user-agent": "MediaHubMX/2",
            "accept": "application/json",
            "content-type": "application/json; charset=utf-8", 
            "content-length": "115",
            "accept-encoding": "gzip",
            "mediahubmx-signature": signature
        }
        data = {
            "language": "de",
            "region": "AT", 
            "url": link,
            "clientVersion": "3.0.2"
        }
        
        try:
            # Usa il sistema di proxy configurato
            proxy_config = get_proxy_for_url("https://vavoo.to/mediahubmx-resolve.json", original_url=link)
            proxy_key = proxy_config['http'] if proxy_config else None
            
            # Usa make_persistent_request per sfruttare il sistema di proxy
            resp = make_persistent_request(
                "https://vavoo.to/mediahubmx-resolve.json",
                headers=headers,
                timeout=10,
                proxy_url=proxy_key,
                method='POST',
                json=data
            )
            resp.raise_for_status()
            
            if verbose:
                app.logger.info(f"Vavoo response status: {resp.status_code}")
                app.logger.info(f"Vavoo response body: {resp.text}")
            
            result = resp.json()
            if isinstance(result, list) and result and result[0].get("url"):
                resolved_url = result[0]["url"]
                channel_name = result[0].get("name", "Unknown")
                app.logger.info(f"✅ Vavoo risolto: {channel_name} -> {resolved_url}")
                return resolved_url
            elif isinstance(result, dict) and result.get("url"):
                app.logger.info(f"✅ Vavoo risolto: {result['url']}")
                return result["url"]
            else:
                app.logger.warning("Nessun link valido trovato nella risposta Vavoo")
                return None
                
        except Exception as e:
            app.logger.error(f"Errore nella risoluzione Vavoo: {e}")
            return None

# Istanza globale del resolver Vavoo
vavoo_resolver = VavooResolver()

# --- Configurazione Autenticazione ---
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password123')
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '').split(',') if os.environ.get('ALLOWED_IPS') else []

def setup_all_caches():
    global M3U8_CACHE, TS_CACHE, KEY_CACHE
    config = config_manager.load_config()
    if config.get('CACHE_ENABLED', True):
        M3U8_CACHE = TTLCache(maxsize=config['CACHE_MAXSIZE_M3U8'], ttl=config['CACHE_TTL_M3U8'])
        TS_CACHE = TTLCache(maxsize=config['CACHE_MAXSIZE_TS'], ttl=config['CACHE_TTL_TS'])
        KEY_CACHE = TTLCache(maxsize=config['CACHE_MAXSIZE_KEY'], ttl=config['CACHE_TTL_KEY'])
        app.logger.info("Cache ABILITATA su tutte le risorse.")
    else:
        M3U8_CACHE = {}
        TS_CACHE = {}
        KEY_CACHE = {}
        app.logger.warning("TUTTE LE CACHE DISABILITATE: stream diretto attivo.")

def check_auth(username, password):
    """Verifica le credenziali di accesso"""
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def check_ip_allowed():
    """Verifica se l'IP è nella lista degli IP consentiti - Lettura dinamica"""
    try:
        # Leggi dinamicamente dalla configurazione salvata
        config = config_manager.load_config()
        allowed_ips_str = config.get('ALLOWED_IPS', '')
        
        # Se non ci sono IP configurati, consenti tutto
        if not allowed_ips_str or allowed_ips_str.strip() == '':
            return True
        
        # Parsing della lista IP
        allowed_ips = [ip.strip() for ip in allowed_ips_str.split(',') if ip.strip()]
        
        # Se la lista è vuota dopo il parsing, consenti tutto
        if not allowed_ips:
            return True
        
        # Ottieni l'IP del client
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        
        # Verifica se l'IP è nella lista
        is_allowed = client_ip in allowed_ips
        
        if not is_allowed:
            app.logger.warning(f"IP non autorizzato: {client_ip}. IP consentiti: {allowed_ips}")
        
        return is_allowed
        
    except Exception as e:
        app.logger.error(f"Errore nella verifica IP: {e}")
        # In caso di errore, consenti l'accesso per evitare lockout
        return True

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
    
# --- Funzioni di Supporto IPv6 ---
def is_ipv6_address(ip_str):
    """Verifica se un indirizzo è IPv6"""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def is_ipv4_address(ip_str):
    """Verifica se un indirizzo è IPv4"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def extract_ip_from_proxy_url(proxy_url):
    """Estrae l'IP da un URL proxy"""
    try:
        parsed = urlparse(proxy_url)
        host = parsed.hostname
        if host:
            # Rimuovi le parentesi quadre se presenti (IPv6)
            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            return host
    except Exception:
        pass
    return None

def get_proxy_ip_version(proxy_url):
    """Determina la versione IP di un proxy (IPv4/IPv6)"""
    ip = extract_ip_from_proxy_url(proxy_url)
    if not ip:
        return "unknown"
    
    if is_ipv6_address(ip):
        return "IPv6"
    elif is_ipv4_address(ip):
        return "IPv4"
    else:
        return "hostname"  # Dominio invece di IP

def detect_proxy_type(proxy_url):
    """Riconosce automaticamente il tipo di proxy dall'URL"""
    proxy_url_lower = proxy_url.lower()
    
    if proxy_url_lower.startswith('socks5://') or proxy_url_lower.startswith('socks5h://'):
        return 'socks5'
    elif proxy_url_lower.startswith('http://'):
        return 'http'
    elif proxy_url_lower.startswith('https://'):
        return 'https'
    else:
        # Se non ha protocollo, prova a indovinare dalla porta
        try:
            # Estrai la porta dall'URL
            if ':' in proxy_url:
                host_port = proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url
                if ':' in host_port:
                    port = int(host_port.split(':')[-1])
                    # Porta 1080 è tipicamente SOCKS5
                    if port == 1080:
                        return 'socks5'
                    # Porte 8080, 3128, 8888 sono tipicamente HTTP
                    elif port in [8080, 3128, 8888]:
                        return 'http'
                    # Porte 8443, 443 sono tipicamente HTTPS
                    elif port in [8443, 443]:
                        return 'https'
        except (ValueError, IndexError):
            pass
        
        # Default: assume HTTP
        return 'http'

# --- Sistema di Blacklist Proxy per Errori 429 ---
PROXY_BLACKLIST = {}  # {proxy_url: {'last_error': timestamp, 'error_count': count, 'blacklisted_until': timestamp}}
PROXY_BLACKLIST_LOCK = Lock()
BLACKLIST_DURATION = 300  # 5 minuti di blacklist per errore 429
MAX_ERRORS_BEFORE_PERMANENT = 5  # Dopo 5 errori, blacklist permanente per 1 ora

def add_proxy_to_blacklist(proxy_url, error_type="429"):
    """Aggiunge un proxy alla blacklist temporanea"""
    global PROXY_BLACKLIST
    
    with PROXY_BLACKLIST_LOCK:
        current_time = time.time()
        
        if proxy_url not in PROXY_BLACKLIST:
            PROXY_BLACKLIST[proxy_url] = {
                'last_error': current_time,
                'error_count': 1,
                'blacklisted_until': current_time + BLACKLIST_DURATION,
                'error_type': error_type
            }
        else:
            # Incrementa il contatore errori
            PROXY_BLACKLIST[proxy_url]['error_count'] += 1
            PROXY_BLACKLIST[proxy_url]['last_error'] = current_time
            
            # Se troppi errori, blacklist più lunga
            if PROXY_BLACKLIST[proxy_url]['error_count'] >= MAX_ERRORS_BEFORE_PERMANENT:
                PROXY_BLACKLIST[proxy_url]['blacklisted_until'] = current_time + 3600  # 1 ora
                app.logger.warning(f"Proxy {proxy_url} blacklistato permanentemente per {MAX_ERRORS_BEFORE_PERMANENT} errori {error_type}")
            else:
                PROXY_BLACKLIST[proxy_url]['blacklisted_until'] = current_time + BLACKLIST_DURATION
            
            PROXY_BLACKLIST[proxy_url]['error_type'] = error_type
        
        app.logger.info(f"Proxy {proxy_url} blacklistato fino a {datetime.fromtimestamp(PROXY_BLACKLIST[proxy_url]['blacklisted_until']).strftime('%H:%M:%S')} per {error_type} errori")
        
        # Log dettagliato per debug
        app.logger.info(f"Blacklist proxy aggiornata: {len(PROXY_BLACKLIST)} proxy totali, {len(get_available_proxies())} disponibili")

def add_daddy_proxy_to_blacklist(proxy_url, error_type="429"):
    """Aggiunge un proxy DaddyLive alla blacklist temporanea"""
    global DADDY_PROXY_BLACKLIST
    
    with PROXY_BLACKLIST_LOCK:
        current_time = time.time()
        
        if proxy_url not in DADDY_PROXY_BLACKLIST:
            DADDY_PROXY_BLACKLIST[proxy_url] = {
                'last_error': current_time,
                'error_count': 1,
                'blacklisted_until': current_time + BLACKLIST_DURATION,
                'error_type': error_type
            }
        else:
            # Incrementa il contatore errori
            DADDY_PROXY_BLACKLIST[proxy_url]['error_count'] += 1
            DADDY_PROXY_BLACKLIST[proxy_url]['last_error'] = current_time
            
            # Se troppi errori, blacklist più lunga
            if DADDY_PROXY_BLACKLIST[proxy_url]['error_count'] >= MAX_ERRORS_BEFORE_PERMANENT:
                DADDY_PROXY_BLACKLIST[proxy_url]['blacklisted_until'] = current_time + 3600  # 1 ora
                app.logger.warning(f"Proxy DaddyLive {proxy_url} blacklistato permanentemente per {MAX_ERRORS_BEFORE_PERMANENT} errori {error_type}")
            else:
                DADDY_PROXY_BLACKLIST[proxy_url]['blacklisted_until'] = current_time + BLACKLIST_DURATION
            
            DADDY_PROXY_BLACKLIST[proxy_url]['error_type'] = error_type
        
        app.logger.info(f"Proxy DaddyLive {proxy_url} blacklistato fino a {datetime.fromtimestamp(DADDY_PROXY_BLACKLIST[proxy_url]['blacklisted_until']).strftime('%H:%M:%S')} per {error_type} errori")
        
        # Log dettagliato per debug
        app.logger.info(f"Blacklist proxy DaddyLive aggiornata: {len(DADDY_PROXY_BLACKLIST)} proxy totali, {len(get_available_daddy_proxies())} disponibili")

def is_proxy_blacklisted(proxy_url):
    """Verifica se un proxy è in blacklist"""
    global PROXY_BLACKLIST
    
    with PROXY_BLACKLIST_LOCK:
        if proxy_url not in PROXY_BLACKLIST:
            return False
        
        current_time = time.time()
        blacklist_info = PROXY_BLACKLIST[proxy_url]
        
        # Se il periodo di blacklist è scaduto, rimuovi dalla blacklist
        if current_time > blacklist_info['blacklisted_until']:
            del PROXY_BLACKLIST[proxy_url]
            app.logger.info(f"Proxy {proxy_url} rimosso dalla blacklist (scaduto)")
            return False
        
        return True

def is_daddy_proxy_blacklisted(proxy_url):
    """Verifica se un proxy DaddyLive è in blacklist"""
    global DADDY_PROXY_BLACKLIST
    
    with PROXY_BLACKLIST_LOCK:
        if proxy_url not in DADDY_PROXY_BLACKLIST:
            return False
        
        current_time = time.time()
        blacklist_info = DADDY_PROXY_BLACKLIST[proxy_url]
        
        # Se il periodo di blacklist è scaduto, rimuovi dalla blacklist
        if current_time > blacklist_info['blacklisted_until']:
            del DADDY_PROXY_BLACKLIST[proxy_url]
            app.logger.info(f"Proxy DaddyLive {proxy_url} rimosso dalla blacklist (scaduto)")
            return False
        
        return True

def get_available_proxies():
    """Restituisce solo i proxy non blacklistati"""
    available_proxies = []
    
    for proxy in PROXY_LIST:
        if not is_proxy_blacklisted(proxy):
            available_proxies.append(proxy)
    
    return available_proxies

def get_available_daddy_proxies():
    """Restituisce solo i proxy DaddyLive non blacklistati"""
    available_proxies = []
    
    for proxy in DADDY_PROXY_LIST:
        if not is_daddy_proxy_blacklisted(proxy):
            available_proxies.append(proxy)
    
    return available_proxies

def cleanup_expired_blacklist():
    """Pulisce la blacklist dai proxy scaduti"""
    global PROXY_BLACKLIST, DADDY_PROXY_BLACKLIST
    
    with PROXY_BLACKLIST_LOCK:
        current_time = time.time()
        expired_proxies = []
        expired_daddy_proxies = []
        
        # Pulisci blacklist proxy normali
        for proxy_url, blacklist_info in PROXY_BLACKLIST.items():
            if current_time > blacklist_info['blacklisted_until']:
                expired_proxies.append(proxy_url)
        
        for proxy_url in expired_proxies:
            del PROXY_BLACKLIST[proxy_url]
            app.logger.info(f"Proxy {proxy_url} rimosso dalla blacklist (scaduto)")
        
        # Pulisci blacklist proxy DaddyLive
        for proxy_url, blacklist_info in DADDY_PROXY_BLACKLIST.items():
            if current_time > blacklist_info['blacklisted_until']:
                expired_daddy_proxies.append(proxy_url)
        
        for proxy_url in expired_daddy_proxies:
            del DADDY_PROXY_BLACKLIST[proxy_url]
            app.logger.info(f"Proxy DaddyLive {proxy_url} rimosso dalla blacklist (scaduto)")
    
    return len(expired_proxies) + len(expired_daddy_proxies)

# Sistema di broadcasting per statistiche real-time
def broadcast_stats():
    """Invia statistiche in tempo reale a tutti i client connessi"""
    while True:
        try:
            stats = get_system_stats()
            stats['daddy_base_url'] = get_daddylive_base_url()
            stats['session_count'] = len(SESSION_POOL)
            stats['proxy_count'] = len(PROXY_LIST)
            
            # Aggiungi statistiche proxy
            available_proxies = get_available_proxies()
            
            # Calcola statistiche IP
            ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
            for proxy in PROXY_LIST:
                ip_version = get_proxy_ip_version(proxy)
                if ip_version in ip_stats:
                    ip_stats[ip_version] += 1
            
            available_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
            for proxy in available_proxies:
                ip_version = get_proxy_ip_version(proxy)
                if ip_version in available_ip_stats:
                    available_ip_stats[ip_version] += 1
            
            # Calcola statistiche proxy DaddyLive
            available_daddy_proxies = get_available_daddy_proxies()
            daddy_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
            for proxy in DADDY_PROXY_LIST:
                ip_version = get_proxy_ip_version(proxy)
                if ip_version in daddy_ip_stats:
                    daddy_ip_stats[ip_version] += 1
            
            available_daddy_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
            for proxy in available_daddy_proxies:
                ip_version = get_proxy_ip_version(proxy)
                if ip_version in available_daddy_ip_stats:
                    available_daddy_ip_stats[ip_version] += 1
            
            stats['proxy_status'] = {
                'available_proxies': len(available_proxies),
                'blacklisted_proxies': len(PROXY_BLACKLIST),
                'total_proxies': len(PROXY_LIST),
                'available_daddy_proxies': len(available_daddy_proxies),
                'blacklisted_daddy_proxies': len(DADDY_PROXY_BLACKLIST),
                'total_daddy_proxies': len(DADDY_PROXY_LIST),
                'ip_statistics': {
                    'total': ip_stats,
                    'available': available_ip_stats
                },
                'daddy_ip_statistics': {
                    'total': daddy_ip_stats,
                    'available': available_daddy_ip_stats
                }
            }
            
            stats['timestamp'] = time.time()
            
            # Aggiungi statistiche client se disponibile
            try:
                if 'client_tracker' in globals():
                    client_stats = client_tracker.get_realtime_stats()
                    stats.update(client_stats)
                else:
                    # Fallback se client_tracker non è ancora disponibile
                    stats['active_clients'] = 0
                    stats['active_sessions'] = 0
                    stats['total_requests'] = 0
                    stats['m3u_clients'] = 0
                    stats['m3u_requests'] = 0
            except Exception as e:
                app.logger.warning(f"Errore nel recupero statistiche client: {e}")
                # Fallback con valori di default
                stats['active_clients'] = 0
                stats['active_sessions'] = 0
                stats['total_requests'] = 0
                stats['m3u_clients'] = 0
                stats['m3u_requests'] = 0
            
            socketio.emit('stats_update', stats)
            time.sleep(2)  # Aggiorna ogni 2 secondi
        except Exception as e:
            app.logger.error(f"Errore nel broadcast statistiche: {e}")
            time.sleep(5)

@socketio.on('connect')
def handle_connect():
    """Gestisce nuove connessioni WebSocket"""
    app.logger.info("Client connesso")
    # Invia immediatamente le statistiche correnti
    stats = get_system_stats()
    
    # Aggiungi statistiche client se disponibile
    try:
        if 'client_tracker' in globals():
            client_stats = client_tracker.get_realtime_stats()
            stats.update(client_stats)
        else:
            # Fallback se client_tracker non è ancora disponibile
            stats['active_clients'] = 0
            stats['active_sessions'] = 0
            stats['total_requests'] = 0
            stats['m3u_clients'] = 0
            stats['m3u_requests'] = 0
    except Exception as e:
        app.logger.warning(f"Errore nel recupero statistiche client per nuova connessione: {e}")
        # Fallback con valori di default
        stats['active_clients'] = 0
        stats['active_sessions'] = 0
        stats['total_requests'] = 0
        stats['m3u_clients'] = 0
        stats['m3u_requests'] = 0
    
    emit('stats_update', stats)

@socketio.on('disconnect')
def handle_disconnect():
    """Gestisce disconnessioni WebSocket"""
    app.logger.info("Client disconnesso")

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
        # Prova diverse directory per il file di configurazione
        self.config_file = self._get_writable_config_path()
        self.backup_file = '/tmp/tvproxy_config_backup.json'  # Backup per HuggingFace
        self.global_config_file = '/tmp/tvproxy_global_config.json'  # Configurazione globale per tutti i workers
        self.global_lock_file = '/tmp/tvproxy_config.lock'  # Lock file per sincronizzazione
        self.default_config = {
            'PROXY': '',  # Proxy unificati con riconoscimento automatico
            'DADDY_PROXY': '',  # Proxy dedicati per DaddyLive
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
            'ADMIN_PASSWORD': 'password123',
            'CACHE_ENABLED' : True,
            'NO_PROXY_DOMAINS': 'github.com,raw.githubusercontent.com',
            'PREBUFFER_ENABLED': True,
            'PREBUFFER_MAX_SEGMENTS': 3,
            'PREBUFFER_MAX_SIZE_MB': 50,
            'PREBUFFER_CLEANUP_INTERVAL': 300,
            'PREBUFFER_MAX_MEMORY_PERCENT': 30.0,
            'PREBUFFER_EMERGENCY_THRESHOLD': 90.0,
        }
        self._config_cache = None  # Cache in memoria per HuggingFace
        self._is_huggingface = self._detect_huggingface_environment()
        self._use_global_sync = self._should_use_global_sync()
        self._last_backup_time = 0
        self._backup_interval = 300  # Backup ogni 5 minuti
        self._last_sync_time = 0
        self._sync_interval = 60  # Sincronizzazione ogni minuto
        
        # Ripristina configurazione dal backup se siamo su HuggingFace
        if self._is_huggingface:
            self._restore_from_backup()
        
        # Sincronizza con la configurazione globale se necessario
        if self._use_global_sync:
            self._sync_from_global_config()
        
    def _detect_huggingface_environment(self):
        """Rileva se siamo in un ambiente HuggingFace"""
        return (
            os.environ.get('SPACE_ID') is not None or
            os.environ.get('HF_HUB_URL') is not None or
            os.environ.get('HUGGING_FACE_HUB_TOKEN') is not None or
            '/tmp' in os.getcwd() or
            'huggingface' in os.getcwd().lower()
        )
    
    def _should_use_global_sync(self):
        """Determina se usare la sincronizzazione globale (HuggingFace, Docker, Render o Gunicorn con workers multipli)"""
        # Su HuggingFace sempre attiva
        if self._is_huggingface:
            return True
        
        # Controlla se siamo in un ambiente Docker
        if self._is_docker_environment():
            return True
        
        # Controlla se siamo in un ambiente cloud (Render, Railway, Heroku, etc.)
        if self._is_cloud_environment():
            return True
        
        # Controlla se stiamo usando Gunicorn con workers multipli
        # Gunicorn imposta la variabile d'ambiente GUNICORN_CMD_ARGS
        if os.environ.get('GUNICORN_CMD_ARGS'):
            return True
        
        # Controlla se siamo in un processo worker di Gunicorn
        if os.environ.get('GUNICORN_WORKER_ID'):
            return True
        
        # Controlla se il processo padre è Gunicorn
        try:
            import psutil
            current_process = psutil.Process()
            parent = current_process.parent()
            if parent and 'gunicorn' in parent.name().lower():
                return True
        except:
            pass
        
        return False
    
    def _is_cloud_environment(self):
        """Rileva se siamo in un ambiente cloud (Render, Railway, Heroku, etc.)"""
        # Render
        if os.environ.get('RENDER'):
            return True
        
        # Railway
        if os.environ.get('RAILWAY_ENVIRONMENT'):
            return True
        
        # Heroku
        if os.environ.get('DYNO'):
            return True
        
        # Vercel
        if os.environ.get('VERCEL'):
            return True
        
        # Netlify
        if os.environ.get('NETLIFY'):
            return True
        
        # Fly.io
        if os.environ.get('FLY_APP_NAME'):
            return True
        
        # Controlla se siamo in un ambiente con variabili d'ambiente tipiche dei cloud
        cloud_indicators = [
            'PORT',  # Molti cloud usano questa variabile
            'DATABASE_URL',  # Database esterni
            'REDIS_URL',  # Cache esterni
            'WEB_CONCURRENCY',  # Workers multipli
            'GUNICORN_CMD_ARGS'  # Gunicorn configurato
        ]
        
        cloud_vars_found = sum(1 for var in cloud_indicators if os.environ.get(var))
        if cloud_vars_found >= 2:  # Se troviamo almeno 2 indicatori cloud
            return True
        
        return False
    
    def _is_docker_environment(self):
        """Rileva se siamo in un ambiente Docker"""
        # Controlla se il file /proc/1/cgroup contiene 'docker'
        try:
            with open('/proc/1/cgroup', 'r') as f:
                content = f.read()
                if 'docker' in content.lower():
                    return True
        except:
            pass
        
        # Controlla se esiste il file /.dockerenv
        if os.path.exists('/.dockerenv'):
            return True
        
        # Controlla variabili d'ambiente Docker
        if os.environ.get('DOCKER_CONTAINER'):
            return True
        
        # Controlla se il nome del container è presente
        try:
            with open('/proc/self/cgroup', 'r') as f:
                content = f.read()
                if 'docker' in content.lower():
                    return True
        except:
            pass
        
        return False
    
    def _acquire_global_lock(self, timeout=10):
        """Acquisisce il lock globale per la sincronizzazione"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Prova a creare il lock file
                with open(self.global_lock_file, 'w') as f:
                    f.write(f"{os.getpid()}:{time.time()}")
                return True
            except (IOError, OSError):
                # Se il lock esiste, controlla se è ancora valido (più di 30 secondi)
                try:
                    if os.path.exists(self.global_lock_file):
                        lock_age = time.time() - os.path.getmtime(self.global_lock_file)
                        if lock_age > 30:  # Lock scaduto
                            os.remove(self.global_lock_file)
                            continue
                except:
                    pass
                time.sleep(0.1)
        return False
    
    def _release_global_lock(self):
        """Rilascia il lock globale"""
        try:
            if os.path.exists(self.global_lock_file):
                os.remove(self.global_lock_file)
        except:
            pass
    
    def _sync_from_global_config(self):
        """Sincronizza la configurazione dal file globale"""
        try:
            if os.path.exists(self.global_config_file):
                with open(self.global_config_file, 'r') as f:
                    global_config = json.loads(f.read())
                    self._config_cache = global_config
                    app.logger.info(f"Configurazione sincronizzata dal file globale: {self.global_config_file}")
                    return True
        except Exception as e:
            app.logger.warning(f"Errore nella sincronizzazione dal file globale: {e}")
        return False
    
    def _save_to_global_config(self, config):
        """Salva la configurazione nel file globale per tutti i workers"""
        try:
            if self._acquire_global_lock():
                try:
                    with open(self.global_config_file, 'w') as f:
                        json.dump(config, f, indent=4)
                    self._last_sync_time = time.time()
                    app.logger.debug(f"Configurazione salvata nel file globale: {self.global_config_file}")
                    return True
                finally:
                    self._release_global_lock()
        except Exception as e:
            app.logger.warning(f"Errore nel salvataggio nel file globale: {e}")
        return False
    
    def _restore_from_backup(self):
        """Ripristina la configurazione dal file di backup su HuggingFace"""
        try:
            if os.path.exists(self.backup_file):
                with open(self.backup_file, 'r') as f:
                    backup_config = json.loads(f.read())
                    self._config_cache = backup_config
                    app.logger.info(f"Configurazione ripristinata dal backup: {self.backup_file}")
                    return True
        except Exception as e:
            app.logger.warning(f"Errore nel ripristino del backup: {e}")
        return False
    
    def _save_backup(self, config):
        """Salva un backup della configurazione per HuggingFace"""
        try:
            with open(self.backup_file, 'w') as f:
                json.dump(config, f, indent=4)
            self._last_backup_time = time.time()
            app.logger.debug(f"Backup configurazione salvato: {self.backup_file}")
            return True
        except Exception as e:
            app.logger.warning(f"Errore nel salvataggio del backup: {e}")
            return False
    
    def _get_writable_config_path(self):
        """Trova una directory scrivibile per il file di configurazione"""
        possible_paths = [
            'proxy_config.json',  # Directory corrente
            '/tmp/proxy_config.json',  # Directory temporanea
            '/tmp/tvproxy_config.json',  # Directory temporanea con nome specifico
            os.path.join(os.getcwd(), 'proxy_config.json'),  # Directory corrente assoluta
        ]
        
        # Prova a scrivere un file di test in ogni directory
        for path in possible_paths:
            try:
                # Prova a scrivere un file di test
                test_content = '{"test": true}'
                with open(path, 'w') as f:
                    f.write(test_content)
                
                # Se la scrittura ha successo, rimuovi il file di test e usa questo path
                os.remove(path)
                app.logger.info(f"Directory scrivibile trovata per configurazione: {path}")
                return path
                
            except (IOError, OSError, PermissionError):
                continue
        
        # Se nessuna directory è scrivibile, usa la directory corrente
        app.logger.warning("Nessuna directory scrivibile trovata, userò configurazione in memoria")
        return 'proxy_config.json'  # Fallback
        
    def load_config(self):
        """Carica la configurazione combinando proxy da file, memoria e variabili d'ambiente"""
        # Inizia con i valori di default
        config = self.default_config.copy()
        
        # Se abbiamo una cache in memoria (HuggingFace), usala
        if self._config_cache is not None:
            app.logger.info("Caricamento configurazione dalla cache in memoria")
            config.update(self._config_cache)
        
        # Carica dal file se esiste e non abbiamo cache in memoria
        elif os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        app.logger.warning(f"File di configurazione vuoto: {self.config_file}")
                        # Ricrea il file con configurazione di default
                        self.save_config(self.default_config)
                        app.logger.info(f"File di configurazione ricreato con valori di default")
                    else:
                        file_config = json.loads(content)
                        config.update(file_config)
                        app.logger.info(f"Configurazione caricata dal file: {self.config_file}")
            except json.JSONDecodeError as e:
                app.logger.error(f"Errore JSON nel file di configurazione: {e}")
                app.logger.info("Ricreo il file di configurazione con valori di default")
                # Backup del file corrotto
                backup_file = f"{self.config_file}.backup.{int(time.time())}"
                try:
                    import shutil
                    shutil.copy2(self.config_file, backup_file)
                    app.logger.info(f"Backup del file corrotto salvato come: {backup_file}")
                except Exception as backup_error:
                    app.logger.error(f"Errore nel backup del file corrotto: {backup_error}")
                
                # Ricrea il file con configurazione di default
                self.save_config(self.default_config)
            except Exception as e:
                app.logger.error(f"Errore generico nel caricamento della configurazione: {e}")
                app.logger.info("Uso configurazione di default")
        
        # Gestione proxy unificati
        proxy_keys = ['PROXY', 'DADDY_PROXY']
        
        for key in config.keys():
            if key not in proxy_keys:
                env_value = os.environ.get(key)
                if env_value is not None:
                    if key == 'CACHE_ENABLED':
                        config[key] = env_value.lower() in ('true', '1', 'yes')
                        
        for key in proxy_keys:
            env_value = os.environ.get(key)
            if env_value and env_value.strip():
                file_value = config.get(key, '')
                
                # Combina i proxy: prima quelli del file, poi quelli delle env vars
                combined_proxies = []
                
                # Aggiungi proxy dal file
                if file_value and file_value.strip():
                    file_proxies = [p.strip() for p in file_value.split(',') if p.strip()]
                    combined_proxies.extend(file_proxies)
                
                # Aggiungi proxy dalle variabili d'ambiente
                env_proxies = [p.strip() for p in env_value.split(',') if p.strip()]
                combined_proxies.extend(env_proxies)
                
                # Rimuovi duplicati mantenendo l'ordine
                unique_proxies = []
                for proxy in combined_proxies:
                    if proxy not in unique_proxies:
                        unique_proxies.append(proxy)
                
                # Aggiorna la configurazione con i proxy combinati
                config[key] = ','.join(unique_proxies)
                
                app.logger.info(f"Proxy combinati per {key}: {len(unique_proxies)} totali")
        
        # Per le altre variabili, mantieni la priorità alle env vars SOLO se non sono già state caricate
        for key in config.keys():
            if key not in proxy_keys:  # Salta i proxy che abbiamo già gestito
                env_value = os.environ.get(key)
                if env_value is not None:
                    # Controlla se il valore è già stato caricato da file/cache (non è il default)
                    current_value = config[key]
                    default_value = self.default_config.get(key)
                    
                    # Sovrascrivi solo se il valore corrente è uguale al default (non è stato salvato)
                    if current_value == default_value:
                        # Converti il tipo appropriato
                        if key in ['VERIFY_SSL', 'CACHE_ENABLED', 'PREBUFFER_ENABLED']:
                            config[key] = env_value.lower() in ('true', '1', 'yes')
                        elif key in ['REQUEST_TIMEOUT', 'KEEP_ALIVE_TIMEOUT', 'MAX_KEEP_ALIVE_REQUESTS', 
                                    'POOL_CONNECTIONS', 'POOL_MAXSIZE', 'CACHE_TTL_M3U8', 'CACHE_TTL_TS', 
                                    'CACHE_TTL_KEY', 'CACHE_MAXSIZE_M3U8', 'CACHE_MAXSIZE_TS', 'CACHE_MAXSIZE_KEY',
                                    'PREBUFFER_MAX_SEGMENTS', 'PREBUFFER_MAX_SIZE_MB', 'PREBUFFER_CLEANUP_INTERVAL']:
                            try:
                                config[key] = int(env_value)
                            except ValueError:
                                app.logger.warning(f"Valore non valido per {key}: {env_value}")
                        elif key in ['PREBUFFER_MAX_MEMORY_PERCENT', 'PREBUFFER_EMERGENCY_THRESHOLD']:
                            try:
                                config[key] = float(env_value)
                            except ValueError:
                                app.logger.warning(f"Valore non valido per {key}: {env_value}")
                        else:
                            config[key] = env_value
                        app.logger.debug(f"Variabile d'ambiente {key} sovrascrive default: {env_value}")
                    else:
                        app.logger.debug(f"Valore salvato per {key} ({current_value}) ha priorità su env var ({env_value})")
        
        return config
    
    def save_config(self, config):
        """Salva la configurazione nel file JSON o in memoria per HuggingFace"""
        try:
            # Se usiamo sincronizzazione globale (HuggingFace o Gunicorn con workers)
            if self._use_global_sync:
                self._config_cache = config.copy()
                # Salva anche un backup su file per persistenza (solo HuggingFace)
                if self._is_huggingface:
                    self._save_backup(config)
                # Sincronizza con tutti i workers tramite file globale
                self._save_to_global_config(config)
                env_name = "HuggingFace" if self._is_huggingface else "Gunicorn con workers multipli"
                app.logger.info(f"Configurazione salvata in memoria e file globale ({env_name})")
                return True
            
            # Prova a salvare nel file (ambiente standard)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            app.logger.info(f"Configurazione salvata nel file: {self.config_file}")
            return True
            
        except (IOError, OSError, PermissionError) as e:
            # Se non riusciamo a scrivere il file, usa la cache in memoria
            app.logger.warning(f"Impossibile scrivere il file di configurazione: {e}")
            app.logger.info("Configurazione salvata in memoria come fallback")
            self._config_cache = config.copy()
            # Prova comunque a salvare il backup e la sincronizzazione globale
            if self._use_global_sync:
                if self._is_huggingface:
                    self._save_backup(config)
                self._save_to_global_config(config)
            return True
            
        except Exception as e:
            app.logger.error(f"Errore nel salvataggio della configurazione: {e}")
            return False
    
    def apply_config_to_app(self, config):
        """Applica la configurazione all'app Flask"""
        proxy_keys = ['PROXY', 'DADDY_PROXY']
        
        for key, value in config.items():
            if hasattr(app, 'config'):
                app.config[key] = value
            # Non impostare le variabili d'ambiente per i proxy per evitare conflitti
            if key not in proxy_keys:
                os.environ[key] = str(value)
        return True
    
    def get_config_status(self):
        """Restituisce informazioni sullo stato della configurazione"""
        backup_exists = os.path.exists(self.backup_file) if self._is_huggingface else False
        backup_age = 0
        if backup_exists:
            backup_age = time.time() - os.path.getmtime(self.backup_file)
        
        # Informazioni sulla sincronizzazione globale
        global_exists = os.path.exists(self.global_config_file) if self._is_huggingface else False
        global_age = 0
        if global_exists:
            global_age = time.time() - os.path.getmtime(self.global_config_file)
        
        return {
            'is_huggingface': self._is_huggingface,
            'is_docker': self._is_docker_environment(),
            'is_cloud': self._is_cloud_environment(),
            'use_global_sync': self._use_global_sync,
            'config_file': self.config_file,
            'backup_file': self.backup_file,
            'global_config_file': self.global_config_file,
            'has_memory_cache': self._config_cache is not None,
            'file_exists': os.path.exists(self.config_file),
            'file_writable': self._test_file_writable(),
            'backup_exists': backup_exists,
            'backup_age_seconds': backup_age,
            'backup_age_human': f"{int(backup_age // 3600)}h {int((backup_age % 3600) // 60)}m" if backup_age > 0 else "N/A",
            'global_exists': global_exists,
            'global_age_seconds': global_age,
            'global_age_human': f"{int(global_age // 3600)}h {int((global_age % 3600) // 60)}m" if global_age > 0 else "N/A",
            'current_config_source': 'memory' if self._config_cache is not None else 'file' if os.path.exists(self.config_file) else 'default'
        }
    
    def _test_file_writable(self):
        """Testa se il file di configurazione è scrivibile"""
        try:
            with open(self.config_file, 'a') as f:
                pass
            return True
        except (IOError, OSError, PermissionError):
            return False

config_manager = ConfigManager()

# --- Sistema di Pre-Buffering per Evitare Buffering ---
class PreBufferManager:
    def __init__(self):
        self.pre_buffer = {}  # {stream_id: {segment_url: content}}
        self.pre_buffer_lock = Lock()
        self.pre_buffer_threads = {}  # {stream_id: thread}
        self.last_cleanup_time = time.time()
        self.update_config()
    
    def update_config(self):
        """Aggiorna la configurazione dal config manager"""
        try:
            config = config_manager.load_config()
            
            # Assicurati che tutti i valori numerici siano convertiti correttamente
            max_segments = config.get('PREBUFFER_MAX_SEGMENTS', 3)
            if isinstance(max_segments, str):
                max_segments = int(max_segments)
            
            max_size_mb = config.get('PREBUFFER_MAX_SIZE_MB', 50)
            if isinstance(max_size_mb, str):
                max_size_mb = int(max_size_mb)
            
            cleanup_interval = config.get('PREBUFFER_CLEANUP_INTERVAL', 300)
            if isinstance(cleanup_interval, str):
                cleanup_interval = int(cleanup_interval)
            
            max_memory_percent = config.get('PREBUFFER_MAX_MEMORY_PERCENT', 30)
            if isinstance(max_memory_percent, str):
                max_memory_percent = float(max_memory_percent)
            
            emergency_threshold = config.get('PREBUFFER_EMERGENCY_THRESHOLD', 90)
            if isinstance(emergency_threshold, str):
                emergency_threshold = float(emergency_threshold)
            
            self.pre_buffer_config = {
                'enabled': config.get('PREBUFFER_ENABLED', True),
                'max_segments': max_segments,
                'max_buffer_size': max_size_mb * 1024 * 1024,  # Converti in bytes
                'cleanup_interval': cleanup_interval,
                'max_memory_percent': max_memory_percent,  # Max RAM percent
                'emergency_cleanup_threshold': emergency_threshold  # Cleanup se RAM > threshold%
            }
            app.logger.info(f"Configurazione pre-buffer aggiornata: {self.pre_buffer_config}")
        except Exception as e:
            app.logger.error(f"Errore nell'aggiornamento configurazione pre-buffer: {e}")
            # Configurazione di fallback
            self.pre_buffer_config = {
                'enabled': True,
                'max_segments': 3,
                'max_buffer_size': 50 * 1024 * 1024,
                'cleanup_interval': 300,
                'max_memory_percent': 30.0,
                'emergency_cleanup_threshold': 90.0
            }
    
    def check_memory_usage(self):
        """Controlla l'uso di memoria e attiva cleanup se necessario"""
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Calcola la dimensione totale del buffer
            with self.pre_buffer_lock:
                total_buffer_size = sum(
                    sum(len(content) for content in segments.values())
                    for segments in self.pre_buffer.values()
                )
                buffer_memory_percent = (total_buffer_size / memory.total) * 100
            
            app.logger.info(f"Memoria sistema: {memory_percent:.1f}%, Buffer: {buffer_memory_percent:.1f}%")
            
            # Cleanup di emergenza se la RAM supera la soglia
            emergency_threshold = self.pre_buffer_config['emergency_cleanup_threshold']
            app.logger.debug(f"Controllo memoria: {memory_percent:.1f}% vs soglia {emergency_threshold}")
            if memory_percent > emergency_threshold:
                app.logger.warning(f"RAM critica ({memory_percent:.1f}%), pulizia di emergenza del buffer")
                self.emergency_cleanup()
                return False
            
            # Cleanup se il buffer usa troppa memoria
            max_memory_percent = self.pre_buffer_config['max_memory_percent']
            app.logger.debug(f"Controllo buffer: {buffer_memory_percent:.1f}% vs limite {max_memory_percent}")
            if buffer_memory_percent > max_memory_percent:
                app.logger.warning(f"Buffer troppo grande ({buffer_memory_percent:.1f}%), pulizia automatica")
                self.cleanup_oldest_streams()
                return False
            
            return True
            
        except Exception as e:
            app.logger.error(f"Errore nel controllo memoria: {e}")
            return True
    
    def emergency_cleanup(self):
        """Pulizia di emergenza - rimuove tutti i buffer"""
        with self.pre_buffer_lock:
            streams_cleared = len(self.pre_buffer)
            total_size = sum(
                sum(len(content) for content in segments.values())
                for segments in self.pre_buffer.values()
            )
            self.pre_buffer.clear()
            self.pre_buffer_threads.clear()
        
        app.logger.warning(f"Pulizia di emergenza completata: {streams_cleared} stream, {total_size / (1024*1024):.1f}MB liberati")
    
    def cleanup_oldest_streams(self):
        """Rimuove gli stream più vecchi per liberare memoria"""
        with self.pre_buffer_lock:
            if len(self.pre_buffer) <= 1:
                return
            
            # Calcola la dimensione di ogni stream
            stream_sizes = {}
            for stream_id, segments in self.pre_buffer.items():
                stream_size = sum(len(content) for content in segments.values())
                stream_sizes[stream_id] = stream_size
            
            # Rimuovi gli stream più grandi fino a liberare abbastanza memoria
            target_reduction = self.pre_buffer_config['max_buffer_size'] * 0.5  # Riduci del 50%
            current_total = sum(stream_sizes.values())
            
            if current_total <= target_reduction:
                return
            
            # Ordina per dimensione (più grandi prima)
            sorted_streams = sorted(stream_sizes.items(), key=lambda x: x[1], reverse=True)
            
            freed_memory = 0
            streams_to_remove = []
            
            for stream_id, size in sorted_streams:
                if freed_memory >= target_reduction:
                    break
                streams_to_remove.append(stream_id)
                freed_memory += size
            
            # Rimuovi gli stream selezionati
            for stream_id in streams_to_remove:
                if stream_id in self.pre_buffer:
                    del self.pre_buffer[stream_id]
                if stream_id in self.pre_buffer_threads:
                    del self.pre_buffer_threads[stream_id]
            
            app.logger.info(f"Pulizia automatica: {len(streams_to_remove)} stream rimossi, {freed_memory / (1024*1024):.1f}MB liberati")
    
    def get_stream_id_from_url(self, url):
        """Estrae un ID stream univoco dall'URL"""
        # Usa l'hash dell'URL come stream ID
        return hashlib.md5(url.encode()).hexdigest()[:12]
    
    def pre_buffer_segments(self, m3u8_content, base_url, headers, stream_id):
        """Pre-scarica i segmenti successivi in background"""
        # Controlla se il pre-buffering è abilitato
        if not self.pre_buffer_config.get('enabled', True):
            app.logger.info(f"Pre-buffering disabilitato per stream {stream_id}")
            return
        
        # Controlla l'uso di memoria prima di iniziare
        if not self.check_memory_usage():
            app.logger.warning(f"Memoria insufficiente, pre-buffering saltato per stream {stream_id}")
            return
        
        try:
            # Trova i segmenti nel M3U8
            segment_urls = []
            for line in m3u8_content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    segment_url = urljoin(base_url, line)
                    segment_urls.append(segment_url)
            
            if not segment_urls:
                return
            
            # Pre-scarica i primi N segmenti
            max_segments = self.pre_buffer_config['max_segments']
            app.logger.info(f"Pre-buffering per stream {stream_id}: {len(segment_urls)} segmenti disponibili, max_segments={max_segments}")
            segments_to_buffer = segment_urls[:max_segments]
            
            def buffer_worker():
                try:
                    current_buffer_size = 0
                    
                    for segment_url in segments_to_buffer:
                        # Controlla memoria prima di ogni segmento
                        if not self.check_memory_usage():
                            app.logger.warning(f"Memoria insufficiente durante pre-buffering, interrotto per stream {stream_id}")
                            break
                        
                        # Controlla se il segmento è già nel buffer
                        with self.pre_buffer_lock:
                            if stream_id in self.pre_buffer and segment_url in self.pre_buffer[stream_id]:
                                continue
                        
                        try:
                            # Scarica il segmento
                            # Note: These functions are defined later in the file
                            # They will be available when the class is actually used
                            proxy_config = globals().get('get_proxy_for_url', lambda x, y=None: None)(segment_url)
                            proxy_key = proxy_config['http'] if proxy_config else None
                            
                            response = globals().get('make_persistent_request', lambda *args, **kwargs: None)(
                                segment_url,
                                headers=headers,
                                timeout=globals().get('get_dynamic_timeout', lambda x, y=30: y)(segment_url),
                                proxy_url=proxy_key,
                                allow_redirects=True
                            )
                            response.raise_for_status()
                            
                            segment_content = response.content
                            segment_size = len(segment_content)
                            
                            # Controlla se il buffer non supera il limite
                            if current_buffer_size + segment_size > self.pre_buffer_config['max_buffer_size']:
                                app.logger.warning(f"Buffer pieno per stream {stream_id}, salto segmento {segment_url}")
                                break
                            
                            # Aggiungi al buffer
                            with self.pre_buffer_lock:
                                if stream_id not in self.pre_buffer:
                                    self.pre_buffer[stream_id] = {}
                                self.pre_buffer[stream_id][segment_url] = segment_content
                                current_buffer_size += segment_size
                            
                            app.logger.info(f"Segmento pre-buffato: {segment_url} ({segment_size} bytes) per stream {stream_id}")
                            
                        except Exception as e:
                            app.logger.error(f"Errore nel pre-buffering del segmento {segment_url}: {e}")
                            continue
                    
                    app.logger.info(f"Pre-buffering completato per stream {stream_id}: {len(segments_to_buffer)} segmenti")
                    
                except Exception as e:
                    app.logger.error(f"Errore nel worker di pre-buffering per stream {stream_id}: {e}")
                finally:
                    # Rimuovi il thread dalla lista
                    with self.pre_buffer_lock:
                        if stream_id in self.pre_buffer_threads:
                            del self.pre_buffer_threads[stream_id]
            
            # Avvia il thread di pre-buffering
            buffer_thread = Thread(target=buffer_worker, daemon=True)
            buffer_thread.start()
            
            with self.pre_buffer_lock:
                self.pre_buffer_threads[stream_id] = buffer_thread
            
        except Exception as e:
            app.logger.error(f"Errore nell'avvio del pre-buffering per stream {stream_id}: {e}")
    
    def get_buffered_segment(self, segment_url, stream_id):
        """Recupera un segmento dal buffer se disponibile"""
        with self.pre_buffer_lock:
            if stream_id in self.pre_buffer and segment_url in self.pre_buffer[stream_id]:
                content = self.pre_buffer[stream_id][segment_url]
                # Rimuovi dal buffer dopo l'uso
                del self.pre_buffer[stream_id][segment_url]
                app.logger.info(f"Segmento servito dal buffer: {segment_url} per stream {stream_id}")
                return content
        return None
    
    def cleanup_old_buffers(self):
        """Pulisce i buffer vecchi"""
        while True:
            try:
                time.sleep(self.pre_buffer_config['cleanup_interval'])
                
                # Controlla memoria e pulisci se necessario
                self.check_memory_usage()
                
                with self.pre_buffer_lock:
                    current_time = time.time()
                    streams_to_remove = []
                    
                    for stream_id, segments in self.pre_buffer.items():
                        # Rimuovi stream senza thread attivo e con buffer vecchio
                        if stream_id not in self.pre_buffer_threads:
                            streams_to_remove.append(stream_id)
                    
                    for stream_id in streams_to_remove:
                        del self.pre_buffer[stream_id]
                        app.logger.info(f"Buffer pulito per stream {stream_id}")
                
            except Exception as e:
                app.logger.error(f"Errore nella pulizia del buffer: {e}")

# Istanza globale del pre-buffer manager
pre_buffer_manager = PreBufferManager()

# Avvia il thread di pulizia del buffer
cleanup_thread = Thread(target=pre_buffer_manager.cleanup_old_buffers, daemon=True)
cleanup_thread.start()

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
system_stats = {}

# Inizializza cache globali (verranno sovrascritte da setup_all_caches)
M3U8_CACHE = {}
TS_CACHE = {}
KEY_CACHE = {}

# Pool globale di sessioni per connessioni persistenti
SESSION_POOL = {}
SESSION_LOCK = Lock()

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

# Thread per backup automatico della configurazione su HuggingFace
def config_backup_thread():
    """Thread per salvare automaticamente la configurazione su HuggingFace"""
    while True:
        try:
            if config_manager._is_huggingface and config_manager._config_cache:
                current_time = time.time()
                if current_time - config_manager._last_backup_time > config_manager._backup_interval:
                    config_manager._save_backup(config_manager._config_cache)
            time.sleep(60)  # Controlla ogni minuto
        except Exception as e:
            app.logger.warning(f"Errore nel thread di backup configurazione: {e}")
            time.sleep(60)

# Thread per sincronizzazione automatica tra workers
def config_sync_thread():
    """Thread per sincronizzare automaticamente la configurazione tra workers"""
    while True:
        try:
            if config_manager._use_global_sync:
                current_time = time.time()
                if current_time - config_manager._last_sync_time > config_manager._sync_interval:
                    # Sincronizza dal file globale
                    config_manager._sync_from_global_config()
            time.sleep(30)  # Controlla ogni 30 secondi
        except Exception as e:
            app.logger.warning(f"Errore nel thread di sincronizzazione configurazione: {e}")
            time.sleep(30)

# Avvia thread di backup solo per HuggingFace
if config_manager._is_huggingface:
    backup_thread = Thread(target=config_backup_thread, daemon=True)
    backup_thread.start()
    app.logger.info("Thread di backup configurazione avviato per HuggingFace")

# Avvia thread di sincronizzazione per tutti gli ambienti con workers multipli
if config_manager._use_global_sync:
    sync_thread = Thread(target=config_sync_thread, daemon=True)
    sync_thread.start()
    if config_manager._is_huggingface:
        env_name = "HuggingFace"
    elif config_manager._is_docker_environment():
        env_name = "Docker"
    elif config_manager._is_cloud_environment():
        env_name = "Cloud (Render/Railway/Heroku)"
    else:
        env_name = "Gunicorn con workers multipli"
    app.logger.info(f"Thread di sincronizzazione configurazione avviato per {env_name}")

# --- Configurazione Proxy ---
PROXY_LIST = []

def setup_proxies():
    """Carica la lista di proxy unificati dalla configurazione salvata e dalle variabili d'ambiente."""
    global PROXY_LIST, DADDY_PROXY_LIST
    proxies_found = []
    daddy_proxies_found = []
    ipv4_count = 0
    ipv6_count = 0
    hostname_count = 0
    daddy_ipv4_count = 0
    daddy_ipv6_count = 0
    daddy_hostname_count = 0

    # Carica configurazione salvata
    config = config_manager.load_config()
    
    # Configurazione proxy unificati - prima dalle env vars, poi dalla config salvata
    proxy_list_str = os.environ.get('PROXY') or config.get('PROXY', '')
    
    if proxy_list_str:
        raw_proxy_list = [p.strip() for p in proxy_list_str.split(',') if p.strip()]
        if raw_proxy_list:
            app.logger.info(f"Trovati {len(raw_proxy_list)} proxy unificati. Riconoscimento automatico del tipo in corso...")
            for proxy in raw_proxy_list:
                # Riconosci automaticamente il tipo di proxy
                proxy_type = detect_proxy_type(proxy)
                
                # Normalizza l'URL del proxy
                final_proxy_url = proxy
                if proxy_type == 'socks5':
                    if proxy.startswith('socks5://'):
                        final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                        app.logger.info(f"Proxy SOCKS5 convertito per garantire la risoluzione DNS remota: {final_proxy_url}")
                    elif not proxy.startswith('socks5h://'):
                        app.logger.warning(f"ATTENZIONE: L'URL del proxy SOCKS5 non è in formato valido: {proxy}")
                        app.logger.info("Formati supportati: socks5://user:pass@host:port o socks5h://user:pass@host:port")
                elif proxy_type == 'http' and not proxy.startswith('http://'):
                    final_proxy_url = 'http://' + proxy
                    app.logger.info(f"Proxy HTTP normalizzato: {final_proxy_url}")
                elif proxy_type == 'https' and not proxy.startswith('https://'):
                    final_proxy_url = 'https://' + proxy
                    app.logger.info(f"Proxy HTTPS normalizzato: {final_proxy_url}")
                
                # Analizza il tipo di IP
                ip_version = get_proxy_ip_version(final_proxy_url)
                if ip_version == "IPv6":
                    ipv6_count += 1
                    app.logger.info(f"Proxy IPv6 rilevato ({proxy_type}): {final_proxy_url}")
                elif ip_version == "IPv4":
                    ipv4_count += 1
                else:
                    hostname_count += 1
                
                proxies_found.append(final_proxy_url)
                app.logger.info(f"Proxy configurato ({proxy_type}): {final_proxy_url}")
            
            if any('socks5' in p for p in proxies_found):
                app.logger.info("Assicurati di aver installato la dipendenza per SOCKS: 'pip install PySocks'")

    # Configurazione proxy DaddyLive - prima dalle env vars, poi dalla config salvata
    daddy_proxy_list_str = os.environ.get('DADDY_PROXY') or config.get('DADDY_PROXY', '')
    if daddy_proxy_list_str:
        daddy_proxies = [p.strip() for p in daddy_proxy_list_str.split(',') if p.strip()]
        if daddy_proxies:
            app.logger.info(f"Trovati {len(daddy_proxies)} proxy DaddyLive. Verranno usati solo per DaddyLive.")
            for proxy in daddy_proxies:
                # Riconosci automaticamente il tipo di proxy
                proxy_type = detect_proxy_type(proxy)
                
                # Normalizza l'URL del proxy
                final_proxy_url = proxy
                if proxy_type == 'socks5' and proxy.startswith('socks5://'):
                    final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                    app.logger.info(f"Proxy DaddyLive SOCKS5 convertito per garantire la risoluzione DNS remota")
                elif proxy_type == 'socks5' and not proxy.startswith('socks5h://'):
                    app.logger.warning(f"ATTENZIONE: Il proxy DaddyLive SOCKS5 non è in formato valido: {proxy}")
                elif proxy_type == 'http' and not proxy.startswith('http://'):
                    final_proxy_url = 'http://' + proxy
                elif proxy_type == 'https' and not proxy.startswith('https://'):
                    final_proxy_url = 'https://' + proxy
                
                # Analizza il tipo di IP
                ip_version = get_proxy_ip_version(final_proxy_url)
                if ip_version == "IPv6":
                    daddy_ipv6_count += 1
                    app.logger.info(f"Proxy DaddyLive IPv6 rilevato: {final_proxy_url} ({proxy_type})")
                elif ip_version == "IPv4":
                    daddy_ipv4_count += 1
                else:
                    daddy_hostname_count += 1
                
                daddy_proxies_found.append(final_proxy_url)
                app.logger.info(f"Proxy DaddyLive configurato: {final_proxy_url} (tipo: {proxy_type})")

    PROXY_LIST = proxies_found
    DADDY_PROXY_LIST = daddy_proxies_found

    if PROXY_LIST:
        app.logger.info(f"Totale di {len(PROXY_LIST)} proxy normali configurati:")
        app.logger.info(f"  - IPv4: {ipv4_count}")
        app.logger.info(f"  - IPv6: {ipv6_count}")
        app.logger.info(f"  - Hostname: {hostname_count}")
        app.logger.info("Verranno usati a rotazione per ogni richiesta.")
    else:
        app.logger.info("Nessun proxy normale (SOCKS5, HTTP, HTTPS) configurato.")
    
    if DADDY_PROXY_LIST:
        app.logger.info(f"Totale di {len(DADDY_PROXY_LIST)} proxy DaddyLive configurati:")
        app.logger.info(f"  - IPv4: {daddy_ipv4_count}")
        app.logger.info(f"  - IPv6: {daddy_ipv6_count}")
        app.logger.info(f"  - Hostname: {daddy_hostname_count}")
        app.logger.info("Verranno usati solo per richieste DaddyLive.")
    else:
        app.logger.info("Nessun proxy DaddyLive configurato.")



def get_proxy_with_fallback(url, max_retries=3):
    """Ottiene un proxy con fallback automatico in caso di errore"""
    if not PROXY_LIST:
        return None
    
    # Prova diversi proxy in caso di errore
    for attempt in range(max_retries):
        try:
            proxy_config = get_proxy_for_url(url)
            if proxy_config:
                return proxy_config
        except Exception:
            continue
    
    return None

def create_robust_session():
    """Crea una sessione con configurazione robusta e keep-alive per connessioni persistenti."""
    session = requests.Session()
    
    # Ignora le variabili d'ambiente proxy per evitare conflitti
    session.trust_env = False
    
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

def make_persistent_request(url, headers=None, timeout=None, proxy_url=None, method='GET', **kwargs):
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
        if method.upper() == 'POST':
            response = session.post(
                url, 
                headers=request_headers, 
                timeout=timeout or REQUEST_TIMEOUT,
                verify=VERIFY_SSL,
                **kwargs
            )
        else:
            response = session.get(
                url, 
                headers=request_headers, 
                timeout=timeout or REQUEST_TIMEOUT,
                verify=VERIFY_SSL,
                **kwargs
            )
        return response
    except requests.exceptions.ProxyError as e:
        # Gestione specifica per errori proxy (incluso 429)
        error_str = str(e).lower()
        if ("429" in error_str or "too many requests" in error_str) and proxy_url:
            app.logger.warning(f"Proxy {proxy_url} ha restituito errore 429, aggiungendo alla blacklist")
            add_proxy_to_blacklist(proxy_url, "429")
        app.logger.error(f"Errore proxy nella richiesta persistente: {e}")
        # In caso di errore, rimuovi la sessione dal pool
        with SESSION_LOCK:
            if proxy_url in SESSION_POOL:
                del SESSION_POOL[proxy_url]
        raise
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
setup_all_caches()

# --- Dynamic DaddyLive URL Fetcher ---
DADDYLIVE_BASE_URL = None
LAST_FETCH_TIME = 0
FETCH_INTERVAL = 3600

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
    """
    Risolve URL con una logica selettiva: processa solo i link riconosciuti come
    DaddyLive, altrimenti li passa direttamente.
    """
    if not url:
        app.logger.error("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    current_headers = headers.copy() if headers else {}
    
    # 1. Estrazione degli header dall'URL (logica invariata)
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
    
    final_headers = {**current_headers, **extracted_headers}

    # --- NUOVA SEZIONE DI CONTROLLO ---
    # 2. Verifica se l'URL deve essere processato come DaddyLive.
    #    La risoluzione speciale si attiva solo se l'URL contiene "newkso.ru"
    #    o "/stream-", altrimenti viene passato direttamente.
    
    is_daddylive_link = (
        'newkso.ru' in clean_url.lower() or 
        '/stream-' in clean_url.lower() or
        # Aggiungiamo anche i pattern del vecchio estrattore per mantenere la compatibilità
        re.search(r'/premium(\d+)/mono\.m3u8$', clean_url) is not None
    )

    if not is_daddylive_link:
        # --- GESTIONE VAVOO ---
        # Controlla se è un link Vavoo e prova a risolverlo
        # Supporta sia /vavoo-iptv/play/ che /play/ 
        if 'vavoo.to' in clean_url.lower() and ('/vavoo-iptv/play/' in clean_url.lower() or '/play/' in clean_url.lower()):
            app.logger.info(f"🔍 Rilevato link Vavoo, tentativo di risoluzione: {clean_url}")
            
            try:
                resolved_vavoo = vavoo_resolver.resolve_vavoo_link(clean_url, verbose=True)
                if resolved_vavoo:
                    app.logger.info(f"✅ Vavoo risolto con successo: {resolved_vavoo}")
                    return {
                        "resolved_url": resolved_vavoo,
                        "headers": final_headers
                    }
                else:
                    app.logger.warning(f"❌ Impossibile risolvere il link Vavoo, passo l'originale: {clean_url}")
                    return {
                        "resolved_url": clean_url,
                        "headers": final_headers
                    }
            except Exception as e:
                app.logger.error(f"❌ Errore nella risoluzione Vavoo: {e}")
                return {
                    "resolved_url": clean_url,
                    "headers": final_headers
                }
        
        # Per tutti gli altri link non-DaddyLive
        app.logger.info(f"URL non riconosciuto come DaddyLive o Vavoo, verrà passato direttamente: {clean_url}")
        return {
            "resolved_url": clean_url,
            "headers": final_headers
        }
    # --- FINE DELLA NUOVA SEZIONE ---

    # 3. Se il controllo è superato, procede con la logica di risoluzione DaddyLive (invariata)
    app.logger.info(f"Tentativo di risoluzione URL (DaddyLive): {clean_url}")

    daddy_base_url = get_daddylive_base_url()
    daddy_origin = urlparse(daddy_base_url).scheme + "://" + urlparse(daddy_base_url).netloc

    daddylive_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': daddy_base_url,
        'Origin': daddy_origin
    }
    final_headers_for_resolving = {**final_headers, **daddylive_headers}

    try:
        app.logger.info("Ottengo URL base dinamico...")
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        
        # Crea una sessione che ignora le variabili d'ambiente per forzare connessione diretta
        session = requests.Session()
        session.trust_env = False  # Ignora HTTP_PROXY, HTTPS_PROXY environment variables
        
        main_url_req = session.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
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
        proxy_config = get_proxy_for_url(stream_url, original_url=clean_url)
        response = safe_http_request(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=proxy_config)
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
        proxy_config = get_proxy_for_url(url2, original_url=clean_url)
        response = safe_http_request(url2, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=proxy_config)
        response.raise_for_status()

        iframes = re.findall(r'iframe src="([^"]*)', response.text)
        if not iframes:
            app.logger.error("Nessun iframe trovato nella pagina Player 2")
            return {"resolved_url": clean_url, "headers": current_headers}

        iframe_url = iframes[0]
        app.logger.info(f"Passo 4: Trovato iframe: {iframe_url}")

        app.logger.info(f"Passo 5: Richiesta iframe: {iframe_url}")
        proxy_config = get_proxy_for_url(iframe_url, original_url=clean_url)
        response = safe_http_request(iframe_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=proxy_config)
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
        proxy_config = get_proxy_for_url(auth_url, original_url=clean_url)
        auth_response = safe_http_request(auth_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=proxy_config)
        auth_response.raise_for_status()

        host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        app.logger.info(f"Passo 7: Server lookup: {server_lookup_url}")

        proxy_config = get_proxy_for_url(server_lookup_url, original_url=clean_url)
        lookup_response = safe_http_request(server_lookup_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=proxy_config)
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
            "headers": {**final_headers, **final_headers_for_fetch}
        }

    except Exception as e:
        app.logger.error(f"Errore durante la risoluzione DaddyLive: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        # In caso di errore nella risoluzione, restituisce l'URL originale
        return {"resolved_url": clean_url, "headers": final_headers}

stats_thread = threading.Thread(target=broadcast_stats, daemon=True)
stats_thread.start()



@app.route('/admin/cache/toggle', methods=['POST'])
@login_required
def toggle_cache():
    config = config_manager.load_config()
    new_value = not config.get('CACHE_ENABLED', True)
    config['CACHE_ENABLED'] = new_value
    config_manager.save_config(config)
    config_manager.apply_config_to_app(config)
    setup_all_caches()
    return jsonify({"status": "success", "cache_enabled": new_value})

@app.route('/admin/debug/proxies')
@login_required
def debug_proxies():
    """Debug dei proxy unificati"""
    config = config_manager.load_config()
    
    proxy_info = {}
    for proxy_type in ['PROXY', 'DADDY_PROXY']:
        proxy_string = config.get(proxy_type, '')
        if proxy_string:
            proxies = [p.strip() for p in proxy_string.split(',') if p.strip()]
            proxy_info[proxy_type] = {
                'count': len(proxies),
                'proxies': proxies,
                'env_value': os.environ.get(proxy_type, 'NON_IMPOSTATA'),
                'combined': proxy_string,
                'detected_types': []
            }
            
            # Analizza i tipi di proxy rilevati
            for proxy in proxies:
                detected_type = detect_proxy_type(proxy)
                ip_version = get_proxy_ip_version(proxy)
                proxy_info[proxy_type]['detected_types'].append({
                    'proxy': proxy,
                    'type': detected_type,
                    'ip_version': ip_version
                })
        else:
            proxy_info[proxy_type] = {
                'count': 0,
                'proxies': [],
                'env_value': os.environ.get(proxy_type, 'NON_IMPOSTATA'),
                'combined': '',
                'detected_types': []
            }
    
    return jsonify(proxy_info)

@app.route('/admin/debug/env')
@login_required
def debug_env():
    """Debug delle variabili d'ambiente"""
    env_vars = {}
    config_keys = [
        'ADMIN_PASSWORD', 'SECRET_KEY', 'CACHE_TTL_M3U8', 'CACHE_MAXSIZE_M3U8',
        'CACHE_TTL_TS', 'CACHE_MAXSIZE_TS', 'CACHE_TTL_KEY', 'CACHE_MAXSIZE_KEY',
        'POOL_CONNECTIONS', 'POOL_MAXSIZE', 'MAX_KEEP_ALIVE_REQUESTS',
        'KEEP_ALIVE_TIMEOUT', 'REQUEST_TIMEOUT'
    ]
    
    for key in config_keys:
        env_vars[key] = {
            'env_value': os.environ.get(key, 'NON_IMPOSTATA'),
            'current_config': config_manager.load_config().get(key, 'NON_TROVATA')
        }
    
    # Informazioni sui proxy
    proxy_vars = ['PROXY', 'DADDY_PROXY']
    
    proxy_info = {
        'variables': {},
        'status': 'not_configured'
    }
    
    # Controlla le variabili proxy
    for proxy_var in proxy_vars:
        value = os.environ.get(proxy_var, 'NON_IMPOSTATA')
        proxy_info['variables'][proxy_var] = value
    
    # Determina lo stato
    has_proxy = any(v != 'NON_IMPOSTATA' for v in proxy_info['variables'].values())
    if has_proxy:
        proxy_info['status'] = 'configured'
    
    env_vars['proxy_info'] = proxy_info
    
    return jsonify(env_vars)

@app.route('/admin/debug/config-status')
@login_required
def debug_config_status():
    """Debug dello stato della configurazione"""
    config_status = config_manager.get_config_status()
    current_config = config_manager.load_config()
    
    # Confronta con i valori di default per identificare cosa è stato salvato
    default_config = config_manager.default_config
    saved_values = {}
    env_overrides = {}
    
    for key, value in current_config.items():
        if key in default_config:
            if value != default_config[key]:
                saved_values[key] = {
                    'current': value,
                    'default': default_config[key],
                    'source': 'saved'
                }
            else:
                # Controlla se c'è una variabile d'ambiente che sovrascrive
                env_value = os.environ.get(key)
                if env_value is not None:
                    env_overrides[key] = {
                        'current': value,
                        'env_value': env_value,
                        'source': 'environment'
                    }
    
    return jsonify({
        'config_status': config_status,
        'current_config_keys': list(current_config.keys()),
        'config_summary': {
            'total_settings': len(current_config),
            'proxy_configured': bool(current_config.get('PROXY')),
            'daddy_proxy_configured': bool(current_config.get('DADDY_PROXY')),
            'cache_enabled': current_config.get('CACHE_ENABLED', True),
            'prebuffer_enabled': current_config.get('PREBUFFER_ENABLED', True)
        },
        'saved_values': saved_values,
        'environment_overrides': env_overrides,
        'default_config': default_config
    })

@app.route('/admin/debug/test-import', methods=['POST'])
@login_required
def test_config_import():
    """Testa l'importazione di una configurazione di esempio"""
    try:
        # Crea una configurazione di test
        test_config = {
            'TEST_IMPORT': 'test_import_value',
            'TIMESTAMP': datetime.now().isoformat(),
            'PROXY': 'socks5://test:1080',
            'CACHE_ENABLED': True,
            'REQUEST_TIMEOUT': 30
        }
        
        # Prova a salvare
        save_result = config_manager.save_config(test_config)
        
        # Ricarica per verificare
        loaded_config = config_manager.load_config()
        test_imported = 'TEST_IMPORT' in loaded_config
        
        # Pulisci la configurazione di test
        current_config = config_manager.load_config()
        if 'TEST_IMPORT' in current_config:
            del current_config['TEST_IMPORT']
        if 'TIMESTAMP' in current_config:
            del current_config['TIMESTAMP']
        config_manager.save_config(current_config)
        
        return jsonify({
            'status': 'success',
            'save_result': save_result,
            'test_imported': test_imported,
            'config_status': config_manager.get_config_status(),
            'loaded_keys': list(loaded_config.keys()),
            'message': f'Test importazione: {"OK" if save_result and test_imported else "FALLITO"}'
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel test importazione: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel test: {str(e)}'
        }), 500

@app.route('/admin/debug/test-save', methods=['POST'])
@login_required
def test_config_save():
    """Testa il salvataggio della configurazione"""
    try:
        # Crea una configurazione di test
        test_config = {
            'TEST_SAVE': 'test_value',
            'TIMESTAMP': datetime.now().isoformat()
        }
        
        # Prova a salvare
        save_result = config_manager.save_config(test_config)
        
        # Ricarica per verificare
        loaded_config = config_manager.load_config()
        test_saved = 'TEST_SAVE' in loaded_config
        
        # Pulisci la configurazione di test
        current_config = config_manager.load_config()
        if 'TEST_SAVE' in current_config:
            del current_config['TEST_SAVE']
        if 'TIMESTAMP' in current_config:
            del current_config['TIMESTAMP']
        config_manager.save_config(current_config)
        
        return jsonify({
            'status': 'success',
            'save_result': save_result,
            'test_saved': test_saved,
            'config_status': config_manager.get_config_status(),
            'message': f'Test salvataggio: {"OK" if save_result and test_saved else "FALLITO"}'
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel test salvataggio: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel test: {str(e)}'
        }), 500

@app.route('/admin/proxy/formats')
@login_required
def proxy_formats():
    """Mostra i formati supportati per i proxy"""
    formats = {
        'supported_formats': {
            'socks5': [
                'socks5://user:pass@host:port',
                'socks5h://user:pass@host:port',
                'socks5://host:port',
                'socks5h://host:port'
            ],
            'http': [
                'http://user:pass@host:port',
                'http://host:port',
                'host:port'  # Auto-riconosciuto come HTTP
            ],
            'https': [
                'https://user:pass@host:port',
                'https://host:port'
            ]
        },
        'examples': {
            'single_proxy': 'PROXY=socks5://user:pass@proxy1.com:1080',
            'multiple_proxies': 'PROXY=socks5://user:pass@proxy1.com:1080,http://user:pass@proxy2.com:8080,https://user:pass@proxy3.com:8443',
            'mixed_types': 'PROXY=socks5://proxy1.com:1080,proxy2.com:8080,https://proxy3.com:8443'
        },
        'examples': {
            'single_proxy': 'PROXY=socks5://user:pass@proxy1.com:1080',
            'multiple_proxies': 'PROXY=socks5://user:pass@proxy1.com:1080,http://user:pass@proxy2.com:8080,https://user:pass@proxy3.com:8443',
            'mixed_types': 'PROXY=socks5://proxy1.com:1080,proxy2.com:8080,https://proxy3.com:8443'
        },
        'auto_detection': {
            'description': 'Il sistema riconosce automaticamente il tipo di proxy basandosi sul protocollo o sulla porta',
            'rules': [
                'socks5:// o socks5h:// → SOCKS5',
                'http:// → HTTP',
                'https:// → HTTPS',
                'porta 1080 senza protocollo → SOCKS5',
                'altre porte senza protocollo → HTTP'
            ]
        }
    }
    
    return jsonify(formats)







@app.route('/login', methods=['GET', 'POST'])
def login():
    """Pagina di login"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals() and client_tracker is not None:
            getattr(client_tracker, 'track_request', lambda *args, **kwargs: None)(request, '/login')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta login: {e}")
    
    if not check_ip_allowed():
        app.logger.warning(f"Tentativo di accesso da IP non autorizzato: {request.remote_addr}")
        return "Accesso negato: IP non autorizzato", 403
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_auth(username, password):
            session['logged_in'] = True
            session['username'] = username
            # Traccia la sessione se client_tracker è disponibile
            try:
                if 'client_tracker' in globals():
                    client_tracker.track_session(session.get('_id', str(id(session))), request)
            except Exception as e:
                app.logger.warning(f"Errore nel tracking sessione login: {e}")
            app.logger.info(f"Login riuscito per utente: {username}")
            return redirect(url_for('dashboard'))
        else:
            app.logger.warning(f"Tentativo di login fallito per utente: {username}")
            error = 'Credenziali non valide'
            return render_template('login.html', error=error)
    
    return render_template('login.html')
    
@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard avanzata con statistiche di sistema"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/dashboard')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta dashboard: {e}")
    
    stats = get_system_stats()
    daddy_base_url = get_daddylive_base_url()
    
    # Aggiungi informazioni pre-buffer alle statistiche
    stats['prebuffer_info'] = {
        'active_streams': stats.get('prebuffer_streams', 0),
        'buffered_segments': stats.get('prebuffer_segments', 0),
        'buffer_size_mb': stats.get('prebuffer_size_mb', 0),
        'active_threads': stats.get('prebuffer_threads', 0)
    }
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         daddy_base_url=daddy_base_url,
                         session_count=len(SESSION_POOL),
                         proxy_count=len(PROXY_LIST))

@app.route('/admin')
@login_required
def admin_panel():
    """Pannello di amministrazione"""
    return render_template('admin.html')

@app.route('/admin/config')
@login_required
def admin_config():
    """Pagina di gestione configurazioni"""
    config = config_manager.load_config()
    return render_template('config.html', config=config)

@app.route('/admin/config/current')
@login_required
def get_current_config():
    """Ottiene la configurazione corrente in tempo reale"""
    try:
        config = config_manager.load_config()
        config_status = config_manager.get_config_status()
        
        return jsonify({
            'status': 'success',
            'config': config,
            'config_status': config_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"Errore nel recupero configurazione corrente: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel recupero configurazione: {str(e)}'
        }), 500

@app.route('/admin/config/check-changes', methods=['POST'])
@login_required
def check_config_changes():
    """Verifica se la configurazione è cambiata rispetto a quella fornita"""
    try:
        current_config = config_manager.load_config()
        provided_config = request.get_json()
        
        changes = {}
        for key in current_config:
            if key in provided_config:
                if current_config[key] != provided_config[key]:
                    changes[key] = {
                        'current': current_config[key],
                        'provided': provided_config[key]
                    }
            else:
                # Chiave presente nella configurazione corrente ma non in quella fornita
                changes[key] = {
                    'current': current_config[key],
                    'provided': 'NON_PRESENTE'
                }
        
        # Controlla anche le chiavi presenti nella configurazione fornita ma non in quella corrente
        for key in provided_config:
            if key not in current_config:
                changes[key] = {
                    'current': 'NON_PRESENTE',
                    'provided': provided_config[key]
                }
        
        return jsonify({
            'status': 'success',
            'has_changes': len(changes) > 0,
            'changes': changes,
            'changes_count': len(changes),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel controllo cambiamenti configurazione: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel controllo cambiamenti: {str(e)}'
        }), 500
    
@app.route('/admin/logs')
@login_required
def admin_logs():
    """Pagina di visualizzazione log"""
    log_files = log_manager.get_log_files()
    return render_template('logs.html', log_files=log_files)
    
@app.route('/')
def index():
    """Pagina principale migliorata con informazioni Vavoo"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta index: {e}")
    
    stats = get_system_stats()
    base_url = get_daddylive_base_url()
    
    # Aggiungi informazioni pre-buffer alle statistiche
    stats['prebuffer_info'] = {
        'active_streams': stats.get('prebuffer_streams', 0),
        'buffered_segments': stats.get('prebuffer_segments', 0),
        'buffer_size_mb': stats.get('prebuffer_size_mb', 0),
        'active_threads': stats.get('prebuffer_threads', 0)
    }
    
    # Informazioni sulla funzionalità Vavoo
    vavoo_info = {
        "enabled": True,
        "supported_patterns": [
            "https://vavoo.to/vavoo-iptv/play/[ID]",
            "https://vavoo.to/play/[ID]"
        ],
        "test_url": "https://vavoo.to/vavoo-iptv/play/277580225585f503fbfc87",
        "endpoints": {
            "m3u_proxy": "/proxy/m3u?url=[VAVOO_URL]",
            "vavoo_direct": "/proxy/vavoo?url=[VAVOO_URL]"
        }
    }
    
    return render_template('index.html', 
                         stats=stats, 
                         base_url=base_url,
                         session_count=len(SESSION_POOL),
                         vavoo_info=vavoo_info)

@app.route('/logout')
def logout():
    """Logout"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/logout')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta logout: {e}")
    
    username = session.get('username', 'unknown')
    session_id = session.get('_id', str(id(session)))
    
    # Rimuovi la sessione dal tracker se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.remove_session(session_id)
    except Exception as e:
        app.logger.warning(f"Errore nella rimozione sessione logout: {e}")
    
    session.pop('logged_in', None)
    session.pop('username', None)
    app.logger.info(f"Logout per utente: {username}")
    return redirect(url_for('index'))

@app.route('/admin/config/save', methods=['POST'])
@login_required
def save_config():
    """Salva la configurazione"""
    try:
        new_config = request.get_json()

        if 'CACHE_ENABLED' in new_config:
            val = new_config['CACHE_ENABLED']
            if isinstance(val, str):
                new_config['CACHE_ENABLED'] = val.lower() in ('true', '1', 'yes')
            else:
                new_config['CACHE_ENABLED'] = bool(val)
        
        # Gestisci configurazioni pre-buffer
        if 'PREBUFFER_ENABLED' in new_config:
            val = new_config['PREBUFFER_ENABLED']
            if isinstance(val, str):
                new_config['PREBUFFER_ENABLED'] = val.lower() in ('true', '1', 'yes')
            else:
                new_config['PREBUFFER_ENABLED'] = bool(val)
        
        # Converti valori numerici per pre-buffer
        prebuffer_numeric_fields = [
            'PREBUFFER_MAX_SEGMENTS',
            'PREBUFFER_MAX_SIZE_MB', 
            'PREBUFFER_CLEANUP_INTERVAL',
            'PREBUFFER_MAX_MEMORY_PERCENT',
            'PREBUFFER_EMERGENCY_THRESHOLD'
        ]
        
        for field in prebuffer_numeric_fields:
            if field in new_config:
                val = new_config[field]
                if isinstance(val, str):
                    try:
                        if field in ['PREBUFFER_MAX_MEMORY_PERCENT', 'PREBUFFER_EMERGENCY_THRESHOLD']:
                            new_config[field] = float(val)
                        else:
                            new_config[field] = int(val)
                    except ValueError:
                        app.logger.warning(f"Valore non valido per {field}: {val}, usando default")
                        # Rimuovi il campo invalido, userà il default
                        del new_config[field]
        
        # Salva la configurazione
        if config_manager.save_config(new_config):
            config_manager.apply_config_to_app(new_config)
            setup_proxies()  # Ricarica i proxy dalla nuova configurazione
            setup_all_caches()
            # Aggiorna la configurazione del pre-buffer
            pre_buffer_manager.update_config()
            
            # Log delle statistiche proxy aggiornate
            available_proxies = get_available_proxies()
            available_daddy_proxies = get_available_daddy_proxies()
            app.logger.info(f"Configurazione salvata - Proxy caricati: {len(PROXY_LIST)} normali ({len(available_proxies)} disponibili), {len(DADDY_PROXY_LIST)} DaddyLive ({len(available_daddy_proxies)} disponibili)")
            
            return jsonify({
                "status": "success", 
                "message": f"Configurazione salvata con successo. Proxy caricati: {len(PROXY_LIST)} normali, {len(DADDY_PROXY_LIST)} DaddyLive"
            })
        else:
            return jsonify({"status": "error", "message": "Errore nel salvataggio"})
            
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
    """Testa le configurazioni proxy e i link DaddyLive/Vavoo con tutti i protocolli in parallelo"""
    try:
        config = config_manager.load_config()
        results = []

        def test_proxy(proxy, proto, url, headers=None):
            try:
                proxies = {proto.lower(): proxy}
                response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=VERIFY_SSL)
                if response.status_code == 200:
                    return f"✅ {url} {proto} {proxy}: OK"
                else:
                    return f"❌ {url} {proto} {proxy}: Status {response.status_code}"
            except Exception as e:
                return f"❌ {url} {proto} {proxy}: {str(e)}"

        # Test proxy unificati su httpbin
        proxy_tests = []
        if config.get('PROXY'):
            proxies = [p.strip() for p in config['PROXY'].split(',') if p.strip()]
            for proxy in proxies:
                proxy_type = detect_proxy_type(proxy)
                if proxy_type == 'socks5':
                    test_url = 'https://httpbin.org/ip'
                elif proxy_type == 'http':
                    test_url = 'http://httpbin.org/ip'
                else:  # https
                    test_url = 'https://httpbin.org/ip'
                proxy_tests.append((proxy_type.upper(), proxy, test_url, None))

        # DaddyLive e Vavoo URLs
        daddy_url = "https://new.newkso.ru/wind/"
        vavoo_url = 'https://vavoo.to/play/1534161807/index.m3u8'
        vavoo_headers = {
            'user-agent': 'VAVOO/2.6',
            'referer': 'https://vavoo.to/',
            'origin': 'https://vavoo.to'
        }

                # Test DaddyLive con proxy unificati
        if config.get('PROXY'):
            proxies = [p.strip() for p in config['PROXY'].split(',') if p.strip()]
            for proxy in proxies:
                proxy_type = detect_proxy_type(proxy)
                proxy_tests.append((proxy_type.upper(), proxy, daddy_url, None))

        # Test Vavoo con proxy unificati
        if config.get('PROXY'):
            proxies = [p.strip() for p in config['PROXY'].split(',') if p.strip()]
            for proxy in proxies:
                proxy_type = detect_proxy_type(proxy)
                proxy_tests.append((proxy_type.upper(), proxy, vavoo_url, vavoo_headers))

        # Esegui tutti i test in parallelo (max 50 thread)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_test = {
                executor.submit(test_proxy, proxy, proto, url, headers): (proto, proxy, url)
                for proto, proxy, url, headers in proxy_tests
            }
            for future in concurrent.futures.as_completed(future_to_test):
                result = future.result()
                results.append(result)

        # Test DaddyLive diretto (senza proxy)
        try:
            cmd = [
                'curl', '-k', '--max-time', '10', '--silent', '--show-error',
                '--connect-timeout', '7', daddy_url
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                results.append(f"✅ DaddyLive CURL: OK")
            else:
                results.append(f"❌ DaddyLive CURL: Errore (code {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
        except Exception as e:
            results.append(f"❌ DaddyLive CURL: {str(e)}")

        # Test Vavoo diretto (senza proxy)
        try:
            cmd2 = [
                'curl', '-k', '--max-time', '10', '--silent', '--show-error', '--connect-timeout', '7',
                '-H', 'user-agent: VAVOO/2.6',
                '-H', 'referer: https://vavoo.to/',
                '-H', 'origin: https://vavoo.to',
                vavoo_url
            ]
            proc2 = subprocess.run(cmd2, capture_output=True, text=True)
            if proc2.returncode == 0:
                results.append(f"✅ Vavoo CURL: OK")
            else:
                results.append(f"❌ Vavoo CURL: Errore (code {proc2.returncode}): {proc2.stderr.strip() or proc2.stdout.strip()}")
        except Exception as e:
            results.append(f"❌ Vavoo CURL: {str(e)}")

        app.logger.info("Test configurazioni eseguito")
        message = "Test completato:\n" + "\n".join(results)
        return jsonify({"status": "success", "message": message})

    except Exception as e:
        app.logger.error(f"Errore nel test configurazioni: {e}")
        return jsonify({"status": "error", "message": f"Errore nel test: {str(e)}"})

@app.route('/admin/config/export')
@login_required
def export_config():
    """Esporta la configurazione corrente in formato JSON"""
    try:
        config = config_manager.load_config()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"config_export_{timestamp}.json"
        
        return Response(
            json.dumps(config, indent=2, ensure_ascii=False),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Cache-Control': 'no-cache'
            }
        )
    except Exception as e:
        app.logger.error(f"Errore nell'esportazione configurazione: {e}")
        return jsonify({"status": "error", "message": f"Errore nell'esportazione: {str(e)}"}), 500

@app.route('/admin/config/import', methods=['POST'])
@login_required
def import_config():
    """Importa una configurazione da file JSON"""
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "Nessun file caricato"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "Nessun file selezionato"}), 400
        
        if not file.filename or not file.filename.endswith('.json'):
            return jsonify({"status": "error", "message": "Il file deve essere in formato JSON"}), 400
        
        # Leggi il contenuto del file
        content = file.read().decode('utf-8')
        imported_config = json.loads(content)
        
        # Valida la configurazione importata
        if not isinstance(imported_config, dict):
            return jsonify({"status": "error", "message": "Formato configurazione non valido"}), 400
        
        # Applica la configurazione importata
        if config_manager.save_config(imported_config):
            config_manager.apply_config_to_app(imported_config)
            setup_proxies()
            setup_all_caches()
            # Aggiorna la configurazione del pre-buffer
            pre_buffer_manager.update_config()
            
            # Verifica che la configurazione sia stata applicata
            current_config = config_manager.load_config()
            config_status = config_manager.get_config_status()
            
            app.logger.info(f"Configurazione importata con successo da {file.filename}")
            app.logger.info(f"Configurazione attuale: {len(current_config)} impostazioni caricate")
            
            return jsonify({
                "status": "success", 
                "message": f"Configurazione importata con successo da {file.filename}",
                "config_status": config_status,
                "imported_keys": list(imported_config.keys()),
                "current_keys": list(current_config.keys()),
                "is_huggingface": config_status.get('is_huggingface', False)
            })
        else:
            return jsonify({"status": "error", "message": "Errore nel salvataggio della configurazione importata"}), 500
            
    except json.JSONDecodeError as e:
        app.logger.error(f"Errore nel parsing JSON del file importato: {e}")
        return jsonify({"status": "error", "message": f"Errore nel parsing del file JSON: {str(e)}"}), 400
    except Exception as e:
        app.logger.error(f"Errore nell'importazione configurazione: {e}")
        return jsonify({"status": "error", "message": f"Errore nell'importazione: {str(e)}"}), 500

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

# NUOVA ROTTA: Pulisci Cache
@app.route('/admin/clear-cache', methods=['POST'])
@login_required
def clear_cache():
    """Pulisce tutte le cache di sistema (M3U8, TS, KEY)."""
    try:
        # La funzione setup_all_caches() reinizializza le cache,
        # che è il modo più efficace per pulirle completamente.
        setup_all_caches()
        app.logger.info("Cache di sistema pulita manualmente dall'amministratore.")
        return jsonify({
            "status": "success", 
            "message": "Tutte le cache (M3U8, TS, KEY) sono state pulite con successo."
        })
    except Exception as e:
        app.logger.error(f"Errore durante la pulizia manuale della cache: {e}")
        return jsonify({
            "status": "error", 
            "message": f"Errore durante la pulizia della cache: {str(e)}"
        }), 500

# NUOVA ROTTA: Pre-buffering Avanzato
@app.route('/proxy/prebuffer')
def proxy_prebuffer():
    """Endpoint per pre-buffering manuale di segmenti specifici"""
    m3u8_url = request.args.get('m3u8_url', '').strip()
    stream_id = request.args.get('stream_id', '').strip()
    
    if not m3u8_url or not stream_id:
        return jsonify({
            "error": "Parametri mancanti",
            "required": ["m3u8_url", "stream_id"]
        }), 400
    
    try:
        # Scarica il M3U8
        headers = {
            unquote(key[2:]).replace("_", "-"): unquote(value).strip()
            for key, value in request.args.items()
            if key.lower().startswith("h_")
        }
        
        # Usa il sistema di proxy configurato
        proxy_config = get_proxy_for_url(m3u8_url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        response = make_persistent_request(
            m3u8_url,
            headers=headers,
            timeout=get_dynamic_timeout(m3u8_url),
            proxy_url=proxy_key,
            allow_redirects=True
        )
        response.raise_for_status()
        
        m3u8_content = response.text
        final_url = response.url
        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"
        
        # Avvia il pre-buffering
        pre_buffer_manager.pre_buffer_segments(m3u8_content, base_url, headers, stream_id)
        
        return jsonify({
            "status": "success",
            "message": f"Pre-buffering avviato per stream {stream_id}",
            "stream_id": stream_id,
            "segments_to_buffer": pre_buffer_manager.pre_buffer_config['max_segments']
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel pre-buffering manuale: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nel pre-buffering: {str(e)}"
        }), 500

# NUOVA ROTTA: Stato Pre-buffer
@app.route('/admin/prebuffer/status')
@login_required
def prebuffer_status():
    """Mostra lo stato del sistema di pre-buffering"""
    try:
        with pre_buffer_manager.pre_buffer_lock:
            buffer_info = {}
            total_segments = 0
            total_size = 0
            
            for stream_id, segments in pre_buffer_manager.pre_buffer.items():
                stream_size = sum(len(content) for content in segments.values())
                buffer_info[stream_id] = {
                    "segments_count": len(segments),
                    "total_size_mb": round(stream_size / (1024 * 1024), 2),
                    "segments": list(segments.keys())[:5]  # Primi 5 segmenti
                }
                total_segments += len(segments)
                total_size += stream_size
            
            active_threads = len(pre_buffer_manager.pre_buffer_threads)
            
        return jsonify({
            "status": "success",
            "pre_buffer_config": pre_buffer_manager.pre_buffer_config,
            "active_streams": len(buffer_info),
            "active_threads": active_threads,
            "total_segments_buffered": total_segments,
            "total_buffer_size_mb": round(total_size / (1024 * 1024), 2),
            "streams": buffer_info
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel recupero stato pre-buffer: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nel recupero stato: {str(e)}"
        }), 500

# NUOVA ROTTA: Pulisci Pre-buffer
@app.route('/admin/prebuffer/clear', methods=['POST'])
@login_required
def clear_prebuffer():
    """Pulisce tutti i buffer di pre-buffering"""
    try:
        with pre_buffer_manager.pre_buffer_lock:
            streams_cleared = len(pre_buffer_manager.pre_buffer)
            pre_buffer_manager.pre_buffer.clear()
            pre_buffer_manager.pre_buffer_threads.clear()
        
        app.logger.info(f"Pre-buffer pulito: {streams_cleared} stream rimossi")
        return jsonify({
            "status": "success",
            "message": f"Pre-buffer pulito: {streams_cleared} stream rimossi"
        })
        
    except Exception as e:
        app.logger.error(f"Errore nella pulizia del pre-buffer: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nella pulizia: {str(e)}"
        }), 500

# NUOVA ROTTA: Controllo Memoria
@app.route('/admin/memory/status')
@login_required
def memory_status():
    """Mostra lo stato della memoria e del buffer"""
    try:
        memory = psutil.virtual_memory()
        
        with pre_buffer_manager.pre_buffer_lock:
            total_buffer_size = sum(
                sum(len(content) for content in segments.values())
                for segments in pre_buffer_manager.pre_buffer.values()
            )
            buffer_memory_percent = (total_buffer_size / memory.total) * 100
        
        return jsonify({
            "status": "success",
            "system_memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "percent": round(memory.percent, 1)
            },
            "buffer_memory": {
                "size_mb": round(total_buffer_size / (1024*1024), 2),
                "percent": round(buffer_memory_percent, 1),
                "streams": len(pre_buffer_manager.pre_buffer),
                "segments": sum(len(segments) for segments in pre_buffer_manager.pre_buffer.values())
            },
            "config": pre_buffer_manager.pre_buffer_config
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel recupero stato memoria: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nel recupero stato: {str(e)}"
        }), 500

@app.route('/admin/memory/cleanup', methods=['POST'])
@login_required
def memory_cleanup():
    """Pulizia manuale della memoria"""
    try:
        before_memory = psutil.virtual_memory()
        
        # Pulisci il pre-buffer
        with pre_buffer_manager.pre_buffer_lock:
            streams_cleared = len(pre_buffer_manager.pre_buffer)
            total_size = sum(
                sum(len(content) for content in segments.values())
                for segments in pre_buffer_manager.pre_buffer.values()
            )
            pre_buffer_manager.pre_buffer.clear()
            pre_buffer_manager.pre_buffer_threads.clear()
        
        # Pulisci le cache
        setup_all_caches()
        
        after_memory = psutil.virtual_memory()
        memory_freed = before_memory.used - after_memory.used
        
        app.logger.info(f"Pulizia memoria manuale: {streams_cleared} stream, {total_size / (1024*1024):.1f}MB liberati")
        
        return jsonify({
            "status": "success",
            "message": f"Pulizia completata: {streams_cleared} stream rimossi",
            "memory_freed_mb": round(memory_freed / (1024*1024), 2),
            "buffer_cleared_mb": round(total_size / (1024*1024), 2)
        })
        
    except Exception as e:
        app.logger.error(f"Errore nella pulizia memoria: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nella pulizia: {str(e)}"
        }), 500

# NUOVA ROTTA: Test Pre-buffering
@app.route('/admin/prebuffer/test', methods=['POST'])
@login_required
def test_prebuffer():
    """Testa il sistema di pre-buffering con un URL di esempio"""
    try:
        test_url = (request.json or {}).get('test_url', 'https://dash.akamaized.net/akamai/bbb_30fps/bbb_30fps.m3u8')
        stream_id = pre_buffer_manager.get_stream_id_from_url(test_url)
        
        # Test del pre-buffering
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Scarica il M3U8 di test
        response = make_persistent_request(
            test_url,
            headers=headers,
            timeout=10,
            allow_redirects=True
        )
        response.raise_for_status()
        
        m3u8_content = response.text
        final_url = response.url
        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"
        
        # Avvia il pre-buffering
        pre_buffer_manager.pre_buffer_segments(m3u8_content, base_url, headers, stream_id)
        
        # Attendi un momento per il pre-buffering
        time.sleep(2)
        
        # Controlla lo stato del buffer
        with pre_buffer_manager.pre_buffer_lock:
            stream_buffer = pre_buffer_manager.pre_buffer.get(stream_id, {})
            buffer_status = {
                'stream_id': stream_id,
                'segments_buffered': len(stream_buffer),
                'buffer_size_mb': round(
                    sum(len(content) for content in stream_buffer.values()) / (1024 * 1024), 2
                ),
                'test_url': test_url
            }
        
        return jsonify({
            "status": "success",
            "message": "Test pre-buffering completato",
            "results": buffer_status
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel test pre-buffering: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nel test: {str(e)}"
        }), 500

@app.route('/stats')
def get_stats():
    """Endpoint per ottenere le statistiche di sistema"""
    stats = get_system_stats()
    stats['daddy_base_url'] = get_daddylive_base_url()
    stats['session_count'] = len(SESSION_POOL)
    stats['proxy_count'] = len(PROXY_LIST)
    stats['daddy_proxy_count'] = len(DADDY_PROXY_LIST)
    
    # Aggiungi statistiche proxy
    available_proxies = get_available_proxies()
    available_daddy_proxies = get_available_daddy_proxies()
    
    # Calcola statistiche IP
    ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
    for proxy in PROXY_LIST:
        ip_version = get_proxy_ip_version(proxy)
        if ip_version in ip_stats:
            ip_stats[ip_version] += 1
    
    available_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
    for proxy in available_proxies:
        ip_version = get_proxy_ip_version(proxy)
        if ip_version in available_ip_stats:
            available_ip_stats[ip_version] += 1
    
    # Calcola statistiche proxy DaddyLive
    daddy_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
    for proxy in DADDY_PROXY_LIST:
        ip_version = get_proxy_ip_version(proxy)
        if ip_version in daddy_ip_stats:
            daddy_ip_stats[ip_version] += 1
    
    available_daddy_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
    for proxy in available_daddy_proxies:
        ip_version = get_proxy_ip_version(proxy)
        if ip_version in available_daddy_ip_stats:
            available_daddy_ip_stats[ip_version] += 1
    
    stats['proxy_status'] = {
        'available_proxies': len(available_proxies),
        'blacklisted_proxies': len(PROXY_BLACKLIST),
        'total_proxies': len(PROXY_LIST),
        'available_daddy_proxies': len(available_daddy_proxies),
        'blacklisted_daddy_proxies': len(DADDY_PROXY_BLACKLIST),
        'total_daddy_proxies': len(DADDY_PROXY_LIST),
        'ip_statistics': {
            'total': ip_stats,
            'available': available_ip_stats
        },
        'daddy_ip_statistics': {
            'total': daddy_ip_stats,
            'available': available_daddy_ip_stats
        }
    }
    
    # Aggiungi campi mancanti per il template admin.html
    stats['active_connections'] = len(SESSION_POOL)
    stats['cache_size'] = f"{len(M3U8_CACHE) + len(TS_CACHE) + len(KEY_CACHE)} items"
    
    # Calcola uptime (tempo dall'avvio del processo)
    try:
        process = psutil.Process()
        uptime_seconds = time.time() - process.create_time()
        uptime_hours = int(uptime_seconds // 3600)
        stats['uptime'] = f"{uptime_hours}h"
    except:
        stats['uptime'] = "0h"
    
    # Calcola richieste per minuto (semplificato)
    stats['requests_per_min'] = len(SESSION_POOL) * 2  # Stima basata su sessioni attive
    
    # Aggiungi statistiche pre-buffer
    stats['prebuffer_info'] = {
        'active_streams': stats.get('prebuffer_streams', 0),
        'buffered_segments': stats.get('prebuffer_segments', 0),
        'buffer_size_mb': stats.get('prebuffer_size_mb', 0),
        'active_threads': stats.get('prebuffer_threads', 0)
    }
    
    # Aggiungi statistiche client
    try:
        if 'client_tracker' in globals():
            client_stats = client_tracker.get_realtime_stats()
            stats.update(client_stats)
        else:
            # Fallback se client_tracker non è ancora disponibile
            stats['active_clients'] = 0
            stats['active_sessions'] = 0
            stats['total_requests'] = 0
            stats['m3u_clients'] = 0
            stats['m3u_requests'] = 0
    except Exception as e:
        app.logger.warning(f"Errore nel recupero statistiche client per /stats: {e}")
        # Fallback con valori di default
        stats['active_clients'] = 0
        stats['active_sessions'] = 0
        stats['total_requests'] = 0
        stats['m3u_clients'] = 0
        stats['m3u_requests'] = 0
    
    # Debug log per verificare i dati
    app.logger.info(f"Stats endpoint chiamato - RAM: {stats.get('ram_usage', 0)}%, Cache: {stats.get('cache_size', '0')}, Sessions: {stats.get('session_count', 0)}, Clients: {stats.get('active_clients', 0)}, Pre-buffer: {stats.get('prebuffer_streams', 0)} streams")
    
    return jsonify(stats)

@app.route('/admin/clients')
@login_required
def admin_clients():
    """Pagina di amministrazione per visualizzare i client connessi"""
    return render_template('clients.html')

@app.route('/admin/clients/stats')
@login_required
def get_client_stats():
    """Endpoint per ottenere statistiche dettagliate sui client"""
    try:
        if 'client_tracker' in globals():
            return jsonify(client_tracker.get_client_stats())
        else:
            return jsonify({
                'total_clients': 0,
                'total_sessions': 0,
                'client_counter': 0,
                'active_clients': 0,
                'active_sessions': 0,
                'total_requests': 0,
                'm3u_clients': 0,
                'm3u_requests': 0,
                'avg_connection_time': 0,
                'clients': []
            })
    except Exception as e:
        app.logger.error(f"Errore nel recupero statistiche client: {e}")
        return jsonify({
            'total_clients': 0,
            'total_sessions': 0,
            'client_counter': 0,
            'active_clients': 0,
            'active_sessions': 0,
            'total_requests': 0,
            'm3u_clients': 0,
            'm3u_requests': 0,
            'avg_connection_time': 0,
            'clients': []
        }), 500

@app.route('/admin/clients/m3u-stats')
@login_required
def get_m3u_client_stats():
    """Endpoint per ottenere statistiche specifiche sui client che usano /proxy/m3u"""
    try:
        if 'client_tracker' not in globals():
            return jsonify({
                'total_m3u_clients': 0,
                'total_m3u_requests': 0,
                'url_type_distribution': {},
                'top_urls': [],
                'clients': [],
                'timestamp': datetime.now().isoformat()
            })
        
        stats = client_tracker.get_client_stats()
        
        # Filtra solo client che usano /proxy/m3u
        m3u_clients = [client for client in stats['clients'] if client['is_m3u_user']]
        
        # Calcola statistiche aggregate
        total_m3u_requests = sum(client['m3u_requests'] for client in m3u_clients)
        url_type_counts = {}
        for client in m3u_clients:
            for url_type in client['url_types']:
                url_type_counts[url_type] = url_type_counts.get(url_type, 0) + 1
        
        # Top 10 URL più utilizzati
        url_usage = {}
        for client in m3u_clients:
            if client['last_m3u_url']:
                url = client['last_m3u_url']
                url_usage[url] = url_usage.get(url, 0) + 1
        
        top_urls = sorted(url_usage.items(), key=lambda x: x[1], reverse=True)[:10]
        
        m3u_stats = {
            'total_m3u_clients': len(m3u_clients),
            'total_m3u_requests': total_m3u_requests,
            'url_type_distribution': url_type_counts,
            'top_urls': [{'url': url, 'count': count} for url, count in top_urls],
            'clients': m3u_clients,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(m3u_stats)
        
    except Exception as e:
        app.logger.error(f"Errore nel recupero statistiche M3U: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nel recupero statistiche: {str(e)}"
        }), 500

@app.route('/admin/clients/export')
@login_required
def export_client_stats():
    """Esporta le statistiche dei client in formato CSV"""
    try:
        if 'client_tracker' not in globals():
            return jsonify({"status": "error", "message": "Client tracker non disponibile"}), 500
        
        stats = client_tracker.get_client_stats()
        
        # Crea CSV
        csv_data = "ID,IP,User Agent,Prima Connessione,Ultima Attività,Tempo Connessione (min),Richieste,Endpoint,Sessione\n"
        
        for client in stats['clients']:
            csv_data += f"{client['id']},{client['ip']},\"{client['user_agent']}\",{client['first_seen']},{client['last_seen']},{client['connection_time_minutes']},{client['requests']},\"{','.join(client['endpoints'])}\",{'Sì' if client['has_session'] else 'No'}\n"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"client_stats_{timestamp}.csv"
        
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Cache-Control': 'no-cache'
            }
        )
    except Exception as e:
        app.logger.error(f"Errore nell'esportazione statistiche client: {e}")
        return jsonify({"status": "error", "message": f"Errore nell'esportazione: {str(e)}"}), 500

@app.route('/admin/clients/clear', methods=['POST'])
@login_required
def clear_client_stats():
    """Pulisce le statistiche dei client"""
    try:
        if 'client_tracker' not in globals():
            return jsonify({"status": "error", "message": "Client tracker non disponibile"}), 500
        
        with client_tracker.client_lock:
            cleared_count = len(client_tracker.active_clients)
            client_tracker.active_clients.clear()
            client_tracker.session_clients.clear()
            client_tracker.client_counter = 0
        
        app.logger.info(f"Statistiche client pulite: {cleared_count} client rimossi")
        return jsonify({
            "status": "success",
            "message": f"Statistiche client pulite: {cleared_count} client rimossi"
        })
    except Exception as e:
        app.logger.error(f"Errore nella pulizia statistiche client: {e}")
        return jsonify({
            "status": "error",
            "message": f"Errore nella pulizia: {str(e)}"
        }), 500

# --- Route Proxy (mantieni tutte le route proxy esistenti) ---

@app.route('/proxy/vavoo')
def proxy_vavoo():
    """Route specifica per testare la risoluzione Vavoo"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/proxy/vavoo')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta Vavoo: {e}")
    
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({
            "error": "Parametro 'url' mancante",
            "example": "/proxy/vavoo?url=https://vavoo.to/vavoo-iptv/play/277580225585f503fbfc87"
        }), 400

    # Verifica che sia un link Vavoo
    if 'vavoo.to' not in url.lower():
        return jsonify({
            "error": "URL non è un link Vavoo",
            "received": url
        }), 400

    try:
        app.logger.info(f"🔍 Richiesta risoluzione Vavoo: {url}")
        resolved = vavoo_resolver.resolve_vavoo_link(url, verbose=True)
        
        if resolved:
            app.logger.info(f"✅ Vavoo risolto: {resolved}")
            return jsonify({
                "status": "success",
                "original_url": url,
                "resolved_url": resolved,
                "method": "vavoo_direct"
            })
        else:
            app.logger.warning(f"❌ Risoluzione Vavoo fallita per: {url}")
            return jsonify({
                "status": "error",
                "original_url": url,
                "resolved_url": None,
                "error": "Impossibile risolvere il link Vavoo"
            }), 500
            
    except Exception as e:
        app.logger.error(f"❌ Errore nella risoluzione Vavoo: {e}")
        return jsonify({
            "status": "error",
            "original_url": url,
            "error": str(e)
        }), 500

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto DaddyLive 2025, caching intelligente e pre-buffering"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/proxy/m3u')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta M3U: {e}")
    
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"

    config = config_manager.load_config()
    cache_enabled = config.get('CACHE_ENABLED', True)
    
    if cache_enabled and cache_key in M3U8_CACHE:
        app.logger.info(f"Cache HIT per M3U8: {m3u_url}")
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl")

    app.logger.info(f"Cache MISS per M3U8: {m3u_url} (primo avvio, risposta diretta)")

    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = request_headers
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
        proxy_config = get_proxy_for_url(resolved_url, original_url=m3u_url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        # Retry speciale per link Vavoo risolti
        max_retries = 3 if 'vavoo.to' in m3u_url.lower() else 1
        last_error = None
        
        for attempt in range(max_retries):
            try:
                m3u_response = make_persistent_request(
                    resolved_url,
                    headers=current_headers_for_proxy,
                    timeout=timeout,
                    proxy_url=proxy_key,
                    allow_redirects=True
                )
                m3u_response.raise_for_status()
                break  # Successo, esci dal loop
            except requests.exceptions.HTTPError as e:
                last_error = e
                if e.response.status_code in [502, 503, 504] and attempt < max_retries - 1:
                    app.logger.warning(f"Errore {e.response.status_code} per link Vavoo (tentativo {attempt + 1}/{max_retries}), riprovo...")
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    raise  # Rilancia l'errore se non è recuperabile
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    app.logger.warning(f"Errore per link Vavoo (tentativo {attempt + 1}/{max_retries}): {e}")
                    time.sleep(2 ** attempt)
                    continue
                else:
                    raise

        m3u_content = m3u_response.text
        final_url = m3u_response.url

        file_type = detect_m3u_type(m3u_content)
        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl")

        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in current_headers_for_proxy.items()])

        # Genera stream ID per il pre-buffering
        stream_id = pre_buffer_manager.get_stream_id_from_url(m3u_url)

        modified_m3u8 = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-KEY") and 'URI="' in line:
                line = replace_key_uri(line, headers_query)
            elif line and not line.startswith("#"):
                segment_url = urljoin(base_url, line)
                if headers_query:
                    line = f"/proxy/ts?url={quote(segment_url)}&{headers_query}&stream_id={stream_id}"
                else:
                    line = f"/proxy/ts?url={quote(segment_url)}&stream_id={stream_id}"
            modified_m3u8.append(line)

        modified_m3u8_content = "\n".join(modified_m3u8)

        # Avvia il pre-buffering in background
        def start_pre_buffering():
            try:
                pre_buffer_manager.pre_buffer_segments(m3u_content, base_url, current_headers_for_proxy, stream_id)
            except Exception as e:
                app.logger.error(f"Errore nell'avvio del pre-buffering: {e}")

        Thread(target=start_pre_buffering, daemon=True).start()

        def cache_later():
            if not cache_enabled:
                return
            try:
                M3U8_CACHE[cache_key] = modified_m3u8_content
                app.logger.info(f"M3U8 cache salvata per {m3u_url}")
            except Exception as e:
                app.logger.error(f"Errore nel salvataggio cache M3U8: {e}")

        Thread(target=cache_later, daemon=True).start()

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

    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = request_headers

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
    """Proxy per segmenti .TS con connessioni persistenti, headers personalizzati, caching e pre-buffering"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/proxy/ts')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta TS: {e}")
    
    ts_url = request.args.get('url', '').strip()
    stream_id = request.args.get('stream_id', '').strip()
    
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    # Carica configurazione cache
    config = config_manager.load_config()
    cache_enabled = config.get('CACHE_ENABLED', True)
    
    # 1. Controlla prima il pre-buffer (più veloce)
    if stream_id:
        buffered_content = pre_buffer_manager.get_buffered_segment(ts_url, stream_id)
        if buffered_content:
            app.logger.info(f"Pre-buffer HIT per TS: {ts_url}")
            return Response(buffered_content, content_type="video/mp2t")
    
    # 2. Controlla la cache normale
    if cache_enabled and ts_url in TS_CACHE:
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
    
    # Retry speciale per segmenti TS di link Vavoo
    max_retries = 3
    is_vavoo_segment = any('vavoo.to' in arg.lower() for arg in request.args.values())
    
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
                        return b""  # Return empty bytes instead of None
                    raise
                finally:
                    ts_content = b"".join(content_parts)
                    if cache_enabled and ts_content and len(ts_content) > 1024:
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
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [502, 503, 504] and is_vavoo_segment and attempt < max_retries - 1:
                app.logger.warning(f"Errore {e.response.status_code} per segmento TS Vavoo (tentativo {attempt + 1}/{max_retries}): {ts_url}")
                time.sleep(2 ** attempt)
                continue
            else:
                app.logger.error(f"Errore HTTP per il segmento TS: {str(e)}")
                return f"Errore HTTP per il segmento TS: {str(e)}", e.response.status_code
        except requests.exceptions.ReadTimeout as e:
            app.logger.warning(f"Read timeout esplicito per il segmento TS (tentativo {attempt + 1}/{max_retries}): {ts_url}")
            if attempt == max_retries - 1:
                return f"Errore: Read timeout persistente per il segmento TS dopo {max_retries} tentativi", 504
            time.sleep(2 ** attempt)
            continue
        except requests.RequestException as e:
            app.logger.error(f"Errore durante il download del segmento TS: {str(e)}")
            return f"Errore durante il download del segmento TS: {str(e)}", 500
    
    # If we get here, all retries failed
    return "Errore: Impossibile scaricare il segmento TS dopo tutti i tentativi", 500

@app.route('/proxy')
def proxy():
    """Proxy per liste M3U che aggiunge automaticamente /proxy/m3u?url= con IP prima dei link"""
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/proxy')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta proxy: {e}")
    
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
    # Traccia la richiesta se client_tracker è disponibile
    try:
        if 'client_tracker' in globals():
            client_tracker.track_request(request, '/proxy/key')
    except Exception as e:
        app.logger.warning(f"Errore nel tracking richiesta key: {e}")
    
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

    # Carica configurazione cache
    config = config_manager.load_config()
    cache_enabled = config.get('CACHE_ENABLED', True)
    
    if cache_enabled and key_url in KEY_CACHE:
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

        if cache_enabled:
            KEY_CACHE[key_url] = key_content
        return Response(key_content, content_type="application/octet-stream")

    except requests.RequestException as e:
        app.logger.error(f"Errore durante il download della chiave AES-128: {str(e)}")
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

# --- Inizializzazione dell'app ---

# Carica e applica la configurazione salvata al startup
saved_config = config_manager.load_config()
config_manager.apply_config_to_app(saved_config)

# Log dello stato della configurazione
config_status = config_manager.get_config_status()
app.logger.info("="*50)
app.logger.info("🔧 STATO CONFIGURAZIONE")
app.logger.info("="*50)

# Determina il tipo di ambiente
if config_status['is_huggingface']:
    env_type = "HuggingFace"
elif config_status['is_docker']:
    env_type = "Docker"
elif config_status['is_cloud']:
    env_type = "Cloud (Render/Railway/Heroku)"
elif config_status['use_global_sync']:
    env_type = "Gunicorn con workers multipli"
else:
    env_type = "Standard"

app.logger.info(f"Ambiente: {env_type}")
app.logger.info(f"File config: {config_status['config_file']}")
app.logger.info(f"Cache memoria: {'Sì' if config_status['has_memory_cache'] else 'No'}")
app.logger.info(f"File scrivibile: {'Sì' if config_status['file_writable'] else 'No'}")
app.logger.info(f"Fonte config: {config_status['current_config_source']}")

if config_status['is_huggingface']:
    app.logger.info("⚠️  AMBIENTE HUGGINGFACE: Configurazione salvata in memoria")
    app.logger.info("🔄 Sincronizzazione globale tra workers attiva")
    app.logger.info("💡 Per configurazione permanente, usa i Secrets di HuggingFace")
elif config_status['is_docker']:
    app.logger.info("🐳 AMBIENTE DOCKER: Sincronizzazione globale tra workers attiva")
    app.logger.info("📁 Configurazione salvata in memoria e file globale")
elif config_status['is_cloud']:
    app.logger.info("☁️  AMBIENTE CLOUD: Sincronizzazione globale tra workers attiva")
    app.logger.info("📁 Configurazione salvata in memoria e file globale")
    app.logger.info("💡 Per configurazione permanente, usa le variabili d'ambiente del cloud")
elif config_status['use_global_sync']:
    app.logger.info("🔄 AMBIENTE GUNICORN: Sincronizzazione globale tra workers attiva")
    app.logger.info("📁 Configurazione salvata in memoria e file globale")
else:
    app.logger.info("✅ Configurazione salvata su file (ambiente standard)")

app.logger.info("="*50)

# Valida e aggiorna la configurazione del pre-buffer
pre_buffer_manager.update_config()
app.logger.info("Configurazione pre-buffer inizializzata con successo")

# Inizializza le cache
setup_all_caches()
setup_proxies()

# --- Sistema di Tracking Client Connessi ---
class ClientTracker:
    def __init__(self):
        self.active_clients = {}  # {client_id: {'ip': ip, 'user_agent': ua, 'first_seen': timestamp, 'last_seen': timestamp, 'requests': 0, 'endpoints': set()}}
        self.client_lock = Lock()
        self.client_counter = 0
        self.session_clients = {}  # {session_id: client_id} per tracking sessioni Flask
    
    def get_client_id(self, request):
        """Genera un ID univoco per il client"""
        # Usa IP + User-Agent per identificare client unici
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Crea un hash per identificare client unici
        client_hash = hashlib.md5(f"{ip}:{user_agent}".encode()).hexdigest()[:12]
        return client_hash
    
    def track_request(self, request, endpoint):
        """Traccia una richiesta da un client"""
        client_id = self.get_client_id(request)
        current_time = time.time()
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Estrai informazioni aggiuntive per /proxy/m3u
        additional_info = {}
        if endpoint == '/proxy/m3u':
            url_param = request.args.get('url', '')
            if url_param:
                additional_info['last_m3u_url'] = url_param
                # Categorizza il tipo di URL
                if 'vavoo.to' in url_param.lower():
                    additional_info['url_type'] = 'vavoo'
                elif 'newkso.ru' in url_param.lower() or '/stream-' in url_param.lower():
                    additional_info['url_type'] = 'daddylive'
                elif '.m3u8' in url_param.lower():
                    additional_info['url_type'] = 'm3u8'
                elif '.m3u' in url_param.lower():
                    additional_info['url_type'] = 'm3u'
                else:
                    additional_info['url_type'] = 'other'
        
        with self.client_lock:
            if client_id not in self.active_clients:
                self.active_clients[client_id] = {
                    'ip': ip,
                    'user_agent': user_agent,
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'requests': 0,
                    'endpoints': set(),
                    'session_id': None,
                    'm3u_requests': 0,
                    'last_m3u_url': None,
                    'url_types': set(),
                    'additional_info': {}
                }
                self.client_counter += 1
                app.logger.info(f"Nuovo client connesso: {ip} (ID: {client_id})")
            
            # Aggiorna statistiche
            client = self.active_clients[client_id]
            client['last_seen'] = current_time
            client['requests'] += 1
            client['endpoints'].add(endpoint)
            
            # Aggiorna statistiche specifiche per M3U
            if endpoint == '/proxy/m3u':
                client['m3u_requests'] += 1
                if 'last_m3u_url' in additional_info:
                    client['last_m3u_url'] = additional_info['last_m3u_url']
                if 'url_type' in additional_info:
                    client['url_types'].add(additional_info['url_type'])
            
            # Aggiorna informazioni aggiuntive
            client['additional_info'].update(additional_info)
    
    def track_session(self, session_id, request):
        """Traccia una sessione Flask"""
        client_id = self.get_client_id(request)
        with self.client_lock:
            self.session_clients[session_id] = client_id
            if client_id in self.active_clients:
                self.active_clients[client_id]['session_id'] = session_id
    
    def remove_session(self, session_id):
        """Rimuove una sessione"""
        with self.client_lock:
            if session_id in self.session_clients:
                client_id = self.session_clients[session_id]
                if client_id in self.active_clients:
                    self.active_clients[client_id]['session_id'] = None
                del self.session_clients[session_id]
    
    def cleanup_inactive_clients(self, timeout=300):  # 5 minuti di inattività
        """Rimuove client inattivi"""
        current_time = time.time()
        with self.client_lock:
            inactive_clients = []
            for client_id, client_data in self.active_clients.items():
                if current_time - client_data['last_seen'] > timeout:
                    inactive_clients.append(client_id)
            
            for client_id in inactive_clients:
                client_data = self.active_clients[client_id]
                app.logger.info(f"Client disconnesso: {client_data['ip']} (ID: {client_id}) - Inattivo per {timeout}s")
                del self.active_clients[client_id]
                self.client_counter -= 1
    
    def get_client_stats(self):
        """Restituisce statistiche sui client"""
        with self.client_lock:
            current_time = time.time()
            
            # Calcola statistiche aggregate M3U
            m3u_clients = [client for client in self.active_clients.values() if '/proxy/m3u' in client['endpoints']]
            total_m3u_requests = sum(client.get('m3u_requests', 0) for client in m3u_clients)
            
            stats = {
                'total_clients': len(self.active_clients),
                'total_sessions': len(self.session_clients),
                'client_counter': self.client_counter,
                'active_clients': len(self.active_clients),
                'active_sessions': len(self.session_clients),
                'total_requests': sum(client['requests'] for client in self.active_clients.values()),
                'm3u_clients': len(m3u_clients),
                'm3u_requests': total_m3u_requests,
                'clients': []
            }
            
            # Calcola tempo medio di connessione
            if self.active_clients:
                total_connection_time = sum(current_time - client['first_seen'] for client in self.active_clients.values())
                stats['avg_connection_time'] = (total_connection_time / len(self.active_clients)) / 60  # in minuti
            else:
                stats['avg_connection_time'] = 0
            
            for client_id, client_data in self.active_clients.items():
                # Calcola tempo di connessione
                connection_time = current_time - client_data['first_seen']
                last_activity = current_time - client_data['last_seen']
                
                stats['clients'].append({
                    'id': client_id,
                    'ip': client_data['ip'],
                    'user_agent': client_data['user_agent'][:50] + '...' if len(client_data['user_agent']) > 50 else client_data['user_agent'],
                    'first_seen': datetime.fromtimestamp(client_data['first_seen']).strftime('%H:%M:%S'),
                    'last_seen': datetime.fromtimestamp(client_data['last_seen']).strftime('%H:%M:%S'),
                    'connection_time_minutes': round(connection_time / 60, 1),
                    'last_activity_seconds': round(last_activity, 1),
                    'requests': client_data['requests'],
                    'm3u_requests': client_data.get('m3u_requests', 0),
                    'endpoints': list(client_data['endpoints']),
                    'has_session': client_data['session_id'] is not None,
                    'last_m3u_url': client_data.get('last_m3u_url'),
                    'url_types': list(client_data.get('url_types', set())),
                    'is_m3u_user': '/proxy/m3u' in client_data['endpoints']
                })
            
            # Ordina per ultima attività
            stats['clients'].sort(key=lambda x: x['last_activity_seconds'])
            return stats
    
    def get_realtime_stats(self):
        """Statistiche in tempo reale per WebSocket"""
        with self.client_lock:
            # Calcola statistiche M3U
            m3u_clients = [client for client in self.active_clients.values() if '/proxy/m3u' in client['endpoints']]
            total_m3u_requests = sum(client.get('m3u_requests', 0) for client in m3u_clients)
            
            return {
                'active_clients': len(self.active_clients),
                'active_sessions': len(self.session_clients),
                'total_requests': sum(client['requests'] for client in self.active_clients.values()),
                'm3u_clients': len(m3u_clients),
                'm3u_requests': total_m3u_requests,
                'timestamp': time.time()
            }

# Istanza globale del tracker - inizializzata subito dopo la definizione della classe
client_tracker = ClientTracker()

# Thread per pulizia client inattivi
def cleanup_clients_thread():
    while True:
        try:
            client_tracker.cleanup_inactive_clients()
            time.sleep(60)  # Controlla ogni minuto
        except Exception as e:
            app.logger.error(f"Errore nella pulizia client: {e}")
            time.sleep(300)

cleanup_clients_thread_instance = Thread(target=cleanup_clients_thread, daemon=True)
cleanup_clients_thread_instance.start()

def get_proxy_for_url(url, original_url=None):
    """
    Ottiene un proxy per un URL, controllando anche l'URL originale per link Vavoo risolti
    
    Args:
        url: URL finale da controllare
        original_url: URL originale (usato per link Vavoo risolti)
    """
    config = config_manager.load_config()
    no_proxy_domains = [d.strip() for d in config.get('NO_PROXY_DOMAINS', '').split(',') if d.strip()]
    
    # Pulisci blacklist scaduta
    cleanup_expired_blacklist()
    
    # Determina se è una richiesta DaddyLive
    is_daddylive_request = (
        'newkso.ru' in url.lower() or 
        '/stream-' in url.lower() or
        (original_url and ('newkso.ru' in original_url.lower() or '/stream-' in original_url.lower()))
    )
    
    # Ottieni proxy appropriati
    if is_daddylive_request and DADDY_PROXY_LIST:
        available_proxies = get_available_daddy_proxies()
        proxy_type = "DaddyLive"
    else:
        available_proxies = get_available_proxies()
        proxy_type = "normale"
    
    if not available_proxies:
        if is_daddylive_request:
            app.logger.warning("Nessun proxy DaddyLive disponibile, uso proxy normali")
            available_proxies = get_available_proxies()
            proxy_type = "normale (fallback)"
        
        if not available_proxies:
            app.logger.warning("Nessun proxy disponibile (tutti in blacklist)")
            return None
    
    try:
        # Controlla prima l'URL finale
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in no_proxy_domains):
            app.logger.info(f"URL finale {url} è in NO_PROXY_DOMAINS, connessione diretta")
            return None
        
        # Se c'è un URL originale e contiene vavoo.to, controlla anche quello
        if original_url and 'vavoo.to' in original_url.lower():
            parsed_original = urlparse(original_url)
            if any(domain in parsed_original.netloc for domain in no_proxy_domains):
                app.logger.info(f"URL originale Vavoo {original_url} è in NO_PROXY_DOMAINS, connessione diretta per {url}")
                return None
                
    except Exception as e:
        app.logger.warning(f"Errore nel parsing URL per NO_PROXY_DOMAINS: {e}")
    
    chosen_proxy = random.choice(available_proxies)
    app.logger.debug(f"Proxy {proxy_type} selezionato per {url}: {chosen_proxy}")
    return {'http': chosen_proxy, 'https': chosen_proxy}

def safe_http_request(url, headers=None, timeout=None, proxies=None, **kwargs):
    """Effettua una richiesta HTTP con gestione automatica degli errori 429 sui proxy"""
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            # Convert string proxy to dict format if needed
            proxy_dict = None
            if isinstance(proxies, dict):
                proxy_dict = proxies
            elif isinstance(proxies, str):
                proxy_dict = {'http': proxies, 'https': proxies}
            
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout or REQUEST_TIMEOUT,
                proxies=proxy_dict,
                verify=VERIFY_SSL,
                **kwargs
            )
            return response
            
        except requests.exceptions.ProxyError as e:
            # Gestione specifica per errori proxy (incluso 429)
            error_str = str(e).lower()
            if ("429" in error_str or "too many requests" in error_str) and proxies:
                # Estrai l'URL del proxy dall'errore
                proxy_url = None
                if isinstance(proxies, dict):
                    proxy_url = proxies.get('http') or proxies.get('https')
                elif isinstance(proxies, str):
                    proxy_url = proxies
                
                if proxy_url:
                    app.logger.warning(f"Proxy {proxy_url} ha restituito errore 429 (tentativo {attempt + 1}/{max_retries})")
                    
                    # Determina se è un proxy DaddyLive
                    is_daddy_proxy = proxy_url in DADDY_PROXY_LIST
                    if is_daddy_proxy:
                        add_daddy_proxy_to_blacklist(proxy_url, "429")
                    else:
                        add_proxy_to_blacklist(proxy_url, "429")
                    
                    # Prova con un nuovo proxy se disponibile
                    if attempt < max_retries - 1:
                        new_proxy_config = get_proxy_for_url(url)
                        if new_proxy_config:
                            proxies = new_proxy_config
                            app.logger.info(f"Tentativo con nuovo proxy per {url}")
                            time.sleep(retry_delay)
                            retry_delay *= 2  # Exponential backoff
                            continue
            
            app.logger.error(f"Errore proxy nella richiesta HTTP: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(retry_delay)
            retry_delay *= 2
            
        except requests.RequestException as e:
            app.logger.error(f"Errore nella richiesta HTTP: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(retry_delay)
            retry_delay *= 2
    
    # Se arriviamo qui, tutti i tentativi sono falliti
    raise requests.RequestException(f"Tutti i {max_retries} tentativi falliti per {url}")

@app.route('/admin/proxy/status')
@login_required
def proxy_status():
    """Mostra lo stato dei proxy e della blacklist"""
    try:
        with PROXY_BLACKLIST_LOCK:
            blacklist_info = {}
            for proxy_url, info in PROXY_BLACKLIST.items():
                blacklist_info[proxy_url] = {
                    'error_count': info['error_count'],
                    'error_type': info['error_type'],
                    'last_error': datetime.fromtimestamp(info['last_error']).strftime('%H:%M:%S'),
                    'blacklisted_until': datetime.fromtimestamp(info['blacklisted_until']).strftime('%H:%M:%S'),
                    'is_expired': time.time() > info['blacklisted_until'],
                    'ip_version': get_proxy_ip_version(proxy_url)
                }
        
        available_proxies = get_available_proxies()
        
        # Analizza i tipi di IP per tutti i proxy
        ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
        for proxy in PROXY_LIST:
            ip_version = get_proxy_ip_version(proxy)
            if ip_version in ip_stats:
                ip_stats[ip_version] += 1
        
        # Analizza i tipi di IP per i proxy disponibili
        available_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
        for proxy in available_proxies:
            ip_version = get_proxy_ip_version(proxy)
            if ip_version in available_ip_stats:
                available_ip_stats[ip_version] += 1
        
        return jsonify({
            'status': 'success',
            'total_proxies': len(PROXY_LIST),
            'available_proxies': len(available_proxies),
            'blacklisted_proxies': len(PROXY_BLACKLIST),
            'ip_statistics': {
                'total': ip_stats,
                'available': available_ip_stats
            },
            'blacklist_info': blacklist_info,
            'available_proxy_list': available_proxies,
            'all_proxy_list': PROXY_LIST
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel recupero stato proxy: {e}")
        return jsonify({
            'status': 'error',
            'message': f"Errore nel recupero stato: {str(e)}"
        }), 500

@app.route('/admin/proxy/clear-blacklist', methods=['POST'])
@login_required
def clear_proxy_blacklist():
    """Pulisce la blacklist dei proxy"""
    try:
        with PROXY_BLACKLIST_LOCK:
            cleared_count = len(PROXY_BLACKLIST)
            PROXY_BLACKLIST.clear()
        
        app.logger.info(f"Blacklist proxy pulita: {cleared_count} proxy rimossi")
        return jsonify({
            'status': 'success',
            'message': f"Blacklist proxy pulita: {cleared_count} proxy rimossi"
        })
        
    except Exception as e:
        app.logger.error(f"Errore nella pulizia blacklist proxy: {e}")
        return jsonify({
            'status': 'error',
            'message': f"Errore nella pulizia: {str(e)}"
        }), 500

# Thread per pulizia blacklist scaduta
def cleanup_blacklist_thread():
    """Thread per pulire automaticamente la blacklist scaduta"""
    while True:
        try:
            time.sleep(60)  # Controlla ogni minuto
            cleaned = cleanup_expired_blacklist()
            if cleaned > 0:
                app.logger.info(f"Pulizia automatica blacklist: {cleaned} proxy rimossi")
        except Exception as e:
            app.logger.error(f"Errore nella pulizia automatica blacklist: {e}")
            time.sleep(300)  # In caso di errore, aspetta 5 minuti

cleanup_blacklist_thread_instance = Thread(target=cleanup_blacklist_thread, daemon=True)
cleanup_blacklist_thread_instance.start()

@app.route('/admin/test/github', methods=['POST'])
@login_required
def test_github_connection():
    """Testa la connessione diretta a GitHub senza proxy"""
    try:
        github_url = 'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml'
        
        # Test con connessione diretta (senza proxy)
        session = requests.Session()
        session.trust_env = False  # Ignora variabili d'ambiente proxy
        
        start_time = time.time()
        response = session.get(github_url, timeout=10, verify=VERIFY_SSL)
        end_time = time.time()
        
        if response.status_code == 200:
            return jsonify({
                'status': 'success',
                'message': f'Connessione diretta a GitHub OK in {end_time - start_time:.2f}s',
                'response_time': round(end_time - start_time, 2),
                'status_code': response.status_code,
                'content_length': len(response.text)
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'GitHub risponde con status {response.status_code}',
                'status_code': response.status_code
            })
            
    except requests.exceptions.Timeout:
        return jsonify({
            'status': 'error',
            'message': 'Timeout nella connessione diretta a GitHub'
        }), 500
    except requests.exceptions.ConnectionError as e:
        return jsonify({
            'status': 'error',
            'message': f'Errore di connessione diretta a GitHub: {str(e)}'
        }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Errore generico nel test GitHub: {str(e)}'
        }), 500

@app.route('/admin/debug/repair-config', methods=['POST'])
@login_required
def repair_config():
    """Ripara il file di configurazione corrotto"""
    try:
        config_status = config_manager.get_config_status()
        
        if config_status['file_exists']:
            # Prova a leggere il file
            try:
                with open(config_manager.config_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        raise ValueError("File vuoto")
                    json.loads(content)  # Testa se è JSON valido
                
                return jsonify({
                    'status': 'success',
                    'message': 'File di configurazione è valido',
                    'config_status': config_status
                })
                
            except (json.JSONDecodeError, ValueError) as e:
                # File corrotto, ricrealo
                app.logger.warning(f"File di configurazione corrotto, ricreo: {e}")
                
                # Backup del file corrotto
                backup_file = f"{config_manager.config_file}.backup.{int(time.time())}"
                try:
                    import shutil
                    shutil.copy2(config_manager.config_file, backup_file)
                    app.logger.info(f"Backup salvato: {backup_file}")
                except Exception as backup_error:
                    app.logger.error(f"Errore backup: {backup_error}")
                
                # Ricrea il file
                config_manager.save_config(config_manager.default_config)
                
                return jsonify({
                    'status': 'success',
                    'message': f'File di configurazione riparato. Backup: {backup_file}',
                    'config_status': config_manager.get_config_status()
                })
        else:
            # File non esiste, crealo
            config_manager.save_config(config_manager.default_config)
            return jsonify({
                'status': 'success',
                'message': 'File di configurazione creato con valori di default',
                'config_status': config_manager.get_config_status()
            })
            
    except Exception as e:
        app.logger.error(f"Errore nella riparazione configurazione: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nella riparazione: {str(e)}'
        }), 500

@app.route('/admin/debug/force-save-config', methods=['POST'])
@login_required
def force_save_config():
    """Forza il salvataggio della configurazione corrente"""
    try:
        # Carica la configurazione corrente
        current_config = config_manager.load_config()
        
        # Forza il salvataggio
        save_result = config_manager.save_config(current_config)
        
        # Forza anche il backup se siamo su HuggingFace
        backup_result = False
        if config_manager._is_huggingface and config_manager._config_cache:
            backup_result = config_manager._save_backup(config_manager._config_cache)
        
        if save_result:
            # Ricarica per verificare
            reloaded_config = config_manager.load_config()
            
            # Conta quanti valori sono stati salvati (diversi dal default)
            saved_count = 0
            for key, value in reloaded_config.items():
                if key in config_manager.default_config:
                    if value != config_manager.default_config[key]:
                        saved_count += 1
            
            backup_message = f', Backup: {"OK" if backup_result else "FALLITO"}' if config_manager._is_huggingface else ''
            
            return jsonify({
                'status': 'success',
                'message': f'Configurazione forzatamente salvata ({saved_count} valori personalizzati){backup_message}',
                'config_status': config_manager.get_config_status(),
                'saved_values_count': saved_count,
                'total_values': len(reloaded_config),
                'backup_result': backup_result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Errore nel salvataggio forzato'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Errore nel salvataggio forzato: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel salvataggio forzato: {str(e)}'
        }), 500

@app.route('/admin/debug/reload-proxies', methods=['POST'])
@login_required
def reload_proxies():
    """Ricarica i proxy dalla configurazione salvata"""
    try:
        # Ricarica i proxy
        setup_proxies()
        
        # Ottieni statistiche aggiornate
        available_proxies = get_available_proxies()
        available_daddy_proxies = get_available_daddy_proxies()
        
        # Calcola statistiche IP
        ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
        for proxy in PROXY_LIST:
            ip_version = get_proxy_ip_version(proxy)
            if ip_version in ip_stats:
                ip_stats[ip_version] += 1
        
        daddy_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
        for proxy in DADDY_PROXY_LIST:
            ip_version = get_proxy_ip_version(proxy)
            if ip_version in daddy_ip_stats:
                daddy_ip_stats[ip_version] += 1
        
        return jsonify({
            'status': 'success',
            'message': f'Proxy ricaricati: {len(PROXY_LIST)} normali, {len(DADDY_PROXY_LIST)} DaddyLive',
            'proxy_stats': {
                'total_proxies': len(PROXY_LIST),
                'available_proxies': len(available_proxies),
                'total_daddy_proxies': len(DADDY_PROXY_LIST),
                'available_daddy_proxies': len(available_daddy_proxies),
                'ip_statistics': ip_stats,
                'daddy_ip_statistics': daddy_ip_stats
            },
            'proxy_list': PROXY_LIST[:5],  # Primi 5 per debug
            'daddy_proxy_list': DADDY_PROXY_LIST[:5]  # Primi 5 per debug
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel ricaricamento proxy: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel ricaricamento proxy: {str(e)}'
        }), 500

@app.route('/admin/debug/proxy-status')
@login_required
def debug_proxy_status():
    """Mostra lo stato dettagliato dei proxy"""
    try:
        # Ricarica i proxy dalla configurazione corrente
        setup_proxies()
        
        # Ottieni statistiche aggiornate
        available_proxies = get_available_proxies()
        available_daddy_proxies = get_available_daddy_proxies()
        
        # Calcola statistiche IP per i proxy attuali
        ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
        for proxy in PROXY_LIST:
            ip_version = get_proxy_ip_version(proxy)
            if ip_version in ip_stats:
                ip_stats[ip_version] += 1
        
        daddy_ip_stats = {'IPv4': 0, 'IPv6': 0, 'hostname': 0}
        for proxy in DADDY_PROXY_LIST:
            ip_version = get_proxy_ip_version(proxy)
            if ip_version in daddy_ip_stats:
                daddy_ip_stats[ip_version] += 1
        
        # Carica configurazione per vedere i proxy configurati
        config = config_manager.load_config()
        
        # Analizza i proxy dalla configurazione
        config_proxy_list = []
        config_daddy_proxy_list = []
        
        if config.get('PROXY'):
            config_proxy_list = [p.strip() for p in config.get('PROXY', '').split(',') if p.strip()]
        
        if config.get('DADDY_PROXY'):
            config_daddy_proxy_list = [p.strip() for p in config.get('DADDY_PROXY', '').split(',') if p.strip()]
        
        return jsonify({
            'status': 'success',
            'proxy_status': {
                'total_proxies': len(PROXY_LIST),
                'available_proxies': len(available_proxies),
                'blacklisted_proxies': len(PROXY_BLACKLIST),
                'total_daddy_proxies': len(DADDY_PROXY_LIST),
                'available_daddy_proxies': len(available_daddy_proxies),
                'blacklisted_daddy_proxies': len(DADDY_PROXY_BLACKLIST),
                'ip_statistics': ip_stats,
                'daddy_ip_statistics': daddy_ip_stats
            },
            'config_proxies': {
                'PROXY': config.get('PROXY', ''),
                'DADDY_PROXY': config.get('DADDY_PROXY', ''),
                'env_PROXY': os.environ.get('PROXY', 'NON_IMPOSTATA'),
                'env_DADDY_PROXY': os.environ.get('DADDY_PROXY', 'NON_IMPOSTATA'),
                'config_proxy_count': len(config_proxy_list),
                'config_daddy_proxy_count': len(config_daddy_proxy_list)
            },
            'proxy_list': PROXY_LIST,
            'daddy_proxy_list': DADDY_PROXY_LIST,
            'config_proxy_list': config_proxy_list,
            'config_daddy_proxy_list': config_daddy_proxy_list,
            'blacklist_info': {
                'normal_proxies': list(PROXY_BLACKLIST.keys()),
                'daddy_proxies': list(DADDY_PROXY_BLACKLIST.keys())
            },
            'proxy_details': [
                {
                    'url': proxy,
                    'type': detect_proxy_type(proxy),
                    'ip_version': get_proxy_ip_version(proxy),
                    'blacklisted': is_proxy_blacklisted(proxy),
                    'available': proxy in available_proxies
                }
                for proxy in PROXY_LIST
            ],
            'daddy_proxy_details': [
                {
                    'url': proxy,
                    'type': detect_proxy_type(proxy),
                    'ip_version': get_proxy_ip_version(proxy),
                    'blacklisted': is_daddy_proxy_blacklisted(proxy),
                    'available': proxy in available_daddy_proxies
                }
                for proxy in DADDY_PROXY_LIST
            ]
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel recupero stato proxy: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel recupero stato proxy: {str(e)}'
        }), 500

@app.route('/admin/debug/backup-status')
@login_required
def debug_backup_status():
    """Debug dello stato del backup configurazione"""
    try:
        backup_exists = os.path.exists(config_manager.backup_file) if config_manager._is_huggingface else False
        backup_size = 0
        backup_age = 0
        
        if backup_exists:
            backup_size = os.path.getsize(config_manager.backup_file)
            backup_age = time.time() - os.path.getmtime(config_manager.backup_file)
        
        # Informazioni sul file globale
        global_exists = os.path.exists(config_manager.global_config_file) if config_manager._is_huggingface else False
        global_size = 0
        global_age = 0
        
        if global_exists:
            global_size = os.path.getsize(config_manager.global_config_file)
            global_age = time.time() - os.path.getmtime(config_manager.global_config_file)
        
        return jsonify({
            'status': 'success',
            'backup_info': {
                'is_huggingface': config_manager._is_huggingface,
                'backup_file': config_manager.backup_file,
                'backup_exists': backup_exists,
                'backup_size': backup_size,
                'backup_age_seconds': backup_age,
                'backup_age_human': f"{int(backup_age // 3600)}h {int((backup_age % 3600) // 60)}m" if backup_age > 0 else "N/A",
                'last_backup_time': config_manager._last_backup_time,
                'backup_interval': config_manager._backup_interval,
                'config_cache_exists': config_manager._config_cache is not None
            },
            'global_sync_info': {
                'global_config_file': config_manager.global_config_file,
                'global_exists': global_exists,
                'global_size': global_size,
                'global_age_seconds': global_age,
                'global_age_human': f"{int(global_age // 3600)}h {int((global_age % 3600) // 60)}m" if global_age > 0 else "N/A",
                'last_sync_time': config_manager._last_sync_time,
                'sync_interval': config_manager._sync_interval
            }
        })
        
    except Exception as e:
        app.logger.error(f"Errore nel recupero stato backup: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel recupero stato backup: {str(e)}'
        }), 500

@app.route('/admin/debug/force-sync-config', methods=['POST'])
@login_required
def force_sync_config():
    """Forza la sincronizzazione della configurazione tra workers"""
    try:
        if not config_manager._use_global_sync:
            return jsonify({
                'status': 'error',
                'message': 'Sincronizzazione disponibile solo con workers multipli (HuggingFace o Gunicorn)'
            }), 400
        
        # Forza la sincronizzazione dal file globale
        sync_result = config_manager._sync_from_global_config()
        
        # Se abbiamo una configurazione in cache, sincronizzala anche nel file globale
        global_save_result = False
        if config_manager._config_cache:
            global_save_result = config_manager._save_to_global_config(config_manager._config_cache)
        
        if config_manager._is_huggingface:
            env_name = "HuggingFace"
        elif config_manager._is_docker_environment():
            env_name = "Docker"
        elif config_manager._is_cloud_environment():
            env_name = "Cloud (Render/Railway/Heroku)"
        else:
            env_name = "Gunicorn con workers multipli"
        
        return jsonify({
            'status': 'success',
            'sync_result': sync_result,
            'global_save_result': global_save_result,
            'message': f'Sincronizzazione forzata ({env_name}): Lettura {"OK" if sync_result else "FALLITA"}, Scrittura {"OK" if global_save_result else "FALLITA"}',
            'config_status': config_manager.get_config_status()
        })
        
    except Exception as e:
        app.logger.error(f"Errore nella sincronizzazione forzata: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nella sincronizzazione: {str(e)}'
        }), 500

@app.route('/admin/debug/websocket-status')
@login_required
def debug_websocket_status():
    """Debug dello stato del WebSocket"""
    try:
        return jsonify({
            'status': 'success',
            'websocket_info': {
                'ping_timeout': 60,
                'ping_interval': 25,
                'max_http_buffer_size': 100000000,
                'cors_enabled': True
            },
            'server_info': {
                'uptime_seconds': time.time() - psutil.Process().create_time(),
                'memory_usage_percent': psutil.virtual_memory().percent
            }
        })
    except Exception as e:
        app.logger.error(f"Errore nel debug WebSocket: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Errore nel debug: {str(e)}'
        }), 500

@app.route('/admin/test/ipv6-proxies', methods=['POST'])
@login_required
def test_ipv6_proxies():
    """Testa specificamente i proxy IPv6"""
    try:
        # Filtra solo i proxy IPv6
        ipv6_proxies = []
        for proxy in PROXY_LIST:
            if get_proxy_ip_version(proxy) == "IPv6":
                ipv6_proxies.append(proxy)
        
        if not ipv6_proxies:
            return jsonify({
                'status': 'info',
                'message': 'Nessun proxy IPv6 configurato',
                'ipv6_proxies': []
            })
        
        results = []
        test_url = 'https://httpbin.org/ip'
        
        for proxy in ipv6_proxies:
            try:
                # Test con timeout ridotto per IPv6
                proxies = {'http': proxy, 'https': proxy}
                response = requests.get(test_url, proxies=proxies, timeout=10, verify=VERIFY_SSL)
                
                if response.status_code == 200:
                    ip_info = response.json()
                    results.append({
                        'proxy': proxy,
                        'status': 'success',
                        'response_time': response.elapsed.total_seconds(),
                        'ip_detected': ip_info.get('origin', 'unknown'),
                        'message': f'IPv6 proxy funzionante in {response.elapsed.total_seconds():.2f}s'
                    })
                else:
                    results.append({
                        'proxy': proxy,
                        'status': 'error',
                        'message': f'Status code: {response.status_code}'
                    })
                    
            except requests.exceptions.Timeout:
                results.append({
                    'proxy': proxy,
                    'status': 'timeout',
                    'message': 'Timeout nella connessione IPv6'
                })
            except requests.exceptions.ConnectionError as e:
                results.append({
                    'proxy': proxy,
                    'status': 'connection_error',
                    'message': f'Errore di connessione IPv6: {str(e)}'
                })
            except Exception as e:
                results.append({
                    'proxy': proxy,
                    'status': 'error',
                    'message': f'Errore generico: {str(e)}'
                })
        
        # Calcola statistiche
        successful = len([r for r in results if r['status'] == 'success'])
        total = len(results)
        
        return jsonify({
            'status': 'success',
            'message': f'Test IPv6 completato: {successful}/{total} proxy funzionanti',
            'ipv6_proxies': ipv6_proxies,
            'results': results,
            'statistics': {
                'total': total,
                'successful': successful,
                'failed': total - successful
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Errore nel test IPv6: {str(e)}'
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    
    # Log di avvio
    app.logger.info("="*50)
    app.logger.info("🚀 PROXY SERVER AVVIATO CON WEBSOCKET")
    app.logger.info("="*50)
    app.logger.info(f"Porta: {port}")
    app.logger.info(f"WebSocket abilitato per aggiornamenti real-time")
    app.logger.info("="*50)
    
    # Informazioni sulla configurazione proxy
    proxy_env = os.environ.get('PROXY')
    
    if proxy_env:
        app.logger.info("✅ Configurazione proxy unificata rilevata (PROXY)")
        app.logger.info(f"   Proxy configurati: {len(proxy_env.split(','))}")
    else:
        app.logger.info("ℹ️  Nessun proxy configurato - connessioni dirette")
    
    app.logger.info("📖 Formati supportati: /admin/proxy/formats")
    app.logger.info("🔧 Debug proxy: /admin/debug/proxies")
    app.logger.info("="*50)
    
    # Usa socketio.run invece di app.run
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
