from flask import Flask, request, Response, jsonify
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
import threading
from datetime import datetime, timedelta
import math

app = Flask(__name__)

load_dotenv()

# --- Classe VavooResolver per gestire i link Vavoo ---
class VavooResolver:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MediaHubMX/2'
        })
    
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
            resp = self.session.post("https://www.vavoo.tv/api/app/ping", json=data, headers=headers, timeout=10)
            resp.raise_for_status()
            result = resp.json()
            addon_sig = result.get("addonSig")
            if addon_sig:
                app.logger.info("Signature Vavoo ottenuta con successo")
                return addon_sig
            else:
                app.logger.warning("Signature Vavoo non trovata nella risposta")
                return None
        except requests.RequestException as e:
            app.logger.error(f"Errore di rete nel recupero della signature Vavoo: {e}")
            return None
        except json.JSONDecodeError as e:
            app.logger.error(f"Errore nel parsing JSON della risposta Vavoo: {e}")
            return None
        except Exception as e:
            app.logger.error(f"Errore generico nel recupero della signature Vavoo: {e}")
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
            resp = self.session.post("https://vavoo.to/mediahubmx-resolve.json", json=data, headers=headers, timeout=10)
            resp.raise_for_status()
            
            if verbose:
                app.logger.info(f"Vavoo response status: {resp.status_code}")
                app.logger.info(f"Vavoo response body: {resp.text}")
            
            result = resp.json()
            if isinstance(result, list) and result and result[0].get("url"):
                resolved_url = result[0]["url"]
                channel_name = result[0].get("name", "Unknown")
                app.logger.info(f"Vavoo risolto: {channel_name} -> {resolved_url}")
                return resolved_url
            elif isinstance(result, dict) and result.get("url"):
                app.logger.info(f"Vavoo risolto: {result['url']}")
                return result["url"]
            else:
                app.logger.warning("Nessun link valido trovato nella risposta Vavoo")
                return None
                
        except Exception as e:
            app.logger.error(f"Errore nella risoluzione Vavoo: {e}")
            return None

# Istanza globale del resolver Vavoo
vavoo_resolver = VavooResolver()

# --- Configurazione Cache ---
def setup_all_caches():
    global M3U8_CACHE, TS_CACHE, KEY_CACHE
    try:
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
    except NameError:
        # Fallback se config_manager non è ancora disponibile
        M3U8_CACHE = TTLCache(maxsize=100, ttl=300)
        TS_CACHE = TTLCache(maxsize=1000, ttl=60)
        KEY_CACHE = TTLCache(maxsize=50, ttl=3600)
        app.logger.info("Cache inizializzata con valori di fallback.")

# --- Configurazione Generale ---
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() not in ('false', '0', 'no')
if not VERIFY_SSL:
    print("ATTENZIONE: La verifica del certificato SSL è DISABILITATA. Questo potrebbe esporre a rischi di sicurezza.")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Timeout aumentato per gestire meglio i segmenti TS di grandi dimensioni
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))
print(f"Timeout per le richieste impostato a {REQUEST_TIMEOUT} secondi.")

# Sistema di statistiche (senza WebSocket) - spostato dopo la definizione di pre_buffer_manager

# Configurazioni Keep-Alive
KEEP_ALIVE_TIMEOUT = int(os.environ.get('KEEP_ALIVE_TIMEOUT', 300))  # 5 minuti
MAX_KEEP_ALIVE_REQUESTS = int(os.environ.get('MAX_KEEP_ALIVE_REQUESTS', 1000))
POOL_CONNECTIONS = int(os.environ.get('POOL_CONNECTIONS', 20))
POOL_MAXSIZE = int(os.environ.get('POOL_MAXSIZE', 50))

print(f"Keep-Alive configurato: timeout={KEEP_ALIVE_TIMEOUT}s, max_requests={MAX_KEEP_ALIVE_REQUESTS}")

# --- Setup Logging System ---
def setup_logging():
    """Configura il sistema di logging solo su console"""
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # Handler solo per console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Configura il logger principale
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)

setup_logging()

# --- Configurazione Manager ---
class ConfigManager:
    def __init__(self):
        self.config_file = 'proxy_config.json'
        self.default_config = {
            'PROXY': '',
            'DADDY_PROXY': '',
            'REQUEST_TIMEOUT': 45,
            'VERIFY_SSL': False,
            'KEEP_ALIVE_TIMEOUT': 900,
            'MAX_KEEP_ALIVE_REQUESTS': 5000,
            'POOL_CONNECTIONS': 50,
            'POOL_MAXSIZE': 300,
            'CACHE_TTL_M3U8': 5,
            'CACHE_TTL_TS': 600,
            'CACHE_TTL_KEY': 600,
            'CACHE_MAXSIZE_M3U8': 500,
            'CACHE_MAXSIZE_TS': 8000,
            'CACHE_MAXSIZE_KEY': 1000,
            'CACHE_ENABLED' : True,
            'NO_PROXY_DOMAINS': 'github.com,raw.githubusercontent.com',
            'PREBUFFER_ENABLED': True,
            'PREBUFFER_MAX_SEGMENTS': 5,
            'PREBUFFER_MAX_SIZE_MB': 200,
            'PREBUFFER_CLEANUP_INTERVAL': 300,
            'PREBUFFER_MAX_MEMORY_PERCENT': 30.0,
            'PREBUFFER_EMERGENCY_THRESHOLD': 99.9,
        }
        
    def load_config(self):
        """Carica la configurazione combinando proxy da file e variabili d'ambiente"""
        # Inizia con i valori di default
        config = self.default_config.copy()
        
        # Carica dal file se esiste (seconda priorità)
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    config.update(file_config)
            except Exception as e:
                app.logger.error(f"Errore nel caricamento della configurazione: {e}")
        
        # Gestione proxy unificata
        proxy_value = os.environ.get('PROXY', '')
        if proxy_value and proxy_value.strip():
            config['PROXY'] = proxy_value.strip()
            app.logger.info(f"Proxy generale configurato: {proxy_value}")
        
        # Gestione proxy DaddyLive specifico
        daddy_proxy_value = os.environ.get('DADDY_PROXY', '')
        if daddy_proxy_value and daddy_proxy_value.strip():
            config['DADDY_PROXY'] = daddy_proxy_value.strip()
            app.logger.info(f"Proxy DaddyLive configurato: {daddy_proxy_value}")
        
        # Per le altre variabili, mantieni la priorità alle env vars
        for key in config.keys():
            if key not in ['PROXY', 'DADDY_PROXY']:  # Salta i proxy che abbiamo già gestito
                env_value = os.environ.get(key)
                if env_value is not None:
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
        
        return config
    
    def save_config(self, config):
        """Salva la configurazione nel file JSON"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
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
                            proxy_config = get_proxy_for_url(segment_url)
                            proxy_key = proxy_config['http'] if proxy_config else None
                            
                            response = make_persistent_request(
                                segment_url,
                                headers=headers,
                                timeout=get_dynamic_timeout(segment_url),
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

# --- Playlist Generator Functions ---
def rewrite_m3u_links_streaming(m3u_lines_iterator, base_url, api_password):
    """
    Riscrive i link da un iteratore di linee M3U secondo le regole specificate,
    includendo gli headers da #EXTVLCOPT e #EXTHTTP. Yields rewritten lines.
    """
    current_ext_headers = {} # Dizionario per conservare gli headers dalle direttive
    
    for line_with_newline in m3u_lines_iterator:
        line_content = line_with_newline.rstrip('\n')
        logical_line = line_content.strip()
        
        is_header_tag = False
        if logical_line.startswith('#EXTVLCOPT:'):
            is_header_tag = True
            try:
                option_str = logical_line.split(':', 1)[1]
                if '=' in option_str:
                    key_vlc, value_vlc = option_str.split('=', 1)
                    key_vlc = key_vlc.strip()
                    value_vlc = value_vlc.strip()
 
                    # Gestione speciale per http-header che contiene "Key: Value"
                    if key_vlc == 'http-header' and ':' in value_vlc:
                        header_key, header_value = value_vlc.split(':', 1)
                        header_key = header_key.strip()
                        header_value = header_value.strip()
                        current_ext_headers[header_key] = header_value
                        app.logger.info(f"Trovato header da #EXTVLCOPT (http-header): {{'{header_key}': '{header_value}'}}")
                    elif key_vlc.startswith('http-'):
                        # Gestisce http-user-agent, http-referer etc.
                        header_key = '-'.join(word.capitalize() for word in key_vlc[len('http-'):].split('-'))
                    
                        current_ext_headers[header_key] = value_vlc
                        app.logger.info(f"Trovato header da #EXTVLCOPT: {{'{header_key}': '{value_vlc}'}}")
            except Exception as e:
                app.logger.error(f"Errore nel parsing di #EXTVLCOPT '{logical_line}': {e}")
        
        elif logical_line.startswith('#EXTHTTP:'):
            is_header_tag = True
            try:
                json_str = logical_line.split(':', 1)[1]
                # Sostituisce tutti gli header correnti con quelli del JSON
                current_ext_headers = json.loads(json_str)
                app.logger.info(f"Trovati headers da #EXTHTTP: {current_ext_headers}")
            except Exception as e:
                app.logger.error(f"Errore nel parsing di #EXTHTTP '{logical_line}': {e}")
                current_ext_headers = {} # Resetta in caso di errore

        if is_header_tag:
            yield line_with_newline
            continue
        
        if logical_line and not logical_line.startswith('#') and \
           ('http://' in logical_line or 'https://' in logical_line):
            app.logger.info(f"Processando link: {logical_line[:100]}...")
            
            # Decide la logica di riscrittura in base alla presenza della password
            if api_password is not None:
                # --- LOGICA CON PASSWORD (ESISTENTE) ---
                processed_url_content = logical_line
                
                if 'vixsrc.to' in logical_line:
                    processed_url_content = f"{base_url}/extractor/video?host=VixCloud&redirect_stream=true&api_password={api_password}&d={logical_line}"
                    app.logger.info(f"Riscritto VixCloud: {logical_line[:50]}... -> {processed_url_content[:50]}...")
                elif '.m3u8' in logical_line:
                    processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?api_password={api_password}&d={logical_line}"
                    app.logger.info(f"Riscritto M3U8: {logical_line[:50]}... -> {processed_url_content[:50]}...")
                elif '.mpd' in logical_line:
                    processed_url_content = f"{base_url}/proxy/mpd/manifest.m3u8?api_password={api_password}&d={logical_line}"
                    app.logger.info(f"Riscritto MPD: {logical_line[:50]}... -> {processed_url_content[:50]}...")
                elif '.php' in logical_line:
                    processed_url_content = f"{base_url}/extractor/video?host=DLHD&redirect_stream=true&api_password={api_password}&d={logical_line}"
                    app.logger.info(f"Riscritto PHP: {logical_line[:50]}... -> {processed_url_content[:50]}...")
                else:
                    # Link non modificato dalle regole, ma gli header potrebbero essere aggiunti
                    app.logger.info(f"Link non modificato (pattern): {logical_line[:50]}...")
            else:
                # --- NUOVA LOGICA SENZA PASSWORD ---
                processed_url_content = f"{base_url}/proxy/m3u?url={logical_line}"
                app.logger.info(f"Riscritto (senza password): {logical_line[:50]}... -> {processed_url_content[:50]}...")
            
            # Applica gli header raccolti, indipendentemente dalla modalità
            if current_ext_headers:
                header_params_str = "".join([f"&h_{quote(key)}={quote(quote(value))}" for key, value in current_ext_headers.items()])
                processed_url_content += header_params_str
                app.logger.info(f"Aggiunti headers a URL: {header_params_str} -> {processed_url_content[:150]}...")
                current_ext_headers = {}
            
            yield processed_url_content + '\n'
        else:
            yield line_with_newline

def download_m3u_playlist_streaming(url):
    """Scarica una playlist M3U in modalità streaming"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        app.logger.info(f"Scaricamento (streaming) da: {url}")
        
        proxy_config = get_proxy_for_url(url)
        proxy_key = proxy_config['http'] if proxy_config else None
        
        with make_persistent_request(url, headers=headers, timeout=REQUEST_TIMEOUT, proxy_url=proxy_key, stream=True) as response:
            app.logger.info(f"Status code: {response.status_code}")
            app.logger.info(f"Headers risposta (prime parti): {{k: v[:100] for k, v in dict(response.headers).items()}}")
            response.raise_for_status()
            for line_bytes in response.iter_lines():
                decoded_line = line_bytes.decode('utf-8', errors='replace')
                # Explicitly check for and skip empty lines after decoding
                yield decoded_line + '\n' if decoded_line else ''
        
    except requests.RequestException as e:
        app.logger.error(f"Errore download (streaming): {str(e)}")
        raise Exception(f"Errore nel download (streaming) della playlist: {str(e)}")
    except Exception as e:
        app.logger.error(f"Errore generico durante lo streaming del download da {url}: {str(e)}")
        raise

# Sistema di statistiche (senza WebSocket)
def get_system_stats():
    """Ottiene le statistiche di sistema"""
    stats = {}
    
    # Memoria RAM
    memory = psutil.virtual_memory()
    stats['ram_usage'] = memory.percent
    stats['ram_used_gb'] = memory.used / (1024**3)  # GB
    stats['ram_total_gb'] = memory.total / (1024**3)  # GB
    
    # Utilizzo di rete
    net_io = psutil.net_io_counters()
    stats['network_sent'] = net_io.bytes_sent / (1024**2)  # MB
    stats['network_recv'] = net_io.bytes_recv / (1024**2)  # MB
    
    # Statistiche pre-buffer
    try:
        with pre_buffer_manager.pre_buffer_lock:
            total_segments = sum(len(segments) for segments in pre_buffer_manager.pre_buffer.values())
            total_size = sum(
                sum(len(content) for content in segments.values())
                for segments in pre_buffer_manager.pre_buffer.values()
            )
            stats['prebuffer_streams'] = len(pre_buffer_manager.pre_buffer)
            stats['prebuffer_segments'] = total_segments
            stats['prebuffer_size_mb'] = round(total_size / (1024 * 1024), 2)
            stats['prebuffer_threads'] = len(pre_buffer_manager.pre_buffer_threads)
    except Exception as e:
        app.logger.error(f"Errore nel calcolo statistiche pre-buffer: {e}")
        stats['prebuffer_streams'] = 0
        stats['prebuffer_segments'] = 0
        stats['prebuffer_size_mb'] = 0
        stats['prebuffer_threads'] = 0
    
    return stats

# Avvia il thread di pulizia del buffer
cleanup_thread = Thread(target=pre_buffer_manager.cleanup_old_buffers, daemon=True)
cleanup_thread.start()

# --- Log Manager ---
class LogManager:
    def __init__(self):
        pass
        
    def get_log_files(self):
        """Log non salvati su file"""
        return []
    
    def read_log_file(self, filename, lines=100):
        """Log non salvati su file"""
        return ["Log non salvati su file - solo output console"]
    
    def stream_log_file(self, filename):
        """Log non salvati su file"""
        def generate():
            yield f"data: {json.dumps({'error': 'Log non salvati su file'})}\n\n"
        return generate()

log_manager = LogManager()

# --- Variabili globali per cache e sessioni ---

# Inizializza cache globali (verranno sovrascritte da setup_all_caches)
M3U8_CACHE = {}
TS_CACHE = {}
KEY_CACHE = {}

# Pool globale di sessioni per connessioni persistenti
SESSION_POOL = {}
SESSION_LOCK = Lock()

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

# Avvia il thread di gestione connessioni
connection_thread = Thread(target=connection_manager, daemon=True)
connection_thread.start()

# --- Configurazione Proxy ---
PROXY_LIST = []

def setup_proxies():
    """Carica la lista di proxy dalla variabile PROXY unificata."""
    global PROXY_LIST
    proxies_found = []

    # Carica configurazione
    config = config_manager.load_config()
    proxy_value = config.get('PROXY', '')

    if proxy_value and proxy_value.strip():
        # Separa i proxy se ce ne sono più di uno
        proxy_list = [p.strip() for p in proxy_value.split(',') if p.strip()]
        
        for proxy in proxy_list:
            # Gestione automatica del tipo di proxy
            if proxy.startswith('socks5://'):
                # Converti SOCKS5 in SOCKS5H per risoluzione DNS remota
                final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                app.logger.info(f"Proxy SOCKS5 convertito: {proxy} -> {final_proxy_url}")
            elif proxy.startswith('socks5h://'):
                final_proxy_url = proxy
                app.logger.info(f"Proxy SOCKS5H configurato: {proxy}")
            elif proxy.startswith('http://') or proxy.startswith('https://'):
                final_proxy_url = proxy
                app.logger.info(f"Proxy HTTP/HTTPS configurato: {proxy}")
            else:
                # Se non ha protocollo, assume HTTP
                if not proxy.startswith('http://') and not proxy.startswith('https://'):
                    final_proxy_url = f"http://{proxy}"
                    app.logger.info(f"Proxy senza protocollo, convertito in HTTP: {proxy} -> {final_proxy_url}")
                else:
                    final_proxy_url = proxy
                    app.logger.info(f"Proxy configurato: {proxy}")
            
            proxies_found.append(final_proxy_url)
        
        app.logger.info(f"Trovati {len(proxies_found)} proxy generali. Verranno usati a rotazione per ogni richiesta.")
        
        # Avviso per SOCKS5
        if any('socks5' in proxy for proxy in proxies_found):
            app.logger.info("Assicurati di aver installato la dipendenza per SOCKS: 'pip install PySocks'")

    PROXY_LIST = proxies_found

    if PROXY_LIST:
        app.logger.info(f"Totale di {len(PROXY_LIST)} proxy generali configurati.")
    else:
        app.logger.info("Nessun proxy generale configurato.")

def get_daddy_proxy_list():
    """Carica la lista di proxy specifici per DaddyLive."""
    config = config_manager.load_config()
    daddy_proxy_value = config.get('DADDY_PROXY', '')
    daddy_proxies = []

    if daddy_proxy_value and daddy_proxy_value.strip():
        # Separa i proxy se ce ne sono più di uno
        proxy_list = [p.strip() for p in daddy_proxy_value.split(',') if p.strip()]
        
        for proxy in proxy_list:
            # Gestione automatica del tipo di proxy
            if proxy.startswith('socks5://'):
                # Converti SOCKS5 in SOCKS5H per risoluzione DNS remota
                final_proxy_url = 'socks5h' + proxy[len('socks5'):]
                app.logger.info(f"Proxy DaddyLive SOCKS5 convertito: {proxy} -> {final_proxy_url}")
            elif proxy.startswith('socks5h://'):
                final_proxy_url = proxy
                app.logger.info(f"Proxy DaddyLive SOCKS5H configurato: {proxy}")
            elif proxy.startswith('http://') or proxy.startswith('https://'):
                final_proxy_url = proxy
                app.logger.info(f"Proxy DaddyLive HTTP/HTTPS configurato: {proxy}")
            else:
                # Se non ha protocollo, assume HTTP
                if not proxy.startswith('http://') and not proxy.startswith('https://'):
                    final_proxy_url = f"http://{proxy}"
                    app.logger.info(f"Proxy DaddyLive senza protocollo, convertito in HTTP: {proxy} -> {final_proxy_url}")
                else:
                    final_proxy_url = proxy
                    app.logger.info(f"Proxy DaddyLive configurato: {proxy}")
            
            daddy_proxies.append(final_proxy_url)
        
        app.logger.info(f"Trovati {len(daddy_proxies)} proxy DaddyLive. Verranno usati a rotazione per contenuti DaddyLive.")
        
        # Avviso per SOCKS5
        if any('socks5' in proxy for proxy in daddy_proxies):
            app.logger.info("Assicurati di aver installato la dipendenza per SOCKS: 'pip install PySocks'")
    
    return daddy_proxies

def get_proxy_for_url(url):
    config = config_manager.load_config()
    no_proxy_domains = [d.strip() for d in config.get('NO_PROXY_DOMAINS', '').split(',') if d.strip()]
    
    # Controlla se è un URL DaddyLive
    is_daddylive = (
        'newkso.ru' in url.lower() or 
        '/stream-' in url.lower() or
        re.search(r'/premium(\d+)/mono\.m3u8$', url) is not None
    )
    
    # Se è DaddyLive, usa i proxy specifici
    if is_daddylive:
        daddy_proxies = get_daddy_proxy_list()
        if daddy_proxies:
            chosen_proxy = random.choice(daddy_proxies)
            app.logger.debug(f"Usando proxy DaddyLive per {url}: {chosen_proxy}")
            return {'http': chosen_proxy, 'https': chosen_proxy}
    
    # Altrimenti usa i proxy generali
    if not PROXY_LIST:
        return None
    
    try:
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in no_proxy_domains):
            return None
    except Exception:
        pass
    
    chosen_proxy = random.choice(PROXY_LIST)
    app.logger.debug(f"Usando proxy generale per {url}: {chosen_proxy}")
    return {'http': chosen_proxy, 'https': chosen_proxy}

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
    
    # Configurazione Keep-Alive
    session.headers.update({
        'Connection': 'keep-alive',
        'Keep-Alive': f'timeout={KEEP_ALIVE_TIMEOUT}, max={MAX_KEEP_ALIVE_REQUESTS}'
    })
    
    # Configurazione retry automatico
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=POOL_CONNECTIONS, pool_maxsize=POOL_MAXSIZE)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    


def get_persistent_session(proxy_url=None):
    """Ottiene una sessione persistente dal pool o ne crea una nuova"""
    global SESSION_POOL, SESSION_LOCK
    
    # Usa proxy_url come chiave, o 'default' se non c'è proxy
    pool_key = proxy_url if proxy_url else 'default'
    
    with SESSION_LOCK:
        if pool_key not in SESSION_POOL:
            session = create_robust_session()
            
            if session is None:
                app.logger.error(f"Impossibile creare sessione per: {pool_key}")
                return None
            
            # Configura proxy se fornito
            if proxy_url:
                session.proxies.update({'http': proxy_url, 'https': proxy_url})
            
            SESSION_POOL[pool_key] = session
            app.logger.info(f"Nuova sessione persistente creata per: {pool_key}")
        
        return SESSION_POOL[pool_key]

def make_persistent_request(url, headers=None, timeout=None, proxy_url=None, **kwargs):
    """Effettua una richiesta usando connessioni persistenti"""
    session = get_persistent_session(proxy_url)
    
    if session is None:
        app.logger.error("Impossibile ottenere sessione persistente")
        raise Exception("Impossibile ottenere sessione persistente")
    
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
        
        # Force direct connection for GitHub (no proxy)
        response = requests.get(
            github_url,
            timeout=REQUEST_TIMEOUT,
            proxies=None,  # Force direct connection
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
            app.logger.info(f"Rilevato link Vavoo, tentativo di risoluzione: {clean_url}")
            
            try:
                resolved_vavoo = vavoo_resolver.resolve_vavoo_link(clean_url, verbose=True)
                if resolved_vavoo:
                    app.logger.info(f"Vavoo risolto con successo: {resolved_vavoo}")
                    return {
                        "resolved_url": resolved_vavoo,
                        "headers": final_headers
                    }
                else:
                    app.logger.warning(f"Impossibile risolvere il link Vavoo, passo l'originale: {clean_url}")
                    return {
                        "resolved_url": clean_url,
                        "headers": final_headers
                    }
            except Exception as e:
                app.logger.error(f"Errore nella risoluzione Vavoo: {e}")
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
        max_retries = 3
        for retry in range(max_retries):
            try:
                proxy_config = get_proxy_with_fallback(stream_url)
                response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=proxy_config, verify=VERIFY_SSL)
                response.raise_for_status()
                break  # Success, exit retry loop
            except requests.exceptions.ProxyError as e:
                if "429" in str(e) and retry < max_retries - 1:
                    app.logger.warning(f"Proxy rate limited (429), retry {retry + 1}/{max_retries}: {stream_url}")
                    time.sleep(2 ** retry)  # Exponential backoff
                    continue
                else:
                    raise
            except requests.RequestException as e:
                if retry < max_retries - 1:
                    app.logger.warning(f"Request failed, retry {retry + 1}/{max_retries}: {stream_url}")
                    time.sleep(1)
                    continue
                else:
                    raise

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
            "headers": {**final_headers, **final_headers_for_fetch}
        }

    except Exception as e:
        app.logger.error(f"Errore durante la risoluzione DaddyLive: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        # In caso di errore nella risoluzione, restituisce l'URL originale
        return {"resolved_url": clean_url, "headers": final_headers}

# Thread di statistiche rimosso - solo proxy

    
@app.route('/')
def index():
    """Pagina principale con interfaccia web"""
    html_content = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TV Proxy Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 800px;
            width: 100%;
            text-align: center;
        }
        
        .logo {
            font-size: 3rem;
            font-weight: bold;
            color: #4a5568;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .subtitle {
            font-size: 1.2rem;
            color: #718096;
            margin-bottom: 30px;
        }
        
        .status {
            background: #f7fafc;
            border: 2px solid #e2e8f0;
            border-radius: 15px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .status h3 {
            color: #2d3748;
            margin-bottom: 15px;
        }
        
        .endpoints {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .endpoint {
            background: #edf2f7;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid #4299e1;
        }
        
        .endpoint h4 {
            color: #2b6cb0;
            margin-bottom: 10px;
        }
        
        .endpoint p {
            color: #4a5568;
            font-size: 0.9rem;
            line-height: 1.5;
        }
        
        .example {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .features {
            background: #f0fff4;
            border: 2px solid #9ae6b4;
            border-radius: 15px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .features h3 {
            color: #22543d;
            margin-bottom: 15px;
        }
        
        .feature-list {
            list-style: none;
            text-align: left;
        }
        
        .feature-list li {
            padding: 8px 0;
            color: #2f855a;
            position: relative;
            padding-left: 25px;
        }
        
        .feature-list li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #38a169;
            font-weight: bold;
        }
        
        .footer {
            margin-top: 30px;
            color: #718096;
            font-size: 0.9rem;
        }
        
        @media (max-width: 600px) {
            .container {
                padding: 20px;
            }
            
            .logo {
                font-size: 2rem;
            }
            
            .endpoints {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">📺 TV Proxy Server</div>
        <div class="subtitle">Server proxy intelligente per streaming TV e IPTV</div>
        
        <div class="status">
            <h3>🟢 Server Online</h3>
            <p>Il server è attivo e pronto a gestire le richieste proxy</p>
        </div>
        
        <div class="endpoints">
            <div class="endpoint">
                <h4>📋 Proxy M3U/M3U8</h4>
                <p>Gestisce playlist M3U e stream M3U8 con supporto per DaddyLive e Vavoo</p>
                <div class="example">/proxy/m3u?url=URL_PLAYLIST</div>
            </div>
            
            <div class="endpoint">
                <h4>🔗 Proxy TS</h4>
                <p>Gestisce segmenti video .ts con caching e pre-buffering</p>
                <div class="example">/proxy/ts?url=URL_SEGMENTO</div>
            </div>
            
            <div class="endpoint">
                <h4>🔑 Proxy Key</h4>
                <p>Gestisce chiavi di crittografia AES-128 per stream protetti</p>
                <div class="example">/proxy/key?url=URL_CHIAVE</div>
            </div>
            
            <div class="endpoint">
                <h4>🎯 Risoluzione URL</h4>
                <p>Risolve URL PHP di DADDY</p>
                <div class="example">/proxy/resolve?url=URL_COMPLESSO</div>
            </div>
            
            <div class="endpoint">
                <h4>🔗 Playlist Builder</h4>
                <p>Combina multiple playlist M3U in una singola</p>
                <div class="example">/builder</div>
            </div>
        </div>
        
        <div class="features">
            <h3>✨ Funzionalità Avanzate</h3>
            <ul class="feature-list">
                <li>Supporto per proxy SOCKS5 e HTTP/HTTPS</li>
                <li>Caching intelligente per M3U8, TS e chiavi</li>
                <li>Pre-buffering automatico per ridurre il buffering</li>
                <li>Risoluzione automatica DaddyLive 2025</li>
                <li>Supporto per link Vavoo con risoluzione</li>
                <li>Gestione headers personalizzati</li>
                <li>Connessioni persistenti con Keep-Alive</li>
                <li>Retry automatico in caso di errori</li>
                <li>Playlist Builder per combinare multiple playlist</li>
                <li>Riscrittura automatica di link VixCloud, M3U8, MPD e PHP</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Server configurato per Huggingface Spaces e deployment cloud</p>
            <p>© 2024 TV Proxy Server - Tutti i diritti riservati</p>
        </div>
        
        <div class="home-link" style="margin-top: 30px;">
            <a href="/builder" class="btn" style="background: #28a745;">🔗 Playlist Builder</a>
        </div>
    </div>
</body>
</html>
    """
    return html_content

@app.route('/builder')
def url_builder():
    """
    Pagina con un'interfaccia per generare l'URL del proxy.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="it">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>URL Builder - Server Proxy M3U</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; margin-bottom: 30px; }
            h2 { color: #2c5aa0; border-bottom: 2px solid #2c5aa0; padding-bottom: 5px; text-align: left; margin-top: 30px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
            input[type="text"], input[type="url"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            .btn { display: inline-block; padding: 10px 20px; background: #2c5aa0; color: white; text-decoration: none; border-radius: 5px; margin: 5px; cursor: pointer; border: none; font-size: 16px; }
            .btn:hover { background: #1e3d6f; }
            .btn-add { background-color: #28a745; }
            .btn-remove { background-color: #dc3545; padding: 5px 10px; font-size: 12px; }
            .playlist-entry { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 15px; border-left: 4px solid #17a2b8; position: relative; }
            .output-area { margin-top: 20px; }
            #generated-url { background: #e9ecef; padding: 10px; border: 1px solid #ced4da; border-radius: 4px; font-family: 'Courier New', monospace; word-break: break-all; min-height: 50px; white-space: pre-wrap; }
            .home-link { text-align: center; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔗 URL Builder per Proxy M3U</h1>
            
            <div class="form-group">
                <label for="server-address">Indirizzo del tuo Server Proxy</label>
                <input type="text" id="server-address" placeholder="Indirizzo del server corrente" value="" readonly style="background-color: #e9ecef;">
            </div>

            <h2>Playlist da Unire</h2>
            <div id="playlist-container">
                <!-- Le playlist verranno aggiunte qui dinamicamente -->
            </div>

            <button type="button" class="btn btn-add" onclick="addPlaylistEntry()">Aggiungi Playlist</button>
            <hr style="margin: 20px 0;">

            <button type="button" class="btn" onclick="generateUrl()">Genera URL</button>

            <div class="output-area">
                <label for="generated-url">URL Generato</label>
                <div id="generated-url">L'URL apparirà qui...</div>
            </div>

            <div class="home-link">
                <a href="/" class="btn">Torna alla Home</a>
            </div>
        </div>

        <!-- Template per una singola playlist -->
        <template id="playlist-template">
            <div class="playlist-entry">
                <button type="button" class="btn btn-remove" style="position: absolute; top: 10px; right: 10px;" onclick="this.parentElement.remove()">Rimuovi</button>
                <div class="form-group">
                    <label>Dominio (MFP o TvProxy, con porta se necessario)</label>
                    <input type="text" class="dominio" placeholder="Es: https://mfp.com oppure https://tvproxy.com">
                </div>
                <div class="form-group">
                    <label>Password API</label>
                    <input type="text" class="password" placeholder="Obbligatoria per MFP, lasciare vuoto per TvProxy">
                    <small style="color: #6c757d; display: block; margin-top: 4px;">
                        <b>MFP:</b> Inserire la password. <br><b>TvProxy:</b> Lasciare vuoto.</small>
                </div>
                <div class="form-group">
                    <label>URL della Playlist M3U</label>
                    <input type="url" class="playlist-url" placeholder="Es: http://provider.com/playlist.m3u">
                </div>
            </div>
        </template>

        <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Imposta l'indirizzo del server di default
                document.getElementById('server-address').value = window.location.origin;
                // Aggiunge una playlist di default all'avvio
                addPlaylistEntry();
            });

            function addPlaylistEntry() {
                const template = document.getElementById('playlist-template').content.cloneNode(true);
                document.getElementById('playlist-container').appendChild(template);
            }

            function generateUrl() {
                const serverAddress = document.getElementById('server-address').value.trim().replace(/\\/$/, '');
                if (!serverAddress) {
                    alert('Indirizzo del server non disponibile. Ricarica la pagina.');
                    return;
                }

                const entries = document.querySelectorAll('.playlist-entry');
                const definitions = [];

                entries.forEach(entry => {
                    const dominio = entry.querySelector('.dominio').value.trim();
                    const password = entry.querySelector('.password').value.trim();
                    const playlistUrl = entry.querySelector('.playlist-url').value.trim();

                    if (dominio && playlistUrl) {
                        let credsPart = dominio;
                        if (password) {
                            credsPart += ':' + password;
                        }
                        definitions.push(credsPart + '&' + playlistUrl);
                    }
                });

                if (definitions.length === 0) {
                    document.getElementById('generated-url').textContent = 'Nessuna playlist valida inserita.';
                    return;
                }

                const finalUrl = serverAddress + '/proxy?' + definitions.join(';');
                document.getElementById('generated-url').textContent = finalUrl;
            }


        </script>
    </body>
    </html>
    """
    return html_content


@app.route('/proxy/vavoo')
def proxy_vavoo():
    """Route specifica per testare la risoluzione Vavoo"""
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
        app.logger.info(f"Richiesta risoluzione Vavoo: {url}")
        resolved = vavoo_resolver.resolve_vavoo_link(url, verbose=True)
        
        if resolved:
            app.logger.info(f"Vavoo risolto: {resolved}")
            return jsonify({
                "status": "success",
                "original_url": url,
                "resolved_url": resolved,
                "method": "vavoo_direct"
            })
        else:
            app.logger.warning(f"Risoluzione Vavoo fallita per: {url}")
            return jsonify({
                "status": "error",
                "original_url": url,
                "resolved_url": None,
                "error": "Impossibile risolvere il link Vavoo"
            }), 500
            
    except Exception as e:
        app.logger.error(f"Errore nella risoluzione Vavoo: {e}")
        return jsonify({
            "status": "error",
            "original_url": url,
            "error": str(e)
        }), 500

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto DaddyLive 2025, caching intelligente e pre-buffering"""
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
    # Controlla se è una richiesta di combinazione playlist (formato: /proxy?def1&url1;def2&url2)
    query_string = request.query_string.decode('utf-8')
    
    if ';' in query_string:
        # Modalità combinazione playlist
        return proxy_playlist_combiner()
    else:
        # Modalità proxy singola playlist (comportamento originale)
        return proxy_single_playlist()

def proxy_playlist_combiner():
    """Gestisce la combinazione di multiple playlist"""
    try:
        query_string = request.query_string.decode('utf-8')
        app.logger.info(f"=== DEBUG PROXY COMBINER ===")
        app.logger.info(f"Query string: {query_string}")

        if not query_string:
            return "Query string mancante", 400

        playlist_definitions = query_string.split(';')

        def generate_combined_playlist():
            first_playlist_header_handled = False # Tracks if the main #EXTM3U header context is done
            total_bytes_yielded = 0
            log_interval_bytes = 10 * 1024 * 1024 # Log every 10MB
            last_log_bytes_milestone = 0

            for definition_idx, definition in enumerate(playlist_definitions):
                if '&' not in definition:
                    app.logger.warning(f"[{definition_idx}] Skipping invalid playlist definition (manca '&'): {definition}")
                    yield f"# SKIPPED Invalid Definition: {definition}\n"
                    continue

                parts = definition.split('&', 1)
                creds_part, playlist_url_str = parts
                
                api_password = None
                base_url_part = creds_part

                # Heuristics to distinguish domain:port or scheme:// from domain:password
                if ':' in creds_part:
                    possible_base, possible_pass = creds_part.rsplit(':', 1)
                    
                    # A password is assumed if the part after the last colon is not a port (all digits)
                    # and does not start with '//' (which would mean we split a URL scheme like http://)
                    if not possible_pass.startswith('//') and not possible_pass.isdigit():
                        base_url_part = possible_base
                        api_password = possible_pass
                
                if api_password is not None:
                    app.logger.info(f"  [{definition_idx}] Base URL: {base_url_part}, Password: {'*' * len(api_password)}")
                else:
                    # Nessuna password fornita (o la parte dopo ':' era una porta/scheme)
                    app.logger.info(f"  [{definition_idx}] Base URL: {base_url_part}, Modalità senza password.")

                base_url_part = base_url_part.rstrip('/')
                app.logger.info(f"[{definition_idx}] Processing Playlist (streaming): {playlist_url_str}")

                current_playlist_had_lines = False
                first_line_of_this_segment = True
                lines_processed_for_current_playlist = 0
                try:
                    downloaded_lines_iter = download_m3u_playlist_streaming(playlist_url_str)
                    app.logger.info(f"  [{definition_idx}] Download stream initiated for {playlist_url_str}")
                    rewritten_lines_iter = rewrite_m3u_links_streaming(
                        downloaded_lines_iter, base_url_part, api_password
                    )
                    
                    for line in rewritten_lines_iter:
                        current_playlist_had_lines = True
                        is_extm3u_line = line.strip().startswith('#EXTM3U')
                        lines_processed_for_current_playlist += 1

                        if not first_playlist_header_handled: # Still in the context of the first playlist's header
                            yield line
                            if is_extm3u_line:
                                first_playlist_header_handled = True  # Main header yielded
                            
                            line_bytes = len(line.encode('utf-8', 'replace')) # Use 'replace' for safety
                            total_bytes_yielded += line_bytes
                            
                            if total_bytes_yielded // log_interval_bytes > last_log_bytes_milestone:
                                last_log_bytes_milestone = total_bytes_yielded // log_interval_bytes
                                app.logger.info(f"ℹ️ [{definition_idx}] Total data yielded: {total_bytes_yielded / (1024*1024):.2f} MB. Current playlist lines: {lines_processed_for_current_playlist}")

                            if len(line) > 10000: 
                                app.logger.warning(f"⚠️ [{definition_idx}] VERY LONG LINE encountered (length={len(line)}, lines in current playlist={lines_processed_for_current_playlist}): {line[:100]}...")


                        else: # Main header already handled (or first playlist didn't have one)
                            if first_line_of_this_segment and is_extm3u_line:
                                # Skip #EXTM3U if it's the first line of a subsequent segment
                                pass
                            else:
                                yield line
                        first_line_of_this_segment = False

                        # This block for logging and length check was duplicated, ensure it's correctly placed for all yielded lines
                        if first_playlist_header_handled: # If not the first header part, calculate bytes and log here too
                            line_bytes = len(line.encode('utf-8', 'replace'))
                            total_bytes_yielded += line_bytes
                            if total_bytes_yielded // log_interval_bytes > last_log_bytes_milestone:
                                last_log_bytes_milestone = total_bytes_yielded // log_interval_bytes
                                app.logger.info(f"ℹ️ [{definition_idx}] Total data yielded: {total_bytes_yielded / (1024*1024):.2f} MB. Current playlist lines: {lines_processed_for_current_playlist}")
                            if len(line) > 10000:
                                app.logger.warning(f"⚠️ [{definition_idx}] VERY LONG LINE encountered (length={len(line)}, lines in current playlist={lines_processed_for_current_playlist}): {line[:100]}...")

                except Exception as e:
                    app.logger.error(f"💥 [{definition_idx}] Error processing playlist {playlist_url_str} (after ~{lines_processed_for_current_playlist} lines yielded for it): {str(e)}")
                    yield f"# ERROR processing playlist {playlist_url_str}: {str(e)}\n"
                
                app.logger.info(f"✅ [{definition_idx}] Finished processing playlist {playlist_url_str}. Lines processed in this segment: {lines_processed_for_current_playlist}")
                if current_playlist_had_lines and not first_playlist_header_handled:
                    # This playlist (which was effectively the first with content) finished,
                    # and no #EXTM3U was found to mark as the main header.
                    # Mark header as handled so subsequent playlists skip their #EXTM3U.
                    first_playlist_header_handled = True
        
        app.logger.info(f"🏁 Avvio streaming del contenuto combinato... (Total definitions: {len(playlist_definitions)})")
        # The final total_bytes_yielded will be known only if the generator completes fully.
        return Response(
            generate_combined_playlist(),
            mimetype='application/vnd.apple.mpegurl',
            headers={
                'Content-Disposition': 'attachment; filename="playlist.m3u"',
                'Access-Control-Allow-Origin': '*'
            }
        )
        
    except Exception as e:
        app.logger.error(f"ERRORE GENERALE: {str(e)}")
        import traceback
        traceback.print_exc()
        return f"Errore: {str(e)}", 500

def proxy_single_playlist():
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

# Valida e aggiorna la configurazione del pre-buffer
pre_buffer_manager.update_config()
app.logger.info("Configurazione pre-buffer inizializzata con successo")

# Inizializza le cache e i proxy
setup_all_caches()
setup_proxies()



if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    
    # Log di avvio
    app.logger.info("="*50)
    app.logger.info("PROXY SERVER AVVIATO")
    app.logger.info("="*50)
    app.logger.info(f"Porta: {port}")
    app.logger.info("="*50)
    
    # Avvia solo Flask senza WebSocket
    app.run(host="0.0.0.0", port=port, debug=False)
