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
app.secret_key = secrets.token_hex(16)

# --- Configurazione Dinamica (sostituisce .env) ---
class DynamicConfig:
    def __init__(self):
        self.config = {
            'verify_ssl': False,
            'request_timeout': 30,
            'keep_alive_timeout': 300,
            'max_keep_alive_requests': 1000,
            'pool_connections': 20,
            'pool_maxsize': 50,
            'admin_username': 'admin',
            'admin_password': 'password123',
            'api_keys': [],
            'socks5_proxies': [],
            'http_proxies': [],
            'https_proxies': [],
            'cache_m3u8_size': 200,
            'cache_m3u8_ttl': 5,
            'cache_ts_size': 1000,
            'cache_ts_ttl': 300,
            'cache_key_size': 200,
            'cache_key_ttl': 300,
            'rate_limit_requests': 100,
            'rate_limit_window': 3600,
            'blocked_ips': [],
            'whitelisted_ips': []
        }
        self.load_from_file()
    
    def load_from_file(self):
        """Carica configurazione da file JSON se esiste"""
        try:
            if os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
                    print("Configurazione caricata da config.json")
        except Exception as e:
            print(f"Errore nel caricamento configurazione: {e}")
    
    def save_to_file(self):
        """Salva configurazione su file JSON"""
        try:
            with open('config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
            print("Configurazione salvata su config.json")
            return True
        except Exception as e:
            print(f"Errore nel salvataggio configurazione: {e}")
            return False
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
    
    def update(self, updates):
        self.config.update(updates)
        return self.save_to_file()

# Istanza globale della configurazione
config = DynamicConfig()

# --- Variabili globali aggiornate dinamicamente ---
def update_global_vars():
    """Aggiorna le variabili globali dalla configurazione"""
    global VERIFY_SSL, REQUEST_TIMEOUT, KEEP_ALIVE_TIMEOUT, MAX_KEEP_ALIVE_REQUESTS
    global POOL_CONNECTIONS, POOL_MAXSIZE, ADMIN_USERNAME, ADMIN_PASSWORD, API_KEYS
    global M3U8_CACHE, TS_CACHE, KEY_CACHE, PROXY_LIST
    
    VERIFY_SSL = config.get('verify_ssl', False)
    REQUEST_TIMEOUT = config.get('request_timeout', 30)
    KEEP_ALIVE_TIMEOUT = config.get('keep_alive_timeout', 300)
    MAX_KEEP_ALIVE_REQUESTS = config.get('max_keep_alive_requests', 1000)
    POOL_CONNECTIONS = config.get('pool_connections', 20)
    POOL_MAXSIZE = config.get('pool_maxsize', 50)
    ADMIN_USERNAME = config.get('admin_username', 'admin')
    ADMIN_PASSWORD = config.get('admin_password', 'password123')
    API_KEYS = set(config.get('api_keys', []))
    
    # Ricrea le cache con nuove dimensioni
    M3U8_CACHE = TTLCache(maxsize=config.get('cache_m3u8_size', 200), ttl=config.get('cache_m3u8_ttl', 5))
    TS_CACHE = TTLCache(maxsize=config.get('cache_ts_size', 1000), ttl=config.get('cache_ts_ttl', 300))
    KEY_CACHE = TTLCache(maxsize=config.get('cache_key_size', 200), ttl=config.get('cache_key_ttl', 300))
    
    # Aggiorna proxy
    setup_proxies()

# Inizializza variabili globali
update_global_vars()

# Resto del codice rimane uguale fino ai decoratori...
# [Include tutto il codice precedente per autenticazione, rate limiting, etc.]

# --- Configurazione Proxy Dinamica ---
def setup_proxies():
    """Carica la lista di proxy dalla configurazione dinamica"""
    global PROXY_LIST
    proxies_found = []
    
    # SOCKS5 Proxies
    socks5_proxies = config.get('socks5_proxies', [])
    for proxy in socks5_proxies:
        if proxy.strip():
            final_proxy_url = proxy.strip()
            if proxy.startswith('socks5://'):
                final_proxy_url = 'socks5h' + proxy[len('socks5'):]
            proxies_found.append(final_proxy_url)
            proxy_stats[final_proxy_url] = {'success': 0, 'failures': 0, 'last_used': None, 'status': 'unknown'}
    
    # HTTP Proxies
    http_proxies = config.get('http_proxies', [])
    for proxy in http_proxies:
        if proxy.strip():
            proxies_found.append(proxy.strip())
            proxy_stats[proxy.strip()] = {'success': 0, 'failures': 0, 'last_used': None, 'status': 'unknown'}
    
    # HTTPS Proxies
    https_proxies = config.get('https_proxies', [])
    for proxy in https_proxies:
        if proxy.strip():
            proxies_found.append(proxy.strip())
            proxy_stats[proxy.strip()] = {'success': 0, 'failures': 0, 'last_used': None, 'status': 'unknown'}
    
    PROXY_LIST = proxies_found
    logger.info(f"Configurati {len(PROXY_LIST)} proxy dalla configurazione web")

# --- Routes per gestione configurazione ---
@app.route('/config-panel')
@require_auth
def config_panel():
    """Pannello di configurazione web"""
    return render_template_string(CONFIG_PANEL_TEMPLATE)

@app.route('/api/config', methods=['GET', 'POST'])
@require_auth
def api_config():
    """API per gestire la configurazione"""
    if request.method == 'GET':
        return jsonify({
            'config': config.config,
            'masked_proxies': {
                'socks5': [mask_proxy_url(p) for p in config.get('socks5_proxies', [])],
                'http': [mask_proxy_url(p) for p in config.get('http_proxies', [])],
                'https': [mask_proxy_url(p) for p in config.get('https_proxies', [])]
            }
        })
    
    # POST per aggiornare configurazione
    try:
        new_config = request.get_json()
        
        # Validazione dei dati
        if 'request_timeout' in new_config:
            new_config['request_timeout'] = max(5, min(300, int(new_config['request_timeout'])))
        
        if 'cache_m3u8_size' in new_config:
            new_config['cache_m3u8_size'] = max(10, min(10000, int(new_config['cache_m3u8_size'])))
        
        # Aggiorna configurazione
        success = config.update(new_config)
        
        if success:
            # Aggiorna variabili globali
            update_global_vars()
            
            # Log della modifica
            log_security_event(get_client_ip(), 'config_updated', f"Updated by {session.get('username', 'unknown')}")
            
            return jsonify({
                'success': True,
                'message': 'Configurazione aggiornata e salvata con successo'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Errore nel salvataggio della configurazione'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Errore nell\'aggiornamento: {str(e)}'
        }), 400

@app.route('/api/config/reset', methods=['POST'])
@require_auth
def api_config_reset():
    """Reset configurazione ai valori di default"""
    try:
        # Backup configurazione corrente
        backup_config = config.config.copy()
        
        # Reset ai valori di default
        config.config = DynamicConfig().config
        
        if config.save_to_file():
            update_global_vars()
            log_security_event(get_client_ip(), 'config_reset', f"Reset by {session.get('username', 'unknown')}")
            
            return jsonify({
                'success': True,
                'message': 'Configurazione resettata ai valori di default'
            })
        else:
            # Ripristina backup in caso di errore
            config.config = backup_config
            return jsonify({
                'success': False,
                'message': 'Errore nel reset della configurazione'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Errore nel reset: {str(e)}'
        }), 500

@app.route('/api/config/export')
@require_auth
def api_config_export():
    """Esporta configurazione come file JSON"""
    try:
        # Crea una copia della configurazione senza dati sensibili
        export_config = config.config.copy()
        
        # Rimuovi password e API keys per sicurezza
        if 'admin_password' in export_config:
            export_config['admin_password'] = '***HIDDEN***'
        if 'api_keys' in export_config:
            export_config['api_keys'] = ['***HIDDEN***'] * len(export_config['api_keys'])
        
        return Response(
            json.dumps(export_config, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=proxy_config_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
        )
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Errore nell\'esportazione: {str(e)}'
        }), 500

@app.route('/api/config/import', methods=['POST'])
@require_auth
def api_config_import():
    """Importa configurazione da file JSON"""
    try:
        if 'config_file' not in request.files:
            return jsonify({
                'success': False,
                'message': 'Nessun file selezionato'
            }), 400
        
        file = request.files['config_file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'message': 'Nessun file selezionato'
            }), 400
        
        # Leggi e valida il file JSON
        try:
            import_config = json.loads(file.read().decode('utf-8'))
        except json.JSONDecodeError:
            return jsonify({
                'success': False,
                'message': 'File JSON non valido'
            }), 400
        
        # Backup configurazione corrente
        backup_config = config.config.copy()
        
        # Aggiorna configurazione
        if config.update(import_config):
            update_global_vars()
            log_security_event(get_client_ip(), 'config_imported', f"Imported by {session.get('username', 'unknown')}")
            
            return jsonify({
                'success': True,
                'message': 'Configurazione importata con successo'
            })
        else:
            # Ripristina backup in caso di errore
            config.config = backup_config
            return jsonify({
                'success': False,
                'message': 'Errore nell\'importazione della configurazione'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Errore nell\'importazione: {str(e)}'
        }), 500

# --- Template per il pannello di configurazione ---
CONFIG_PANEL_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Configuration Panel</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
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
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: var(--bg-color); 
            color: var(--text-color);
            line-height: 1.6;
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
        
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
        }
        
        .config-section {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border: 1px solid var(--border-color);
        }
        
        .config-section h3 {
            margin-bottom: 1.5rem;
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 0.5rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--text-color);
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid var(--border-color);
            border-radius: 6px;
            background: var(--card-bg);
            color: var(--text-color);
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .form-group textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 1rem;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }
        
        .btn-primary { background: var(--primary-color); color: white; }
        .btn-success { background: var(--success-color); color: white; }
        .btn-danger { background: var(--danger-color); color: white; }
        .btn-warning { background: var(--warning-color); color: black; }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        
        .proxy-list {
            background: var(--bg-color);
            border-radius: 4px;
            padding: 1rem;
            margin-top: 0.5rem;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .proxy-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            background: var(--card-bg);
            border-radius: 4px;
            border: 1px solid var(--border-color);
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 6px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            transform: translateX(100%);
            transition: transform 0.3s ease;
            max-width: 400px;
        }
        
        .notification.show { transform: translateX(0); }
        .notification.success { background: var(--success-color); }
        .notification.error { background: var(--danger-color); }
        .notification.warning { background: var(--warning-color); color: black; }
        
        .actions-bar {
            background: var(--card-bg);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .file-input {
            display: none;
        }
        
        .file-label {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: var(--warning-color);
            color: black;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .file-label:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        
        @media (max-width: 768px) {
            .config-grid {
                grid-template-columns: 1fr;
            }
            .container {
                padding: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚙️ Configuration Panel</h1>
        <div>
            <a href="/advanced-dashboard" class="btn btn-primary">📊 Dashboard</a>
            <a href="/logout" class="btn btn-danger">🚪 Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="actions-bar">
            <button class="btn btn-success" onclick="saveConfig()">💾 Save Configuration</button>
            <button class="btn btn-warning" onclick="exportConfig()">📤 Export Config</button>
            <label for="importFile" class="file-label">📥 Import Config</label>
            <input type="file" id="importFile" class="file-input" accept=".json" onchange="importConfig()">
            <button class="btn btn-danger" onclick="resetConfig()">🔄 Reset to Default</button>
        </div>

        <div class="config-grid">
            <!-- Configurazione Generale -->
            <div class="config-section">
                <h3>🔧 General Settings</h3>
                
                <div class="form-group">
                    <label for="requestTimeout">Request Timeout (seconds):</label>
                    <input type="number" id="requestTimeout" min="5" max="300" value="30">
                </div>
                
                <div class="form-group">
                    <label for="verifySsl">Verify SSL Certificates:</label>
                    <select id="verifySsl">
                        <option value="false">Disabled (Not Recommended)</option>
                        <option value="true">Enabled (Recommended)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="keepAliveTimeout">Keep-Alive Timeout (seconds):</label>
                    <input type="number" id="keepAliveTimeout" min="60" max="3600" value="300">
                </div>
                
                <div class="form-group">
                    <label for="poolConnections">Pool Connections:</label>
                    <input type="number" id="poolConnections" min="5" max="100" value="20">
                </div>
            </div>

            <!-- Configurazione Cache -->
            <div class="config-section">
                <h3>💾 Cache Settings</h3>
                
                <div class="form-group">
                    <label for="cacheM3u8Size">M3U8 Cache Size:</label>
                    <input type="number" id="cacheM3u8Size" min="10" max="10000" value="200">
                </div>
                
                <div class="form-group">
                    <label for="cacheM3u8Ttl">M3U8 Cache TTL (seconds):</label>
                    <input type="number" id="cacheM3u8Ttl" min="1" max="3600" value="5">
                </div>
                
                <div class="form-group">
                    <label for="cacheTsSize">TS Cache Size:</label>
                    <input type="number" id="cacheTsSize" min="100" max="50000" value="1000">
                </div>
                
                <div class="form-group">
                    <label for="cacheTsTtl">TS Cache TTL (seconds):</label>
                    <input type="number" id="cacheTsTtl" min="60" max="3600" value="300">
                </div>
            </div>

            <!-- Configurazione Autenticazione -->
            <div class="config-section">
                <h3>🔐 Authentication</h3>
                
                <div class="form-group">
                    <label for="adminUsername">Admin Username:</label>
                    <input type="text" id="adminUsername" value="admin">
                </div>
                
                <div class="form-group">
                    <label for="adminPassword">Admin Password:</label>
                    <input type="password" id="adminPassword" value="">
                    <small>Leave empty to keep current password</small>
                </div>
                
                <div class="form-group">
                    <label for="apiKeys">API Keys (one per line):</label>
                    <textarea id="apiKeys" placeholder="Enter API keys, one per line"></textarea>
                </div>
            </div>

            <!-- Configurazione Rate Limiting -->
            <div class="config-section">
                <h3>🛡️ Rate Limiting & Security</h3>
                
                <div class="form-group">
                    <label for="rateLimitRequests">Max Requests per Window:</label>
                    <input type="number" id="rateLimitRequests" min="10" max="10000" value="100">
                </div>
                
                <div class="form-group">
                    <label for="rateLimitWindow">Rate Limit Window (seconds):</label>
                    <input type="number" id="rateLimitWindow" min="60" max="86400" value="3600">
                </div>
                
                <div class="form-group">
                    <label for="blockedIps">Blocked IPs (one per line):</label>
                    <textarea id="blockedIps" placeholder="Enter blocked IP addresses, one per line"></textarea>
                </div>
                
                <div class="form-group">
                    <label for="whitelistedIps">Whitelisted IPs (one per line):</label>
                    <textarea id="whitelistedIps" placeholder="Enter whitelisted IP addresses, one per line"></textarea>
                </div>
            </div>

            <!-- Configurazione Proxy SOCKS5 -->
            <div class="config-section">
                <h3>🔗 SOCKS5 Proxies</h3>
                
                <div class="form-group">
                    <label for="socks5Proxies">SOCKS5 Proxy URLs (one per line):</label>
                    <textarea id="socks5Proxies" placeholder="socks5://username:password@host:port"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Current SOCKS5 Proxies:</label>
                    <div id="socks5ProxyList" class="proxy-list">
                        Loading...
                    </div>
                </div>
            </div>

            <!-- Configurazione Proxy HTTP -->
            <div class="config-section">
                <h3>🌐 HTTP/HTTPS Proxies</h3>
                
                <div class="form-group">
                    <label for="httpProxies">HTTP Proxy URLs (one per line):</label>
                    <textarea id="httpProxies" placeholder="http://username:password@host:port"></textarea>
                </div>
                
                <div class="form-group">
                    <label for="httpsProxies">HTTPS Proxy URLs (one per line):</label>
                    <textarea id="httpsProxies" placeholder="https://username:password@host:port"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Current HTTP/HTTPS Proxies:</label>
                    <div id="httpProxyList" class="proxy-list">
                        Loading...
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentConfig = {};

        document.addEventListener('DOMContentLoaded', function() {
            loadConfig();
        });

        function loadConfig() {
            fetch('/api/config')
                .then(response => response.json())
                .then(data => {
                    currentConfig = data.config;
                    populateForm(data.config);
                    updateProxyLists(data.masked_proxies);
                })
                .catch(error => {
                    console.error('Error loading config:', error);
                    showNotification('Error loading configuration', 'error');
                });
        }

        function populateForm(config) {
            document.getElementById('requestTimeout').value = config.request_timeout || 30;
            document.getElementById('verifySsl').value = config.verify_ssl ? 'true' : 'false';
            document.getElementById('keepAliveTimeout').value = config.keep_alive_timeout || 300;
            document.getElementById('poolConnections').value = config.pool_connections || 20;
            
            document.getElementById('cacheM3u8Size').value = config.cache_m3u8_size || 200;
            document.getElementById('cacheM3u8Ttl').value = config.cache_m3u8_ttl || 5;
            document.getElementById('cacheTsSize').value = config.cache_ts_size || 1000;
            document.getElementById('cacheTsTtl').value = config.cache_ts_ttl || 300;
            
            document.getElementById('adminUsername').value = config.admin_username || 'admin';
            document.getElementById('apiKeys').value = (config.api_keys || []).join('\\n');
            
            document.getElementById('rateLimitRequests').value = config.rate_limit_requests || 100;
            document.getElementById('rateLimitWindow').value = config.rate_limit_window || 3600;
            document.getElementById('blockedIps').value = (config.blocked_ips || []).join('\\n');
            document.getElementById('whitelistedIps').value = (config.whitelisted_ips || []).join('\\n');
            
            document.getElementById('socks5Proxies').value = (config.socks5_proxies || []).join('\\n');
            document.getElementById('httpProxies').value = (config.http_proxies || []).join('\\n');
            document.getElementById('httpsProxies').value = (config.https_proxies || []).join('\\n');
        }

        function updateProxyLists(maskedProxies) {
            const socks5List = document.getElementById('socks5ProxyList');
            const httpList = document.getElementById('httpProxyList');
            
            socks5List.innerHTML = maskedProxies.socks5.length > 0 
                ? maskedProxies.socks5.map(proxy => `<div class="proxy-item">${proxy}</div>`).join('')
                : '<div class="proxy-item">No SOCKS5 proxies configured</div>';
            
            const allHttpProxies = [...maskedProxies.http, ...maskedProxies.https];
            httpList.innerHTML = allHttpProxies.length > 0
                ? allHttpProxies.map(proxy => `<div class="proxy-item">${proxy}</div>`).join('')
                : '<div class="proxy-item">No HTTP/HTTPS proxies configured</div>';
        }

        function saveConfig() {
            const newConfig = {
                request_timeout: parseInt(document.getElementById('requestTimeout').value),
                verify_ssl: document.getElementById('verifySsl').value === 'true',
                keep_alive_timeout: parseInt(document.getElementById('keepAliveTimeout').value),
                pool_connections: parseInt(document.getElementById('poolConnections').value),
                
                cache_m3u8_size: parseInt(document.getElementById('cacheM3u8Size').value),
                cache_m3u8_ttl: parseInt(document.getElementById('cacheM3u8Ttl').value),
                cache_ts_size: parseInt(document.getElementById('cacheTsSize').value),
                cache_ts_ttl: parseInt(document.getElementById('cacheTsTtl').value),
                
                admin_username: document.getElementById('adminUsername').value,
                api_keys: document.getElementById('apiKeys').value.split('\\n').filter(key => key.trim()),
                
                rate_limit_requests: parseInt(document.getElementById('rateLimitRequests').value),
                rate_limit_window: parseInt(document.getElementById('rateLimitWindow').value),
                blocked_ips: document.getElementById('blockedIps').value.split('\\n').filter(ip => ip.trim()),
                whitelisted_ips: document.getElementById('whitelistedIps').value.split('\\n').filter(ip => ip.trim()),
                
                socks5_proxies: document.getElementById('socks5Proxies').value.split('\\n').filter(proxy => proxy.trim()),
                http_proxies: document.getElementById('httpProxies').value.split('\\n').filter(proxy => proxy.trim()),
                https_proxies: document.getElementById('httpsProxies').value.split('\\n').filter(proxy => proxy.trim())
            };
            
            // Aggiungi password solo se specificata
            const newPassword = document.getElementById('adminPassword').value;
            if (newPassword.trim()) {
                newConfig.admin_password = newPassword;
            }

            fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newConfig)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    loadConfig(); // Ricarica la configurazione
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error saving config:', error);
                showNotification('Error saving configuration', 'error');
            });
        }

        function exportConfig() {
            window.location.href = '/api/config/export';
        }

        function importConfig() {
            const fileInput = document.getElementById('importFile');
            const file = fileInput.files[0];
            
            if (!file) return;
            
            const formData = new FormData();
            formData.append('config_file', file);
            
            fetch('/api/config/import', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    loadConfig(); // Ricarica la configurazione
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error importing config:', error);
                showNotification('Error importing configuration', 'error');
            });
            
            // Reset file input
            fileInput.value = '';
        }

        function resetConfig() {
            if (confirm('Are you sure you want to reset all configuration to default values? This action cannot be undone.')) {
                fetch('/api/config/reset', {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showNotification(data.message, 'success');
                        loadConfig(); // Ricarica la configurazione
                    } else {
                        showNotification(data.message, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error resetting config:', error);
                    showNotification('Error resetting configuration', 'error');
                });
            }
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
            }, 4000);
        }
    </script>
</body>
</html>
'''

# Aggiorna il template del dashboard avanzato per includere il link al pannello di configurazione
ADVANCED_DASHBOARD_TEMPLATE = ADVANCED_DASHBOARD_TEMPLATE.replace(
    '<a href="/logout" class="btn btn-primary">🚪 Logout</a>',
    '<a href="/config-panel" class="btn btn-warning">⚙️ Config</a>\n            <a href="/logout" class="btn btn-primary">🚪 Logout</a>'
)

# Resto del codice rimane uguale...
# [Include tutto il resto del codice precedente]

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 7860))
    print(f"Advanced Proxy Dashboard ONLINE - Porta {port}")
    print(f"Login: {config.get('admin_username')} / {config.get('admin_password')}")
    print("Configurazione gestita tramite pannello web: /config-panel")
    app.run(host="0.0.0.0", port=port, debug=False)
