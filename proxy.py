import subprocess
import json
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Configurazione
URL_PROXY_LIST = 'https://advanced.name/freeproxy/685e2fe5e5f45'
URL_TO_TEST = 'https://new.newkso.ru/wind/'
VAVOO_URL = 'https://vavoo.to/play/1534161807/index.m3u8'
MAX_WORKERS = 20  # Numero di thread paralleli
TIMEOUT_CURL = 10
TIMEOUT_CONNECT = 7

# Contatori globali thread-safe
results_lock = threading.Lock()
working_proxies_http = []
working_proxies_socks5 = []
completed_count = 0
total_proxies = 0

def download_proxy_list():
    """Scarica la lista dei proxy dal link fornito"""
    print(f"📥 Scaricamento proxy da: {URL_PROXY_LIST}")
    try:
        response = requests.get(URL_PROXY_LIST, timeout=30)
        response.raise_for_status()
        
        # Estrai i proxy dal contenuto
        content = response.text
        proxies = []
        
        # Cerca pattern di proxy nel contenuto
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            # Pattern per IP:PORT
            if ':' in line and len(line.split(':')) == 2:
                ip, port = line.split(':')
                # Verifica che sia un IP valido (semplice controllo)
                if ip.count('.') == 3 and port.isdigit():
                    proxies.append(line)
        
        print(f"✅ Trovati {len(proxies)} proxy nella lista")
        return proxies
        
    except Exception as e:
        print(f"❌ Errore nel download della lista proxy: {e}")
        return []

def test_single_proxy(proxy_line, proxy_type, address_for_curl):
    """Test per singolo proxy - versione semplificata"""
    try:
        # Primo test: sito principale
        cmd = ['curl', '-k', '--max-time', str(TIMEOUT_CURL), '--silent', '--show-error', 
               '--connect-timeout', str(TIMEOUT_CONNECT), URL_TO_TEST]
        
        if proxy_type == 'socks5':
            cmd.extend(['--socks5-hostname', address_for_curl])
        elif proxy_type == 'http':
            cmd.extend(['--proxy', address_for_curl])
        else:
            return {'status': 'FAIL', 'details': f'Tipo di proxy non supportato: {proxy_type}'}
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            error_msg = result.stderr.strip().lower()
            if "timed out" in error_msg: 
                return {'status': 'FAIL', 'details': 'Timeout (10s)'}
            details = result.stderr.strip() or f'curl exit code {result.returncode}'
            return {'status': 'FAIL', 'details': details}
        else:
            output_lower = result.stdout.lower()
            if '404' in output_lower or 'error' in output_lower:
                return {'status': 'FAIL', 'details': 'Risposta HTTP 404 o errore nel contenuto'}
        
        # Secondo test: vavoo.to
        cmd2 = [
            'curl', '-k', '--max-time', str(TIMEOUT_CURL), '--silent', '--show-error', 
            '--connect-timeout', str(TIMEOUT_CONNECT),
            '-H', 'user-agent: VAVOO/2.6',
            '-H', 'referer: https://vavoo.to/',
            '-H', 'origin: https://vavoo.to',
            VAVOO_URL
        ]
        
        if proxy_type == 'socks5':
            cmd2.extend(['--socks5-hostname', address_for_curl])
        elif proxy_type == 'http':
            cmd2.extend(['--proxy', address_for_curl])
        
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
        
        if result2.returncode != 0:
            return {'status': 'FAIL', 'details': 'Errore su vavoo.to'}
        if result2.stdout.strip() == '{"error":"Not found"}':
            return {'status': 'FAIL', 'details': 'Risposta vavoo.to: Not found'}
        
        return {'status': 'SUCCESS', 'details': 'Connessione riuscita', 'protocol_used': proxy_type}
    
    except subprocess.TimeoutExpired:
        return {'status': 'FAIL', 'details': 'Timeout script (15s)'}
    except Exception as e:
        return {'status': 'FAIL', 'details': f'Errore esecuzione script: {e}'}

def test_proxy_wrapper(proxy_line):
    """Wrapper per testare un singolo proxy con auto-detection del protocollo"""
    global completed_count
    
    result = None
    
    # Test del proxy con gestione protocolli
    if proxy_line.startswith(('socks5h://', 'socks5://')):
        proxy_address = proxy_line.split('//', 1)[1]
        result = test_single_proxy(proxy_line, 'socks5', proxy_address)
    elif proxy_line.startswith(('http://', 'https://')):
        result = test_single_proxy(proxy_line, 'http', proxy_line)
    else:
        # Prova prima come HTTP
        result_http = test_single_proxy(proxy_line, 'http', proxy_line)
        if result_http['status'] == 'SUCCESS':
            result = result_http
        else:
            # Se fallisce, prova come SOCKS5
            result_socks = test_single_proxy(proxy_line, 'socks5', proxy_line)
            if result_socks['status'] == 'SUCCESS':
                result = result_socks
            else:
                result = result_http

    if result:
        result['proxy'] = proxy_line
        
        # Aggiorna contatori thread-safe
        with results_lock:
            completed_count += 1
            
            if result['status'] == 'SUCCESS':
                protocol_used = result.get('protocol_used', 'sconosciuto')
                proxy_to_save = proxy_line
                
                # Formatta il proxy con il protocollo corretto
                if protocol_used == 'http' and not proxy_line.startswith(('http://', 'https://')):
                    proxy_to_save = f"http://{proxy_line}"
                elif protocol_used == 'socks5' and not proxy_line.startswith(('socks5://', 'socks5h://')):
                    proxy_to_save = f"socks5://{proxy_line}"
                
                # Salva in liste separate per protocollo
                if protocol_used == 'http':
                    working_proxies_http.append(proxy_to_save)
                    save_proxy_to_file(proxy_to_save, 'http')
                elif protocol_used == 'socks5':
                    working_proxies_socks5.append(proxy_to_save)
                    save_proxy_to_file(proxy_to_save, 'socks5')
                
                print(f"✅ [{completed_count}/{total_proxies}] FUNZIONANTE: {proxy_to_save} ({protocol_used.upper()})")
                
            else:
                # Non stampiamo più i proxy falliti per ridurre il rumore
                print(f"⏭️  [{completed_count}/{total_proxies}] Testato: {proxy_line}")
    
    return result

def save_proxy_to_file(proxy, protocol_type):
    """Salva un singolo proxy nel file appropriato"""
    try:
        if protocol_type == 'http':
            filename = 'proxy_http.txt'
        elif protocol_type == 'socks5':
            filename = 'proxy_socks5.txt'
        else:
            return
        
        with open(filename, 'a') as f:
            f.write(proxy + '\n')
    except Exception as e:
        print(f"⚠️ Errore nel salvare proxy nel file {filename}: {e}")

def initialize_proxy_files():
    """Inizializza i file proxy vuoti all'inizio"""
    try:
        # Inizializza file HTTP
        with open('proxy_http.txt', 'w') as f:
            f.write('')
        
        # Inizializza file SOCKS5
        with open('proxy_socks5.txt', 'w') as f:
            f.write('')
        
        print("📄 File proxy_http.txt e proxy_socks5.txt inizializzati")
    except Exception as e:
        print(f"⚠️ Errore nell'inizializzare i file proxy: {e}")

def main():
    """Funzione principale"""
    global total_proxies
    
    print("🚀 Proxy Tester - Download e Test Automatico con Separazione Protocolli")
    print("=" * 70)
    
    # Inizializza i file proxy
    initialize_proxy_files()
    
    # Scarica la lista dei proxy
    proxies = download_proxy_list()
    
    if not proxies:
        print("❌ Nessun proxy trovato. Uscita.")
        return
    
    total_proxies = len(proxies)
    print(f"📊 Inizio test di {total_proxies} proxy con {MAX_WORKERS} thread paralleli")
    print(f"💾 Proxy HTTP salvati in: proxy_http.txt")
    print(f"💾 Proxy SOCKS5 salvati in: proxy_socks5.txt")
    print("=" * 70)
    
    start_time = time.time()
    
    # Esegui test paralleli
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Invia tutti i proxy per il testing parallelo
        future_to_proxy = {executor.submit(test_proxy_wrapper, proxy): proxy for proxy in proxies}
        
        # Attendi completamento
        for future in as_completed(future_to_proxy):
            try:
                future.result()
            except Exception as e:
                print(f"❌ Errore durante il test: {e}")
    
    end_time = time.time()
    duration = end_time - start_time
    total_working = len(working_proxies_http) + len(working_proxies_socks5)
    failed_count = total_proxies - total_working
    
    # Statistiche finali
    print("\n" + "=" * 70)
    print("📈 RISULTATI FINALI")
    print("=" * 70)
    print(f"⏱️  Tempo totale: {duration:.2f} secondi")
    print(f"📊 Proxy testati: {total_proxies}")
    print(f"✅ Proxy funzionanti totali: {total_working}")
    print(f"   🌐 HTTP: {len(working_proxies_http)}")
    print(f"   🔒 SOCKS5: {len(working_proxies_socks5)}")
    print(f"❌ Proxy falliti: {failed_count}")
    print(f"📈 Percentuale successo: {(total_working/total_proxies*100):.1f}%")
    print(f"⚡ Velocità media: {total_proxies/duration:.1f} proxy/secondo")
    print(f"💾 File creati:")
    print(f"   📄 proxy_http.txt ({len(working_proxies_http)} proxy)")
    print(f"   📄 proxy_socks5.txt ({len(working_proxies_socks5)} proxy)")
    
    # Mostra alcuni proxy funzionanti per tipo
    if working_proxies_http:
        print(f"\n🌐 Primi 3 proxy HTTP funzionanti:")
        for i, proxy in enumerate(working_proxies_http[:3]):
            print(f"   {i+1}. {proxy}")
        if len(working_proxies_http) > 3:
            print(f"   ... e altri {len(working_proxies_http)-3} proxy HTTP")
    
    if working_proxies_socks5:
        print(f"\n🔒 Primi 3 proxy SOCKS5 funzionanti:")
        for i, proxy in enumerate(working_proxies_socks5[:3]):
            print(f"   {i+1}. {proxy}")
        if len(working_proxies_socks5) > 3:
            print(f"   ... e altri {len(working_proxies_socks5)-3} proxy SOCKS5")
    
    if total_working == 0:
        print("\n😞 Nessun proxy funzionante trovato")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️ Test interrotto dall'utente")
        total_working = len(working_proxies_http) + len(working_proxies_socks5)
        if total_working > 0:
            print(f"💾 {total_working} proxy funzionanti già salvati:")
            print(f"   📄 proxy_http.txt: {len(working_proxies_http)} proxy")
            print(f"   📄 proxy_socks5.txt: {len(working_proxies_socks5)} proxy")
    except Exception as e:
        print(f"\n❌ Errore generale: {e}")
