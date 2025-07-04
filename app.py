[2025-07-04 18:45:17,794] ERROR in app: Errore durante la risoluzione DaddyLive: HTTPSConnectionPool(host='thedaddy.click', port=443): Max retries exceeded with url: /stream/stream-461.php (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 429 Too Many Requests')))
[2025-07-04 18:45:17,795] ERROR in app: Traceback: Traceback (most recent call last):
File "/usr/local/lib/python3.12/site-packages/urllib3/connectionpool.py", line 773, in urlopen
self._prepare_proxy(conn)
File "/usr/local/lib/python3.12/site-packages/urllib3/connectionpool.py", line 1042, in _prepare_proxy
conn.connect()
File "/usr/local/lib/python3.12/site-packages/urllib3/connection.py", line 770, in connect
self._tunnel()
File "/usr/local/lib/python3.12/http/client.py", line 981, in _tunnel
raise OSError(f"Tunnel connection failed: {code} {message.strip()}")
OSError: Tunnel connection failed: 429 Too Many Requests
The above exception was the direct cause of the following exception:
urllib3.exceptions.ProxyError: ('Unable to connect to proxy', OSError('Tunnel connection failed: 429 Too Many Requests'))
The above exception was the direct cause of the following exception:
Traceback (most recent call last):
File "/usr/local/lib/python3.12/site-packages/requests/adapters.py", line 667, in send
resp = conn.urlopen(
^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/urllib3/connectionpool.py", line 841, in urlopen
retries = retries.increment(
^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/urllib3/util/retry.py", line 519, in increment
raise MaxRetryError(_pool, url, reason) from reason  # type: ignore[arg-type]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='thedaddy.click', port=443): Max retries exceeded with url: /stream/stream-461.php (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 429 Too Many Requests')))
During handling of the above exception, another exception occurred:
Traceback (most recent call last):
File "/app/app.py", line 980, in resolve_m3u8_link
response = requests.get(stream_url, headers=final_headers_for_resolving, timeout=REQUEST_TIMEOUT, proxies=get_proxy_for_url(stream_url), verify=VERIFY_SSL)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/requests/api.py", line 73, in get
return request("get", url, params=params, **kwargs)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/requests/api.py", line 59, in request
return session.request(method=method, url=url, **kwargs)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/requests/sessions.py", line 589, in request
resp = self.send(prep, **send_kwargs)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/requests/sessions.py", line 703, in send
r = adapter.send(request, **kwargs)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.12/site-packages/requests/adapters.py", line 694, in send
raise ProxyError(e, request=request)
requests.exceptions.ProxyError: HTTPSConnectionPool(host='thedaddy.click', port=443): Max retries exceeded with url: /stream/stream-461.php (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 429 Too Many Requests')))
