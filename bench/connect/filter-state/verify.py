"""Replay generated state filters; replace Porter/TLS identity input with test headers.
Validate transported state at the final HCM, plus external HTTP pool reuse.
"""
import argparse
import concurrent.futures
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request

keys = ['sandbox.id', 'sandbox.token', 'agentio.workload.name', 'agentio.workload.namespace',
        'agentio.workload.labels', 'sandbox.labels', 'agentio.sandbox.metadata']
variants = [
    ['sandbox-a', 'token-a', 'workload-a', 'ns-a', '{"team":"a"}', '{"team":"a"}'],
    ['sandbox-a', 'token-a', 'workload-a', 'ns-a', '{"team":"changed"}', '{"team":"changed"}'],
    ['sandbox-a', 'token-new', 'workload-a', 'ns-a', '{}', '{}'],
    ['sandbox-b', 'token-b', 'workload-a', 'ns-a', '{}', '{}'],
    ['sandbox-a', '', 'workload-a', 'ns-a', '{}', '{}'],
    ['', '', 'workload-b', 'ns-b', '{}', '{}'],
]

metadata = [
    'agent-identity.access-token=token-a,agent-identity.sandbox-client-id=client-a',
    'agent-identity.access-token=token-rotated,agent-identity.sandbox-client-id=client-a',
    'agent-identity.access-token=token-b,agent-identity.sandbox-client-id=client-b',
    '',
]
variants = [values + [m] for values in variants for m in metadata]

def typed(name, **kw):
    return {'@type': 'type.googleapis.com/' + name, **kw}

def addr(port):
    return {'socketAddress': {'address': '127.0.0.1', 'portValue': port}}

def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128
    accepts = 0
    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        return result

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        body = json.dumps([self.headers.get('x-observed-' + str(i)) for i in range(len(keys))]).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

router = {'name': 'envoy.filters.http.router', 'typedConfig': typed('envoy.extensions.filters.http.router.v3.Router')}

def run(binary, golden, tls_hop, root):
    resources = json.loads(Path(golden).read_text())['resources']
    generated = {r['name']: r['resource'] for r in resources if r['type_url'].endswith('.Listener')}
    outer_hcm = generated['connect_terminate']['filterChains'][0]['filters'][0]['typedConfig']
    filters = copy.deepcopy([f for f in outer_hcm['httpFilters'] if f['name'] in ['agentio.connect_authority', 'agentio.connect_workload']])
    for f in filters:
        for value in f['typedConfig']['onRequestHeaders']:
            key = value['objectKey']
            if key in keys:
                value['formatString']['textFormatSource']['inlineString'] = '%REQ(x-state-' + str(keys.index(key)) + ')%'
            elif key in ['agentio.peer.principal', 'agentio.local.principal']:
                value['formatString']['textFormatSource']['inlineString'] = 'spiffe://test/ns/test/sa/test'
    server = Server(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port, admin = unused_port(), unused_port()
    destination = '127.0.0.1:' + str(server.server_port)
    terminal = {
        'name': 'main_forward' if tls_hop else 'main_internal', 'internalListener': {},
        'filterChains': [{'filters': [{'name': 'envoy.filters.network.http_connection_manager', 'typedConfig': typed(
            'envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
            statPrefix='terminal', routeConfig={'name': 'terminal', 'virtualHosts': [{'name': 'all', 'domains': ['*'], 'routes': [{
                'match': {'prefix': '/'}, 'route': {'cluster': 'origin'},
                'requestHeadersToAdd': [{'header': {'key': 'x-observed-' + str(i), 'value': '[%FILTER_STATE(' + key + ':PLAIN)%]'}, 'appendAction': 'OVERWRITE_IF_EXISTS_OR_ADD'} for i, key in enumerate(keys)]
            }]}]}, httpFilters=[router])}]}]}
    outer = {'name': 'outer', 'address': addr(port), 'filterChains': [{'filters': [{'name': 'envoy.filters.network.http_connection_manager', 'typedConfig': typed(
        'envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager', statPrefix='outer',
        upgradeConfigs=[{'upgradeType': 'CONNECT'}], routeConfig={'name': 'connect', 'virtualHosts': [{'name': 'all', 'domains': ['*'], 'routes': [{
            'match': {'connectMatcher': {}}, 'route': {'cluster': 'main_internal', 'timeout': '0s', 'upgradeConfigs': [{'upgradeType': 'CONNECT', 'connectConfig': {}}]}
        }]}]}, httpFilters=filters + [router])}]}]}
    listeners = [outer, terminal]
    if tls_hop:
        chain = copy.deepcopy(next(c for c in generated['main_internal']['filterChains'] if c['name'] == 'tls-terminate'))
        chain.pop('filterChainMatch', None)
        chain['transportSocket']['typedConfig'] = typed('envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext', commonTlsContext={
            'tlsCertificates': [{'certificateChain': {'filename': str(root / 'cert.pem')}, 'privateKey': {'filename': str(root / 'key.pem')}}]})
        listeners.append({'name': 'main_internal', 'internalListener': {}, 'listenerFilters': [{'name': 'envoy.filters.listener.tls_inspector', 'typedConfig': typed('envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector')}], 'filterChains': [chain]})
    clusters = [copy.deepcopy(r['resource']) for r in resources if r['type_url'].endswith('.Cluster') and r['name'] in ['main_internal', 'main_forward']]
    clusters.append({'name': 'origin', 'type': 'STATIC', 'connectTimeout': '1s', 'loadAssignment': {'clusterName': 'origin', 'endpoints': [{'lbEndpoints': [{'endpoint': {'address': addr(server.server_port)}}]}]}, 'typedExtensionProtocolOptions': {'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': typed('envoy.extensions.upstreams.http.v3.HttpProtocolOptions', commonHttpProtocolOptions={'idleTimeout': '300s'}, explicitHttpConfig={'httpProtocolOptions': {}})}})
    config = {'admin': {'address': addr(admin)}, 'bootstrapExtensions': [{'name': 'envoy.bootstrap.internal_listener', 'typedConfig': typed('envoy.extensions.bootstrap.internal_listener.v3.InternalListener')}], 'staticResources': {'listeners': listeners, 'clusters': clusters}}
    label = Path(binary).name + '-' + Path(golden).stem + ('-tls' if tls_hop else '-http')
    path = root / (label + '.json')
    path.write_text(json.dumps(config))
    log = (root / (label + '.log')).open('w')
    proc = subprocess.Popen([binary, '-c', str(path), '--concurrency', '1', '--disable-hot-restart', '--log-level', 'warning'], stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError('Envoy failed: ' + (root / (label + '.log')).read_text())
            try:
                urllib.request.urlopen('http://127.0.0.1:' + str(admin) + '/ready', timeout=.2).read()
                break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('Envoy startup timed out')
        def request(index):
            values = variants[index % len(variants)]
            conn = socket.create_connection(('127.0.0.1', port), timeout=5)
            try:
                headers = ''.join('x-state-' + str(i) + ': ' + v + '\r\n' for i, v in enumerate(values) if v)
                conn.sendall(('CONNECT ' + destination + ' HTTP/1.1\r\nHost: ' + destination + '\r\n' + headers + '\r\n').encode())
                head = b''
                while not head.endswith(b'\r\n\r\n'):
                    byte = conn.recv(1)
                    assert byte, head
                    head += byte
                assert head.startswith(b'HTTP/1.1 200'), head
                if tls_hop:
                    ctx = ssl.create_default_context(cafile=str(root / 'cert.pem'))
                    conn = ctx.wrap_socket(conn, server_hostname='localhost')
                conn.sendall(('GET / HTTP/1.1\r\nHost: ' + destination + '\r\n\r\n').encode())
                response = http.client.HTTPResponse(conn)
                response.begin()
                body = response.read()
                assert response.status == 200, (response.status, body)
                got = json.loads(body)
                want = ['[' + v + ']' for v in values]
                assert got == want, {'case': index, 'got': got, 'want': want}
                response.close()
            finally:
                conn.close()
        for i in range(300):
            request(i)
        serial_accepts = server.accepts
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
            list(executor.map(request, range(240)))
        result = {'serial_requests': 300, 'serial_origin_connections': serial_accepts, 'concurrent_requests': 240, 'context_checks': 540 * len(keys), 'context_errors': 0}
        assert serial_accepts == 1, result
        if not tls_hop:
            from h2_check import check
            result['h2_multiplexed_connect_requests'] = check(port, destination, variants)
        print(label, json.dumps(result), flush=True)
        return label, result
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()
        server.shutdown()
        server.server_close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('envoy', type=Path)
    parser.add_argument('--golden', type=Path, default=Path(
                        'pkg/networking/testdata/agentio-egress-gateway.json'))
    parser.add_argument('--output', type=Path, help='Keep generated bootstrap, logs and results here')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='agentio-filter-state-') as temporary:
        output = (args.output or Path(temporary)).resolve()
        output.mkdir(parents=True, exist_ok=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(output / 'key.pem'), '-out', str(output / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
        results = {}
        for tls_hop in [False, True]:
            label, result = run(str(args.envoy.resolve()), args.golden, tls_hop, output)
            results[label] = result
            (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
