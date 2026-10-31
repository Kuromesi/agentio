import json
import socket
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamReset

def check(port, destination, variants):
    config = H2Configuration(client_side=True, header_encoding='utf-8', validate_outbound_headers=False)
    h2 = H2Connection(config=config)
    h2.initiate_connection()
    completed = 0
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        sock.sendall(h2.data_to_send())
        for batch in range(10):
            expected, buffers = {}, {}
            for i in range(24):
                sid = h2.get_next_available_stream_id()
                values = variants[(batch * 24 + i) % len(variants)]
                expected[sid] = ['[' + v + ']' for v in values]
                buffers[sid] = bytearray()
                headers = [(':method', 'CONNECT'), (':authority', destination)]
                headers += [('x-state-' + str(j), value) for j, value in enumerate(values) if value]
                h2.send_headers(sid, headers)
            sock.sendall(h2.data_to_send())
            while expected:
                data = sock.recv(65536)
                assert data, 'H2 connection closed early'
                for event in h2.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        assert dict(event.headers)[':status'] == '200', event.headers
                        h2.send_data(event.stream_id, ('GET / HTTP/1.1\r\nHost: ' + destination + '\r\n\r\n').encode())
                    elif isinstance(event, DataReceived):
                        sid = event.stream_id
                        h2.acknowledge_received_data(event.flow_controlled_length, sid)
                        buffers[sid].extend(event.data)
                        if b'\r\n\r\n' not in buffers[sid]:
                            continue
                        header, body = bytes(buffers[sid]).split(b'\r\n\r\n', 1)
                        assert header.startswith(b'HTTP/1.1 200'), header
                        fields = dict(line.lower().split(b': ', 1) for line in header.split(b'\r\n')[1:])
                        if len(body) < int(fields[b'content-length']):
                            continue
                        got = json.loads(body)
                        assert got == expected.pop(sid), {'stream': sid, 'got': got}
                        completed += 1
                        h2.reset_stream(sid)
                    elif isinstance(event, StreamReset):
                        assert event.stream_id not in expected, event
                sock.sendall(h2.data_to_send())
    assert completed == 240, completed
    return completed
