#!/usr/bin/env python3
# CI-хелпер воркфлоу: контракт stock PT для job'а pt-proxy-contract (.github/workflows/ci.yml);
# файл перенесён из scripts/testing/pt_proxy/ и нужен именно этому job'у, а не произвольному потребителю.
"""Граница stock PT: carrier, а не сквозной Tor или завершённый obfs4."""
import os
import queue
import re
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

CERT = 'EREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg'
TIMEOUT = 12


def exact(s, n):
    data = b''
    while len(data) < n:
        part = s.recv(n - len(data))
        if not part:
            raise AssertionError('неполный SOCKS ответ')
        data += part
    return data


class Recorder:
    def __init__(self, mode='ok'):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(20)
        self.sock.settimeout(.2)
        self.port = self.sock.getsockname()[1]
        self.events = queue.Queue()
        self.mode = mode
        self.stop = threading.Event()
        self.workers = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.handle, args=(conn,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def handle(self, s):
        try:
            with s:
                s.settimeout(TIMEOUT)
                version, n = exact(s, 2)
                methods = exact(s, n)
                assert version == 5 and methods in (b'\x02', b'\x00')
                method = methods[0]
                s.sendall(bytes([5, method]))
                creds = None
                if method == 2:
                    ver, n = exact(s, 2)
                    user = exact(s, n)
                    password = exact(s, exact(s, 1)[0])
                    assert ver == 1
                    creds = (user, password)
                    if self.mode == 'auth-reject':
                        self.events.put(('auth-reject', creds))
                        s.sendall(b'\x01\x01')
                        return
                    s.sendall(b'\x01\x00')
                ver, cmd, reserved, atyp = exact(s, 4)
                assert (ver, cmd, reserved) == (5, 1, 0)
                if atyp == 1:
                    host = socket.inet_ntop(socket.AF_INET, exact(s, 4))
                elif atyp == 4:
                    host = socket.inet_ntop(socket.AF_INET6, exact(s, 16))
                elif atyp == 3:
                    host = exact(s, exact(s, 1)[0]).decode('ascii')
                else:
                    raise AssertionError('неизвестный ATYP')
                port = struct.unpack('!H', exact(s, 2))[0]
                self.events.put(('connect', creds, atyp, host, port))
                if self.mode == 'connect-reject':
                    s.sendall(b'\x05\x05\x00\x01' + bytes(6))
                    return
                s.sendall(b'\x05\x00\x00\x01' + bytes(6))
                data = s.recv(8192)
                self.events.put(('carrier', data))
        except Exception as exc:
            self.events.put(('error', repr(exc)))

    def next(self):
        event = self.events.get(timeout=TIMEOUT)
        assert event[0] != 'error', event
        return event

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(TIMEOUT)
        assert not self.thread.is_alive()
        for worker in self.workers:
            worker.join(TIMEOUT)
            assert not worker.is_alive()


class Child:
    def __init__(self, binary, state, proxy, methods='obfs4,webtunnel'):
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('TOR_PT_'):
                del env[key]
        env.update(TOR_PT_MANAGED_TRANSPORT_VER='1', TOR_PT_STATE_LOCATION=state,
                   TOR_PT_CLIENT_TRANSPORTS=methods, TOR_PT_EXIT_ON_STDIN_CLOSE='1')
        if proxy is not None:
            env['TOR_PT_PROXY'] = proxy
        self.p = subprocess.Popen([binary], env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        for line in self.p.stdout:
            self.lines.put(line.decode('utf8').rstrip('\r\n'))

    def line(self):
        return self.lines.get(timeout=TIMEOUT)

    def ready(self, proxy):
        assert self.line() == 'VERSION 1'
        if proxy:
            assert self.line() == 'PROXY DONE'
        endpoints = {}
        while True:
            line = self.line()
            if line == 'CMETHODS DONE':
                return endpoints
            parts = line.split()
            assert len(parts) == 4 and parts[0] == 'CMETHOD' and parts[2] == 'socks5', line
            host, port = parts[3].rsplit(':', 1)
            endpoints[parts[1]] = (host, int(port))

    def close(self):
        if self.p.poll() is None:
            self.p.stdin.close()
            try:
                self.p.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
                raise AssertionError('PT не завершился после EOF stdin')
        assert self.p.poll() is not None
        self.reader.join(TIMEOUT)
        assert not self.reader.is_alive()
        return self.p.stderr.read()


def request(endpoint, args, ip='127.0.0.77', port=443):
    s = socket.create_connection(endpoint, timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    s.sendall(b'\x05\x01\x02')
    assert exact(s, 2) == b'\x05\x02'
    args = args.encode('utf8')
    assert 0 < len(args) < 256
    s.sendall(b'\x01' + bytes([len(args)]) + args + b'\x01\x00')
    assert exact(s, 2) == b'\x01\x00'
    s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(ip) + struct.pack('!H', port))
    return s


def proxy_uri(port, user=None, password=None):
    auth = '' if user is None else urllib.parse.quote(user, safe='') + ':' + urllib.parse.quote(password, safe='') + '@'
    return f'socks5://{auth}127.0.0.1:{port}'


def assert_failed(s):
    first = s.recv(1)
    if first:
        assert first == b'\x05'
        assert exact(s, 1)[0] != 0


class Trap:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.77', 0))
        self.sock.listen(10)
        self.sock.settimeout(2)
        self.port = self.sock.getsockname()[1]

    def receives(self):
        conn, _ = self.sock.accept()
        with conn:
            conn.settimeout(TIMEOUT)
            return conn.recv(8192)

    def assert_idle(self):
        try:
            conn, _ = self.sock.accept()
        except socket.timeout:
            return
        conn.close()
        raise AssertionError('обнаружено прямое подключение к мосту')

    def close(self):
        self.sock.close()


def reset_audit():
    for command in ('iptables', 'ip6tables'):
        subprocess.run([command, '-Z', 'PT_AUDIT'], check=True, timeout=5)


def audit_counts(command):
    output = subprocess.check_output([command + '-save', '-c', '-t', 'filter'], text=True, timeout=5)
    assert len(output) < 131072
    expected = ([['-d', '127.0.0.77/32'], ['-p', 'udp', '--dport', '53'],
                 ['-p', 'tcp', '--dport', '53'], ['!', '-d', '127.0.0.0/8'],
                 ['!', '-d', '127.0.0.1/32']] if command == 'iptables' else
                [['-p', 'udp', '--dport', '53'], ['-p', 'tcp', '--dport', '53'],
                 ['!', '-d', '::1/128']])
    rules = []
    output_jump = 0
    for line in output.splitlines():
        match = re.fullmatch(r'\[(\d+):(\d+)\] (.*)', line)
        if not match:
            continue
        tokens = shlex.split(match.group(3))
        if tokens == ['-A', 'OUTPUT', '-j', 'PT_AUDIT']:
            output_jump += 1
        if tokens[:2] != ['-A', 'PT_AUDIT']:
            continue
        tokens = tokens[2:]
        for module in ('tcp', 'udp'):
            if '-m' in tokens:
                i = tokens.index('-m')
                if tokens[i:i+2] == ['-m', module]:
                    del tokens[i:i+2]
        assert tokens[-2:] == ['-j', 'RETURN']
        rules.append((tokens[:-2], int(match.group(1))))
    assert output_jump == 1 and [rule for rule, _ in rules] == expected, rules
    return [count for _, count in rules]


def assert_audit_clean():
    for command in ('iptables', 'ip6tables'):
        counts = audit_counts(command)
        assert counts and all(count == 0 for count in counts), counts


def run(binary):
    children, recorders = [], []
    trap = Trap()
    with tempfile.TemporaryDirectory() as root:
        def child(proxy, methods='obfs4,webtunnel'):
            state = tempfile.mkdtemp(dir=root)
            c = Child(binary, state, proxy, methods)
            children.append(c)
            return c
        def recorder(mode='ok'):
            r = Recorder(mode)
            recorders.append(r)
            return r
        try:
            r = recorder()
            pairs = [('юзер@1', 'пароль:1'), ('other', 'p@ss/2'), (None, None)]
            clients = [(child(proxy_uri(r.port, u, p)), u, p) for u, p in pairs]
            endpoints = [(c.ready(True), u, p) for c, u, p in clients]
            direct = child(None)
            direct_ep = direct.ready(False)
            reset_audit()
            s = request(direct_ep['obfs4'], 'cert=' + CERT + ';iat-mode=0', '127.0.0.77', trap.port)
            assert trap.receives()
            s.close()
            assert r.events.empty()
            assert audit_counts('iptables')[0] > 0
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
                probe.sendto(b'control', ('::2', 9000))
            assert audit_counts('ip6tables')[2] > 0
            reset_audit()
            assert_audit_clean()
            cert = CERT
            for ep, u, p in endpoints:
                s = request(ep['obfs4'], 'cert=' + cert + ';iat-mode=0', '127.0.0.77', 4444)
                e = r.next()
                expected = None if u is None else (u.encode(), p.encode())
                assert e == ('connect', expected, 1, '127.0.0.77', 4444), e
                carrier = r.next()
                assert carrier[0] == 'carrier' and len(carrier[1]) > 0, carrier
                s.close()
            ep = endpoints[0][0]['webtunnel']
            for args, expected in [('url=http://bridge.invalid:8080/path', (3, 'bridge.invalid', 8080)),
                                   ('url=http://bridge.invalid:8080/path;addr=override.invalid:8443', (3, 'override.invalid', 8443))]:
                s = request(ep, args)
                event = r.next()
                assert event[2:] == expected, event
                carrier = r.next()
                assert carrier[0] == 'carrier' and carrier[1].startswith(b'GET '), carrier
                s.close()
            for mode in ('auth-reject', 'connect-reject'):
                reject = recorder(mode)
                c = child(proxy_uri(reject.port, 'u', 'p'))
                endpoint = c.ready(True)
                for method, args, port in (
                    ('obfs4', 'cert=' + cert + ';iat-mode=0', trap.port),
                    ('webtunnel', 'url=http://127.0.0.77:' + str(trap.port) + '/path', 443),
                    ('webtunnel', 'url=http://bridge.invalid:8080/path', 443),
                ):
                    s = request(endpoint[method], args, port=port)
                    assert reject.next()[0] == ('auth-reject' if mode == 'auth-reject' else 'connect')
                    assert_failed(s)
                    s.close()
                    assert c.p.poll() is None
                    trap.assert_idle()
                reject.mode = 'ok'
                s = request(endpoint['webtunnel'], 'url=http://bridge.invalid:8080/path')
                assert reject.next()[0] == 'connect'
                carrier = reject.next()
                assert carrier[0] == 'carrier' and carrier[1].startswith(b'GET ')
                s.close()
                assert c.p.poll() is None
            assert_audit_clean()
            for uri in ('http://user:secret@127.0.0.1:1', 'socks5://user:%XX@127.0.0.1:1'):
                c = child(uri)
                assert c.line() == 'VERSION 1'
                line = c.line()
                assert line.startswith('PROXY-ERROR ') and 'user' not in line and 'secret' not in line
                c.p.wait(timeout=TIMEOUT)
                assert c.p.returncode != 0
                assert c.lines.empty()
            trap.assert_idle()
            c = child(None, 'webtunnel')
            assert 'webtunnel' in c.ready(False)
            assert_audit_clean()
        finally:
            for c in children:
                stderr = c.close()
                for secret in ('юзер@1', 'пароль:1', 'p@ss/2'):
                    assert secret.encode() not in stderr
                    assert urllib.parse.quote(secret, safe='').encode() not in stderr
            for r in recorders:
                r.close()
            trap.close()


if __name__ == '__main__':
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('PT_PROXY_ISOLATED') == 'yes'
    assert len(sys.argv) == 2 and os.path.isabs(sys.argv[1])
    run(sys.argv[1])
