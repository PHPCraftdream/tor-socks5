"""GitHub-CI-only audit of the actual owner executable and its descendants."""
import os
import re
import select
import shlex
import signal
import socket
import subprocess
import sys

CHAIN = 'PT_OWNER'
FAMILIES = (
    ('iptables', socket.AF_INET, '127.0.0.1', '192.0.2.1'),
    ('ip6tables', socket.AF_INET6, '::1', '2001:db8::1'),
)
controls = []
peers = {}
interrupted = None
snapshots = {tool: 0 for tool, _, _, _ in FAMILIES}
packet_details = {tool: None for tool, _, _, _ in FAMILIES}
AUDIT_REASONS = frozenset((
    'oversized audit snapshot',
    'duplicate filter table',
    'unexpected filter commit',
    'content outside filter table',
    'duplicate audit chain',
    'unparsed audit line',
    'undeclared audit chain',
    'incomplete filter snapshot',
    'audit chain or policy changed',
    'audit hook or ordered rules changed',
    'live control parent and dedicated counters disagree',
    'audit packet or byte conservation failed',
    'DNS or forbidden egress observed',
    'owner window had no IPv4 traffic',
))

def diagnostic_reason(failure):
    if type(failure) is RuntimeError and str(failure) in AUDIT_REASONS:
        return str(failure)
    return 'unclassified exception; message withheld'

def counter_details(tool, counts):
    limit = (1 << 64) - 1
    clipped = False
    def pair(value):
        nonlocal clipped
        clipped = clipped or any(number > limit for number in value)
        return tuple(min(number, limit) for number in value)
    live = [c for c in controls if tool == 'iptables' and c[3]]
    retired = [c for c in controls if tool == 'iptables' and not c[3]]
    classified = counts[CHAIN] + [counts[c[2]][0] for c in retired]
    details = {
        'output': pair(counts['OUTPUT'][0]),
        'dns_udp': pair(counts[CHAIN][0]),
        'dns_tcp': pair(counts[CHAIN][1]),
        'forbidden': pair(counts[CHAIN][-2]),
        'loopback': pair(counts[CHAIN][-1]),
        'classified_total': pair(tuple(sum(c[i] for c in classified)
                                       for i in (0, 1))),
        'live': [
            (controls.index(control), pair(counts[CHAIN][index]),
             pair(counts[control[2]][0]))
            for index, control in enumerate(live, start=2)
        ],
        'retired': [
            (controls.index(control), pair(counts[control[2]][0]))
            for control in retired
        ],
    }
    details['clipped_to_u64'] = clipped
    return details

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def command(*args):
    return subprocess.run(args, check=True, timeout=5, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def tuple_rule(control):
    source, destination, name, _ = control
    return ['-s', '127.0.0.1/32', '-d', '127.0.0.77/32', '-p', 'tcp',
            '--sport', str(source), '--dport', str(destination), '-g', name]

def expected(tool):
    loopback = '127.0.0.1/32' if tool == 'iptables' else '::1/128'
    result = {'INPUT': [], 'FORWARD': [], 'OUTPUT': [['-j', CHAIN]]}
    body = [['-p', 'udp', '--dport', '53', '-j', 'RETURN'],
            ['-p', 'tcp', '--dport', '53', '-j', 'RETURN']]
    body.extend(tuple_rule(c) for c in controls if tool == 'iptables' and c[3])
    body.extend([['!', '-d', loopback, '-j', 'RETURN'], ['-j', 'RETURN']])
    result[CHAIN] = body
    result.update({c[2]: [['-j', 'RETURN']] for c in controls if tool == 'iptables'})
    return result

def audit(tool):
    packet_details[tool] = None
    text = command(tool + '-save', '-c', '-t', 'filter')
    snapshots[tool] += 1
    require(len(text) < 131072, 'oversized audit snapshot')
    schema = expected(tool)
    policies, rules, counts = {}, {}, {}
    inside, committed = False, False
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        if line == '*filter':
            require(not inside and not committed, 'duplicate filter table')
            inside = True
            continue
        if line == 'COMMIT':
            require(inside and not committed, 'unexpected filter commit')
            inside, committed = False, True
            continue
        require(inside and not committed, 'content outside filter table')
        match = re.fullmatch(r':(\S+) (\S+) \[(\d+):(\d+)\]', line)
        if match:
            name, policy, _, _ = match.groups()
            require(name not in policies, 'duplicate audit chain')
            policies[name] = policy
            rules[name], counts[name] = [], []
            continue
        match = re.fullmatch(r'\[(\d+):(\d+)\] -A (\S+) (.*)', line)
        require(match is not None, 'unparsed audit line')
        packets, octets, name, tail = match.groups()
        require(name in rules, 'undeclared audit chain')
        tokens = shlex.split(tail)
        for module in ('tcp', 'udp'):
            if '-m' in tokens:
                at = tokens.index('-m')
                if tokens[at:at + 2] == ['-m', module]:
                    del tokens[at:at + 2]
        rules[name].append(tokens)
        counts[name].append((int(packets), int(octets)))
    require(committed and not inside, 'incomplete filter snapshot')
    require(policies == {
        name: ('ACCEPT' if name in ('INPUT', 'FORWARD', 'OUTPUT') else '-')
        for name in schema}, 'audit chain or policy changed')
    require(rules == schema, 'audit hook or ordered rules changed')
    packet_details[tool] = counter_details(tool, counts)
    hook = counts['OUTPUT'][0]
    live = [c for c in controls if tool == 'iptables' and c[3]]
    for index, control in enumerate(live, start=2):
        require(counts[CHAIN][index] == counts[control[2]][0],
                'live control parent and dedicated counters disagree')
    retired = [c for c in controls if tool == 'iptables' and not c[3]]
    classified = counts[CHAIN] + [counts[c[2]][0] for c in retired]
    require(hook == tuple(sum(c[i] for c in classified) for i in (0, 1)),
            'audit packet or byte conservation failed')
    return counts

def clean(tool, traffic=False):
    counts = audit(tool)
    forbidden = counts[CHAIN][:2] + [counts[CHAIN][-2]]
    require(all(value == (0, 0) for value in forbidden),
            'DNS or forbidden egress observed')
    if traffic:
        require(counts['OUTPUT'][0][0] > 0, 'owner window had no IPv4 traffic')
    return counts

def protocol_complete():
    return len(controls) == 6 and not any(c[3] for c in controls) and not peers

def packet_audits(traffic=False):
    results = {}
    for tool, _, _, _ in FAMILIES:
        before = snapshots[tool]
        error = None
        reason = None
        try:
            clean(tool, traffic=(traffic and tool == 'iptables'))
            clean_ok = True
        except Exception as failure:
            clean_ok = False
            error = (type(failure).__name__, str(failure))
            reason = diagnostic_reason(failure)
        acquired = snapshots[tool] == before + 1
        results[tool] = (acquired, clean_ok, error)
        print(f'owner-audit {tool}: snapshot={acquired} '
              f'packet_clean={clean_ok} '
              f'error_type={None if error is None else error[0]!r} '
              f'invariant={reason!r} '
              f'counter_units=packets,bytes '
              f'counters={packet_details[tool]!r}',
              file=sys.stderr)
    return results

def close_peers():
    for connection, (reader, _) in list(peers.items()):
        reader.close()
        connection.close()
        del peers[connection]

def reset():
    for tool, _, _, _ in FAMILIES:
        command(tool, '-Z')
    for tool, _, _, _ in FAMILIES:
        counts = audit(tool)
        require(all(value == (0, 0) for values in counts.values() for value in values),
                'audit reset did not produce a zero baseline')

def setup():
    require(len(command('ip', '-o', 'link', 'show').splitlines()) == 1
            and command('ip', '-o', 'link', 'show').split(':', 2)[1].strip() == 'lo',
            'unexpected network interface')
    for family in ('-4', '-6'):
        require(not command('ip', family, 'route', 'show', 'default').strip(),
                'unexpected default route')
    command('ip', 'link', 'set', 'lo', 'up')
    for tool, _, _, _ in FAMILIES:
        command(tool, '-N', CHAIN)
        command(tool, '-A', 'OUTPUT', '-j', CHAIN)
        for rule in expected(tool)[CHAIN]:
            command(tool, '-A', CHAIN, *rule)
        audit(tool)

def calibrate():
    command('ip', 'addr', 'add', '192.0.2.1/32', 'dev', 'lo')
    for address in ('::2/128', '2001:db8::1/128'):
        command('ip', '-6', 'addr', 'add', address, 'dev', 'lo', 'nodad')
    for tool, family, source, external in FAMILIES:
        forbidden = '127.0.0.77' if family == socket.AF_INET else '::2'
        cases = [(destination, 53, kind, index)
                 for destination in (source, external)
                 for kind, index in ((socket.SOCK_DGRAM, 0), (socket.SOCK_STREAM, 1))]
        cases += [(destination, 0, kind, 2)
                  for destination in (forbidden, external)
                  for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM)]
        for destination, port, kind, index in cases:
            reset()
            with socket.socket(family, kind) as server:
                server.settimeout(1)
                server.bind((destination, port))
                if kind == socket.SOCK_STREAM:
                    server.listen(1)
                with socket.socket(family, kind) as client:
                    client.settimeout(1)
                    client.bind((source, 0))
                    if kind == socket.SOCK_DGRAM:
                        client.sendto(b'x', server.getsockname())
                        require(server.recvfrom(1)[0] == b'x', 'UDP control not delivered')
                    else:
                        client.connect(server.getsockname())
                        accepted, _ = server.accept()
                        with accepted:
                            accepted.settimeout(1)
                            client.sendall(b'x')
                            require(accepted.recv(1) == b'x', 'TCP control not delivered')
            for candidate, _, _, _ in FAMILIES:
                counts = audit(candidate)
                bad = counts[CHAIN][:3]
                if candidate == tool:
                    require(bad[index][0] > 0 and bad[index][1] > 0,
                            'calibration did not reach required counter')
                    require(all(c == (0, 0) for i, c in enumerate(bad) if i != index),
                            'calibration reached wrong counter')
                    try:
                        clean(candidate)
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError('dirty calibration accepted as clean')
                else:
                    require(all(c == (0, 0) for c in counts[CHAIN]),
                            'calibration crossed address families')
    command('ip', 'addr', 'del', '192.0.2.1/32', 'dev', 'lo')
    for address in ('::2/128', '2001:db8::1/128'):
        command('ip', '-6', 'addr', 'del', address, 'dev', 'lo')
    reset()

def service(listener, ready):
    if ready is listener:
        connection, _ = listener.accept()
        connection.settimeout(1)
        peers[connection] = [connection.makefile('r', encoding='ascii'), None]
        return
    reader, control = peers[ready]
    line = reader.readline(129)
    if control is None:
        match = re.fullmatch(r'BEGIN ([0-9]{1,5}) ([0-9]{1,5})\n', line)
        require(match is not None, 'invalid trap control registration')
        source, destination = map(int, match.groups())
        require(0 < source < 65536 and 0 < destination < 65536 and destination != 53,
                'invalid trap control ports')
        require(len(controls) < 6 and not any(c[3] for c in controls),
                'duplicate or excessive live trap controls')
        control = [source, destination, f'PT_CONTROL_{len(controls)}', True]
        controls.append(control)
        command('iptables', '-N', control[2])
        command('iptables', '-A', control[2], '-j', 'RETURN')
        command('iptables', '-I', CHAIN, '3', *tuple_rule(control))
        peers[ready][1] = control
    else:
        require(line == 'END\n' and control[3], 'invalid trap control completion')
        command('iptables', '-D', CHAIN, *tuple_rule(control))
        control[3] = False
        counts = audit('iptables')
        require(counts[control[2]][0][0] > 0, 'vacuous trap control')
    ready.sendall(b'OK\n')
    if control is not None and not control[3]:
        reader.close()
        ready.close()
        del peers[ready]

def reap(statuses):
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
        statuses[pid] = os.waitstatus_to_exitcode(status)

def cleanup(statuses):
    leftover = False
    while True:
        reap(statuses)
        with open('/proc/1/task/1/children', encoding='ascii') as file:
            children = [int(value) for value in file.read().split()]
        if not children:
            reap(statuses)
            return not leftover
        leftover = True
        for pid in children:
            try:
                handle = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(handle)
            try:
                actual, status = os.waitpid(pid, 0)
                statuses[actual] = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                require(pid in statuses, 'owned child status lost')

def execute(listener, argv, trigger=False):
    statuses = {}
    process = None
    error = None
    cleanup_ok = False
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if trigger else None)
        if trigger:
            process.stdin.write(b'x')
            process.stdin.close()
        while process.pid not in statuses:
            reap(statuses)
            if process.pid in statuses:
                break
            ready, _, _ = select.select([listener, *peers], [], [], 0.05)
            for endpoint in ready:
                service(listener, endpoint)
    except Exception as failure:
        error = type(failure).__name__
    finally:
        try:
            cleanup_ok = cleanup(statuses)
        except Exception as failure:
            error = error or type(failure).__name__
    status = None if process is None else statuses.get(process.pid)
    if process is not None and status is not None:
        process.returncode = status
    return status, cleanup_ok, error

def on_signal(number, _frame):
    global interrupted
    if interrupted is None:
        interrupted = number
        raise InterruptedError('owner supervisor interrupted')

def fault_controls(listener):
    global interrupted
    retained = (
        'import os,signal; r,w=os.pipe(); p=os.fork(); '
        'os.close(r) if p==0 else os.close(w); '
        '(os.write(w,b"x"),signal.pause()) if p==0 '
        'else (os.read(r,1),os._exit(7))'
    )
    status, cleaned, error = execute(listener, [sys.executable, '-I', '-c', retained])
    require((status, cleaned, error) == (7, False, None),
            'nonzero owner and retained-child control failed')
    killed = 'import os,signal; os.read(0,1); os.kill(os.getppid(),signal.SIGUSR1); signal.pause()'
    status, cleaned, error = execute(listener, [sys.executable, '-I', '-c', killed], True)
    require(interrupted == signal.SIGUSR1 and status == -signal.SIGKILL
            and not cleaned and error == 'InterruptedError',
            'interrupted owner status control failed')
    interrupted = None

def delivered_datagram(family, address, port):
    with socket.socket(family, socket.SOCK_DGRAM) as sink:
        sink.settimeout(1)
        sink.bind((address, port))
        with socket.socket(family, socket.SOCK_DGRAM) as sender:
            sender.settimeout(1)
            require(sender.sendto(b'x', sink.getsockname()) == 1,
                    'fault control datagram not sent')
            require(sink.recvfrom(1)[0] == b'x',
                    'fault control datagram not delivered')

def require_packet_results(results, dirty):
    require(set(results) == {tool for tool, _, _, _ in FAMILIES},
            'fault control family result missing')
    for tool, result in results.items():
        expected_result = (
            True, False, ('RuntimeError', 'DNS or forbidden egress observed')
        ) if tool in dirty else (True, True, None)
        require(result == expected_result,
                'fault control snapshot or exact packet outcome mismatch')
        details = packet_details[tool]
        require(details is not None and not details['clipped_to_u64'],
                'fault control bounded counter diagnostics missing')
        require(details['output'] == details['classified_total'],
                'fault control diagnostic conservation mismatch')
        categories = (details['dns_udp'], details['dns_tcp'], details['forbidden'])
        require(any(value != (0, 0) for value in categories) == (tool in dirty),
                'fault control diagnostic packet categories mismatch')
    require(diagnostic_reason(RuntimeError('DNS or forbidden egress observed'))
            == 'DNS or forbidden egress observed',
            'fault control fixed invariant diagnostic missing')
    require(diagnostic_reason(RuntimeError('untrusted diagnostic text'))
            == 'unclassified exception; message withheld',
            'fault control untrusted diagnostic message exposed')
    require(diagnostic_reason(ValueError('untrusted diagnostic text'))
            == 'unclassified exception; message withheld',
            'fault control foreign exception message exposed')

def unfinished_control_fault(listener):
    require(not controls and not peers, 'fault control requires empty protocol state')
    reset()
    script = '''
import os
import signal
import socket

channel = socket.create_connection(('127.0.0.1', 19053), timeout=1)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.settimeout(1)
server.bind(('127.0.0.77', 0))
server.listen(1)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(1)
client.bind(('127.0.0.1', 0))
message = 'BEGIN {} {}\\n'.format(client.getsockname()[1], server.getsockname()[1])
channel.sendall(message.encode('ascii'))
reply = b''
while len(reply) < 3:
    part = channel.recv(3 - len(reply))
    if not part:
        raise RuntimeError('fault control acknowledgment lost')
    reply += part
if reply != b'OK\\n':
    raise RuntimeError('fault control acknowledgment invalid')
client.connect(server.getsockname())
accepted, _ = server.accept()
accepted.settimeout(1)
client.sendall(b'x')
if accepted.recv(1) != b'x':
    raise RuntimeError('fault control TCP byte not delivered')
readiness, ready = os.pipe()
child = os.fork()
if child == 0:
    os.close(readiness)
    os.write(ready, b'x')
    signal.pause()
    os._exit(8)
os.close(ready)
if os.read(readiness, 1) != b'x':
    raise RuntimeError('fault control retained child not ready')
os._exit(7)
'''
    status, cleaned, error = execute(listener, [sys.executable, '-I', '-c', script])
    require((status, cleaned, error) == (7, False, None),
            'unfinished-control owner status or retained cleanup mismatch')
    require(len(controls) == 1 and controls[0][3] and not protocol_complete(),
            'unfinished control was lost or manufactured complete')

    counts = audit('iptables')
    require(counts[controls[0][2]][0][0] > 0
            and counts[controls[0][2]][0][1] > 0,
            'fault control tuple counter missing')
    require(all(value == (0, 0)
                for value in counts[CHAIN][:2] + [counts[CHAIN][-2]]),
            'registered-only fault control was not packet-clean')
    require(all(value == (0, 0)
                for values in audit('ip6tables').values() for value in values),
            'registered-only fault control crossed address families')
    require_packet_results(packet_audits(traffic=True), set())

    delivered_datagram(socket.AF_INET, '127.0.0.77', 0)
    counts = audit('iptables')
    require(counts[CHAIN][-2][0] > 0 and counts[CHAIN][-2][1] > 0,
            'forbidden-only active-control counter missing')
    require(all(value == (0, 0) for value in counts[CHAIN][:2]),
            'forbidden-only active control unexpectedly contained DNS')
    require_packet_results(packet_audits(traffic=True), {'iptables'})

    for tool, family, address, _ in FAMILIES:
        delivered_datagram(family, address, 53)
        counts = audit(tool)
        require(counts[CHAIN][0][0] > 0 and counts[CHAIN][0][1] > 0,
                'unfinished-control DNS counter missing')
        require(counts[CHAIN][1] == (0, 0),
                'unfinished-control UDP probe unexpectedly contained TCP DNS')
    require_packet_results(packet_audits(traffic=True),
                           {tool for tool, _, _, _ in FAMILIES})
    require(controls[0][3] and not protocol_complete(),
            'fault control manufactured a protocol completion')

    command('iptables', '-D', CHAIN, *tuple_rule(controls[0]))
    command('iptables', '-F', controls[0][2])
    command('iptables', '-X', controls[0][2])
    close_peers()
    controls.clear()

def main():
    require(os.getpid() == 1 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('PT_PROXY_ISOLATED') == 'yes',
            'owner audit requires isolated GitHub CI PID namespace init')
    require(len(sys.argv) == 2 and os.path.isabs(sys.argv[1])
            and os.access(sys.argv[1], os.X_OK), 'invalid owner executable')
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGUSR1):
        signal.signal(number, on_signal)
    status, cleanup_ok, error = None, False, None
    setup_ok, protocol_ok, audit_ok = False, False, False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            setup()
            listener.bind(('127.0.0.1', 19053))
            listener.listen(1)
            fault_controls(listener)
            unfinished_control_fault(listener)
            calibrate()
            setup_ok = True
            status, cleanup_ok, error = execute(listener, [sys.argv[1]])
        except Exception as failure:
            error = type(failure).__name__
        finally:
            try:
                cleanup_ok = cleanup({}) and cleanup_ok
            except Exception as failure:
                error = error or type(failure).__name__
            protocol_ok = protocol_complete()
            results = packet_audits(traffic=True)
            audit_ok = all(acquired and clean_ok
                           for acquired, clean_ok, _ in results.values())
            try:
                close_peers()
            except Exception as failure:
                error = error or type(failure).__name__
    print(f'owner-audit setup={setup_ok} owner_status={status!r} '
          f'cleanup={cleanup_ok} protocol={protocol_ok} packet_audit={audit_ok} '
          f'interrupted={interrupted!r} supervisor_error={error!r}', file=sys.stderr)
    return 0 if (setup_ok and status == 0 and cleanup_ok and protocol_ok and audit_ok
                 and error is None and interrupted is None) else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as failure:
        print(f'owner-audit supervisor: FAIL ({type(failure).__name__})',
              file=sys.stderr)
        sys.exit(1)
