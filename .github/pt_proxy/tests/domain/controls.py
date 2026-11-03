def _probe():
    import select

    deadline = float(os.environ['PT_DOMAIN_DEADLINE'])

    def report(data):
        sys.stdout.buffer.write(data + b'\n')
        sys.stdout.buffer.flush()

    def read_line(source, bound):
        data = bytearray()
        while not data.endswith(b'\n'):
            readable, _, _ = select.select(
                [source], [], [], remaining(deadline))
            require(readable, 'probe-budget')
            part = os.read(source.fileno(), 1)
            require(part, 'probe-eof')
            data.extend(part)
            require(len(data) <= bound, 'probe-frame')
        return bytes(data)

    try:
        channel = socket.create_connection(
            ('127.0.0.1', int(os.environ['PT_DOMAIN_PORT'])),
            timeout=remaining(deadline))
        with channel:
            frame = os.environ['PT_DOMAIN_FRAME']
            request = (f'BIND {os.getpid()}\n'.encode('ascii')
                       if frame == 'self' else bytes.fromhex(frame))
            reply = _gate_transaction(
                channel, deadline, request,
                os.environ.get('PT_DOMAIN_MOVE', 'normal'))
            report(b'R ' + reply.hex().encode('ascii'))
        while True:
            fields = read_line(sys.stdin.buffer, 128).split()
            if fields == [b'STOP']:
                report(b'BYE')
                return
            require(len(fields) == 3 and fields[0] in (b'TCP', b'UDP'),
                    'probe-command')
            kind = socket.SOCK_STREAM if fields[0] == b'TCP' else socket.SOCK_DGRAM
            with socket.socket(socket.AF_INET, kind) as output:
                output.settimeout(remaining(deadline))
                address = (fields[1].decode('ascii'), int(fields[2]))
                if kind == socket.SOCK_STREAM:
                    output.connect(address)
                    output.sendall(b'x')
                else:
                    require(output.sendto(b'x', address) == 1, 'probe-send')
            report(b'S')
    except (Denied, OSError, ValueError, KeyError):
        report(b'E')
        raise SystemExit(1)


class Actor:
    def __init__(self, epoch, leaf, frame='self', proxy=False,
                 move='normal'):
        self.epoch = epoch
        self.process = None
        self.pin = None
        self.lines = []
        self.buffer = bytearray()
        self.eof = False
        self.returncode = None
        self.expected_returncode = 0
        self.stop_requested = False
        self.force_requested = False
        epoch.actors.append(self)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith('TOR_PT_')}
        env.update({
            'TOR_PT_MANAGED_TRANSPORT_VER': '1',
            'TOR_PT_CLIENT_TRANSPORTS': 'synthetic',
            'TOR_PT_EXIT_ON_STDIN_CLOSE': '1',
            'TOR_PT_STATE_LOCATION': str(leaf),
            'PT_DOMAIN_DEADLINE': str(epoch.deadline),
            'PT_DOMAIN_PORT': str(epoch.listener.getsockname()[1]),
            'PT_DOMAIN_FRAME': frame,
            'PT_DOMAIN_MOVE': move,
        })
        if proxy:
            env['TOR_PT_PROXY'] = 'socks5://127.0.0.1:1'
        code = (
            f"import runpy; "
            f"runpy.run_path({str(Path(__file__).resolve())!r})['_probe']()"
        )
        self.process = subprocess.Popen(
            [sys.executable, '-c', code], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        self.pin = Pin(self.process.pid)
        os.set_blocking(self.process.stdout.fileno(), False)
        epoch.reactor.watch(self.process.stdout, self.receive)
        epoch.reactor.track_pin(self.pin, self.terminal)

    def receive(self, mask):
        try:
            data = os.read(self.process.stdout.fileno(), 4096)
        except BlockingIOError:
            return
        if not data:
            self.eof = True
            self.epoch.reactor.unwatch(self.process.stdout)
            return
        self.buffer.extend(data)
        require(len(self.buffer) <= 4096 and len(self.lines) < 32,
                'actor-output-bound')
        while b'\n' in self.buffer:
            at = self.buffer.index(b'\n')
            self.lines.append(bytes(self.buffer[:at]))
            del self.buffer[:at + 1]

    def terminal(self):
        self.returncode = self.process.poll()
        require(self.returncode is not None, 'actor-terminal-race')

    def line(self):
        self.epoch.reactor.until(lambda: bool(self.lines) or self.eof)
        require(bool(self.lines), 'actor-missing-receipt')
        value = self.lines.pop(0)
        require(value != b'E', 'actor-failed')
        return value

    def reply(self, expected):
        require(self.line() == b'R ' + expected.hex().encode('ascii'),
                'actor-unexpected-reply')
        require(self.process.poll() is None, 'actor-exited-after-reply')

    def command(self, data):
        remaining(self.epoch.deadline)
        require(self.process.poll() is None, 'actor-exited-before-command')
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def send(self, protocol, address, port):
        self.command(f'{protocol} {address} {port}\n'.encode('ascii'))
        require(self.line() == b'S', 'actor-send-receipt')
        require(self.process.poll() is None, 'actor-exited-after-send')

    def stop(self):
        require(not self.force_requested and not self.stop_requested,
                'actor-stop-state')
        require(self.process.poll() is None, 'actor-unexpected-early-exit')
        self.stop_requested = True
        self.command(b'STOP\n')
        require(self.line() == b'BYE', 'actor-stop-receipt')
        self.epoch.reactor.until(
            lambda: self.returncode is not None and self.eof)
        require(self.returncode == 0 and not self.lines and not self.buffer,
                'actor-graceful-outcome')

    def expect_domain_kill(self):
        require(not self.stop_requested and not self.force_requested
                and self.process.poll() is None and self.pin.live(),
                'actor-force-state')
        self.force_requested = True
        self.expected_returncode = -signal.SIGKILL

    def check_terminal(self):
        require(self.returncode is not None and self.eof
                and self.returncode == self.expected_returncode
                and (self.force_requested or self.stop_requested)
                and not self.lines and not self.buffer,
                'actor-terminal-outcome')


@dataclass(frozen=True)
class SyntheticEvidence:
    owner: int
    allocated: Path


def _synthetic_allocation(owner, start, executable, evidence):
    require(type(evidence) is SyntheticEvidence
            and evidence.owner == owner and start > 0
            and executable == Path(sys.executable).resolve(strict=True),
            'synthetic-evidence-invalid')
    return Allocation(owner, 0, 1, 1, 2, 1, evidence.allocated, PHASES[0], True)


class ControlEpoch:
    def __init__(self, deadline, index, fresh_epoch, fault, cleanup_deadline=None):
        self.deadline = deadline
        self.cleanup_deadline = deadline if cleanup_deadline is None else cleanup_deadline
        self.index = index
        self.fault = fault
        self.actors = []
        self.traps = []
        self.directories = []
        self.base = None
        self.listener = None
        self.domain = None
        self.reactor = None
        self.phase = PHASES[0]
        self.cleanup_errors = []
        self.closed = False
        self.final_snapshot = None
        self.allocated = None
        self.leaf = None
        self.fresh_epoch = fresh_epoch

    def make_directory(self, path):
        path.mkdir()
        self.directories.append(path)
        return path

    def setup(self):
        remaining(self.deadline)
        self.fresh_epoch(self.deadline)
        self.base = Path(tempfile.mkdtemp(prefix='pt-domain-control-')).resolve()
        self.directories.append(self.base)
        owners = self.make_directory(self.base / 'owners-v1')
        self.allocated = self.make_directory(owners / '1')
        state = self.make_directory(self.allocated / 'state')
        root = self.make_directory(state / 'pt_state')
        self.leaf = self.make_directory(
            root / Path(sys.executable).resolve(strict=True).name)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(MAX_PEERS)
        self.domain = DirectDomain(
            self.deadline, calibration_rules, lambda: 0,
            _synthetic_allocation, fault=self.fault,
            cleanup_deadline=self.cleanup_deadline)
        self.domain.setup()
        self.domain.begin(os.getpid(), Path(sys.executable).resolve(strict=True),
                          phases=(PHASES[0],))
        self.domain.owner.check()
        require(self.domain.owner.pid == os.getpid(),
                'control-supervisor-owner')
        self.reactor = Reactor(
            self.deadline, self.listener, self.domain, phase=lambda: self.phase)
        initial = self.domain.snapshot()
        require(all(pair == (0, 0)
                    for _, rows in initial.data for pair in rows),
                'control-epoch-not-zero')

    def register(self):
        return self.domain.register_allocation(
            SyntheticEvidence(os.getpid(), self.allocated))

    def intent(self):
        require(self.reactor.exchange(intent_frame(self.allocated, self.leaf))
                == b'OK\n', 'control-intent-positive')
        require(len(self.domain.records) == 1
                and self.domain.records[0].intent_ack, 'control-intent-ack')

    def baseline(self):
        actor = Actor(self, self.leaf)
        actor.reply(b'OK\n')
        record = self.domain.records[0]
        require(record.pid == actor.process.pid
                and record.intent_ack and record.bind_ack
                and record.initial_validated and record.assignment_written
                and record.move_reply == b'MOVED\n'
                and record.migrated is True
                and record.rule_command_ok and record.installed is True
                and self.domain.members(record.group) == [record.pid],
                'control-positive-binding')
        return actor

    def trap(self, address, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.traps.append(listener)
        listener.bind((address, port))
        listener.listen(8)
        listener.setblocking(False)
        delivered = []
        connections = []

        def accept(mask):
            try:
                connection, _ = listener.accept()
            except BlockingIOError:
                return
            require(len(connections) < 8, 'control-trap-bound')
            connections.append(connection)
            self.traps.append(connection)
            connection.setblocking(False)

            def receive(events):
                try:
                    data = connection.recv(2)
                except BlockingIOError:
                    return
                require(data == b'x', 'control-trap-payload')
                delivered.append(data)
                self.reactor.unwatch(connection)
                connection.close()

            self.reactor.watch(connection, receive)

        self.reactor.watch(listener, accept)
        return delivered

    def close_traps(self):
        for endpoint in self.traps:
            if endpoint.fileno() >= 0:
                if self.reactor is not None:
                    self.reactor.unwatch(endpoint)
                endpoint.close()
        self.traps.clear()

    def emit(self, actor, address='127.0.0.77', port=443, protocol='TCP'):
        self.close_traps()
        delivered = self.trap(address, port) if protocol == 'TCP' else None
        actor.send(protocol, address, port)
        if delivered is not None:
            self.reactor.until(lambda: len(delivered) == 1)
        self.close_traps()

    def classified(self, direct, forbidden, dns_udp=False, dns_tcp=False):
        snapshot = self.domain.snapshot()
        pairs = self.domain.counts(snapshot)
        require(len(pairs) <= 1, 'control-direct-count')

        def positive(pair):
            return pair[0] > 0 and pair[1] > 0

        require(all(positive(pair) if direct else pair == (0, 0)
                    for pair in pairs), 'control-direct-counter')
        if direct:
            require(len(pairs) == 1, 'control-direct-rule-missing')
        body = snapshot.chain(CHAIN)
        for pair, wanted in (
            (body[0], dns_udp), (body[1], dns_tcp), (body[-2], forbidden),
        ):
            require(positive(pair) if wanted else pair == (0, 0),
                    'control-forbidden-classification')
        require(positive(snapshot.chain('OUTPUT')[0]),
                'control-no-kernel-traffic')
        return snapshot

    def normal_terminal(self):
        for actor in self.actors:
            actor.stop()
            actor.check_terminal()

    def forced_terminal(self, actor):
        actor.expect_domain_kill()
        errors = self.domain.dispose(self.reactor)
        self.cleanup_errors.extend(errors)
        require(not errors, 'control-partial-dispose')
        self.reactor.until(lambda: actor.returncode is not None and actor.eof)
        actor.check_terminal()

    def cleanup(self, failure=False):
        if self.closed:
            return tuple(self.cleanup_errors)
        errors = []
        if failure:
            for actor in self.actors:
                if actor.process is None or actor.process.poll() is not None:
                    continue
                try:
                    if actor.pin is not None:
                        actor.pin.kill()
                    else:
                        actor.process.kill()
                except OSError:
                    errors.append('control-failure-child-signal')
        if self.domain is not None:
            if self.reactor is not None:
                try:
                    errors.extend(self.domain.dispose(self.reactor))
                except (Denied, OSError, ValueError, UnicodeError):
                    errors.append('control-domain-cleanup')
            elif self.domain.root_created:
                try:
                    require(not self.domain.records
                            and not self.domain.members(self.domain.root),
                            'control-setup-group-populated')
                    self.domain.root.rmdir()
                    self.domain.disposed = True
                    if self.domain.owner is not None:
                        self.domain.owner.close()
                except (Denied, OSError):
                    errors.append('control-setup-cleanup')
        if self.reactor is not None:
            try:
                self.reactor.until(lambda: all(
                    actor.process is None or (
                        actor.process.poll() is not None and actor.eof)
                    for actor in self.actors), deadline=self.cleanup_deadline)
            except (Denied, OSError):
                errors.append('control-child-terminal')
        for actor in self.actors:
            if actor.process is None:
                continue
            code = actor.process.poll()
            if code is None:
                errors.append('control-child-retained-live')
                continue
            actor.returncode = code
            if not failure:
                try:
                    actor.check_terminal()
                except Denied:
                    errors.append('control-unexpected-terminal')
            if actor.pin is not None and actor.pin.fd is not None:
                if self.reactor is not None:
                    self.reactor.untrack_pin(actor.pin)
                actor.pin.close()
            for pipe in (actor.process.stdin, actor.process.stdout):
                if pipe is not None and not pipe.closed:
                    if self.reactor is not None:
                        self.reactor.unwatch(pipe)
                    pipe.close()
        self.close_traps()
        if not errors:
            if self.reactor is not None:
                self.reactor.close()
            if self.listener is not None:
                self.listener.close()
            for path in reversed(self.directories):
                try:
                    path.rmdir()
                except OSError:
                    errors.append('control-directory-cleanup')
            if not errors:
                self.closed = True
        self.cleanup_errors.extend(errors)
        return tuple(self.cleanup_errors)


class ControlRun:
    def __init__(self, deadline):
        self.deadline = deadline
        self.epochs = []
        self.reports = []

    def cleanup(self):
        errors = []
        for epoch in reversed(self.epochs):
            if not epoch.closed:
                try:
                    errors.extend(epoch.cleanup(failure=True))
                except (Denied, OSError, ValueError, UnicodeError):
                    errors.append('control-cleanup-unavailable')
        return tuple(errors)


def _require_denial(function, reason):
    try:
        function()
    except Denied as failure:
        require(str(failure) == reason, 'control-wrong-api-denial')
        return
    raise Denied('control-api-accepted-invalid-input')


def _intent_controls(epoch):
    domain, reactor = epoch.domain, epoch.reactor
    frame = intent_frame(epoch.allocated, epoch.leaf)
    require(reactor.exchange(frame) == b'DENY intent-allocation\n',
            'control-intent-without-independent-evidence')
    require(not domain.records and not domain.allocations,
            'control-intent-created-authority')
    epoch.register()
    invalid = (
        (b'INTENT 0 1\n', False, b'DENY intent-bound\n'),
        (b'INTENT 2049 1\n', False, b'DENY intent-bound\n'),
        (b'INTENT 1 1\n61 6262\n', False, b'DENY intent-length\n'),
        (b'INTENT 1 1\nAA 62\n', False, b'DENY intent-frame\n'),
        (b'INTENT 1 1\n61', True, b'DENY frame-eof\n'),
    )
    for request, truncated, reply in invalid:
        require(reactor.exchange(request, truncated=truncated) == reply,
                'control-intent-boundary')
        require(not domain.records, 'control-intent-side-effect')
    epoch.phase = 'reuse-start'
    require(reactor.exchange(frame) == b'DENY intent-phase\n',
            'control-intent-phase')
    epoch.phase = PHASES[0]
    other = epoch.make_directory(epoch.allocated.parent / '2')
    state = epoch.make_directory(other / 'state')
    root = epoch.make_directory(state / 'pt_state')
    other_leaf = epoch.make_directory(root / domain.binary.name)
    require(reactor.exchange(intent_frame(other, other_leaf))
            == b'DENY intent-allocation\n', 'control-intent-allocation')
    sender = Actor(epoch, epoch.leaf, frame=frame.hex())
    sender.reply(b'DENY channel-owner\n')
    require(not domain.records, 'control-intent-sender-side-effect')
    epoch.intent()
    actor = epoch.baseline()
    epoch.emit(actor)
    epoch.classified(True, False)


def _partial_control(epoch, case):
    epoch.register()
    epoch.intent()
    move = case if case.startswith('move-') else 'normal'
    actor = Actor(epoch, epoch.leaf, move=move)
    expected = {
        'migration': b'DENY injected-migration-failure\n',
        'rule-before': b'DENY bind-rule-command\n',
        'rule-after': b'DENY bind-rule-command\n',
        'ack': b'',
        'move-lost': b'',
        'move-invalid': b'DENY bind-move-invalid\n',
        'move-unperformed': b'DENY bind-membership\n',
    }[case]
    actor.reply(expected)
    record = epoch.domain.records[0]
    moved = case != 'move-unperformed'
    require(record.pid == actor.process.pid
            and record.initial_validated
            and record.assignment_attempted and record.assignment_written
            and record.migration_attempted and record.migrated is moved
            and epoch.domain.members(record.group) == (
                [record.pid] if moved else [])
            and not record.bind_ack and record.failure is not None,
            'control-partial-migration-evidence')
    expected_reply = (None if case == 'move-lost' else
                      b'INVALID\n' if case == 'move-invalid' else b'MOVED\n')
    require(record.move_reply == expected_reply
            and record.observed_members == (
                (record.pid,) if moved else ()),
            'control-self-migration-reply-evidence')
    require(record.rule_attempted == (
                case in ('rule-before', 'rule-after', 'ack')),
            'control-rule-attempt-evidence')
    require(record.rule_command_ok == (case == 'ack'),
            'control-rule-command-evidence')
    require(record.installed == (case in ('rule-after', 'ack'))
            and record.installed_ever == (case in ('rule-after', 'ack')),
            'control-rule-install-evidence')
    epoch.domain.finish()
    snapshot = epoch.domain.snapshot()
    require(not epoch.domain.complete(snapshot), 'control-partial-complete')
    epoch.forced_terminal(actor)
    require(record.terminal and record.group_removed
            and record.installed is False and epoch.domain.disposed,
            'control-partial-cleanup-evidence')


def _escape_control(epoch, case):
    domain = epoch.domain
    if case != 'stripped':
        epoch.register()
        epoch.intent()
    record = domain.records[0] if domain.records else None
    if case == 'unregistered':
        other = epoch.make_directory(epoch.allocated.parent / '2')
        state = epoch.make_directory(other / 'state')
        root = epoch.make_directory(state / 'pt_state')
        leaf = epoch.make_directory(root / domain.binary.name)
        actor = Actor(epoch, leaf)
        actor.reply(b'DENY bind-no-intent\n')
        require(record.pin is None, 'control-unregistered-binding')
    elif case == 'configured':
        actor = Actor(epoch, epoch.leaf, proxy=True)
        actor.reply(b'DENY bind-configured-proxy\n')
        require(record.pin is None, 'control-configured-binding')
    else:
        actor = Actor(epoch, epoch.leaf)
        actor.reply(b'DENY bind-no-intent\n')
        require(not domain.records and not domain.allocations,
                'control-stripped-created-authority')
    epoch.emit(actor)
    epoch.classified(False, True)
    if case == 'stripped':
        epoch.register()
        epoch.intent()
    baseline = epoch.baseline()
    epoch.emit(baseline)
    epoch.classified(True, True)


def _pid_boundary_control(epoch):
    require(os.getpid() == 1, 'control-supervisor-not-pid1')
    owner = epoch.domain.owner
    owner.check()
    require(owner.pid == 1 and owner.start == identity(1, self_owner=True),
            'control-pid1-owner-identity')
    for pid in (0, -1, True, 1):
        _require_denial(lambda pid=pid: identity(pid), 'pid-invalid')
        _require_denial(lambda pid=pid: Pin(pid), 'pid-invalid')
    _require_denial(lambda: identity(0, self_owner=True), 'pid-invalid')
    epoch.register()
    epoch.intent()
    record = epoch.domain.records[0]
    require(epoch.reactor.exchange(b'BIND 1\n') == b'DENY bind-pid\n',
            'control-owned-socket-pid1-rejected')
    actor = Actor(epoch, epoch.leaf, frame=b'BIND 1\n'.hex())
    actor.reply(b'DENY bind-pid\n')
    require(record.pin is None and not record.migration_attempted
            and not record.rule_attempted
            and not epoch.domain.members(record.group),
            'control-pid1-no-child-authority')
    epoch.emit(actor)
    epoch.classified(False, True)
    baseline = epoch.baseline()
    epoch.emit(baseline)
    epoch.classified(True, True)


def _borrow_control(epoch, case):
    epoch.register()
    epoch.intent()
    holder = epoch.baseline()
    record = epoch.domain.records[0]
    claimed = os.getpid() if case == 'claimed-owner' else holder.process.pid
    actor = Actor(
        epoch, epoch.leaf, frame=f'BIND {claimed}\n'.encode('ascii').hex())
    actor.reply(b'DENY bind-pid\n' if claimed == 1
                else b'DENY channel-owner\n')
    require(epoch.domain.members(record.group) == [holder.process.pid]
            and record.pid == holder.process.pid, 'control-borrowed-membership')
    epoch.emit(actor)
    epoch.classified(False, True)
    epoch.emit(holder)
    epoch.classified(True, True)


def _classification_control(epoch, case):
    epoch.register()
    epoch.intent()
    actor = epoch.baseline()
    if case == 'wrong-destination':
        epoch.emit(actor, address='127.0.0.78')
    elif case == 'wrong-port':
        epoch.emit(actor, port=444)
    elif case == 'dns-udp':
        epoch.emit(actor, port=53, protocol='UDP')
    elif case == 'dns-tcp':
        epoch.emit(actor, port=53)
    else:
        epoch.emit(actor)
    forbidden = case in ('wrong-destination', 'wrong-port')
    dns_udp, dns_tcp = case == 'dns-udp', case == 'dns-tcp'
    first = epoch.classified(
        case in ('positive', 'counts-association'), forbidden, dns_udp, dns_tcp)
    if case == 'counts-association':
        copied = {name: list(rows) for name, rows in first.data}
        _require_denial(lambda: epoch.domain.counts(copied), 'snapshot-required')
        current = epoch.domain.snapshot()
        _require_denial(lambda: epoch.domain.counts(first), 'snapshot-required')
        require(epoch.domain.counts(current)[0][0] > 0,
                'control-count-token-baseline')
    if case not in ('positive', 'counts-association'):
        epoch.emit(actor)
        epoch.classified(True, forbidden, dns_udp, dns_tcp)


def regression(deadline, fresh_epoch, *, cleanup_deadline=None):
    require(callable(fresh_epoch), 'control-epoch-adapter-required')
    require(os.getpid() == 1, 'control-supervisor-not-pid1')
    run = ControlRun(deadline)
    cases = (
        'pid-boundary', 'intent-boundaries', 'positive', 'counts-association',
        'wrong-destination', 'wrong-port', 'dns-udp', 'dns-tcp',
        'configured', 'stripped', 'unregistered',
        'claimed-owner', 'borrowed-child',
        'migration', 'rule-before', 'rule-after', 'ack',
        'move-lost', 'move-invalid', 'move-unperformed',
    )
    partial = ('migration', 'rule-before', 'rule-after', 'ack',
               'move-lost', 'move-invalid', 'move-unperformed')
    try:
        for index, case in enumerate(cases):
            fault = case if case in (
                'migration', 'rule-before', 'rule-after', 'ack') else None
            epoch = ControlEpoch(deadline, index, fresh_epoch, fault, cleanup_deadline)
            run.epochs.append(epoch)
            epoch.setup()
            if case == 'pid-boundary':
                _pid_boundary_control(epoch)
            elif case == 'intent-boundaries':
                _intent_controls(epoch)
            elif case in partial:
                _partial_control(epoch, case)
            elif case in ('configured', 'stripped', 'unregistered'):
                _escape_control(epoch, case)
            elif case in ('claimed-owner', 'borrowed-child'):
                _borrow_control(epoch, case)
            else:
                _classification_control(epoch, case)
            if case not in partial:
                epoch.normal_terminal()
                epoch.domain.finish()
                epoch.final_snapshot = epoch.domain.snapshot()
                expected_complete = case in ('positive', 'counts-association')
                require(epoch.domain.complete(epoch.final_snapshot)
                        is expected_complete, 'control-final-completion')
            errors = epoch.cleanup()
            require(not errors and epoch.closed and epoch.domain.disposed
                    and all(record.group_removed
                            and record.installed is False
                            for record in epoch.domain.records),
                    'control-cleanup-failed')
            run.reports.append((case, 'synthetic-control-passed'))
        return tuple(run.reports)
    except BaseException:
        cleanup_errors = run.cleanup()
        raise ControlFailure(run, cleanup_errors) from None
