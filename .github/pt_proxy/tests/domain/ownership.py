class DirectDomain:
    def __init__(self, deadline, base_rules, live_count, verify_allocation,
                 fault=None, *, cleanup_deadline=None):
        require(fault in (None, 'migration', 'rule-before', 'rule-after', 'ack'),
                'fault-invalid')
        require(callable(verify_allocation), 'allocation-verifier-required')
        self.deadline = deadline
        self.cleanup_deadline = deadline if cleanup_deadline is None else cleanup_deadline
        require(deadline <= self.cleanup_deadline <= deadline + 15, 'cleanup-budget')
        self._disposing = False
        self.base_rules = base_rules
        self.live_count = live_count
        self.verify_allocation = verify_allocation
        self.allocation_ready = None
        self.fault = fault
        self.root = None
        self.root_created = False
        self.records = []
        self.allocations = []
        self.owner = None
        self.binary = None
        self.phases = ()
        self.denials = []
        self.errors = []
        self.ended = False
        self.disposed = False
        self.generation = 0
        self.issuer = object()
        self.latest = None
        self.snapshots = []

    def touch(self):
        self.generation += 1
        self.latest = None

    def command(self, *args):
        try:
            result = subprocess.run(
                args, check=True, timeout=min(5, remaining(
                    self.cleanup_deadline if self._disposing else self.deadline)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except Denied:
            raise
        except (OSError, subprocess.SubprocessError):
            raise Denied('kernel-command-failed') from None
        return result.stdout

    def setup(self):
        require(self.root is None, 'setup-lifecycle')
        try:
            remaining(self.deadline)
            require(hasattr(os, 'pidfd_open')
                    and hasattr(signal, 'pidfd_send_signal'),
                    'pidfd-unavailable')
            mount = canonical(Path('/sys/fs/cgroup'))
            require((mount / 'cgroup.controllers').is_file(), 'cgroup-v2')
            current = canonical(mount / membership(os.getpid()).lstrip('/'))
            require((current / 'cgroup.procs').is_file(), 'cgroup-process-file')
            self.root = Path(tempfile.mkdtemp(prefix='pt-owner-audit-',
                                              dir=current))
            self.root_created = True
            canonical(self.root)
            require(not self.members(self.root), 'cgroup-root-populated')
        except Denied:
            raise
        except (OSError, ValueError, UnicodeError):
            raise Denied('cgroup-capability-unavailable') from None

    def begin(self, owner, binary, phases=PHASES):
        require(self.root_created and self.owner is None and not self.ended,
                'begin-lifecycle')
        phases = tuple(phases)
        require(phases and len(phases) <= 2
                and phases == tuple(sorted(set(phases), key=PHASES.index)),
                'begin-phases')
        binary = Path(binary)
        require(binary.is_absolute() and binary.resolve(strict=True) == binary
                and binary.is_file(), 'executable-canonical')
        pin = Pin(owner, self_owner=(owner == os.getpid()))
        try:
            _, uids = process_status(owner)
            require(all(uid == os.geteuid() for uid in uids), 'owner-uid')
        except BaseException:
            pin.close()
            raise
        self.owner, self.binary, self.phases = pin, binary, phases
        self.touch()

    def register_allocation(self, evidence):
        require(self.owner is not None and not self.ended,
                'allocation-lifecycle')
        require(len(self.allocations) < len(self.phases), 'allocation-count')
        self.owner.check()
        allocation = self.verify_allocation(
            self.owner.pid, self.owner.start, self.binary, evidence)
        require(type(allocation) is Allocation, 'allocation-verifier-result')
        numbers = (allocation.identity, allocation.reserved_sequence,
                   allocation.assigned_sequence)
        require(all(type(value) is int and value > 0 for value in numbers)
                and allocation.reserved_sequence < allocation.assigned_sequence,
                'allocation-journal-order')
        require(type(allocation.request) is int and allocation.request >= 0
                and type(allocation.registry) is int
                and allocation.registry >= 0
                and allocation.owner == self.owner.pid
                and allocation.disabled is True
                and type(allocation.slot) is int
                and 1 <= allocation.slot <= 15
                and allocation.phase == self.phases[len(self.allocations)],
                'allocation-invalid')
        allocated = canonical(allocation.allocated)
        require(allocated.parent.name == 'owners-v1'
                and allocated.name == str(allocation.slot)
                and allocated.stat().st_uid == os.geteuid(),
                'allocation-slot')
        leaf = allocated / 'state' / 'pt_state' / self.binary.name
        require(all(0 < len(os.fsencode(path)) <= MAX_PATH
                    for path in (allocated, leaf)), 'allocation-path-bound')
        for old in self.allocations:
            require(old.allocated != allocation.allocated,
                    'allocation-conflict')
            require(old.registry != allocation.registry
                    or (old.request != allocation.request
                        and old.identity != allocation.identity
                        and allocation.reserved_sequence > old.assigned_sequence),
                    'allocation-conflict')
        self.allocations.append(allocation)
        self.touch()
        return allocation

    def finish(self):
        if not self.ended:
            self.ended = True
            self.touch()

    def members(self, group):
        values = bounded(group / 'cgroup.procs', 4096).decode('ascii').split()
        require(len(values) <= 16 and all(value.isdecimal() for value in values),
                'cgroup-member-format')
        return sorted(int(value) for value in values)

    def rule(self, record):
        return [
            '-s', '127.0.0.1/32', '-d', '127.0.0.77/32',
            '-p', 'tcp', '--dport', '443',
            '-m', 'cgroup', '--path', record.relative, '-j', 'RETURN',
        ]

    def rules(self):
        require(all(record.installed is not None for record in self.records),
                'rule-state-unknown')
        return [self.rule(record) for record in self.records if record.installed]

    def base(self):
        schema = {name: [list(row) for row in rows]
                  for name, rows in self.base_rules().items()}
        live = self.live_count()
        require(type(live) is int and 0 <= live <= 64, 'live-count')
        require(schema.get('INPUT') == []
                and schema.get('FORWARD') == []
                and schema.get('OUTPUT') == [['-j', CHAIN]]
                and CHAIN in schema
                and len(schema[CHAIN]) == 4 + live
                and schema[CHAIN][:2] == [list(row) for row in DNS]
                and schema[CHAIN][-2:] == [list(row) for row in TAIL],
                'base-rule-layout')
        dedicated = set(schema) - {'INPUT', 'FORWARD', 'OUTPUT', CHAIN}
        require(all(re.fullmatch(r'PT_CONTROL_[0-9]+', name)
                    and schema[name] == [['-j', 'RETURN']]
                    for name in dedicated), 'base-control-schema')
        active = []
        for row in schema[CHAIN][2:2 + live]:
            require(len(row) >= 2 and row[-2] == '-g'
                    and row[-1] in dedicated, 'base-live-control')
            active.append(row[-1])
        require(len(set(active)) == len(active), 'base-live-duplicate')
        return schema, tuple(active)

    def expected(self):
        schema, _ = self.base()
        at = 2 + self.live_count()
        schema[CHAIN][at:at] = self.rules()
        return schema

    def raw_snapshot(self):
        text = self.command('iptables-save', '-c', '-t', 'filter')
        require(len(text) < 131072, 'snapshot-bound')
        policies, rules, counts = {}, {}, {}
        inside = committed = False
        for line in text.splitlines():
            if not line or line.startswith('#'):
                continue
            if line == '*filter':
                require(not inside and not committed, 'snapshot-table')
                inside = True
                continue
            if line == 'COMMIT':
                require(inside and not committed, 'snapshot-commit')
                inside, committed = False, True
                continue
            require(inside and not committed, 'snapshot-content')
            match = re.fullmatch(r':(\S+) (\S+) \[(\d+):(\d+)\]', line)
            if match:
                name, policy, _, _ = match.groups()
                require(name not in policies, 'snapshot-chain')
                policies[name], rules[name], counts[name] = policy, [], []
                continue
            match = re.fullmatch(r'\[(\d+):(\d+)\] -A (\S+) (.*)', line)
            require(match is not None, 'snapshot-line')
            packets, octets, name, tail = match.groups()
            require(name in rules, 'snapshot-undeclared')
            tokens = shlex.split(tail)
            for module in ('tcp', 'udp'):
                for at in range(len(tokens) - 1):
                    if tokens[at:at + 2] == ['-m', module]:
                        del tokens[at:at + 2]
                        break
            rules[name].append(tokens)
            counts[name].append((int(packets), int(octets)))
        require(committed and not inside, 'snapshot-incomplete')
        return policies, rules, counts

    def validate_schema(self, policies, rules):
        schema = self.expected()
        require(policies == {
            name: ('ACCEPT' if name in ('INPUT', 'FORWARD', 'OUTPUT') else '-')
            for name in schema
        }, 'snapshot-policy')
        require(rules == schema, 'snapshot-rule-order')
        return freeze_schema(schema)

    def reconcile(self):
        try:
            policies, rules, counts = self.raw_snapshot()
        except BaseException:
            for record in self.records:
                if record.rule_attempted and record.installed is not None:
                    record.installed = None
                    self.touch()
            raise
        body = rules.get(CHAIN, [])
        for record in self.records:
            occurrences = body.count(self.rule(record))
            require(occurrences <= 1, 'rule-duplicate')
            require(record.rule_attempted or occurrences == 0,
                    'rule-unattempted')
            installed = occurrences == 1
            if record.installed is not installed:
                record.installed = installed
                self.touch()
            record.installed_ever |= installed
        schema = self.validate_schema(policies, rules)
        return schema, counts

    def snapshot(self):
        require(len(self.snapshots) < MAX_SNAPSHOTS, 'snapshot-count-bound')
        schema, counts = self.reconcile()
        _, active = self.base()
        for index, name in enumerate(active, start=2):
            require(counts[CHAIN][index] == counts[name][0],
                    'snapshot-live-counter')
        retired = set(counts) - {
            'INPUT', 'FORWARD', 'OUTPUT', CHAIN, *active
        }
        classified = counts[CHAIN] + [counts[name][0] for name in retired]
        require(counts['OUTPUT'][0] == tuple(
            sum(pair[index] for pair in classified) for index in (0, 1)
        ), 'snapshot-conservation')
        for record in self.records:
            if record.created and not record.group_removed:
                members = self.members(record.group)
                allowed = [] if record.pin is None else [record.pid]
                require(not members or members == allowed,
                        'cgroup-unowned-member')
                if record.bind_ack and record.pin.live():
                    require(members == [record.pid], 'cgroup-binding-lost')
        at = 2 + self.live_count()
        length = len(self.rules())
        direct = tuple(counts[CHAIN][at:at + length])
        data = tuple((name, tuple(rows)) for name, rows in sorted(counts.items()))
        result = Snapshot(self.issuer, self.generation, schema, data, direct)
        self.latest = result
        self.snapshots.append(result)
        return result

    def counts(self, snapshot):
        require(type(snapshot) is Snapshot
                and snapshot.issuer is self.issuer
                and snapshot is self.latest
                and snapshot.generation == self.generation,
                'snapshot-required')
        require(snapshot.schema == freeze_schema(self.expected()),
                'snapshot-layout-changed')
        require(len(snapshot.direct) == len(self.rules()),
                'snapshot-direct-association')
        return snapshot.direct

    def authorize(self, connection, allocated, leaf, phase):
        require(self.owner is not None and not self.ended, 'intent-owner')
        self.owner.check()
        socket_owned(connection, self.owner.pid)
        require(len(self.records) < len(self.allocations), 'intent-allocation')
        allocation = self.allocations[len(self.records)]
        if self.allocation_ready is not None:
            require(self.allocation_ready(allocation),
                    'intent-allocation')
        require(phase == allocation.phase, 'intent-phase')
        expected_leaf = allocation.allocated / 'state' / 'pt_state' / self.binary.name
        require(canonical(allocated) == allocation.allocated
                and canonical(leaf) == expected_leaf
                and expected_leaf.stat().st_uid == os.geteuid(),
                'intent-allocation')
        group = self.root / f'direct-{len(self.records)}'
        record = Record(allocation, expected_leaf, group)
        self.records.append(record)
        self.touch()
        try:
            group.mkdir()
            record.created = True
            require(not self.members(group), 'intent-group-failed')
        except BaseException:
            record.fail('intent-group-failed')
            raise
        return record

    def bind(self, connection, pid, reactor):
        require(self.owner is not None and not self.ended, 'bind-owner')
        require(type(pid) is int and pid > 1, 'bind-pid')
        self.owner.check()
        pin = Pin(pid)
        attached = False
        record = None
        try:
            socket_owned(connection, pid)
            pin.check()
            parent, uids = process_status(pid)
            require(parent == self.owner.pid, 'bind-parent')
            require(all(uid == os.geteuid() for uid in uids), 'bind-uid')
            require(Path(f'/proc/{pid}/exe').resolve(strict=True) == self.binary,
                    'bind-executable')
            values = environment(pid)
            require(values.get(b'TOR_PT_MANAGED_TRANSPORT_VER') == b'1'
                    and bool(values.get(b'TOR_PT_CLIENT_TRANSPORTS'))
                    and values.get(b'TOR_PT_EXIT_ON_STDIN_CLOSE') == b'1',
                    'bind-managed')
            require(b'TOR_PT_PROXY' not in values, 'bind-configured-proxy')
            raw = values.get(b'TOR_PT_STATE_LOCATION', b'')
            require(0 < len(raw) <= MAX_PATH and b'\0' not in raw,
                    'bind-state-bound')
            leaf = canonical(Path(os.fsdecode(raw)))
            matches = [item for item in self.records if item.leaf == leaf]
            require(len(matches) == 1, 'bind-no-intent')
            record = matches[0]
            require(record.intent_ack and not record.failure, 'bind-intent-ack')
            require(record.pin is None, 'bind-consumed')
            require(not self.members(record.group), 'bind-group-populated')
            pin.check()
            self.owner.check()
            require(process_status(pid)[0] == self.owner.pid, 'bind-parent')
            socket_owned(connection, pid)
            record.original_group = membership(pid)
            record.pin, record.pid = pin, pid
            attached = True
            self.touch()
            reactor.track_pin(pin, lambda: setattr(record, 'terminal', True))
            record.initial_validated = True
            record.assignment_attempted = True
            record.migration_attempted = True
            record.migrated = None
            self.touch()
            return record
        except BaseException:
            if attached:
                record.fail('bind-incomplete')
                self.touch()
            raise
        finally:
            if not attached:
                pin.close()

    def observe_migration(self, record):
        try:
            record.observed_members = tuple(self.members(record.group))
            record.pin.check()
            observed = (record.observed_members == (record.pid,)
                        and membership(record.pid) == '/' + record.relative)
            record.pin.check()
            record.migrated = observed
        except (Denied, OSError, ValueError, UnicodeError):
            record.migrated = None
        self.touch()

    def confirm_migration(self, connection, record, line):
        record.move_reply = line
        self.observe_migration(record)
        try:
            require(not self.ended and record.initial_validated
                    and record.assignment_written and not record.failure
                    and not record.bind_ack and not record.rule_attempted,
                    'bind-assignment')
            require(line == b'MOVED\n', 'bind-move-invalid')
            self.owner.check()
            record.pin.check()
            socket_owned(connection, record.pid)
            parent, uids = process_status(record.pid)
            require(parent == self.owner.pid, 'bind-parent')
            require(all(uid == os.geteuid() for uid in uids), 'bind-uid')
            require(Path(f'/proc/{record.pid}/exe').resolve(strict=True)
                    == self.binary, 'bind-executable')
            values = environment(record.pid)
            require(values.get(b'TOR_PT_MANAGED_TRANSPORT_VER') == b'1'
                    and bool(values.get(b'TOR_PT_CLIENT_TRANSPORTS'))
                    and values.get(b'TOR_PT_EXIT_ON_STDIN_CLOSE') == b'1',
                    'bind-managed')
            require(b'TOR_PT_PROXY' not in values, 'bind-configured-proxy')
            raw = values.get(b'TOR_PT_STATE_LOCATION', b'')
            require(0 < len(raw) <= MAX_PATH and b'\0' not in raw,
                    'bind-state-bound')
            require(canonical(Path(os.fsdecode(raw))) == record.leaf,
                    'bind-no-intent')
            require(record.migrated is True, 'bind-membership')
            if self.fault == 'migration':
                raise Denied('injected-migration-failure')
            record.rule_attempted = True
            self.touch()
            error = None
            try:
                if self.fault == 'rule-before':
                    raise Denied('injected-rule-before')
                position = 3 + self.live_count() + len(self.rules())
                self.command('iptables', '-I', CHAIN, str(position),
                             *self.rule(record))
                if self.fault == 'rule-after':
                    raise Denied('injected-rule-after')
                record.rule_command_ok = True
            except (Denied, OSError):
                error = 'bind-rule-command'
            self.reconcile()
            require(error is None, 'bind-rule-command')
            require(record.installed is True, 'bind-rule-unconfirmed')
            record.pin.check()
            socket_owned(connection, record.pid)
            require(self.members(record.group) == [record.pid],
                    'bind-membership')
            record.pin.check()
        except BaseException:
            record.fail('bind-incomplete')
            self.touch()
            raise

    def acknowledge(self, record, kind):
        if kind == 'intent':
            record.intent_ack = True
        elif kind == 'assignment':
            require(record.initial_validated and record.assignment_attempted
                    and not record.failure, 'bind-assignment')
            record.assignment_written = True
        else:
            require(record.migrated is True and record.installed is True
                    and record.rule_command_ok and not record.failure,
                    'ack-invalid-state')
            record.bind_ack = True
        self.touch()

    def handle(self, peer, line, phase):
        if peer.bind_pending:
            require(peer.record is not None, 'bind-assignment')
            require(len(line) <= 128, 'bind-move-frame')
            record = peer.record
            self.confirm_migration(peer.sock, record, line)
            if self.fault == 'ack':
                record.fail('injected-ack-failure')
                self.touch()
                peer.close()
            else:
                peer.reply(b'OK\n', ack=(record, 'bind'))
            return True
        if line.startswith(b'MOVED'):
            raise Denied('bind-assignment')
        if peer.intent_sizes is not None:
            sizes = peer.intent_sizes
            peer.intent_sizes = None
            require(len(line) <= MAX_PAYLOAD, 'intent-frame-bound')
            match = re.fullmatch(rb'([0-9a-f]+) ([0-9a-f]+)\n', line)
            require(match is not None, 'intent-frame')
            parts = match.groups()
            require(all(len(part) % 2 == 0 for part in parts), 'intent-frame')
            paths = [bytes.fromhex(part.decode('ascii')) for part in parts]
            require([len(path) for path in paths] == sizes, 'intent-length')
            require(all(b'\0' not in path for path in paths), 'intent-frame')
            record = self.authorize(
                peer.sock, *(Path(os.fsdecode(path)) for path in paths), phase)
            peer.record = record
            peer.reply(b'OK\n', ack=(record, 'intent'))
            return True
        if line.startswith(b'INTENT'):
            match = re.fullmatch(rb'INTENT ([0-9]{1,4}) ([0-9]{1,4})\n', line)
            require(match is not None, 'intent-header')
            sizes = [int(value) for value in match.groups()]
            require(all(0 < value <= MAX_PATH for value in sizes),
                    'intent-bound')
            peer.intent_sizes = sizes
            return True
        if line.startswith(b'BIND'):
            match = re.fullmatch(rb'BIND ([1-9][0-9]{0,9})\n', line)
            require(match is not None, 'bind-frame')
            record = self.bind(peer.sock, int(match.group(1)), peer.reactor)
            peer.record = record
            peer.bind_pending = True
            encoded = os.fsencode(record.group).hex().encode('ascii')
            require(0 < len(os.fsencode(record.group)) <= MAX_PATH,
                    'bind-assignment')
            peer.reply(b'GROUP ' + encoded + b'\n', close=False,
                       ack=(record, 'assignment'))
            return True
        return False

    def complete(self, snapshot):
        try:
            direct = self.counts(snapshot)
            if (self.denials or self.errors or not self.ended
                    or len(self.allocations) != len(self.phases)
                    or len(self.records) != len(self.phases)
                    or len(direct) != len(self.records)):
                return False
            body = snapshot.chain(CHAIN)
            if any(pair != (0, 0) for pair in (body[0], body[1], body[-2])):
                return False
            if not all(pair[0] > 0 and pair[1] > 0 for pair in direct):
                return False
            for record in self.records:
                if not (record.intent_ack and record.migrated is True
                        and record.initial_validated
                        and record.assignment_written
                        and record.move_reply == b'MOVED\n'
                        and record.rule_command_ok and record.installed is True
                        and record.bind_ack and record.failure is None
                        and record.pin is not None and not record.pin.live()
                        and not self.members(record.group)):
                    return False
            return True
        except (Denied, OSError, ValueError, UnicodeError):
            return False

    def dispose(self, reactor):
        require(not self._disposing, 'cleanup-lifecycle')
        self._disposing = True
        try:
            return self._dispose(reactor)
        finally:
            self._disposing = False

    def _dispose(self, reactor):
        self.finish()
        errors = []
        for peer in list(reactor.peers.values()):
            if peer.bind_pending and not peer.record.bind_ack:
                peer.close()
        for record in self.records:
            if record.pin is not None:
                try:
                    record.pin.kill()
                except OSError:
                    errors.append('cleanup-child-signal')
        try:
            reactor.until(lambda: all(
                record.pin is None or not record.pin.live()
                for record in self.records), deadline=self.cleanup_deadline)
        except (Denied, OSError):
            errors.append('cleanup-child-terminal')
        try:
            self.reconcile()
        except (Denied, OSError, ValueError, UnicodeError):
            errors.append('cleanup-rule-reconcile')
        for record in reversed(self.records):
            if record.pin is not None:
                record.terminal = not record.pin.live()
            if not record.created or record.group_removed:
                continue
            try:
                require(record.pin is None or record.terminal,
                        'cleanup-child-live')
                require(not self.members(record.group), 'cleanup-group-populated')
                require(record.installed is not None, 'cleanup-rule-unknown')
                if record.installed:
                    try:
                        self.command('iptables', '-D', CHAIN, *self.rule(record))
                    except Denied:
                        errors.append('cleanup-rule-command')
                    self.reconcile()
                    require(record.installed is False, 'cleanup-rule-remains')
                record.group.rmdir()
                record.group_removed = True
                self.touch()
                if record.pin is not None:
                    reactor.untrack_pin(record.pin)
                    record.pin.close()
            except (Denied, OSError, ValueError, UnicodeError):
                errors.append('cleanup-record-failed')
        if self.root_created and not self.disposed:
            try:
                require(all(not record.created or record.group_removed
                            for record in self.records), 'cleanup-records-remain')
                require(not self.members(self.root), 'cleanup-root-populated')
                self.root.rmdir()
                self.disposed = True
                if self.owner is not None:
                    self.owner.close()
            except (Denied, OSError):
                errors.append('cleanup-root-failed')
        self.errors.extend(errors)
        return tuple(errors)


