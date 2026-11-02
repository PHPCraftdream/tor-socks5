"""Private retained reactor for the isolated owner audit, not product routing."""
import importlib.util
import os
from pathlib import Path
import re
import sys
import time


def load(name, filename):
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dd = load('_owner_direct_domain', 'direct_domain.py')
ca = load('_owner_construction_adapter', 'construction_adapter.py')


class OwnerRuntime:
    def __init__(self, audit, listener, deadline, domain):
        self.audit = audit
        self.deadline = deadline
        self.control_peers = set()
        self.owner_terminal = False
        self.final_snapshot = None
        self.domain = domain
        self.reactor = dd.Reactor(
            deadline, listener, self.domain, on_line=self.on_line,
            on_close=self.on_close, phase=self.phase)
        self.adapter = ca.ConstructionAdapter(dd, self.domain, self.phase)
        self.adapter.attach(self.reactor)

    @staticmethod
    def unattached_allocation(*_args):
        raise dd.Denied('allocation-verifier-unattached')

    def phase(self):
        records = self.audit.phase_records
        return records[-1][0] if records else 'owner-start'

    def prepare(self):
        self.domain.setup()

    def begin(self, pid, executable):
        executable = Path(executable).resolve(strict=True)
        self.domain.begin(pid, executable)
        dd.require(Path(f'/proc/{pid}/exe').resolve(strict=True) == executable,
                   'owner-executable')
        self.reactor.track_pin(self.domain.owner, self.owner_ended)

    def owner_ended(self):
        self.owner_terminal = True

    def environment(self):
        boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        remaining = dd.remaining(self.deadline)
        milliseconds = int(remaining * 1000)
        dd.require(0 < milliseconds <= 240000, 'owner-budget-projection')
        environment = os.environ.copy()
        environment['PT_OWNER_EVIDENCE_BUDGET_MS'] = str(milliseconds)
        environment['PT_OWNER_EVIDENCE_DEADLINE_BOOTTIME_NS'] = str(
            boottime + int(remaining * 1_000_000_000))
        return environment

    def on_line(self, peer, line):
        audit = self.audit
        self.domain.owner.check()
        dd.socket_owned(peer.sock, self.domain.owner.pid)
        if peer.state is None and line.startswith(b'PHASE '):
            label = line[6:-1].decode('ascii')
            audit.require(line.endswith(b'\n') and label in audit.PHASES,
                          'invalid audit phase label')
            audit.require(len(audit.phase_records) < len(audit.PHASES)
                          and label == audit.PHASES[len(audit.phase_records)],
                          'audit phase missing, repeated or out of order')
            previous = self.phase()
            audit.require(self.adapter.pending is None
                          and all(context.ended for context in self.adapter.contexts.values()
                                  if context.phase == previous),
                          'audit phase advanced before construction END')
            audit.audit('iptables')
            audit.phase_records.append((label, audit.packet_details['iptables']))
            print(f'owner-audit phase={label} counter_units=packets,bytes '
                  f'counters={audit.packet_details["iptables"]!r}', file=sys.stderr)
            peer.reply(b'OK\n')
            return
        if peer.state is None:
            match = re.fullmatch(rb'BEGIN ([0-9]{1,5}) ([0-9]{1,5})\n', line)
            audit.require(match is not None, 'invalid trap control registration')
            source, destination = map(int, match.groups())
            audit.require(0 < source < 65536 and 0 < destination < 65536
                          and destination != 53, 'invalid trap control ports')
            audit.require(len(audit.controls) < 6 and not any(c[3] for c in audit.controls),
                          'duplicate or excessive live trap controls')
            control = [source, destination, f'PT_CONTROL_{len(audit.controls)}', True]
            audit.controls.append(control)
            peer.state = control
            self.control_peers.add(peer)
            audit.command('iptables', '-N', control[2])
            audit.command('iptables', '-A', control[2], '-j', 'RETURN')
            audit.command('iptables', '-I', audit.CHAIN, '3', *audit.tuple_rule(control))
            peer.reply(b'OK\n', close=False)
            return
        control = peer.state
        audit.require(line == b'END\n' and control[3], 'invalid trap control completion')
        audit.command('iptables', '-D', audit.CHAIN, *audit.tuple_rule(control))
        control[3] = False
        counts = audit.audit('iptables')
        audit.require(counts[control[2]][0][0] > 0, 'vacuous trap control')
        peer.reply(b'OK\n')

    def on_close(self, peer):
        self.control_peers.discard(peer)
        if peer.state is not None and peer.state[3]:
            self.domain.errors.append('legacy-control-incomplete')
            self.domain.touch()

    def snapshot(self):
        """Only the domain issues snapshots; caller never manufactures counters."""
        snapshot = self.domain.snapshot()
        self.final_snapshot = snapshot
        return snapshot

    def protocol_complete(self):
        return (self.audit.protocol_complete() and not self.control_peers
                and not self.reactor.peers and self.adapter.reconcile())

    def finish(self):
        self.domain.finish()

    def complete(self):
        return (self.final_snapshot is not None and self.adapter.reconcile()
                and self.domain.complete(self.final_snapshot))

    def dispose(self):
        if self.domain.owner is not None:
            self.reactor.untrack_pin(self.domain.owner)
        try:
            errors = self.domain.dispose(self.reactor)
            return not errors and self.domain.disposed
        finally:
            self.reactor.close()


def fresh_epoch(audit, deadline):
    """Calibration only. Never invoked after an actual owner has started."""
    dd.remaining(deadline)
    audit.require(not audit.controls and not audit.peers
                  and audit.runtime is None, 'domain calibration after owner start')
    audit.reset()


def calibrate(audit, deadline):
    reports = dd.regression(deadline, lambda end: fresh_epoch(audit, end),
                            cleanup_deadline=deadline + 15)
    audit.require(len(reports) == 20, 'domain calibration incomplete')
    print(f'owner-audit process-domain synthetic_controls={len(reports)}', file=sys.stderr)
    # Last calibration epoch is retired before the real zero baseline.
    fresh_epoch(audit, deadline)
