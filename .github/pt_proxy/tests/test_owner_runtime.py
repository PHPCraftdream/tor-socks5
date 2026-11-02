"""Synthetic wiring controls; real PID/cgroup/stock-child proof belongs to CI audit."""
import importlib.util
import os
from pathlib import Path
import socket
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load_audit():
    path = Path(__file__).resolve().parents[1] / 'owner_audit.py'
    spec = importlib.util.spec_from_file_location('_runtime_audit_test', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def filter_text(schema):
    lines = ['*filter']
    for name in schema:
        policy = 'ACCEPT' if name in ('INPUT', 'FORWARD', 'OUTPUT') else '-'
        lines.append(f':{name} {policy} [0:0]')
    for name, rows in schema.items():
        lines.extend(f'[0:0] -A {name} ' + ' '.join(row) for row in rows)
    return '\n'.join([*lines, 'COMMIT', ''])


class Peer:
    def __init__(self):
        self.sock = object()
        self.state = None
        self.replies = []

    def reply(self, data, **kwargs):
        self.replies.append((data, kwargs))


class SyntheticTerminalPin:
    """Pipe readiness substitutes only the pidfd terminal notification."""
    def __init__(self):
        self.fd, self.writer = os.pipe()
        self.alive = True

    def kill(self):
        os.write(self.writer, b'x')

    def live(self):
        return self.alive

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            os.close(self.writer)
            self.fd = None


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.audit = load_audit()
        self.module = self.audit.runtime_module()
        self.deadline = time.monotonic() + 5
        self.domain = self.module.dd.DirectDomain(
            self.deadline, lambda: self.audit.expected('iptables'),
            lambda: sum(bool(c[3]) for c in self.audit.controls),
            self.module.OwnerRuntime.unattached_allocation)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.runtime = self.module.OwnerRuntime(
            self.audit, self.listener, self.deadline, self.domain)

    def tearDown(self):
        self.runtime.reactor.close()
        self.listener.close()

    def test_adapter_is_attached_before_input_and_budget_is_a_projection(self):
        self.assertTrue(self.runtime.adapter.attached)
        self.assertEqual(self.runtime.reactor.on_line, self.runtime.adapter.on_line)
        self.assertEqual(self.domain.verify_allocation, self.runtime.adapter.verify_allocation)
        self.assertEqual(self.domain.allocation_ready, self.runtime.adapter.allocation_ready)
        before = dict(self.module.os.environ)
        environment = self.runtime.environment()
        self.assertGreater(int(environment['PT_OWNER_EVIDENCE_BUDGET_MS']), 0)
        self.assertLessEqual(int(environment['PT_OWNER_EVIDENCE_BUDGET_MS']), 5000)
        self.assertEqual(dict(self.module.os.environ), before)
        with patch.object(self.module.dd, 'remaining', return_value=0.0001):
            with self.assertRaises(self.module.dd.Denied):
                self.runtime.environment()

    def test_absolute_boottime_metadata_is_not_a_descendant_duration(self):
        with patch.object(self.module.time, 'clock_gettime_ns', return_value=100_000_000_000), \
             patch.object(self.module.dd, 'remaining', return_value=4):
            environment = self.runtime.environment()
        self.assertEqual(environment['PT_OWNER_EVIDENCE_BUDGET_MS'], '4000')
        self.assertEqual(environment['PT_OWNER_EVIDENCE_DEADLINE_BOOTTIME_NS'], '104000000000')

    def test_phase_cannot_advance_before_previous_context_end(self):
        self.domain.owner = SimpleNamespace(pid=123, check=Mock())
        self.audit.phase_records[:] = [(label, {}) for label in self.audit.PHASES[:3]]
        context = SimpleNamespace(phase='legacy-start', ended=False)
        self.runtime.adapter.contexts[1] = context
        peer = Peer()
        # Authentication is deliberately mocked here: this tests ordering, not socket ownership.
        with patch.object(self.module.dd, 'socket_owned'), patch.object(self.audit, 'audit') as audit:
            with self.assertRaisesRegex(RuntimeError, 'before construction END'):
                self.runtime.on_line(peer, b'PHASE supplied-positive-start\n')
            audit.assert_not_called()
            self.assertFalse(peer.replies)
            context.ended = True
            self.runtime.on_line(peer, b'PHASE supplied-positive-start\n')
            self.assertEqual(self.audit.phase_records[-1][0], 'supplied-positive-start')
            self.assertEqual(peer.replies, [(b'OK\n', {})])

    def test_live_control_close_is_not_manufactured_complete(self):
        self.domain.owner = SimpleNamespace(pid=123, check=Mock())
        peer = Peer()
        with patch.object(self.module.dd, 'socket_owned'), patch.object(self.audit, 'command'):
            self.runtime.on_line(peer, b'BEGIN 12345 23456\n')
        self.assertTrue(self.audit.controls[0][3])
        self.assertEqual(peer.replies, [(b'OK\n', {'close': False})])
        self.runtime.on_close(peer)
        self.assertTrue(self.audit.controls[0][3])
        self.assertIn('legacy-control-incomplete', self.domain.errors)
        self.assertFalse(self.runtime.protocol_complete())

    def test_actual_domain_issues_snapshot_and_rejects_superseded_counts(self):
        schema = self.audit.expected('iptables')
        policies = {name: ('ACCEPT' if name in ('INPUT', 'FORWARD', 'OUTPUT') else '-')
                    for name in schema}
        counts = {name: [(0, 0) for _ in rows] for name, rows in schema.items()}
        self.audit.runtime = self.runtime
        with patch.object(self.domain, 'raw_snapshot', return_value=(policies, schema, counts)):
            self.audit.audit('iptables')
            first = self.runtime.final_snapshot
            self.assertEqual(self.domain.counts(first), ())
            self.assertEqual(self.audit.packet_details['iptables']['direct'], ())
            self.audit.audit('iptables')
            with self.assertRaises(self.module.dd.Denied):
                self.domain.counts(first)
        self.assertEqual(self.audit.snapshots['iptables'], 2)

    def test_domain_failure_still_reads_both_families_and_fails_audit(self):
        self.audit.runtime = self.runtime
        reads = []

        def command(tool, *_args):
            reads.append(tool)
            return filter_text(self.audit.expected(tool.removesuffix('-save')))

        with patch.object(self.runtime, 'snapshot', side_effect=self.module.dd.Denied('budget-exhausted')):
            with patch.object(self.audit, 'command', side_effect=command):
                results = self.audit.packet_audits()
        self.assertEqual(reads, ['iptables-save', 'ip6tables-save'])
        self.assertEqual(results['iptables'][:2], (True, False))
        self.assertEqual(results['ip6tables'], (True, True, None))

    def test_expired_audit_disposes_owned_record_using_only_existing_grace(self):
        dd = self.module.dd
        deadline = time.monotonic() - 1
        domain = dd.DirectDomain(deadline, dd.calibration_rules, lambda: 0,
                                 lambda *_: None, cleanup_deadline=deadline + 5)
        record = dd.Record(None, Path('/fixture-leaf'),
                           Path('/sys/fs/cgroup/pt-owner-audit-fixture/direct-0'))
        record.group = Mock()
        record.created = record.rule_attempted = record.installed = True
        pin = SyntheticTerminalPin()
        self.addCleanup(pin.close)
        record.pin = pin
        reactor = dd.Reactor(deadline, self.listener, domain)
        self.addCleanup(reactor.close)
        reactor.track_pin(pin, lambda: setattr(pin, 'alive', False))
        domain.records.append(record)
        domain.root = Mock()
        domain.root_created = True
        installed = True
        calls = []

        def kernel(args, **kwargs):
            nonlocal installed
            calls.append(args)
            self.assertGreater(kwargs['timeout'], 0)
            self.assertLessEqual(kwargs['timeout'], 5)
            if args[0] == 'iptables-save':
                schema = dd.calibration_rules()
                if installed:
                    schema[dd.CHAIN][2:2] = [domain.rule(record)]
                return SimpleNamespace(stdout=filter_text(schema))
            self.assertEqual(args, ('iptables', '-D', dd.CHAIN, *domain.rule(record)))
            installed = False
            return SimpleNamespace(stdout='')

        # Kernel and cgroup operations are mocked, but real command/deadline/dispose code runs.
        with patch.object(dd.subprocess, 'run', side_effect=kernel), \
             patch.object(domain, 'members', return_value=[]):
            with self.assertRaises(dd.Denied):
                domain.command('iptables-save', '-c', '-t', 'filter')
            self.assertFalse(calls)
            self.assertTrue(pin.live())
            self.assertEqual(domain.dispose(reactor), ())
            self.assertFalse(pin.live())
            self.assertTrue(record.terminal)
            self.assertTrue(domain.disposed)
            self.assertTrue(record.group_removed)
            self.assertFalse(record.installed)
            record.group.rmdir.assert_called_once()
            domain.root.rmdir.assert_called_once()
            count = len(calls)
            with self.assertRaises(dd.Denied):
                domain.command('iptables-save', '-c', '-t', 'filter')
            self.assertEqual(len(calls), count)
        with self.assertRaises(dd.Denied):
            dd.DirectDomain(deadline, dd.calibration_rules, lambda: 0,
                            lambda *_: None, cleanup_deadline=deadline + 16)

    def test_reactor_rejects_grace_before_finish_and_any_undeclared_end(self):
        dd = self.module.dd
        deadline = time.monotonic() + 3
        domain = dd.DirectDomain(deadline, dd.calibration_rules, lambda: 0,
                                 lambda *_: None, cleanup_deadline=deadline + 5)
        reactor = dd.Reactor(deadline, self.listener, domain)
        self.addCleanup(reactor.close)
        key = reactor.selector.get_key(self.listener)
        with patch.object(reactor.selector, 'select',
                          return_value=[(key, dd.selectors.EVENT_READ)]) as select:
            with self.assertRaises(dd.Denied):
                reactor.step(deadline=domain.cleanup_deadline)
            select.assert_not_called()
            domain.finish()
            with self.assertRaises(dd.Denied):
                reactor.step(deadline=domain.cleanup_deadline - 0.5)
            select.assert_not_called()
            reactor.step(deadline=domain.cleanup_deadline)
            select.assert_called_once()
            self.assertGreater(select.call_args.args[0], 0)
            self.assertLessEqual(select.call_args.args[0], 8)

    def test_termination_during_finalization_records_failure_without_aborting_cleanup(self):
        self.audit.finalizing = True
        self.audit.on_signal(self.audit.signal.SIGTERM, None)
        self.assertEqual(self.audit.interrupted, self.audit.signal.SIGTERM)
        self.audit.interrupted = None
        self.audit.finalizing = False
        with self.assertRaises(InterruptedError):
            self.audit.on_signal(self.audit.signal.SIGTERM, None)

    def test_calibration_refuses_any_actual_runtime(self):
        self.audit.runtime = self.runtime
        with patch.object(self.audit, 'reset') as reset:
            with self.assertRaisesRegex(RuntimeError, 'after owner start'):
                self.module.fresh_epoch(self.audit, self.deadline)
            reset.assert_not_called()


class MainWiringTests(unittest.TestCase):
    def test_main_requires_domain_snapshot_reconciliation_and_cleanup(self):
        for complete, disposed, result in ((True, True, 0), (False, True, 1), (True, False, 1)):
            with self.subTest(complete=complete, disposed=disposed):
                audit = load_audit()
                events = []
                runtime = Mock()
                runtime.protocol_complete.return_value = True
                runtime.complete.return_value = complete
                runtime.dispose.return_value = disposed
                module = Mock()
                module.OwnerRuntime.return_value = runtime
                module.calibrate.side_effect = lambda *_args: events.append('domain-calibration')
                runtime.prepare.side_effect = lambda: events.append('prepare')
                runtime.finish.side_effect = lambda: events.append('finish')
                runtime.complete.side_effect = lambda: events.append('complete') or complete
                runtime.dispose.side_effect = lambda: events.append('dispose') or disposed

                def execute(*_args):
                    self.assertIs(audit.runtime, runtime)
                    self.assertEqual(events, ['domain-calibration', 'prepare'])
                    events.append('execute')
                    audit.phase_records[:] = [(label, {}) for label in audit.PHASES]
                    return 0, True, None

                def audits(**_kwargs):
                    events.append('packet-audits')
                    return {tool: (True, True, None) for tool, *_ in audit.FAMILIES}

                environment = {'GITHUB_ACTIONS': 'true', 'PT_PROXY_ISOLATED': 'yes',
                               'PT_OWNER_AUDIT_DEADLINE': str(time.monotonic() + 30)}
                with patch.object(audit.os, 'getpid', return_value=1), \
                     patch.object(audit.os, 'environ', environment), \
                     patch.object(audit.os, 'access', return_value=True), \
                     patch.object(audit.sys, 'argv', ['owner_audit.py', '/fixture-owner']), \
                     patch.object(audit.signal, 'signal'), \
                     patch.object(audit, 'runtime_module', return_value=module), \
                     patch.object(audit, 'setup'), \
                     patch.object(audit, 'fault_controls'), \
                     patch.object(audit, 'unfinished_control_fault'), \
                     patch.object(audit, 'calibrate'), \
                     patch.object(audit, 'execute', side_effect=execute), \
                     patch.object(audit, 'cleanup', return_value=True), \
                     patch.object(audit, 'packet_audits', side_effect=audits):
                    self.assertEqual(audit.main(), result)
                self.assertEqual(events, ['domain-calibration', 'prepare', 'execute',
                                          'finish', 'packet-audits', 'complete', 'dispose'])


if __name__ == '__main__':
    unittest.main()
