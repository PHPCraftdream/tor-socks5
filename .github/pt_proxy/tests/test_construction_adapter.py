"""Future-CI controls for synthetic construction evidence."""

import importlib.util
import itertools
import os
from pathlib import Path
import selectors
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, filename):
    path = Path(__file__).resolve().parents[1] / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dd = load("_ce_domain", "direct_domain.py")
ca = load("_ce_adapter", "construction_adapter.py")


class FailingSend:
    def __init__(self, socket_):
        self.socket = socket_
        self.calls = 0

    def fileno(self):
        return self.socket.fileno()

    def send(self, data):
        self.calls += 1
        if self.calls == 1:
            return self.socket.send(data[:1])
        raise BrokenPipeError("synthetic final-response write failure")

    def recv(self, size):
        return self.socket.recv(size)

    def getpeername(self):
        return self.socket.getpeername()

    def getsockname(self):
        return self.socket.getsockname()

    @property
    def family(self):
        return self.socket.family

    def close(self):
        self.socket.close()


class Fixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.phase = dd.PHASES[0]
        self.domain = dd.DirectDomain(
            time.monotonic() + 10, dd.calibration_rules, lambda: 0,
            lambda *args: None,
        )
        self.domain.owner = dd.Pin(os.getpid(), self_owner=True)
        self.domain.binary = Path(sys.executable).resolve(strict=True)
        self.domain.phases = dd.PHASES
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.reactor = dd.Reactor(
            self.domain.deadline, self.listener, self.domain,
            phase=lambda: self.phase,
        )
        self.adapter = ca.ConstructionAdapter(dd, self.domain, lambda: self.phase)
        self.adapter.attach(self.reactor)
        self.client = socket.create_connection(self.listener.getsockname())
        self.client.setblocking(False)
        self.output = bytearray()
        self.eof = False
        self.reactor.watch(self.client, self.receive)
        self.transaction = 0
        self.client_closed = False

    def receive(self, mask):
        try:
            data = self.client.recv(256)
        except BlockingIOError:
            return
        if not data:
            self.eof = True
            self.reactor.unwatch(self.client)
            return
        self.output.extend(data)
        if len(self.output) > 256:
            raise AssertionError("unbounded response")

    def send(self, request):
        self.client.setblocking(True)
        self.client.settimeout(1)
        self.client.sendall(request)
        self.client.setblocking(False)

    def line(self, request):
        self.send(request)
        self.reactor.until(lambda: b"\n" in self.output or self.eof)
        if b"\n" not in self.output:
            raise AssertionError("missing response")
        at = self.output.index(b"\n") + 1
        result = bytes(self.output[:at])
        del self.output[:at]
        return result

    def start(self, body):
        self.transaction += 1
        number = self.transaction
        assert self.line(
            f"CE START {number} {len(body)}\n".encode()
        ) == f"CE READY {number}\n".encode()
        offset = 0
        while offset < len(body):
            chunk = body[offset:offset + ca.MAX_CHUNK]
            request = (
                f"CE DATA {number} {offset} ".encode()
                + chunk.hex().encode() + b"\n"
            )
            offset += len(chunk)
            assert self.line(request) == f"CE NEXT {number} {offset}\n".encode()
        return number

    def commit(self, fact, confirm=True):
        number = self.start(ca.encode(fact))
        response = self.line(f"CE COMMIT {number}\n".encode())
        if response == f"CE ACCEPT {number}\n".encode() and confirm:
            assert self.line(
                f"CE CONFIRM {number}\n".encode()
            ) == f"CE CONFIRMED {number}\n".encode()
        return response

    def disconnect(self):
        if not self.client_closed:
            self.reactor.unwatch(self.client)
            self.client.close()
            self.client_closed = True

    def close(self):
        self.disconnect()
        self.reactor.close()
        self.listener.close()
        self.domain.owner.close()
        self.temporary.cleanup()

    def opening(self, registry=1, phase=0):
        return ca.Fact(ca.OPEN, phase, registry)

    def outcome(self, operation=ca.RESERVED, registry=1, sequence=1,
                request=0, identity=41, disabled=True, effective=True,
                phase=0):
        if operation != ca.RESERVED:
            identity = 0
        if operation == ca.FAILED:
            effective = None
        return ca.Fact(
            operation, phase, registry, sequence, request, identity,
            disabled=disabled, effective=effective,
        )

    def assignment(self, registry=1, sequence=2, request=0, identity=41,
                   disabled=True, effective=True, phase=0, slot=1):
        base = self.root / f"registry-{registry}"
        allocated = base / "owners-v1" / "1"
        allocated.mkdir(parents=True, exist_ok=True)
        return ca.Fact(
            ca.ASSIGNED, phase, registry, sequence, request, identity, slot,
            disabled, effective, os.fsencode(base), os.fsencode(allocated),
        )

    def baseline(self, registry=1, phase=0):
        assert self.commit(self.opening(registry, phase)).startswith(b"CE ACCEPT ")
        assert self.commit(self.outcome(registry=registry, phase=phase)).startswith(
            b"CE ACCEPT ")
        assert self.commit(self.assignment(registry=registry, phase=phase)).startswith(
            b"CE ACCEPT ")
        return self.domain.allocations[-1]

    def status(self, failure=0, acknowledged=True, item_failure=0,
               closed=True, dropped=0):
        return ca.ProducerStatus(
            True, closed, failure, 2, dropped, 1,
            (
                ca.ItemStatus(1, True, True, 0),
                ca.ItemStatus(2, True, acknowledged, item_failure),
            ),
        )

    def ending(self, status=None):
        return ca.Fact(
            ca.END, 0, 1,
            status=self.status() if status is None else status,
        )

    def finishing(self):
        return ca.Fact(ca.FINISH, 0, 0)


class ConstructionControls(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def tearDown(self):
        self.f.close()

    def denied(self, response, reason):
        self.assertEqual(response, b"DENY registration-invalid\n")
        self.assertEqual(self.f.adapter.protocol_errors[0], reason)
        self.assertFalse(self.f.adapter.reconcile())

    def test_owned_stream_and_independent_request_zero_journals(self):
        f = self.f
        first = f.baseline()
        self.assertEqual(
            (first.registry, first.request, first.reserved_sequence,
             first.assigned_sequence), (1, 0, 1, 2),
        )
        self.assertTrue(f.adapter.allocation_ready(first))
        f.phase = dd.PHASES[1]
        second = f.baseline(2, 1)
        self.assertEqual(
            (second.registry, second.request, second.reserved_sequence,
             second.assigned_sequence), (2, 0, 1, 2),
        )
        self.assertEqual(first.identity, second.identity)
        self.assertNotEqual(first.allocated, second.allocated)
        self.assertTrue(f.adapter.allocation_ready(second))

    def test_mocked_unowned_stream_is_rejected_before_context_creation(self):
        f = self.f
        with patch.object(dd, "socket_owned",
                          side_effect=dd.Denied("channel-owner")):
            response = f.line(f"CE START 1 {ca.HEADER.size}\n".encode())
        self.assertEqual(response, b"DENY channel-owner\n")
        self.assertEqual(f.adapter.protocol_errors[0], "channel-owner")
        self.assertFalse(f.adapter.contexts)
        self.assertFalse(f.domain.allocations)

    def test_receipt_needs_remote_confirmation_and_response_write(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        self.assertEqual(
            f.commit(f.assignment(), confirm=False), b"CE ACCEPT 3\n")
        allocation = f.domain.allocations[0]
        item = f.adapter.pending
        self.assertTrue(item.accepted)
        self.assertTrue(item.accept_written)
        self.assertFalse(item.remote_confirmed)
        self.assertFalse(item.response_written)
        self.assertFalse(f.adapter.allocation_ready(allocation))
        self.assertEqual(f.line(b"CE CONFIRM 3\n"), b"CE CONFIRMED 3\n")
        self.assertTrue(item.remote_confirmed)
        self.assertTrue(item.response_written)
        self.assertTrue(f.adapter.allocation_ready(allocation))

    def test_late_confirmation_fails_at_direct_input_boundary(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        f.commit(f.assignment(), confirm=False)
        item = f.adapter.pending
        f.domain.deadline = time.monotonic() - 1
        with self.assertRaises(dd.Denied) as failure:
            f.adapter.on_line(f.adapter.peer, b"CE CONFIRM 3\n")
        self.assertEqual(str(failure.exception), "budget-exhausted")
        self.assertEqual(f.adapter.protocol_errors, ["budget-exhausted"])
        self.assertFalse(item.remote_confirmed)
        self.assertFalse(item.response_written)
        self.assertFalse(f.adapter.allocation_ready(f.domain.allocations[0]))
        self.assertFalse(f.adapter.reconcile())

    def test_every_pair_of_reserve_outcomes_rejects_same_request(self):
        for first, second in itertools.product(
                (ca.RESERVED, ca.GLOBAL, ca.FAILED), repeat=2):
            with self.subTest(first=first, second=second):
                f = Fixture()
                try:
                    f.commit(f.opening())
                    f.commit(f.outcome(first, disabled=False))
                    response = f.commit(f.outcome(
                        second, sequence=2, disabled=False))
                    self.assertEqual(response, b"DENY registration-invalid\n")
                    self.assertEqual(
                        f.adapter.protocol_errors[0], "evidence-request-replay")
                    self.assertEqual(len(f.adapter.contexts[1].events), 1)
                    self.assertFalse(f.domain.allocations)
                finally:
                    f.close()

    def test_sequence_replay_and_crossed_assignment(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        self.denied(f.commit(f.outcome()), "evidence-event-order")

    def test_crossed_assignment_request(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        self.denied(
            f.commit(f.assignment(request=1)),
            "evidence-assignment-correlation",
        )
        self.assertFalse(f.domain.allocations)

    def test_duplicate_storage_assignment(self):
        f = self.f
        f.baseline()
        self.denied(
            f.commit(f.assignment(sequence=3)),
            "evidence-assignment-correlation",
        )
        self.assertEqual(len(f.domain.allocations), 1)

    def test_configured_assignment_does_not_authorize_direct(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome(disabled=False, effective=False))
        self.assertEqual(
            f.commit(f.assignment(disabled=False, effective=False)),
            b"CE ACCEPT 3\n",
        )
        self.assertFalse(f.domain.allocations)
        self.assertEqual(len(f.adapter.contexts[1].assignments), 1)

    def test_disabled_contradiction(self):
        f = self.f
        f.commit(f.opening())
        self.denied(
            f.commit(f.outcome(effective=False)),
            "evidence-disabled-contradiction",
        )

    def test_path_slot_mismatch(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        self.denied(f.commit(f.assignment(slot=2)),
                    "evidence-assignment-path")

    def test_failure_status_is_accepted_but_never_successful(self):
        f = self.f
        f.baseline()
        cancelled = ca.failure_code(
            "construction export acknowledgement cancelled")
        status = f.status(
            failure=cancelled, acknowledged=False, item_failure=cancelled)
        self.assertEqual(f.commit(f.ending(status)), b"CE ACCEPT 4\n")
        self.assertEqual(f.adapter.contexts[1].status, status)
        self.assertEqual(f.adapter.producer_failures, [1])
        self.assertFalse(f.adapter.allocation_ready(f.domain.allocations[0]))
        self.assertEqual(f.commit(f.finishing()), b"CE ACCEPT 5\n")
        self.assertTrue(f.adapter.finished)
        self.assertFalse(f.adapter.reconcile())
        self.assertEqual(
            f.adapter.failure_snapshot()["contexts"][0][3], status)

    def test_drops_and_unacknowledged_progress_cannot_claim_success(self):
        f = self.f
        f.baseline()
        self.denied(
            f.commit(f.ending(f.status(dropped=1))),
            "evidence-status-unreported-failure",
        )

    def test_unacknowledged_progress_requires_reported_failure(self):
        f = self.f
        f.baseline()
        self.denied(
            f.commit(f.ending(f.status(acknowledged=False))),
            "evidence-status-unreported-failure",
        )

    def test_failure_snapshot_can_retain_unpublished_progress(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        reason = ca.failure_code("construction export delivery failed")
        status = ca.ProducerStatus(
            True, True, reason, 2, 0, 0,
            (ca.ItemStatus(1, True, True, 0),
             ca.ItemStatus(2, False, False, reason)),
        )
        self.assertEqual(f.commit(f.ending(status)), b"CE ACCEPT 3\n")
        self.assertEqual(f.adapter.contexts[1].status, status)
        self.assertEqual(len(f.adapter.contexts[1].events), 1)
        self.assertFalse(f.adapter.reconcile())

    def test_wrong_fragment_offset(self):
        f = self.f
        self.assertEqual(
            f.line(f"CE START 1 {ca.HEADER.size}\n".encode()),
            b"CE READY 1\n",
        )
        self.denied(f.line(b"CE DATA 1 1 00\n"),
                    "evidence-fragment-order")

    def test_partial_frame_disconnect_is_sticky_server_failure(self):
        f = self.f
        self.assertEqual(
            f.line(f"CE START 1 {ca.HEADER.size}\n".encode()),
            b"CE READY 1\n",
        )
        f.send(b"CE DA")
        f.disconnect()
        f.reactor.until(lambda: bool(f.adapter.protocol_errors))
        self.assertEqual(
            f.adapter.protocol_errors, ["evidence-stream-disconnected"])
        self.assertIsNotNone(f.adapter.pending)
        self.assertFalse(f.adapter.finished)
        self.assertFalse(f.adapter.reconcile())

    def test_terminal_partial_write_then_failure_never_finishes(self):
        f = self.f
        f.baseline()
        f.commit(f.ending())
        self.assertEqual(
            f.commit(f.finishing(), confirm=False), b"CE ACCEPT 5\n")
        peer = f.adapter.peer
        item = f.adapter.pending
        f.adapter.on_line(peer, b"CE CONFIRM 5\n")
        self.assertTrue(item.remote_confirmed)
        self.assertTrue(item.response_queued)
        self.assertFalse(item.response_written)
        original = peer.sock
        f.reactor.unwatch(original)
        replacement = FailingSend(original)
        f.reactor.peers.pop(original)
        peer.sock = replacement
        f.reactor.peers[replacement] = peer
        f.reactor.watch(replacement, peer.service, selectors.EVENT_WRITE)
        peer.service(selectors.EVENT_WRITE)
        self.assertEqual(replacement.calls, 1)
        self.assertFalse(item.response_written)
        self.assertFalse(f.adapter.finished)
        self.assertIs(f.adapter.pending, item)
        peer.service(selectors.EVENT_WRITE)
        self.assertTrue(peer.closed)
        self.assertEqual(replacement.calls, 2)
        self.assertFalse(item.response_written)
        self.assertFalse(f.adapter.finished)
        self.assertIs(f.adapter.pending, item)
        self.assertEqual(
            f.adapter.protocol_errors, ["evidence-stream-disconnected"])
        self.assertFalse(f.adapter.reconcile())

    def test_terminal_receipt_then_close_before_write_completion(self):
        f = self.f
        f.baseline()
        f.commit(f.ending())
        self.assertEqual(
            f.commit(f.finishing(), confirm=False), b"CE ACCEPT 5\n")
        peer = f.adapter.peer
        item = f.adapter.pending
        expected = b"CE CONFIRMED 5\n"
        received = bytearray()

        class ReceiveThenClose(FailingSend):
            def send(self, data):
                sent = self.socket.send(data)
                self.calls += 1
                f.client.setblocking(True)
                f.client.settimeout(dd.remaining(f.domain.deadline))
                remaining = sent
                while remaining:
                    part = f.client.recv(remaining)
                    if not part:
                        raise AssertionError("terminal receipt was truncated")
                    received.extend(part)
                    remaining -= len(part)
                if len(received) == len(expected):
                    if bytes(received) != expected:
                        raise AssertionError("wrong terminal response")
                    f.disconnect()
                return sent

        original = peer.sock
        f.reactor.unwatch(original)
        replacement = ReceiveThenClose(original)
        f.reactor.peers.pop(original)
        peer.sock = replacement
        f.reactor.peers[replacement] = peer
        f.adapter.on_line(peer, b"CE CONFIRM 5\n")
        self.assertTrue(item.remote_confirmed)
        self.assertFalse(item.response_written)
        self.assertFalse(f.adapter.finished)
        f.reactor.until(lambda: peer.closed)
        self.assertEqual(bytes(received), expected)
        self.assertGreaterEqual(replacement.calls, 1)
        self.assertTrue(f.client_closed)
        self.assertTrue(item.response_written)
        self.assertIsNone(f.adapter.pending)
        self.assertTrue(f.adapter.finished)
        self.assertEqual(f.adapter.protocol_errors, [])
        self.assertTrue(f.adapter.reconcile())

    def test_actual_authorize_requires_ready_independent_receipt(self):
        f = self.f
        f.commit(f.opening())
        f.commit(f.outcome())
        self.assertEqual(
            f.commit(f.assignment(), confirm=False), b"CE ACCEPT 3\n")
        allocation = f.domain.allocations[0]
        leaf = allocation.allocated / "state" / "pt_state" / f.domain.binary.name
        leaf.mkdir(parents=True)
        self.assertEqual(dd.canonical(leaf), leaf)
        self.assertFalse(f.adapter.pending.response_written)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = None
        server = None
        root = None
        try:
            f.domain.setup()
            root = f.domain.root
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(dd.remaining(f.domain.deadline))
            client = socket.create_connection(
                listener.getsockname(), timeout=dd.remaining(f.domain.deadline))
            server, _ = listener.accept()
            dd.socket_owned(server, f.domain.owner.pid)
            self.assertEqual(list(root.iterdir()), [])
            with self.assertRaises(dd.Denied) as failure:
                f.domain.authorize(
                    server, allocation.allocated, leaf, f.phase)
            self.assertEqual(str(failure.exception), "intent-allocation")
            self.assertEqual(f.domain.records, [])
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(f.line(b"CE CONFIRM 3\n"), b"CE CONFIRMED 3\n")
            record = f.domain.authorize(
                server, allocation.allocated, leaf, f.phase)
            self.assertIs(record.allocation, allocation)
            self.assertEqual(record.leaf, leaf)
            self.assertTrue(record.created)
            self.assertEqual(f.domain.records, [record])
            self.assertEqual(record.group, root / "direct-0")
            self.assertEqual(list(root.iterdir()), [record.group])
            self.assertEqual(f.domain.members(record.group), [])
        finally:
            if server is not None:
                server.close()
            if client is not None:
                client.close()
            listener.close()
            if root is None and f.domain.root_created:
                root = f.domain.root
            if root is not None:
                for record in reversed(f.domain.records):
                    if record.created and not record.group_removed:
                        self.assertEqual(f.domain.members(record.group), [])
                        record.group.rmdir()
                        record.group_removed = True
                self.assertEqual(f.domain.members(root), [])
                root.rmdir()
                f.domain.disposed = True

    def test_success_requires_final_response_write(self):
        f = self.f
        f.baseline()
        f.commit(f.ending())
        f.commit(f.finishing(), confirm=False)
        item = f.adapter.pending
        self.assertFalse(f.adapter.reconcile())
        f.adapter.on_line(f.adapter.peer, b"CE CONFIRM 5\n")
        self.assertFalse(item.response_written)
        self.assertFalse(f.adapter.finished)
        self.assertFalse(f.adapter.reconcile())
        f.reactor.until(lambda: f.adapter.finished)
        self.assertTrue(item.response_written)
        self.assertIsNone(f.adapter.pending)
        self.assertTrue(f.adapter.peer.closed)
        self.assertTrue(f.adapter.reconcile())

    def test_lossless_path_bytes_and_unknown_failure_rejection(self):
        fact = ca.Fact(
            ca.ASSIGNED, 0, 1, 2, 0, 41, 1, True, True,
            b"/tmp/base-\xff", b"/tmp/base-\xff/owners-v1/1",
        )
        self.assertEqual(ca.decode(ca.encode(fact)), fact)
        self.assertEqual(os.fsencode(os.fsdecode(fact.base)), fact.base)
        with self.assertRaises(KeyError):
            ca.failure_code("unknown producer failure")


if __name__ == "__main__":
    unittest.main()
