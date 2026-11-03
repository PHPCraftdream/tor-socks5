import io
import os
from pathlib import Path
import selectors
import socket
import sys
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


class Wire:
    def __init__(self, data=b"", width=2):
        self.data = bytearray(data)
        self.sent = bytearray()
        self.width = width
        self.eof = False
        self.shutdowns = []
        self.close_calls = 0
        self.fd = 71

    def recv(self, count):
        if self.data:
            size = min(count, self.width, len(self.data))
            result = bytes(self.data[:size])
            del self.data[:size]
            return result
        if self.eof:
            return b""
        raise BlockingIOError()

    def send(self, data):
        size = min(self.width, len(data))
        self.sent.extend(data[:size])
        return size

    def shutdown(self, how):
        self.shutdowns.append(how)

    def close(self):
        self.close_calls += 1
        self.fd = -1

    def fileno(self):
        return self.fd


def build(c, s, entry, deadline, report):
    class Controls(unittest.TestCase):
        def session(self):
            network = c.Network("/private/tor", "/private/gencert", deadline)
            network.target = Wire()
            result = s.Session(network, c, "/private/test")
            process = SimpleNamespace(
                pid=os.getpid(), returncode=None,
                poll=lambda: None,
            )
            result.process = process
            result.process_anchor = (process,)
            result.control = result.hold(Wire())
            result.target = result.hold(Wire())
            result.initial = b"END\n"
            result.initial_written.extend(result.initial)
            result.request = b"owned-request:" + b"1" * 32 + b"\n"
            result.response = b"owned-response:" + b"1" * 32 + b"\n"
            result.target_watch = lambda: None
            result.control_watch = lambda: None
            result.unwatch = lambda resource: None
            return result

        def test_partial_write_and_shutdown_order(self):
            result = self.session()
            result.response_pending.extend(result.response)
            while result.response_pending:
                result.target_io(selectors.EVENT_WRITE)
                if result.response_pending:
                    self.assertFalse(result.target.shutdowns)
            self.assertEqual(bytes(result.target.sent), result.response)
            self.assertEqual(result.target.shutdowns, [socket.SHUT_WR])
            self.assertTrue(result.write_shutdown)
            self.assertFalse(result.target_eof)

        def test_shutdown_error_is_not_terminal_success(self):
            result = self.session()
            result.response_pending.extend(result.response)
            result.target.width = 100
            failure = OSError("private")
            with mock.patch.object(
                result.target, "shutdown", side_effect=failure
            ):
                with self.assertRaises(OSError) as observed:
                    result.target_io(selectors.EVENT_WRITE)
            self.assertIs(observed.exception, failure)
            self.assertFalse(result.write_shutdown)
            self.assertFalse(result.target_eof)

        def test_wrong_request_and_suffix_fail(self):
            for data, gate in (
                (b"wrong", "stream-request"),
                (b"x", "stream-trailing"),
            ):
                result = self.session()
                if gate == "stream-trailing":
                    result.request_seen.extend(result.request)
                    result.response_written.extend(result.response)
                result.target.data.extend(data)
                with self.assertRaisesRegex(s.StreamError, "^" + gate + "$"):
                    result.target_io(selectors.EVENT_READ)
                self.assertFalse(result.target_eof)

        def test_eof_requires_reply_shutdown_and_live_child(self):
            result = self.session()
            result.request_seen.extend(result.request)
            result.response_written.extend(result.response)
            result.target.eof = True
            with self.assertRaisesRegex(
                s.StreamError, "^stream-target-eof$"
            ):
                result.target_io(selectors.EVENT_READ)
            result.write_shutdown = True
            result.target_io(selectors.EVENT_READ)
            self.assertTrue(result.target_eof)
            self.assertTrue(result.eof_child_alive)
            result.process.poll = lambda: 0
            with self.assertRaisesRegex(s.StreamError, "^stream-child$"):
                result.check()

        def test_fragmented_receipt_and_invalid_frames(self):
            result = self.session()
            result.control.data.extend(s.w.VERIFIED)
            while result.control.data:
                result.read_control()
            self.assertTrue(result.verified)
            self.assertFalse(result.done)
            for data in (
                b"STREAM_VERIFIED\r\n", b"\0\n", b"\xff\n",
                b"x" * 512, s.w.DONE,
            ):
                result = self.session()
                result.control = Wire(data, width=513)
                with self.assertRaises(s.StreamError):
                    result.read_control()
                self.assertFalse(result.done)

        def test_receipts_cannot_replace_target_witnesses(self):
            result = self.session()
            result.verified = True
            result.target_eof = True
            with self.assertRaisesRegex(s.StreamError, "^stream-witness$"):
                result.maybe_acknowledge()
            self.assertFalse(result.ack_pending)

        def test_eof_before_verified_is_retained_without_ack(self):
            result = self.session()
            result.authenticated = True
            result.request_seen.extend(result.request)
            result.response_written.extend(result.response)
            result.write_shutdown = True
            result.ownership.extend(("first", "second"))
            result.target.eof = True
            result.target_io(selectors.EVENT_READ)
            result.maybe_acknowledge()
            self.assertFalse(result.ack_pending)
            result.control.data.extend(s.w.VERIFIED)
            while result.control.data:
                result.read_control()
            result.maybe_acknowledge()
            self.assertEqual(bytes(result.ack_pending), s.w.ACK)

        def test_real_unix_credentials_and_wrong_pid(self):
            result = self.session()
            left, right = socket.socketpair()
            try:
                result.control = left
                result.authenticate()
                self.assertEqual(
                    result.peer_credentials[:2],
                    (os.getpid(), os.geteuid()),
                )
                result.authenticated = False
                result.process.pid += 1
                with self.assertRaisesRegex(s.StreamError, "^stream-peer$"):
                    result.authenticate()
                self.assertFalse(result.authenticated)
            finally:
                left.close()
                right.close()

        def test_early_exit_and_missing_done(self):
            result = self.session()
            result.process.poll = lambda: 0
            result.process.returncode = 0
            with self.assertRaisesRegex(s.StreamError, "^stream-child$"):
                result.finish_if_exited()
            result.ack_written.extend(s.w.ACK)
            result.control.eof = True
            with self.assertRaisesRegex(
                s.StreamError, "^stream-control-eof$"
            ):
                result.finish_if_exited()
            self.assertFalse(result.complete)

        def test_helper_mutation_cannot_erase_independent_anchor(self):
            resource = Wire()
            failure = OSError("private")
            resource.close = mock.Mock(side_effect=failure)
            anchor = s.w.SocketAnchor(resource)
            proxy = SimpleNamespace(process=None, _socket=resource)
            with self.assertRaises(c.a.s.CleanupError):
                c.Network.stop_owned([proxy], deadline)
            self.assertIsNone(proxy._socket)
            self.assertIs(anchor.resource, resource)
            self.assertEqual(resource.close.call_count, 1)
            with self.assertRaises(s.StreamError):
                anchor.released()

        def test_session_failed_close_is_once_retained_and_not_released(self):
            result = self.session()
            result.process = None
            result.process_anchor = ()
            result.root = Path(tempfile.mkdtemp(prefix="stream-close-test-"))
            anchor = result.socket_anchors[1]
            resource = anchor.resource
            resource.close = mock.Mock(side_effect=OSError("private"))
            try:
                with self.assertRaises(c.a.s.CleanupError):
                    result.close()
                self.assertIs(anchor.resource, resource)
                self.assertTrue(anchor.attempted)
                self.assertIsNotNone(anchor.error)
                self.assertTrue(result.root.exists())
                self.assertFalse(result.closed)
                with self.assertRaises(c.a.s.CleanupError):
                    result.close()
                self.assertEqual(resource.close.call_count, 1)
                with self.assertRaises(s.StreamError):
                    result.released()
            finally:
                s.shutil.rmtree(result.root)

        def test_actual_dispatcher_fixed_labels_and_privacy(self):
            output = io.StringIO()
            with mock.patch.object(sys, "stderr", output):
                status = report(s.StreamError("stream-peer"), "stream")
            self.assertEqual(status, 1)
            self.assertEqual(
                output.getvalue(),
                "Tor authority consensus failed: stream\n"
                "Tor authority failure detail: type=stream gate=stream-peer\n",
            )
            calls = []

            class Private:
                def __str__(self):
                    calls.append("str")
                    raise AssertionError()

                def __repr__(self):
                    calls.append("repr")
                    raise AssertionError()

            class Subclass(s.StreamError):
                pass

            for error in (
                s.StreamError(Private()),
                s.StreamError("stream-peer", Private()),
                s.StreamError("private-path-key-nonce"),
                Subclass("stream-peer"),
            ):
                output = io.StringIO()
                with mock.patch.object(sys, "stderr", output):
                    self.assertEqual(report(error, Private()), 1)
                self.assertIn("gate=unknown\n", output.getvalue())
                self.assertNotIn("private-path-key-nonce", output.getvalue())
            self.assertEqual(calls, [])

    return Controls
