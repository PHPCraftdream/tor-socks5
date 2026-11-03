"""CI-only mechanism and genuine three-authority consensus controls."""

from datetime import datetime, timezone
import importlib.util
import io
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load("authority_consensus_checks", Path(__file__).with_name("consensus.py"))
p = load("authority_producer_checks", Path(__file__).with_name("producer.py"))


def date(value):
    return datetime.fromtimestamp(
        value, timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S").encode("ascii")


def source_line(node):
    return (
        b"dir-source " + node.name.encode("ascii")
        + b" " + node.identity.encode("ascii")
        + b" 127.0.0.1 127.0.0.1 "
        + str(node.dir_port).encode("ascii")
        + b" " + str(node.or_port).encode("ascii") + b"\n"
    )


def vote_body(node, period):
    return (
        b"network-status-version 3\n"
        b"vote-status vote\n"
        b"valid-after " + date(period) + b"\n"
        + node.certificate
        + source_line(node)
        + b"directory-signature " + node.identity.encode("ascii")
        + b" " + b"F" * 40 + b"\n"
        b"-----BEGIN SIGNATURE-----\n"
        b"mechanism-only\n"
        b"-----END SIGNATURE-----\n"
    )


def consensus_body(nodes, period, signers=2):
    body = (
        b"network-status-version 3\n"
        b"vote-status consensus\n"
        b"valid-after " + date(period) + b"\n"
        b"fresh-until " + date(period + 300) + b"\n"
        b"valid-until " + date(period + 900) + b"\n"
        b"voting-delay 20 20\n"
    )
    for index, node in enumerate(nodes):
        body += source_line(node)
        body += b"vote-digest " + ("%040X" % (index + 1)).encode("ascii") + b"\n"
    for node in nodes[:signers]:
        body += (
            b"directory-signature " + node.identity.encode("ascii")
            + b" " + b"F" * 40 + b"\n"
            b"-----BEGIN SIGNATURE-----\n"
            b"mechanism-only\n"
            b"-----END SIGNATURE-----\n"
        )
    return body


class Wire:
    def __init__(self, response):
        self.response = bytearray(response)
        self.sent = bytearray()
        self.closed = False
        self.endpoint = None

    def settimeout(self, timeout):
        if not 0 < timeout <= 0.05:
            raise AssertionError("unbounded-socket")

    def connect(self, endpoint):
        self.endpoint = endpoint

    def getpeername(self):
        return self.endpoint

    def send(self, payload):
        count = min(3, len(payload))
        self.sent.extend(payload[:count])
        return count

    def recv(self, count):
        result = bytes(self.response[:count])
        del self.response[:count]
        return result

    def close(self):
        self.closed = True

    def fileno(self):
        return -1 if self.closed else 1


class Controls(unittest.TestCase):
    def node(self, implementation=c, index=0, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + 60
        relay = SimpleNamespace(
            deadline=deadline, fingerprint=("%040X" % (index + 101)),
        )
        material = SimpleNamespace(
            deadline=deadline,
            metadata={"v3_identity_fingerprint": "%040X" % (index + 201)},
        )
        node = implementation.VotingNode(
            "/fixture/tor", deadline, relay, material, index,
        )
        node.or_port = 19001 + index * 2
        node.dir_port = 19002 + index * 2
        node.certificate = (
            b"mechanism-only-certificate-" + str(index).encode("ascii") + b"\n"
        )
        return node

    def process(self):
        process = mock.Mock(returncode=None)
        process.poll.side_effect = lambda: process.returncode

        def terminate():
            process.returncode = -15

        process.terminate.side_effect = terminate
        process.wait.side_effect = lambda **_kwargs: process.returncode
        return process

    def prepared_network(self, implementation=c, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + 60
        network = implementation.Network(
            "/fixture/tor", "/fixture/gencert", deadline,
        )
        for index in range(3):
            node = self.node(implementation, index, deadline)
            node._temp = tempfile.TemporaryDirectory(prefix="consensus-mechanism-")
            node.data = Path(node._temp.name)
            node._log = tempfile.TemporaryFile()
            node.process = self.process()
            node.config_path = node.data / "torrc"
            node.config_path.write_bytes(b"mechanism-only-unchanged-config\n")
            node._config_bytes = node.config_path.read_bytes()
            network.nodes.append(node)
            network.active.append(node)
        return network

    def test_http_eof_framing_and_partial_io(self):
        with self.node() as node:
            wire = Wire(b"HTTP/1.0 200 OK\r\nContent-Encoding: identity\r\n\r\nbody")
            endpoint = ("127.0.0.1", node.dir_port)
            with mock.patch.object(node, "_identity_and_listeners", return_value=endpoint):
                with mock.patch.object(c.socket, "socket", return_value=wire):
                    self.assertEqual(
                        node.request(b"/tor/status-vote/current/consensus"),
                        (200, b"body"),
                    )
            self.assertTrue(wire.closed)
            self.assertIn(
                b"GET /tor/status-vote/current/consensus HTTP/1.0\r\n",
                wire.sent,
            )

    def test_http_rejects_truncation_encoding_duplicate_and_transfer(self):
        responses = (
            b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nbody",
            b"HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\nbody",
            b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbody",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nbody",
            b"HTTP/1.0 200 OK\r\n",
        )
        for response in responses:
            with self.subTest(category="bad-response"):
                with self.node() as node:
                    wire = Wire(response)
                    with mock.patch.object(
                        node, "_identity_and_listeners",
                        return_value=("127.0.0.1", node.dir_port),
                    ):
                        with mock.patch.object(c.socket, "socket", return_value=wire):
                            with self.assertRaises(c.ConsensusError):
                                node.request(b"/tor/status-vote/current/consensus")
                    self.assertTrue(wire.closed)

    def test_request_path_is_fixed_and_no_socket_on_bad_path(self):
        with self.node() as node:
            with mock.patch.object(c.socket, "socket") as create:
                with self.assertRaises(c.ConsensusError):
                    node.request(b"/arbitrary")
                create.assert_not_called()

    def test_source_parser_rejects_duplicate_authorities(self):
        with self.node() as node:
            line = source_line(node)
            with self.assertRaises(c.ConsensusError):
                c.sources(line + line)

    def test_vote_requires_generated_identity_certificate_and_period(self):
        with self.node() as node:
            period = 86400
            body = vote_body(node, period)
            c.vote_metadata(body, node, period)
            for changed, expected in (
                (body.replace(node.certificate, b"other-certificate\n"), period),
                (body.replace(node.identity.encode("ascii"), b"E" * 40), period),
                (body, period + 1),
            ):
                with self.subTest(category="bad-binding"):
                    with self.assertRaises(c.ConsensusError):
                        c.vote_metadata(changed, node, expected)

    def test_shared_deadline_and_sticky_cancellation_use_actual_guard(self):
        isolated = load(
            "authority_consensus_guard_copy",
            Path(__file__).with_name("consensus.py"),
        )
        network = isolated.Network("/fixture/tor", "/fixture/gencert", 12)
        with mock.patch.object(isolated.a.time, "monotonic", return_value=12):
            with self.assertRaises(isolated.a.s.DeadlineExceeded):
                network.check()
        self.assertEqual(network.deadline, 12)
        isolated.a.s.cancelled = True
        with self.assertRaises(isolated.a.s.Cancelled):
            network.check()
        self.assertTrue(isolated.a.s.cancelled)

    def test_receive_cancellation_unwinds_owned_resources_in_order(self):
        isolated = load(
            "authority_consensus_cancel_copy",
            Path(__file__).with_name("consensus.py"),
        )
        node = self.node(isolated)
        events = []
        network = isolated.Network(
            "/fixture/tor", "/fixture/gencert", node.deadline,
        )
        network.nodes.append(node)
        network.active.append(node)
        node._temp = tempfile.TemporaryDirectory(prefix="consensus-control-")
        root = Path(node._temp.name)
        node._log = tempfile.TemporaryFile()
        log = node._log
        control, control_peer = socket.socketpair()
        http, http_peer = socket.socketpair()
        node._socket = control
        process = mock.Mock(returncode=None)
        process.poll.side_effect = lambda: process.returncode
        node.process = process

        def retained():
            self.assertTrue(root.is_dir())
            self.assertFalse(log.closed)
            self.assertIs(node.process, process)

        class Receiving:
            def settimeout(inner, timeout):
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 0.05)

            def recv(inner, _count):
                retained()
                self.assertEqual(events, [])
                events.append("cancel")
                isolated.a.s.cancelled = True
                raise socket.timeout()

            def close(inner):
                http.close()

            def fileno(inner):
                return http.fileno()

        node._http = Receiving()

        def terminate():
            retained()
            self.assertEqual(control.fileno(), -1)
            self.assertEqual(http.fileno(), -1)
            self.assertEqual(events, ["cancel"])
            events.append("terminate")
            process.returncode = -15

        def wait(*, timeout):
            retained()
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, 5)
            self.assertIsNotNone(process.returncode)
            if events == ["cancel", "terminate"]:
                events.append("reap")
            return process.returncode

        process.terminate.side_effect = terminate
        process.wait.side_effect = wait
        try:
            with self.assertRaises(isolated.a.s.Cancelled):
                with network:
                    node._receive(1)
            self.assertEqual(events, ["cancel", "terminate", "reap"])
            self.assertFalse(root.exists())
            self.assertTrue(log.closed)
            self.assertTrue(isolated.a.s.cancelled)
        finally:
            control_peer.close()
            http_peer.close()
            if not network.closed:
                process.returncode = -15
                network.close()

    def test_group_kills_and_reaps_all_before_any_file_cleanup(self):
        network = self.prepared_network()
        events = []
        roots = [node.data for node in network.nodes]
        logs = [node._log for node in network.nodes]
        processes = [node.process for node in network.nodes]

        def retained():
            self.assertTrue(all(root.is_dir() for root in roots))
            self.assertTrue(all(not log.closed for log in logs))

        for index, process in enumerate(processes):
            def terminate(i=index):
                retained()
                events.append(("term", i))

            def kill(p=process, i=index):
                retained()
                self.assertEqual(
                    [event for event in events if event[0] == "term"],
                    [("term", 0), ("term", 1), ("term", 2)],
                )
                events.append(("kill", i))
                p.returncode = -9

            def wait(*, timeout, p=process, i=index):
                if any(item.returncode is None for item in processes):
                    retained()
                if p.returncode is None:
                    raise subprocess.TimeoutExpired("mechanism-only", timeout)
                events.append(("reap", i))
                return p.returncode

            process.terminate.side_effect = terminate
            process.kill.side_effect = kill
            process.wait.side_effect = wait
        try:
            network.close()
            self.assertTrue(all(process.returncode == -9 for process in processes))
            self.assertTrue(all(not root.exists() for root in roots))
            self.assertTrue(all(log.closed for log in logs))
            self.assertTrue(network.closed)
        finally:
            if not network.closed:
                for process in processes:
                    process.returncode = -9
                network.close()

    def test_unreaped_group_retains_every_directory_and_material(self):
        network = self.prepared_network()
        node = network.nodes[0]
        roots = [item.data for item in network.nodes]
        logs = [item._log for item in network.nodes]
        node.process.poll.return_value = None
        node.process.poll.side_effect = None
        node.process.terminate.side_effect = None
        node.process.wait.side_effect = subprocess.TimeoutExpired("mechanism-only", 0)
        material = SimpleNamespace(process=None, close=mock.Mock())
        network.materials.append(material)
        try:
            with self.assertRaises(c.a.s.CleanupError):
                network.close()
            self.assertTrue(all(root.is_dir() for root in roots))
            self.assertTrue(all(not log.closed for log in logs))
            material.close.assert_not_called()
            self.assertFalse(network.closed)
        finally:
            node.process.returncode = -9
            node.process.poll.return_value = -9
            node.process.wait.side_effect = None
            node.process.wait.return_value = -9
            network.close()

    def test_positive_correlates_quorum_identities_votes_cache_and_serving(self):
        for variant in ("good", "one-signature", "duplicate-source", "cache", "admitted"):
            with self.subTest(category=variant):
                network = self.prepared_network()
                period = 86400
                body = consensus_body(network.nodes, period)
                if variant == "one-signature":
                    body = consensus_body(network.nodes, period, signers=1)
                if variant == "duplicate-source":
                    body = body.replace(
                        network.nodes[1].identity.encode("ascii"),
                        network.nodes[0].identity.encode("ascii"),
                    )
                votes = {
                    node.identity: vote_body(node, period)
                    for node in network.nodes
                }
                paths = {
                    b"/tor/status-vote/current/d/"
                    + ("%040X" % (index + 1)).encode("ascii"): votes[node.identity]
                    for index, node in enumerate(network.nodes)
                }
                for index, node in enumerate(network.nodes):
                    (node.data / "cached-consensus").write_bytes(
                        b"different" if variant == "cache" and index == 1 else body
                    )

                    def request(path, owner=node, position=index):
                        if path == b"/tor/status-vote/current/consensus":
                            return 200, body
                        if path == b"/tor/status-vote/current/authority":
                            return 200, votes[owner.identity]
                        self.assertIn(path, paths)
                        admitted = paths[path]
                        if variant == "admitted" and position == 1:
                            admitted += b"different"
                        return 200, admitted

                    node.request = mock.Mock(side_effect=request)
                try:
                    with mock.patch.object(c.time, "time", return_value=period + 1):
                        if variant == "good":
                            self.assertEqual(
                                network.positive(), "three-authority-consensus"
                            )
                            self.assertEqual(network.baseline, body)
                            self.assertEqual(len(network.metadata[3]), 3)
                            for node in network.nodes:
                                self.assertEqual(node.request.call_count, 5)
                        else:
                            with self.assertRaises(c.ConsensusError):
                                network.positive()
                finally:
                    network.close()

    def test_negative_rejects_missing_marker_stale_vote_and_new_consensus(self):
        for variant in (
            "good", "missing-marker", "stale-vote",
            "new-consensus", "pending", "no-rotation",
        ):
            with self.subTest(category=variant):
                isolated = load(
                    "authority_consensus_negative_" + variant.replace("-", "_"),
                    Path(__file__).with_name("consensus.py"),
                )
                network = self.prepared_network(isolated, deadline=14)
                period = 86550
                boundary = 86700
                baseline = consensus_body(network.nodes, period)
                network.baseline = baseline
                network.metadata = isolated.consensus_metadata(
                    baseline, network.nodes, period + 1,
                )
                survivor = network.nodes[0]
                vote = vote_body(
                    survivor, boundary - 300 if variant == "stale-vote" else boundary
                )
                (survivor.data / "cached-consensus").write_bytes(baseline)
                (survivor.data / "v3-status-votes").write_bytes(vote)
                clock = {"mono": 10.0, "wall": boundary - 60.0}
                log_calls = 0
                requests = []

                def private_log(_owner):
                    nonlocal log_calls
                    log_calls += 1
                    if log_calls == 1 or variant == "missing-marker":
                        return b""
                    return isolated.SHORTAGE + b"\n"

                def request(path):
                    requests.append(path)
                    if path == b"/tor/status-vote/next/authority":
                        self.assertTrue(
                            all(node.process.returncode is not None
                                for node in network.nodes[1:])
                        )
                        clock["wall"] = boundary + 1
                        return 200, vote
                    if path == b"/tor/status-vote/current/authority":
                        return (
                            200,
                            b"previous-vote" if variant == "no-rotation" else vote,
                        )
                    if path == b"/tor/status-vote/next/consensus":
                        return (200, b"minority") if variant == "pending" else (404, b"")
                    self.assertEqual(path, b"/tor/status-vote/current/consensus")
                    return (
                        200,
                        b"new-minority-consensus" if variant == "new-consensus"
                        else baseline,
                    )

                def advance(_duration):
                    clock["mono"] += 1
                    self.assertLessEqual(clock["mono"], 15)

                survivor.request = mock.Mock(side_effect=request)
                try:
                    with mock.patch.object(isolated.time, "monotonic", side_effect=lambda: clock["mono"]):
                        with mock.patch.object(isolated.time, "time", side_effect=lambda: clock["wall"]):
                            with mock.patch.object(isolated.time, "sleep", side_effect=advance):
                                with mock.patch.object(isolated.a, "_private_log", side_effect=private_log):
                                    if variant == "good":
                                        self.assertEqual(
                                            network.negative(),
                                            "one-of-three-vote-quorum-rejected",
                                        )
                                        self.assertIn(
                                            b"/tor/status-vote/current/authority",
                                            requests,
                                        )
                                        self.assertIsNone(survivor.process.returncode)
                                    elif variant in ("missing-marker", "no-rotation"):
                                        with self.assertRaises(isolated.a.s.DeadlineExceeded):
                                            network.negative()
                                    else:
                                        with self.assertRaises(isolated.ConsensusError):
                                            network.negative()
                finally:
                    network.close()

    def test_next_round_regression_aligned_intervening_and_offset(self):
        aligned = (86400, 86700, 87300, {})
        intervening = (86550, 86850, 87450, {})
        self.assertEqual(c.next_round(aligned), 86700)
        self.assertEqual(c.next_round(intervening), 86700)
        self.assertNotEqual(c.next_round(intervening), intervening[1])
        self.assertEqual(c.period_after(86550, 300, 17), 86717)
        self.assertEqual(c.period_after(172799, 300, 0), 172800)
        self.assertEqual(c.period_after(86700, 300, 0), 87000)

    def test_quorum_window_edges_before_and_after_owned_stop(self):
        c.require_window(86700, 86659.999)
        for value in (86660, 86660.001, 86700):
            with self.subTest(category="closed-window"):
                with self.assertRaises(c.ConsensusError):
                    c.require_window(86700, value)
        network = self.prepared_network()
        baseline = consensus_body(network.nodes, 86550)
        network.baseline = baseline
        network.metadata = c.consensus_metadata(baseline, network.nodes, 86551)
        values = iter((86659.0, 86660.0))
        survivor = network.nodes[0]
        survivor.request = mock.Mock()
        try:
            with mock.patch.object(c.time, "time", side_effect=lambda: next(values)):
                with self.assertRaisesRegex(c.ConsensusError, "^quorum-window-missed$"):
                    network.negative()
            self.assertTrue(
                all(node.process.returncode is not None for node in network.nodes[1:])
            )
            survivor.request.assert_not_called()
            self.assertIsNone(survivor.process.returncode)
        finally:
            network.close()

    def test_start_preparation_cancellation_owns_multiple_real_guards(self):
        isolated = load(
            "authority_consensus_prepare_copy",
            Path(__file__).with_name("consensus.py"),
        )
        network = isolated.Network(
            "/fixture/tor", "/fixture/gencert", time.monotonic() + 60,
        )
        launches = []
        witnesses = []
        events = []

        def launch(argv, **kwargs):
            ordinal = len(launches)
            process = mock.Mock(returncode=None)
            process.poll.side_effect = lambda: process.returncode
            launches.append(process)
            if ordinal == 1:
                owner = network.relays[0]
                root = Path(owner._temp.name)
                fingerprint = " ".join(["AAAA"] * 10)
                kwargs["stdout"].write(
                    (isolated.a.NICKNAME + " " + fingerprint + "\n").encode("ascii")
                )
                kwargs["stdout"].flush()
                stream = owner._log
            else:
                owner = network.materials[-1]
                root = Path(owner._temp.name)
                stream = owner._input
            witnesses.append((process, stream, root))

            def retained():
                self.assertTrue(root.is_dir())
                self.assertFalse(stream.closed)
                self.assertEqual(owner.deadline, network.deadline)

            def terminate():
                retained()
                events.append(("term", ordinal))
                process.returncode = -15

            waits = 0

            def wait(*, timeout):
                nonlocal waits
                if owner._closed:
                    self.assertIsNotNone(process.returncode)
                    self.assertTrue(stream.closed)
                    self.assertFalse(root.exists())
                    self.assertEqual(owner.deadline, network.deadline)
                else:
                    retained()
                self.assertGreaterEqual(timeout, 0)
                if process.returncode is None:
                    waits += 1
                    self.assertEqual(waits, 1)
                    if ordinal == 2:
                        self.assertEqual(len(network.materials), 2)
                        self.assertEqual(len(network.relays), 1)
                        self.assertTrue(all(item[2].is_dir() for item in witnesses))
                        isolated.a.m.cancelled = True
                        isolated.a.s.cancelled = True
                        events.append(("cancel", ordinal))
                        raise subprocess.TimeoutExpired("mechanism-only", timeout)
                    process.returncode = 0
                return process.returncode

            process.terminate.side_effect = terminate
            process.wait.side_effect = wait
            return process

        def validate(material):
            material.metadata = {
                "v3_identity_fingerprint": "%040X" % len(network.materials),
            }

        try:
            with mock.patch.object(isolated.a.m.subprocess, "Popen", side_effect=launch):
                with mock.patch.object(
                    isolated.a.m.AuthorityMaterials, "_validate", validate,
                ):
                    with self.assertRaises(isolated.a.m.Cancelled):
                        with network:
                            network.start()
            self.assertEqual(len(launches), 3)
            self.assertEqual(events, [("cancel", 2), ("term", 2)])
            self.assertTrue(network.closed)
            for process, stream, root in witnesses:
                self.assertIsNotNone(process.returncode)
                self.assertTrue(stream.closed)
                self.assertFalse(root.exists())
            self.assertTrue(isolated.a.s.cancelled)
            self.assertTrue(isolated.a.m.cancelled)
        finally:
            if not network.closed:
                for process in launches:
                    process.returncode = -15
                network.close()

    def test_actual_config_rewrite_keeps_three_bindings_and_offline_separation(self):
        network = c.Network(
            "/fixture/tor", "/fixture/gencert", time.monotonic() + 60,
        )
        with tempfile.TemporaryDirectory(prefix="consensus-config-") as root_name:
            root = Path(root_name)
            candidates = []
            for index in range(3):
                node = self.node(index=index, deadline=network.deadline)
                relay_root = root / ("relay" + str(index))
                keys = relay_root / "keys"
                keys.mkdir(parents=True, mode=0o700)
                (keys / "secret_id_key").write_bytes(b"mechanism-only-relay")
                material_root = root / ("material" + str(index))
                material_root.mkdir(mode=0o700)
                (material_root / "authority_certificate").write_bytes(node.certificate)
                (material_root / "authority_signing_key").write_bytes(
                    b"mechanism-only-online-signing"
                )
                (material_root / "authority_identity_key").write_bytes(
                    b"mechanism-only-encrypted-offline"
                )
                node.relay.data = relay_root
                node.relay._closed = False
                node.relay.process = SimpleNamespace(returncode=0)
                node.materials._closed = False
                node.materials.process = SimpleNamespace(returncode=0)
                node.materials._check_file = lambda name, base=material_root: base / name
                node.candidates = []
                for _kind in range(2):
                    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    candidates.append(reservation)
                    node.candidates.append(reservation)
                    reservation.bind(("127.0.0.1", 0))
                node.or_port, node.dir_port = [
                    item.getsockname()[1] for item in node.candidates
                ]
                network.nodes.append(node)
            for node in network.nodes:
                node.peers = network.nodes
            try:
                for index, node in enumerate(network.nodes):
                    data = root / ("online" + str(index))
                    data.mkdir(mode=0o700)
                    config = root / ("torrc" + str(index))
                    with mock.patch.object(
                        c.a.m, "certificate_metadata",
                        return_value=node.materials.metadata,
                    ):
                        node._write_config(
                            str(data), str(root / ("control" + str(index))),
                            str(root / ("cookie" + str(index))), str(config),
                        )
                    text = config.read_text(encoding="utf-8")
                    actual = [
                        line for line in text.splitlines()
                        if line.startswith("DirAuthority ")
                    ]
                    expected = [
                        "DirAuthority " + peer.name
                        + " orport=" + str(peer.or_port)
                        + " v3ident=" + peer.identity
                        + " 127.0.0.1:" + str(peer.dir_port)
                        + " " + peer.relay.fingerprint
                        for peer in network.nodes
                    ]
                    self.assertEqual(actual, expected)
                    self.assertIn("PublishServerDescriptor 1\n", text)
                    self.assertNotIn("PublishServerDescriptor 0\n", text)
                    self.assertIn("TestingV3AuthVotingStartOffset 0\n", text)
                    self.assertIn("RunAsDaemon 0\n", text)
                    self.assertIn("SocksPort 0\n", text)
                    self.assertIn("UseDefaultFallbackDirs 0\n", text)
                    self.assertEqual(
                        (data / "keys" / "authority_certificate").read_bytes(),
                        node.certificate,
                    )
                    self.assertEqual(
                        (data / "keys" / "authority_signing_key").read_bytes(),
                        b"mechanism-only-online-signing",
                    )
                    self.assertEqual(
                        (data / "keys" / "secret_id_key").read_bytes(),
                        b"mechanism-only-relay",
                    )
                    self.assertFalse((data / "keys" / "authority_identity_key").exists())
                    self.assertTrue(
                        node.materials._check_file("authority_identity_key").exists()
                    )
                    self.assertEqual(config.read_bytes(), node._config_bytes)
            finally:
                network.close()
                for candidate in candidates:
                    candidate.close()


def cancel(signum, frame):
    c.a.s.cancelled = True
    c.a.m.cancelled = True


def report_failures(result):
    allowed = set(unittest.defaultTestLoader.getTestCaseNames(Controls))
    for category, entries in (("FAIL", result.failures), ("ERROR", result.errors)):
        for test, _traceback in entries:
            case = getattr(test, "test_case", test)
            method = getattr(case, "_testMethodName", None)
            identity = (
                "Controls." + method
                if type(case) is Controls and method in allowed
                else "<unknown-test>"
            )
            print(category + " " + identity, file=sys.stderr)


PRODUCER_FAILURE_GATES = frozenset("""
producer-field producer-base64 producer-router producer-duplicate-router
producer-flags producer-md-line producer-bandwidth producer-protocols
producer-router-limit producer-router-binding producer-router-eligibility
producer-role-binding producer-zero-bandwidth producer-router-protocols
producer-missing-md producer-descriptor producer-descriptor-router
producer-descriptor-identity producer-descriptor-family
producer-port-only-policy producer-ipv6-policy producer-descriptor-signature
producer-microdescriptor-digest producer-microdescriptor-keys
producer-microdescriptor-family producer-microdescriptor-policy
producer-microdescriptor-ipv6 producer-topology producer-baseline-config
producer-request-path producer-negative-input
producer-specific-admission-negative producer-single-use
producer-target-listener producer-good-baseline producer-config-changed
producer-ns-metadata producer-distinct-identities producer-ns-membership
producer-ns-baseline producer-md-consensus producer-md-cache
producer-md-flavor producer-md-period producer-md-disagreement
producer-md-membership producer-flavor-flags producer-admitted-descriptor
producer-descriptor-disagreement producer-descriptor-digest
producer-owned-descriptor producer-owned-ed25519
producer-served-microdescriptor producer-microdescriptor-disagreement
producer-negative-descriptor-changed producer-negative-md-changed
producer-negative-consensus-changed producer-consensus-not-executed
producer-positive-not-executed producer-negative-not-executed
producer-quorum-not-executed producer-target-unreleased
""".split())

CONSENSUS_FAILURE_GATES = frozenset("""
document-field schedule-input consensus-interval quorum-window-missed
document-version document-signature document-source duplicate-source
document-vote-digest document-type consensus-not-current consensus-delays
consensus-voters consensus-binding consensus-signers vote-type vote-period
vote-identity vote-binding vote-certificate file-limit topology-unprepared
baseline-config baseline-authority-config request-path request-limit
http-peer http-limit http-header http-status http-framing http-length
listener-changed cached-empty invalid-deadline single-use
independent-identities candidate-ports loaded-certificate consensus-http
consensus-disagreement daemon-current-consensus origin-vote participating-vote
good-baseline baseline-config-changed removed-voters-not-reaped next-vote-http
minority-vote-changed log-truncated rotated-vote-http quorum-admitted-votes
minority-pending-consensus minority-published-consensus quorum-config-changed
child-unreaped stream-unreleased directory-unreleased socket-unreleased
""".split())

FAILURE_STAGES = frozenset({
    "prepare", "launch", "consensus", "votes", "quorum",
    "producer", "producer-negative",
})


def report_runtime_failure(error, stage):
    if type(stage) is not str or stage not in FAILURE_STAGES:
        stage = "prepare"
    error_type = type(error)
    categories = {
        p.ProducerError: "producer",
        c.ConsensusError: "consensus",
        c.a.StartupError: "startup",
        c.a.s.ChildExit: "child-exit",
        c.a.s.ProtocolError: "protocol",
        c.a.s.AuthError: "authentication",
        FileNotFoundError: "file-missing",
        PermissionError: "permission",
        OSError: "os",
        ValueError: "value",
        TypeError: "type",
        KeyError: "key",
        AttributeError: "attribute",
    }
    category = categories.get(error_type, "unknown")
    gate = "unknown"
    allowed = (
        PRODUCER_FAILURE_GATES if error_type is p.ProducerError
        else CONSENSUS_FAILURE_GATES if error_type is c.ConsensusError
        else None
    )
    if allowed is not None:
        arguments = error.args
        if (
            type(arguments) is tuple
            and len(arguments) == 1
            and type(arguments[0]) is str
            and len(arguments[0]) <= 96
            and arguments[0] in allowed
        ):
            gate = arguments[0]
    print("Tor authority consensus failed: " + stage, file=sys.stderr)
    print(
        "Tor authority failure detail:"
        + " type=" + category
        + " gate=" + gate,
        file=sys.stderr,
    )
    return 1


class DiagnosticControls(unittest.TestCase):
    def capture_failure(self, error, stage="producer"):
        output = io.StringIO()
        with mock.patch.object(sys, "stderr", output):
            status = report_runtime_failure(error, stage)
        self.assertEqual(status, 1)
        return output.getvalue()

    def test_genuine_failed_gates_have_fixed_labels(self):
        row = {
            "name": b"localA",
            "address": b"127.0.0.1",
            "or": b"21001",
            "dir": b"21002",
            "flags": {b"Running", b"Valid", b"Guard"},
            "bandwidth": 1,
            "protocols": b"Link=1-5 Relay=1-4",
            "md": bytes(32),
        }
        node = SimpleNamespace(
            name="localA", or_port=21001, dir_port=21002,
        )
        with self.assertRaises(p.ProducerError) as producer_failure:
            p.check_row(row, node, "guard", True)
        self.assertEqual(
            self.capture_failure(producer_failure.exception),
            "Tor authority consensus failed: producer\n"
            "Tor authority failure detail:"
            " type=producer gate=producer-router-eligibility\n",
        )
        with self.assertRaises(c.ConsensusError) as consensus_failure:
            c.require_window(100, 60)
        self.assertEqual(
            self.capture_failure(consensus_failure.exception),
            "Tor authority consensus failed: producer\n"
            "Tor authority failure detail:"
            " type=consensus gate=quorum-window-missed\n",
        )

    def test_unknown_and_private_payloads_are_not_formatted(self):
        calls = []

        class PrivateValue:
            def __str__(self):
                calls.append("value-str")
                raise AssertionError("private-value-formatted")

            def __repr__(self):
                calls.append("value-repr")
                raise AssertionError("private-value-formatted")

        class PrivateFailure(Exception):
            def __str__(self):
                calls.append("error-str")
                raise AssertionError("private-error-formatted")

            def __repr__(self):
                calls.append("error-repr")
                raise AssertionError("private-error-formatted")

        class ProducerSubclass(p.ProducerError):
            pass

        for error, category in (
            (p.ProducerError("private-path-or-key"), "producer"),
            (p.ProducerError("producer-field", "private"), "producer"),
            (p.ProducerError(PrivateValue()), "producer"),
            (p.ProducerError("x" * 97), "producer"),
            (c.ConsensusError("producer-field"), "consensus"),
            (PrivateFailure(PrivateValue()), "unknown"),
            (ProducerSubclass("producer-field"), "unknown"),
            (FileNotFoundError("private-path-or-key"), "file-missing"),
        ):
            with self.subTest(category=category):
                self.assertEqual(
                    self.capture_failure(error, PrivateValue()),
                    "Tor authority consensus failed: prepare\n"
                    "Tor authority failure detail:"
                    + " type=" + category + " gate=unknown\n",
                )
        self.assertEqual(calls, [])

    def test_main_failure_status_and_special_handlers_are_preserved(self):
        cases = (
            (
                p.ProducerError("producer-md-cache"),
                1,
                "Tor authority consensus failed: producer\n"
                "Tor authority failure detail:"
                " type=producer gate=producer-md-cache\n",
            ),
            (
                c.ConsensusError("quorum-window-missed"),
                1,
                "Tor authority consensus failed: producer\n"
                "Tor authority failure detail:"
                " type=consensus gate=quorum-window-missed\n",
            ),
            (
                c.a.s.Cancelled("private"),
                143,
                "Tor authority consensus cancelled\n",
            ),
            (
                c.a.m.Cancelled("private"),
                143,
                "Tor authority consensus cancelled\n",
            ),
            (
                c.a.s.DeadlineExceeded("private"),
                1,
                "Tor authority consensus deadline\n",
            ),
            (
                c.a.m.DeadlineExceeded("private"),
                1,
                "Tor authority consensus deadline\n",
            ),
            (
                c.a.s.CleanupError("private"),
                1,
                "Tor authority consensus cleanup\n",
            ),
            (
                c.a.m.CleanupError("private"),
                1,
                "Tor authority consensus cleanup\n",
            ),
        )
        for error, expected_status, expected_error in cases:
            with self.subTest(category=type(error)):
                network = SimpleNamespace(stage="producer")
                output = io.StringIO()
                errors = io.StringIO()
                results = [
                    SimpleNamespace(
                        testsRun=15, wasSuccessful=lambda: True,
                    ),
                    SimpleNamespace(
                        testsRun=3, wasSuccessful=lambda: True,
                    ),
                ]
                runner = mock.Mock()
                runner.run.side_effect = results
                environment = {
                    "GITHUB_ACTIONS": "true",
                    "TOR_REAL_ISOLATED": "yes",
                    "TOR_REAL_DEADLINE": str(time.monotonic() + 60),
                    "TOR_REAL_BINARY": "/fixture/tor",
                    "TOR_REAL_GENCERT_BINARY": "/fixture/gencert",
                }
                with mock.patch.dict(os.environ, environment):
                    with mock.patch.object(
                        unittest, "TextTestRunner", return_value=runner,
                    ):
                        with mock.patch.object(
                            signal, "signal", return_value=None,
                        ):
                            with mock.patch.object(
                                p, "run_controls",
                                return_value=(True, ()),
                            ) as producer_controls:
                                with mock.patch.object(
                                    p, "implementation",
                                    return_value=mock.Mock(
                                        return_value=network,
                                    ),
                                ):
                                    with mock.patch.object(
                                        p, "run_live", side_effect=error,
                                    ) as operation:
                                        with mock.patch.object(
                                            sys, "stdout", output,
                                        ):
                                            with mock.patch.object(
                                                sys, "stderr", errors,
                                            ):
                                                status = main()
                self.assertEqual(status, expected_status)
                self.assertEqual(errors.getvalue(), expected_error)
                self.assertEqual(runner.run.call_count, 2)
                producer_controls.assert_called_once_with(c)
                operation.assert_called_once_with(network, c)
                self.assertNotIn(
                    "Tor owned guard middle exit producer controls passed",
                    output.getvalue(),
                )
                self.assertNotIn(
                    "Tor one-of-three vote quorum rejection controls passed",
                    output.getvalue(),
                )


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("TOR_REAL_ISOLATED") != "yes"
    ):
        print("Tor authority consensus requires isolated CI", file=sys.stderr)
        return 1
    try:
        deadline = float(os.environ["TOR_REAL_DEADLINE"])
        binary = os.environ["TOR_REAL_BINARY"]
        gencert = os.environ["TOR_REAL_GENCERT_BINARY"]
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise ValueError()
    except (KeyError, ValueError):
        print("Tor authority consensus invalid operation input", file=sys.stderr)
        return 1
    previous = {
        sig: signal.signal(sig, cancel)
        for sig in (signal.SIGTERM, signal.SIGINT)
    }
    network = None
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        if result.testsRun != 15 or not result.wasSuccessful():
            print("Tor authority consensus mechanism controls failed", file=sys.stderr)
            report_failures(result)
            return 1
        print("Tor authority consensus mechanism controls passed: 15")
        diagnostic_suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            DiagnosticControls
        )
        diagnostic_result = unittest.TextTestRunner(
            stream=io.StringIO()
        ).run(diagnostic_suite)
        if (
            diagnostic_result.testsRun != 3
            or not diagnostic_result.wasSuccessful()
        ):
            print(
                "Tor authority failure diagnostic controls failed",
                file=sys.stderr,
            )
            return 1
        print("Tor authority failure diagnostic controls passed: 3")
        producer_ok, producer_failures = p.run_controls(c)
        if not producer_ok:
            print("Tor relay producer mechanism controls failed", file=sys.stderr)
            for failure in producer_failures:
                print(failure, file=sys.stderr)
            return 1
        print("Tor relay producer mechanism controls passed: 23")
        network = p.implementation(c)(binary, gencert, deadline)
        p.run_live(network, c)
        print("Tor three-authority current consensus controls passed: 1")
        print("Tor one-of-three vote quorum rejection controls passed: 1")
        print("Tor owned guard middle exit producer controls passed: 1")
        print("Tor BOM descriptor admission rejection controls passed: 1")
        return 0
    except (c.a.s.Cancelled, c.a.m.Cancelled):
        print("Tor authority consensus cancelled", file=sys.stderr)
        return 143
    except (c.a.s.DeadlineExceeded, c.a.m.DeadlineExceeded):
        print("Tor authority consensus deadline", file=sys.stderr)
        return 1
    except (c.a.s.CleanupError, c.a.m.CleanupError):
        print("Tor authority consensus cleanup", file=sys.stderr)
        return 1
    except Exception as error:
        stage = network.stage if network is not None else "prepare"
        return report_runtime_failure(error, stage)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
