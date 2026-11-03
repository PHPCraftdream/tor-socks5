import base64
import io
from contextlib import contextmanager
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


EXIT_SOURCE = r'''
import os
import socket
import sys

listener = socket.socket(fileno=int(sys.argv[1]))
peer, _ = listener.accept()
target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
target.connect(("127.0.0.1", int(sys.argv[2])))
request = bytearray()
while not request.endswith(b"\n"):
    part = peer.recv(1)
    if not part or len(request) >= 128:
        raise SystemExit(2)
    request.extend(part)
target.sendall(request)
response = bytearray()
while True:
    part = target.recv(128 - len(response))
    if not part:
        break
    response.extend(part)
    if len(response) >= 128:
        raise SystemExit(3)
peer.sendall(response)
peer.shutdown(socket.SHUT_WR)
if peer.recv(1):
    raise SystemExit(4)
target.close()
peer.close()
listener.close()
sys.stdin.buffer.read(1)
'''


CONSUMER_SOURCE = r'''
import os
import socket
import struct
import sys

def line(channel, bound):
    value = bytearray()
    while not value.endswith(b"\n"):
        part = channel.recv(1)
        if not part or len(value) >= bound:
            raise SystemExit(2)
        value.extend(part)
    return bytes(value)

control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
control.connect(os.environ["TOR_REAL_STREAM_CONTROL"])
pid, uid, _ = struct.unpack(
    "3i", control.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
)
if pid != int(os.environ["TOR_REAL_STREAM_PARENT_PID"]):
    raise SystemExit(3)
if uid != int(os.environ["TOR_REAL_STREAM_PARENT_UID"]):
    raise SystemExit(4)
mode = os.environ["STREAM_MECHANISM_MODE"]
if mode == "early":
    raise SystemExit(0)
if mode == "pending":
    while control.recv(1):
        pass
    raise SystemExit(5)
records = []
total = 0
while True:
    record = line(control, 512)
    total += len(record)
    if total > 4096:
        raise SystemExit(6)
    records.append(record)
    if record == b"END\n":
        break
if records[0] != b"TOR_OWNED_STREAM_V2\n":
    raise SystemExit(7)
nonces = [r[6:-1] for r in records if r.startswith(b"NONCE ")]
if len(nonces) != 1:
    raise SystemExit(8)
nonce = nonces[0]
stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
stream.connect(os.environ["STREAM_MECHANISM_RELAY"])
stream.sendall(b"owned-request:" + nonce + b"\n")
expected = b"owned-response:" + nonce + b"\n"
response = bytearray()
while True:
    part = stream.recv(len(expected) + 1 - len(response))
    if not part:
        break
    response.extend(part)
    if len(response) > len(expected):
        raise SystemExit(9)
if bytes(response) != expected:
    raise SystemExit(10)
stream.close()
for byte in b"STREAM_VERIFIED\n":
    control.sendall(bytes([byte]))
if line(control, 512) != b"TARGET_TERMINATED\n":
    raise SystemExit(11)
if mode != "no-done":
    control.sendall(b"CONSUMER_DONE\n")
control.close()
'''


def build(c, s, entry, deadline, report):
    actual_popen = subprocess.Popen
    actual_selector = selectors.DefaultSelector
    Network = entry["implementation"](c)

    class Node:
        def __init__(self, index, process, host):
            self.name = ("localA", "localB", "localC")[index]
            self.role = ("guard", "middle", "exit")[index]
            self.address = host
            self.process = process
            self.identity = "%040X" % (index + 101)
            self.relay = SimpleNamespace(fingerprint="%040X" % (index + 1))
            self.materials = SimpleNamespace(metadata={
                "v3_identity_fingerprint": self.identity,
            })
            self.or_port = 22001 + index * 2
            self.dir_port = self.or_port + 1
            self._temp = None
            self._log = None
            self._socket = None
            self._http = None

        def _check(self):
            c.a._budget(self)
            if self.process.poll() is not None:
                raise c.a.s.ChildExit("mechanism child exited")

        def close(self):
            if self.process.stdin is not None:
                self.process.stdin.close()

    @contextmanager
    def fixture(mode="normal"):
        network = Network(sys.executable, "/private/gencert", deadline)
        network.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        network.reservations.append(network.target)
        network.target.bind(("127.0.0.1", 0))
        network.target.listen(1)
        network.target_port = network.target.getsockname()[1]
        root = Path(tempfile.mkdtemp(prefix="stream-mechanism-"))
        relay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        relay.bind(str(root / "relay"))
        relay.listen(1)
        processes = []
        events = []
        consumers = []
        try:
            for index in range(3):
                if index == 2:
                    argv = [
                        sys.executable, "-c", EXIT_SOURCE,
                        str(relay.fileno()),
                        str(network.target_port),
                    ]
                    process = actual_popen(
                        argv, pass_fds=(relay.fileno(),),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    process = actual_popen(
                        [sys.executable, "-c",
                         "import sys; sys.stdin.buffer.read(1)"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                processes.append(process)
                node = Node(index, process, f"127.0.0.{index + 2}")
                node.deadline = deadline
                network.nodes.append(node)
            network.active = list(network.nodes)
            packets = []
            for index, node in enumerate(network.nodes):
                ed = base64.b64encode(bytes([index + 1]) * 32).rstrip(b"=")
                body = (
                    f"router {node.name} {node.address} "
                    f"{node.or_port} 0 {node.dir_port}\n"
                    f"fingerprint {node.relay.fingerprint}\n"
                ).encode("ascii") + b"master-key-ed25519 " + ed + b"\n"
                packets.append((b"path", body, b"md-path", b"md"))
            network.packet = tuple(packets)

            def start():
                network.check()
                events.append("start")

            def positive():
                network.check()
                events.append("positive")
                return "three-authority-consensus"

            def ready():
                network.check()
                events.append("ready")
                return "owned-three-relay-producer"

            def admission():
                network.check()
                network.admission_checked = True
                events.append("bom")
                return "bom-descriptor-admission-rejected"

            def negative():
                network.stream.require_complete()
                if not network.stream.complete:
                    raise AssertionError()
                events.append("quorum")
                return "one-of-three-vote-quorum-rejected"

            network.start = start
            network.positive = positive
            network.await_ready = ready
            network.producer_negative = admission
            network.negative = negative

            def launch(argv, **kwargs):
                if argv != [
                    sys.executable, s.w.TEST,
                    "--exact", "--ignored", "--nocapture",
                ]:
                    raise AssertionError("mechanism-argv")
                if any(kwargs[name] != subprocess.DEVNULL for name in (
                    "stdin", "stdout", "stderr",
                )):
                    raise AssertionError("mechanism-stdio")
                environment = kwargs["env"].copy()
                environment.update({
                    "STREAM_MECHANISM_RELAY": str(root / "relay"),
                    "STREAM_MECHANISM_MODE": mode,
                })
                child = actual_popen(
                    [sys.executable, "-c", CONSUMER_SOURCE],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                consumers.append(child)
                return child

            yield SimpleNamespace(
                network=network, root=root, relay=relay,
                events=events, consumers=consumers, launch=launch,
            )
        finally:
            owners = [SimpleNamespace(process=p) for p in processes]
            owners.extend(SimpleNamespace(process=p) for p in consumers)
            c.Network.stop_owned(owners, deadline)
            for process in processes:
                if process.stdin is not None:
                    process.stdin.close()
            relay.close()
            for reservation in network.reservations:
                if reservation.fileno() >= 0:
                    reservation.close()
            if network.stream is not None:
                if not network.stream.closed and not network.stream.cleanup_failed:
                    network.stream.close()
            s.shutil.rmtree(root)

    def connected_target(f):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(f.root / "relay"))
        client.sendall(b"owned-request:" + b"1" * 32 + b"\n")
        with actual_selector() as selector:
            selector.register(f.network.target, selectors.EVENT_READ)
            if not selector.select(c.a._budget(f.network)):
                raise c.a.s.DeadlineExceeded("mechanism deadline")
        target, _address = f.network.target.accept()
        return client, target

    class Controls(unittest.TestCase):
        def test_real_exit_proof_and_independent_guard_counterfactuals(self):
            with fixture() as f:
                result = s.Session(f.network, c, sys.executable)
                f.network.stream = result
                result.bind_exit()
                client, target = connected_target(f)
                result.target = result.hold(target)
                try:
                    self.assertEqual(target.getpeername()[0], "127.0.0.1")
                    self.assertEqual(result.exit_address, "127.0.0.4")
                    self.assertNotEqual(
                        target.getpeername()[0], result.exit_address
                    )
                    result.prove_exit_peer()
                    self.assertEqual(len(result.ownership), 1)
                    witness = result.ownership.pop()
                    self.assertIs(witness[0], f.network.nodes[2].process)
                    self.assertEqual(witness[1], witness[0].pid)
                    self.assertEqual(witness[3], "127.0.0.4")
                    self.assertEqual(witness[4][0], target.getpeername())
                    self.assertEqual(witness[4][1], target.getsockname())
                    self.assertGreater(witness[4][2], 0)
                    self.assertTrue(witness[4][3])

                    original = f.network.nodes[2].process
                    alias = SimpleNamespace(
                        pid=original.pid, poll=original.poll
                    )
                    with mock.patch.object(
                        f.network.nodes[2], "process", alias
                    ):
                        with self.assertRaisesRegex(
                            s.StreamError, "^stream-owner$"
                        ):
                            result.prove_exit_peer()

                    other = f.network.nodes[0].process
                    other_pin = result.dd.Pin(other.pid)
                    try:
                        with mock.patch.object(
                            result, "exit_pin", other_pin
                        ):
                            with self.assertRaisesRegex(
                                s.StreamError, "^stream-owner$"
                            ):
                                result.prove_exit_peer()
                    finally:
                        other_pin.close()

                    for name, value in (
                        ("role", "middle"),
                        ("address", f.network.nodes[0].address),
                    ):
                        with mock.patch.object(
                            f.network.nodes[2], name, value
                        ):
                            with self.assertRaisesRegex(
                                s.StreamError, "^stream-owner$"
                            ):
                                result.prove_exit_peer()

                    class EndpointView:
                        family = socket.AF_INET

                        def __init__(self, peer, local):
                            self.peer = peer
                            self.local = local

                        def getpeername(self):
                            return self.peer

                        def getsockname(self):
                            return self.local

                    actual_peer = target.getpeername()
                    actual_local = target.getsockname()
                    for peer, local in (
                        (
                            ("127.0.0.2", actual_peer[1]),
                            actual_local,
                        ),
                        (
                            actual_peer,
                            ("127.0.0.2", actual_local[1]),
                        ),
                        (
                            actual_peer,
                            (
                                actual_local[0],
                                1 if actual_local[1] != 1 else 2,
                            ),
                        ),
                    ):
                        with mock.patch.object(
                            result, "target", EndpointView(peer, local)
                        ):
                            with self.assertRaisesRegex(
                                s.StreamError, "^stream-endpoint$"
                            ):
                                result.prove_exit_peer()

                    result.exit_pin.close()
                    with self.assertRaisesRegex(
                        s.StreamError, "^stream-owner$"
                    ):
                        result.prove_exit_peer()
                    self.assertFalse(result.ownership)
                finally:
                    client.close()

        def test_actual_classifier_rejects_other_live_node_pid(self):
            with fixture() as f:
                result = s.Session(f.network, c, sys.executable)
                f.network.stream = result
                result.bind_exit()
                client, target = connected_target(f)
                result.target = result.hold(target)
                try:
                    self.assertEqual(target.getpeername()[0], "127.0.0.1")
                    evidence = []
                    returned = result.dd.socket_owned(
                        target,
                        f.network.nodes[2].process.pid,
                        peer_address="127.0.0.1",
                        local_address="127.0.0.1",
                        evidence=evidence,
                    )
                    self.assertIsNone(returned)
                    self.assertEqual(len(evidence), 1)
                    self.assertEqual(
                        evidence[0][0], target.getpeername()
                    )
                    self.assertEqual(
                        evidence[0][1], target.getsockname()
                    )
                    self.assertGreater(evidence[0][2], 0)
                    self.assertTrue(evidence[0][3])

                    with self.assertRaises(result.dd.Denied):
                        result.dd.socket_owned(
                            target,
                            f.network.nodes[0].process.pid,
                            peer_address="127.0.0.1",
                            local_address="127.0.0.1",
                        )
                    with self.assertRaises(result.dd.Denied):
                        result.dd.socket_owned(
                            target,
                            f.network.nodes[2].process.pid,
                            peer_address="127.0.0.2",
                            local_address="127.0.0.1",
                        )
                finally:
                    client.close()

        def test_actual_full_run_and_entry_order(self):
            with fixture() as f:
                with mock.patch.object(
                    s.subprocess, "Popen", side_effect=f.launch
                ):
                    result = entry["run_stream_live"](
                        f.network, c, sys.executable
                    )
                self.assertEqual(
                    f.events, ["start", "positive", "ready", "bom", "quorum"]
                )
                self.assertTrue(result.complete)
                self.assertTrue(result.write_shutdown)
                self.assertTrue(result.eof_child_alive)
                self.assertEqual(len(result.ownership), 2)
                self.assertEqual(
                    bytes(result.response_written), result.response
                )
                self.assertEqual(result.process.returncode, 0)
                self.assertIs(result.process, f.consumers[0])
                self.assertIs(result.process_anchor[0], f.consumers[0])
                self.assertEqual(result.deadline, deadline)
                result.released()
                self.assertTrue(all(
                    anchor.resource.fileno() == -1
                    for anchor in result.socket_anchors
                ))

        def test_real_early_exit_and_no_done_do_not_reach_quorum(self):
            for mode in ("early", "no-done"):
                with fixture(mode) as f:
                    with mock.patch.object(
                        s.subprocess, "Popen", side_effect=f.launch
                    ):
                        with self.assertRaises(s.StreamError):
                            entry["run_stream_live"](
                                f.network, c, sys.executable
                            )
                    self.assertNotIn("quorum", f.events)
                    self.assertIsNotNone(f.network.stream.process.returncode)
                    self.assertFalse(f.network.stream.complete)

        def test_popen_retained_before_post_spawn_cancellation(self):
            with fixture("pending") as f:
                def launch(argv, **kwargs):
                    child = f.launch(argv, **kwargs)
                    c.a.s.cancelled = True
                    return child

                with mock.patch.object(c.a.s, "cancelled", False):
                    with mock.patch.object(
                        s.subprocess, "Popen", side_effect=launch
                    ):
                        with self.assertRaises(c.a.s.Cancelled):
                            f.network.consume(sys.executable)
                    result = f.network.stream
                    self.assertIs(result.process, f.consumers[0])
                    self.assertIs(result.process_anchor[0], f.consumers[0])
                    self.assertTrue(result.root.exists())
                f.network.close()
                self.assertIsNotNone(f.consumers[0].returncode)

        def test_original_deadline_and_cancel_during_selector_supervision(self):
            for kind in ("deadline", "cancel"):
                with self.subTest(kind=kind):
                    with fixture("pending") as f:
                        clock = [s.time.monotonic()]
                        observations = []

                        class Selector:
                            def __init__(self):
                                self.real = actual_selector()

                            def register(self, *args):
                                return self.real.register(*args)

                            def modify(self, *args):
                                return self.real.modify(*args)

                            def unregister(self, *args):
                                return self.real.unregister(*args)

                            def select(self, timeout):
                                if not 0 < timeout <= 0.05:
                                    raise AssertionError("mechanism-timeout")
                                result = f.network.stream
                                if (
                                    result.authenticated
                                    and not result.initial_pending
                                    and not observations
                                ):
                                    if len(f.consumers) != 1:
                                        raise AssertionError("mechanism-child")
                                    child = f.consumers[0]
                                    if (
                                        result.process is not child
                                        or result.process_anchor != (child,)
                                        or child.poll() is not None
                                        or result.root is None
                                        or not result.root.exists()
                                        or result.control is None
                                        or result.control.fileno() < 0
                                        or bytes(result.initial_written)
                                        != result.initial
                                        or result.deadline != deadline
                                        or f.network.deadline != deadline
                                    ):
                                        raise AssertionError(
                                            "mechanism-pending-ownership"
                                        )
                                    observations.append((
                                        child,
                                        result.root,
                                        result.control,
                                        tuple(
                                            anchor.resource
                                            for anchor in result.socket_anchors
                                        ),
                                    ))
                                    if kind == "deadline":
                                        clock[0] = deadline
                                    else:
                                        c.a.s.cancelled = True
                                    return []
                                return self.real.select(timeout)

                            def close(self):
                                self.real.close()

                        expected = (
                            c.a.s.DeadlineExceeded
                            if kind == "deadline"
                            else c.a.s.Cancelled
                        )
                        with mock.patch.object(c.a.s, "cancelled", False):
                            with mock.patch.object(
                                s.time,
                                "monotonic",
                                side_effect=lambda: clock[0],
                            ):
                                with mock.patch.object(
                                    s, "_session_selector", Selector
                                ):
                                    with mock.patch.object(
                                        s.subprocess,
                                        "Popen",
                                        side_effect=f.launch,
                                    ):
                                        with self.assertRaises(expected):
                                            f.network.consume(sys.executable)

                        self.assertEqual(len(observations), 1)
                        child, root, control, resources = observations[0]
                        result = f.network.stream
                        self.assertIs(result.process, child)
                        self.assertIs(result.process_anchor[0], child)
                        self.assertIs(result.control, control)
                        self.assertEqual(result.deadline, deadline)
                        self.assertEqual(f.network.deadline, deadline)
                        self.assertTrue(root.exists())
                        self.assertFalse(result.complete)
                        self.assertFalse(result.closed)
                        self.assertIsNone(child.poll())
                        self.assertFalse(result.ack_written)
                        self.assertFalse(result.done)

                        f.network.close()

                        self.assertIsNotNone(child.returncode)
                        self.assertTrue(result.closed)
                        self.assertFalse(result.complete)
                        self.assertFalse(root.exists())
                        self.assertTrue(result.selector_closed)
                        self.assertTrue(result.pin_closed)
                        self.assertTrue(all(
                            resource.fileno() == -1
                            for resource in resources
                        ))
                        self.assertTrue(all(
                            anchor.error is None
                            for anchor in result.socket_anchors
                        ))

        def test_remaining_uses_original_deadline_without_guard_mock(self):
            with fixture() as f:
                result = s.Session(f.network, c, sys.executable)
                f.network.stream = result
                with mock.patch.object(
                    s.time, "monotonic", return_value=deadline - 0.25
                ):
                    self.assertEqual(result.remaining(), 0.25)
                with mock.patch.object(
                    s.time, "monotonic", return_value=deadline
                ):
                    with self.assertRaises(c.a.s.DeadlineExceeded):
                        result.remaining()
                self.assertEqual(result.deadline, deadline)

        def test_unreaped_cleanup_retains_dependencies_and_finalizers(self):
            with fixture() as f:
                temporary = tempfile.TemporaryDirectory(
                    prefix="stream-retained-dependency-"
                )
                dependency = Path(temporary.name)
                f.network.nodes[0]._temp = temporary
                f.network.anchor_dependencies()
                result = s.Session(f.network, c, sys.executable)
                f.network.stream = result

                class Unreaped:
                    pid = 123456
                    returncode = None

                    def poll(self):
                        return None

                    def terminate(self):
                        pass

                    def kill(self):
                        pass

                    def wait(self, timeout):
                        raise subprocess.TimeoutExpired("private", timeout)

                child = Unreaped()
                result.process = child
                result.process_anchor = (child,)
                result.root = Path(tempfile.mkdtemp(
                    prefix="stream-unreaped-root-"
                ))
                try:
                    with self.assertRaises(c.a.s.CleanupError):
                        f.network.close()
                    self.assertIs(result.process_anchor[0], child)
                    self.assertIsNone(child.returncode)
                    self.assertTrue(result.root.exists())
                    self.assertTrue(dependency.exists())
                    self.assertFalse(temporary._finalizer.alive)
                    self.assertTrue(any(
                        resources[1] is temporary
                        for owner, resources in f.network.cleanup_anchors
                        if owner is not f.network
                    ))
                    self.assertFalse(f.network.closed)
                finally:
                    temporary.cleanup()
                    s.shutil.rmtree(result.root)

        def test_main_stream_controls_boundary_uses_actual_dispatcher(self):
            main = report.__globals__["main"]
            main_globals = main.__globals__
            producer = main_globals["p"]
            runner = mock.Mock()
            runner.run.side_effect = [
                SimpleNamespace(
                    testsRun=16,
                    wasSuccessful=lambda: True,
                ),
                SimpleNamespace(
                    testsRun=3,
                    wasSuccessful=lambda: True,
                ),
            ]
            output = io.StringIO()
            errors = io.StringIO()
            environment = {
                "GITHUB_ACTIONS": "true",
                "TOR_REAL_ISOLATED": "yes",
                "TOR_REAL_DEADLINE": str(deadline),
                "TOR_REAL_BINARY": "/fixture/tor",
                "TOR_REAL_GENCERT_BINARY": "/fixture/gencert",
                "TOR_REAL_STREAM_BINARY": "/fixture/owned_stream",
            }
            failure = s.StreamError("stream-controls")
            with (
                mock.patch.dict(os.environ, environment),
                mock.patch.object(Path, "is_file", return_value=True),
                mock.patch.object(
                    main_globals["signal"],
                    "signal",
                    return_value=None,
                ),
                mock.patch.object(
                    unittest,
                    "TextTestRunner",
                    return_value=runner,
                ),
                mock.patch.object(
                    producer,
                    "run_controls",
                    return_value=(True, ()),
                ) as producer_controls,
                mock.patch.object(
                    producer,
                    "run_stream_controls",
                    side_effect=failure,
                ) as stream_controls,
                mock.patch.object(
                    producer, "implementation"
                ) as construct_network,
                mock.patch.object(sys, "stdout", output),
                mock.patch.object(sys, "stderr", errors),
            ):
                status = main()

            self.assertEqual(status, 1)
            self.assertEqual(
                errors.getvalue(),
                "Tor authority consensus failed: stream-controls\n"
                "Tor authority failure detail:"
                " type=stream gate=stream-controls\n",
            )
            self.assertEqual(runner.run.call_count, 2)
            producer_controls.assert_called_once_with(c)
            stream_controls.assert_called_once_with(c, deadline, report)
            construct_network.assert_not_called()
            self.assertNotIn(
                "Tor owned stream mechanism controls passed",
                output.getvalue(),
            )
            self.assertNotIn(
                "Tor owned stream positive controls passed",
                output.getvalue(),
            )

    return Controls
