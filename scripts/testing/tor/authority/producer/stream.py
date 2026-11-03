import os
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
import importlib.util


_session_selector = selectors.DefaultSelector
_EXIT_SOURCE_ADDRESS = "127.0.0.1"

_wire_path = Path(__file__).with_name("stream_wire.py")
_wire_spec = importlib.util.spec_from_file_location(
    "producer_stream_wire", _wire_path
)
w = importlib.util.module_from_spec(_wire_spec)
_wire_spec.loader.exec_module(w)

StreamError = w.StreamError
FAILURE_GATES = w.FAILURE_GATES
require = w.require


class Session:
    def __init__(self, network, c, binary):
        self.network = network
        self.c = c
        self.binary = binary
        self.deadline = network.deadline
        self.process = None
        self.process_anchor = ()
        self.stdio = (
            subprocess.DEVNULL, subprocess.DEVNULL, subprocess.DEVNULL
        )
        self.socket_anchors = []
        self.target_listener = network.target
        self.hold(self.target_listener, owned=False)
        self.listener = None
        self.control = None
        self.target = None
        self.selector = None
        self.selector_attempted = False
        self.selector_closed = False
        self.root = None
        self.storage = None
        self.dd = None
        self.exit_node = None
        self.exit_process = None
        self.exit_address = None
        self.target_endpoint = None
        self.exit_pin = None
        self.pin_attempted = False
        self.pin_closed = False
        self.initial = b""
        self.initial_pending = bytearray()
        self.initial_written = bytearray()
        self.request = b""
        self.response = b""
        self.request_seen = bytearray()
        self.response_pending = bytearray()
        self.response_written = bytearray()
        self.control_buffer = bytearray()
        self.control_total = 0
        self.ack_pending = bytearray()
        self.ack_written = bytearray()
        self.peer_credentials = None
        self.ownership = []
        self.authenticated = False
        self.write_shutdown = False
        self.target_eof = False
        self.eof_child_alive = False
        self.verified = False
        self.done = False
        self.control_eof = False
        self.complete = False
        self.closed = False
        self.cleanup_failed = False
        self.cleanup_errors = []
        self.stop_proxy = None
        self.argv = None
        self.environment = None

    def hold(self, resource, owned=True):
        require(len(self.socket_anchors) < 8, "stream-resource")
        self.socket_anchors.append(w.SocketAnchor(resource, owned))
        return resource

    def check(self):
        self.network.check()
        require(self.network.deadline == self.deadline,
                "stream-producer")
        require(not self.closed, "stream-resource")
        if self.process_anchor:
            require(self.process is self.process_anchor[0],
                    "stream-child")
            if bytes(self.ack_written) != w.ACK:
                require(self.process.poll() is None, "stream-child")

    def remaining(self):
        self.check()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise self.c.a.s.DeadlineExceeded(
                "owned stream deadline expired"
            )
        return remaining

    def watch(self, resource, callback, events):
        try:
            self.selector.modify(resource, events, callback)
        except KeyError:
            self.selector.register(resource, events, callback)

    def unwatch(self, resource):
        try:
            self.selector.unregister(resource)
        except KeyError:
            pass

    def bind_exit(self):
        self.check()
        require(
            len(self.network.nodes) == 3
            and self.exit_node is None,
            "stream-owner",
        )
        node = self.network.nodes[2]
        require(node.role == "exit", "stream-owner")
        self.exit_node = node
        self.exit_address = w.address(node.address)
        self.exit_process = node.process
        require(
            self.exit_process is not None
            and self.exit_process.poll() is None,
            "stream-owner",
        )
        require(
            self.target_listener is self.network.target,
            "stream-endpoint",
        )
        self.target_endpoint = self.target_listener.getsockname()
        require(
            self.target_endpoint
            == ("127.0.0.1", self.network.target_port),
            "stream-endpoint",
        )
        self.dd = w.ownership()
        try:
            self.exit_pin = self.dd.Pin(self.exit_process.pid)
        except self.dd.Denied:
            raise StreamError("stream-owner") from None
        self.check()

    def start(self):
        require(
            self.process is None and self.root is None
            and not self.closed,
            "stream-single-use",
        )
        self.check()
        require(
            os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("TOR_REAL_ISOLATED") == "yes",
            "stream-isolation",
        )
        require(
            type(self.binary) is str
            and os.path.isabs(self.binary)
            and Path(self.binary).is_file(),
            "stream-binary",
        )
        self.network.target_binding()
        require(self.target_listener is self.network.target,
                "stream-endpoint")
        self.bind_exit()
        self.root = Path(tempfile.mkdtemp(
            prefix="tor-owned-stream-", dir="/tmp"
        ))
        os.chmod(self.root, 0o700)
        self.storage = self.root / "storage"
        self.storage.mkdir(mode=0o700)
        self.listener = self.hold(socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM
        ))
        control_path = self.root / "control"
        self.listener.bind(str(control_path))
        os.chmod(control_path, 0o600)
        self.listener.listen(1)
        self.listener.setblocking(False)
        self.selector = _session_selector()
        self.watch(self.listener, self.accept_control, selectors.EVENT_READ)
        self.target_listener.setblocking(False)
        self.watch(self.target_listener, self.accept_target,
                   selectors.EVENT_READ)
        nonce = os.urandom(16).hex().encode("ascii")
        self.request = b"owned-request:" + nonce + b"\n"
        self.response = b"owned-response:" + nonce + b"\n"
        self.initial = w.capabilities(self.network, nonce)
        self.initial_pending.extend(self.initial)
        self.environment = os.environ.copy()
        self.environment.update({
            "TOR_REAL_STREAM_CONTROL": str(control_path),
            "TOR_REAL_STREAM_PARENT_PID": str(os.getpid()),
            "TOR_REAL_STREAM_PARENT_UID": str(os.geteuid()),
            "TOR_REAL_STREAM_STORAGE": str(self.storage),
        })
        self.argv = [
            self.binary, w.TEST, "--exact", "--ignored", "--nocapture",
        ]
        self.check()
        self.process = subprocess.Popen(
            self.argv, env=self.environment,
            stdin=self.stdio[0], stdout=self.stdio[1],
            stderr=self.stdio[2], close_fds=True,
        )
        self.process_anchor = (self.process,)
        self.check()

    def authenticate(self):
        self.check()
        credentials = self.control.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, gid = struct.unpack("3i", credentials)
        require(
            pid == self.process_anchor[0].pid
            and uid == os.geteuid(),
            "stream-peer",
        )
        self.peer_credentials = (pid, uid, gid)
        self.check()
        self.authenticated = True

    def accept_control(self, mask):
        self.check()
        try:
            connection, _address = self.listener.accept()
        except BlockingIOError:
            return
        connection = self.hold(connection)
        require(self.control is None, "stream-peer")
        self.control = connection
        connection.setblocking(False)
        self.authenticate()
        self.control_watch()

    def prove_exit_peer(self):
        self.check()
        require(
            self.exit_node is self.network.nodes[2]
            and self.exit_node.role == "exit"
            and self.exit_node.address == self.exit_address
            and self.exit_node.process is self.exit_process
            and self.exit_process.poll() is None
            and self.exit_pin.pid == self.exit_process.pid,
            "stream-owner",
        )
        peer = self.target.getpeername()
        local = self.target.getsockname()
        require(
            self.target_listener is self.network.target
            and self.target_listener.getsockname() == self.target_endpoint
            and self.target_endpoint
            == ("127.0.0.1", self.network.target_port)
            and local == self.target_endpoint
            and peer[0] == _EXIT_SOURCE_ADDRESS
            and type(peer[1]) is int and 0 < peer[1] < 65536,
            "stream-endpoint",
        )
        evidence = []
        try:
            self.exit_pin.check()
            result = self.dd.socket_owned(
                self.target,
                self.exit_process.pid,
                peer_address=_EXIT_SOURCE_ADDRESS,
                local_address=self.target_endpoint[0],
                evidence=evidence,
            )
            self.exit_pin.check()
        except self.dd.Denied:
            raise StreamError("stream-owner") from None
        self.check()
        require(
            self.exit_process.poll() is None
            and self.target.getpeername() == peer
            and self.target.getsockname() == local
            and result is None and len(evidence) == 1
            and evidence[0][0] == peer
            and evidence[0][1] == local
            and evidence[0][2] > 0 and evidence[0][3],
            "stream-owner",
        )
        require(len(self.ownership) < 2, "stream-witness")
        self.ownership.append((
            self.exit_process,
            self.exit_process.pid,
            self.exit_pin.start,
            self.exit_address,
            evidence[0],
        ))

    def accept_target(self, mask):
        self.check()
        try:
            connection, _address = self.target_listener.accept()
        except BlockingIOError:
            return
        connection = self.hold(connection)
        require(self.target is None and self.authenticated,
                "stream-owner")
        self.target = connection
        connection.setblocking(False)
        self.prove_exit_peer()
        self.target_watch()

    def control_watch(self):
        events = selectors.EVENT_READ
        if self.initial_pending or self.ack_pending:
            events |= selectors.EVENT_WRITE
        self.watch(self.control, self.control_io, events)

    def target_watch(self):
        events = 0
        if not self.target_eof:
            events |= selectors.EVENT_READ
        if self.response_pending:
            events |= selectors.EVENT_WRITE
        if events:
            self.watch(self.target, self.target_io, events)
        else:
            self.unwatch(self.target)

    def write_part(self, channel, pending, written):
        self.check()
        try:
            count = channel.send(pending)
        except BlockingIOError:
            return
        require(0 < count <= len(pending), "stream-write")
        written.extend(pending[:count])
        del pending[:count]
        self.check()

    def shutdown_response(self):
        require(
            not self.write_shutdown and not self.response_pending
            and bytes(self.response_written) == self.response,
            "stream-shutdown",
        )
        self.check()
        self.target.shutdown(socket.SHUT_WR)
        self.write_shutdown = True
        self.check()

    def target_io(self, mask):
        self.check()
        if mask & selectors.EVENT_READ:
            try:
                data = self.target.recv(
                    len(self.request) + 1 - len(self.request_seen)
                )
            except BlockingIOError:
                data = None
            if data == b"":
                require(
                    bytes(self.request_seen) == self.request
                    and bytes(self.response_written) == self.response
                    and self.write_shutdown,
                    "stream-target-eof",
                )
                require(self.process.poll() is None, "stream-child")
                self.target_eof = True
                self.eof_child_alive = True
            elif data is not None:
                require(
                    not self.response_pending and not self.response_written,
                    "stream-trailing",
                )
                self.request_seen.extend(data)
                require(
                    len(self.request_seen) <= len(self.request)
                    and self.request.startswith(self.request_seen),
                    "stream-request",
                )
                if bytes(self.request_seen) == self.request:
                    self.prove_exit_peer()
                    self.response_pending.extend(self.response)
        if mask & selectors.EVENT_WRITE and self.response_pending:
            self.write_part(
                self.target, self.response_pending, self.response_written
            )
            if not self.response_pending:
                self.shutdown_response()
        self.target_watch()

    def read_control(self):
        try:
            data = self.control.recv(513)
        except BlockingIOError:
            return False
        if not data:
            require(self.done and not self.control_buffer,
                    "stream-control-eof")
            self.control_eof = True
            self.unwatch(self.control)
            return True
        self.control_total += len(data)
        require(
            self.control_total <= 1024
            and all(byte == 10 or 32 <= byte <= 126 for byte in data),
            "stream-frame",
        )
        self.control_buffer.extend(data)
        while b"\n" in self.control_buffer:
            end = self.control_buffer.index(b"\n") + 1
            require(end <= 512, "stream-frame")
            line = bytes(self.control_buffer[:end])
            del self.control_buffer[:end]
            require(
                not self.initial_pending
                and bytes(self.initial_written) == self.initial,
                "stream-receipt",
            )
            if not self.verified:
                require(line == w.VERIFIED, "stream-receipt")
                self.verified = True
            else:
                require(
                    bytes(self.ack_written) == w.ACK
                    and not self.done and line == w.DONE,
                    "stream-receipt",
                )
                self.done = True
        require(
            len(self.control_buffer) < 512
            and not (self.done and self.control_buffer),
            "stream-trailing",
        )
        return True

    def control_io(self, mask):
        self.check()
        if mask & selectors.EVENT_READ:
            self.read_control()
        if mask & selectors.EVENT_WRITE:
            if self.initial_pending:
                self.write_part(
                    self.control, self.initial_pending, self.initial_written
                )
            elif self.ack_pending:
                self.write_part(
                    self.control, self.ack_pending, self.ack_written
                )
        if not self.control_eof:
            self.control_watch()

    def maybe_acknowledge(self):
        if (
            self.verified and self.target_eof
            and not self.ack_pending and not self.ack_written
        ):
            require(
                self.authenticated and self.eof_child_alive
                and self.write_shutdown
                and bytes(self.request_seen) == self.request
                and bytes(self.response_written) == self.response
                and len(self.ownership) == 2,
                "stream-witness",
            )
            self.check()
            require(self.process.poll() is None, "stream-child")
            self.ack_pending.extend(w.ACK)
            self.control_watch()

    def require_complete(self):
        require(
            self.authenticated
            and bytes(self.initial_written) == self.initial
            and not self.initial_pending
            and bytes(self.request_seen) == self.request
            and bytes(self.response_written) == self.response
            and not self.response_pending and self.write_shutdown
            and len(self.ownership) == 2
            and self.target_eof and self.eof_child_alive
            and self.verified and bytes(self.ack_written) == w.ACK
            and not self.ack_pending and self.done and self.control_eof
            and not self.control_buffer
            and self.process is self.process_anchor[0]
            and self.process.returncode == 0,
            "stream-incomplete",
        )

    def finish_if_exited(self):
        status = self.process.poll()
        if status is None:
            return False
        require(bytes(self.ack_written) == w.ACK, "stream-child")
        while not self.control_eof:
            if not self.read_control():
                break
        require(status == 0, "stream-status")
        self.process.wait(timeout=0)
        self.require_complete()
        self.complete = True
        return True

    def run(self):
        self.start()
        while True:
            self.check()
            self.maybe_acknowledge()
            if self.finish_if_exited():
                return self
            events = self.selector.select(min(0.05, self.remaining()))
            for key, mask in events:
                self.check()
                key.data(mask)
            self.maybe_acknowledge()

    def cleanup_error(self, error):
        self.cleanup_failed = True
        self.cleanup_errors.append(error)

    def close(self):
        if self.closed:
            return
        if self.cleanup_failed:
            raise self.c.a.s.CleanupError("owned stream cleanup failed")
        if self.selector is not None:
            self.selector_attempted = True
            try:
                self.selector.close()
                self.selector_closed = True
            except BaseException as error:
                self.cleanup_error(error)
        for anchor in self.socket_anchors:
            try:
                anchor.close_once()
            except BaseException as error:
                self.cleanup_error(error)
        if self.process_anchor:
            self.stop_proxy = SimpleNamespace(
                process=self.process_anchor[0]
            )
            try:
                self.c.Network.stop_owned([self.stop_proxy], self.deadline)
            except BaseException as error:
                self.cleanup_error(error)
            if self.process_anchor[0].returncode is None:
                self.cleanup_error(StreamError("stream-child"))
        if not self.cleanup_failed and self.exit_pin is not None:
            self.pin_attempted = True
            try:
                self.exit_pin.close()
                self.pin_closed = True
            except BaseException as error:
                self.cleanup_error(error)
        if self.cleanup_failed:
            raise self.c.a.s.CleanupError(
                "owned stream cleanup failed"
            ) from None
        if self.root is not None:
            try:
                shutil.rmtree(self.root)
            except BaseException as error:
                self.cleanup_error(error)
                raise self.c.a.s.CleanupError(
                    "owned stream cleanup failed"
                ) from None
        self.closed = True

    def released(self):
        require(
            self.complete and self.closed and not self.cleanup_failed
            and self.process is self.process_anchor[0]
            and self.process.returncode == 0
            and self.selector_attempted and self.selector_closed
            and self.pin_attempted and self.pin_closed
            and self.root is not None and not self.root.exists(),
            "stream-resource",
        )
        for anchor in self.socket_anchors:
            anchor.released()


def extend(Base, c):
    class OwnedNetwork(Base):
        def __init__(self, binary, gencert, deadline):
            super().__init__(binary, gencert, deadline)
            self.stream = None
            self.cleanup_anchors = None
            self.cleanup_errors = []
            self.cleanup_failed = False

        def consume(self, binary):
            require(self.stream is None, "stream-single-use")
            self.stage = "stream"
            self.target_binding()
            self.stream = Session(self, c, binary)
            self.stream.run()
            self.stream.require_complete()
            return self.stream

        def anchor_dependencies(self):
            if self.cleanup_anchors is None:
                self.cleanup_anchors = tuple(
                    (
                        owner,
                        tuple(getattr(owner, name, None) for name in (
                            "process", "_temp", "_log", "_input",
                            "_socket", "_http",
                        )),
                    )
                    for owner in self.nodes + self.relays + self.materials
                ) + ((self, tuple(self.reservations)),)

        def retain_owned_files(self):
            self.anchor_dependencies()
            for owner, resources in self.cleanup_anchors:
                if owner is self:
                    continue
                temporary = resources[1]
                if temporary is not None:
                    temporary._finalizer.detach()

        def close(self):
            if self.closed:
                return
            if self.stream is None:
                return super().close()
            if self.cleanup_failed:
                raise c.a.s.CleanupError("owned stream network cleanup failed")
            self.anchor_dependencies()
            try:
                if self.stream is not None:
                    self.stream.close()
                super().close()
            except BaseException as error:
                self.cleanup_failed = True
                self.cleanup_errors.append(error)
                if self.stream is not None and not self.stream.closed:
                    try:
                        self.stop_owned(
                            self.nodes + self.relays + self.materials,
                            self.deadline,
                        )
                    except BaseException as stop_error:
                        self.cleanup_errors.append(stop_error)
                self.retain_owned_files()
                raise c.a.s.CleanupError(
                    "owned stream network cleanup failed"
                ) from None

    return OwnedNetwork
