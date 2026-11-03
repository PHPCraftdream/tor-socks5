"""Unapplied Task126 source proposal: process-bound Disabled PT audit domains.

Status
------
The previous proposals remain independently FAIL. This replacement has not
been applied, compiled, imported, tested, or executed. No local capability or
runtime success is claimed. Task103/100 acceptance and Task127 wiring remain
outside this component.

Task127 integration contract
---------------------------
All execution described here is for future exclusive GitHub CI only.

1. Supply the EXISTING absolute time.monotonic() deadline. No operation creates
   a replacement deadline or extends the outer budget. Kernel commands use
   min(5 seconds, remaining budget). The outer process/job budget remains the
   hard bound for synchronous filesystem syscalls.

2. Construct:
       DirectDomain(deadline, base_rules, live_count, verify_allocation)
   base_rules() returns the existing complete IPv4 expected-rule dictionary,
   excluding direct-domain rules. live_count() returns the actual current
   count of live control tuples. These callbacks and all domain methods run
   serially on the supervisor event loop.

   Existing order is retained:
       DNS UDP, DNS TCP, live control tuples, direct rules,
       forbidden, loopback.
   Existing dedicated live/retired control chains and their counter
   relationships are retained. There are no destination-only allowances,
   counter subtraction, real-window resets, or IPv6 direct allowances.

3. Call setup(), then begin(actual_owner_pid, actual_child_executable).
   begin() does NOT require future allocations. Its default expected phases
   are legacy-start and supplied-positive-start. Calibration explicitly uses
   a single expected phase.

4. Dynamic independent allocation provenance:

   register_allocation(evidence) is a TRUSTED SUPERVISOR API, never a wire
   command. It invokes:
       verify_allocation(owner_pid, owner_start_time, executable, evidence)
   and requires an Allocation result.

   Task127 must provide that verifier and a bounded independent evidence
   producer. The producer must observe the existing construction journal's
   actual Reserved and StorageAssigned events, before child startup, without
   acquiring entry.state. In particular it must not wait for a constructing
   entry's mutex while bootstrap retains that mutex.

   A realizable producer is a test-private, bounded construction-event export
   at those existing journal emission points, delivered to the supervisor
   independently of INTENT. Task127 must authenticate that export as belonging
   to the pinned owner, validate framing/limits, correlate request and entry
   identity, require the actual explicit Disabled selection, require one
   Reserved followed by its unique StorageAssigned, reject dropped/conflicting
   events and slot sharing, and derive the allocated path from the actual
   owner's dynamic temporary root and actual assigned slot. It must not accept
   a path/slot/Disabled assertion merely because an INTENT supplies it.

   The verifier returns the exact owner, request, identity, ordered journal
   sequence numbers, slot, allocated path, expected phase and Disabled result.
   This module validates those correlations and the directory shape again,
   but cannot manufacture the journal's truth from an incoming path.

   The allocated directory must already exist when registered. Its managed
   leaf need not exist yet: the leaf is derived as
       allocated / "state" / "pt_state" / executable.name
   and is required to exist canonically at INTENT/BIND. This accounts for the
   manager appending the executable filename on Linux.

   Ordering must be explicit: the owner may send INTENT only AFTER Task127
   has processed and acknowledged the independent allocation export. Merely
   emitting an unacknowledged event on a different socket is insufficient
   ordering. If evidence is missing, late, ambiguous or unavailable, deny
   authorization rather than infer it from INTENT, environment or UID.

   Task127 owns this bounded export/verifier integration; it is not implemented
   as fake journal proof in this source leaf. The synthetic controls use an
   explicitly synthetic verifier and make no stock/journal receipt claim.

5. Use Reactor for the supplied registration/control listener:
       Reactor(deadline, listener, domain, on_line, on_close, phase)
   phase() returns the actual existing current phase. on_line(peer, bytes_line)
   handles OTHER existing protocol lines, including the terminating newline.
   on_close(peer) performs their existing retirement bookkeeping.
   peer.state is available for that protocol.
   peer.reply(data, close=False) supports its acknowledgments.

   Reactor watches listener, all peers, retained child pidfds and caller
   descriptors through ONE selector. watch(fileobj, callback, events) integrates
   a bounded journal-export reader and other existing descriptors. Callbacks
   must be nonblocking, bounded, and use this deadline for commands. Unregister
   a descriptor before closing it.

   Reactor owns accepted peer sockets, not the supplied listener or caller
   descriptors. It uses incremental bounded frames, not buffered readline.

6. Registration wire protocol:
       INTENT <allocated-byte-length> <leaf-byte-length>\\n
       <lowercase-hex-allocated> <lowercase-hex-leaf>\\n
       BIND <actual-child-pid>\\n

   INTENT remains a single request with OK or DENY. BIND is a retained-socket
   transaction: supervisor sends GROUP <lowercase-hex-canonical-group-path>\\n;
   that authenticated child writes exactly "0" to that group's cgroup.procs,
   then sends MOVED\\n on the SAME socket. The supervisor revalidates the
   child/socket, observes actual membership, installs and confirms its exact
   rule, then sends final OK\\n. GROUP and MOVED are not continuation authority.
   DENY, incomplete replies, unexpected frames and EOF are terminal gate
   failures. No other connection can complete an assigned transaction.
   Ordinary clients MUST keep both socket directions open while authentication
   occurs and until the complete response has been received. They close only
   afterwards. Only deliberate truncated-frame and lost-migration-reply EOF
   calibration paths call shutdown(SHUT_WR).

   INTENT requires an ESTABLISHED IPv4 loopback socket actually held by the
   pinned owner and an independently registered matching allocation.
   BIND requires an ESTABLISHED socket actually held by the claimed pinned
   direct child, the exact executable, correct parent/UID/managed environment,
   absent TOR_PT_PROXY, acknowledged INTENT and the exact canonical leaf.
   Missing TOR_PT_PROXY alone never creates authority.

   The actual managed child gate must precede creation of transport/DNS
   sockets. It must continue only after complete OK\\n and exit otherwise.
   xt_cgroup classifies sockets at creation; migration cannot bless earlier
   sockets. Inherited/pre-gate egress sockets and child descendants are not
   authorized. Task127 must preserve the actual executable, environment, UID,
   CWD, state, permissions, and existing descriptors.

   The supervisor NEVER writes a numeric child PID into cgroup.procs. Only
   the gate child calls self_migrate(group), which writes "0": the kernel's
   current writer, not a supervisor-supplied process number. If that writer
   exits, this operation cannot subsequently migrate a recycled foreign PID.
   No manager no-reap interlock is required or assumed.

   Concrete gate API: direct_child_gate(address, existing_deadline) performs
   the complete transaction and returns only after final OK. It creates no
   transport sockets. Task129/127 must call it in the actual managed child
   before lyrebird, preserving the real process and its existing environment,
   CWD, UID, state and descriptors. Errors must terminate that gate child.
   self_migrate(group) accepts only a canonical direct-N directory below an
   exclusively named pt-owner-audit-* group and writes only the literal "0".
   No helper accepts a target migration PID. Reactor consumers use the real
   handle()/Peer.reply()/Reactor.watch() methods; no parallel API is implied.
   Independent allocation/journal provenance remains unchanged. This source
   supplies no bridge, journal export, vendor interlock or caller wiring.

7. rules() exposes confirmed installed direct rules, INCLUDING rules retained
   after later failure. Task127 adds these exact rules to its expected IPv4
   schema, never IPv6, and preserves its existing full audits and diagnostics.

   snapshot() acquires and strictly validates one actual IPv4 filter snapshot:
   policies, exact ordered rules, live/dedicated equality and packet/byte
   conservation including retired dedicated counters. It returns an immutable
   Snapshot issued by this domain.

   counts(snapshot) accepts ONLY this domain's latest issued Snapshot with an
   unchanged generation and exact current expected schema. A mapping, copied
   counts, foreign token or superseded token is rejected. Its direct pairs and
   Snapshot.data therefore come from the SAME validated acquisition. It does
   not claim to validate arbitrary caller-provided count dictionaries.

   Concrete Task127 reconciliation: keep its existing audit contract for other
   consumers. For direct reporting/completion use this issued Snapshot, and use
   its data for any report which claims same-snapshot association. Do not pass
   the old audit() count dictionary to counts(). Task127 may compare independent
   acquisitions but must not present them as one acquisition.

8. finish() stops registration without discarding evidence. After all actual
   owned children terminate, call finish(), acquire the final snapshot, and
   require complete(snapshot). This checks both intended records, all progress,
   terminal membership, zero DNS/forbidden counters and positive direct packet
   AND byte counts. Also retain every existing real lyrebird, legacy
   journal/slot/PID/live-socket and IPv6 proof. Synthetic controls replace none
   of those Task127 obligations.

   Take the final evidence BEFORE dispose(reactor). Rule removal necessarily
   removes its kernel counters; cleanup never pretends that a post-removal
   snapshot conserves the already captured real-window classification.

9. dispose(reactor) stops only concrete validated pidfd-pinned children retained
   by this domain, waits through the same reactor/budget, reconciles ambiguous
   rule attempts, removes only its exact rules and empty exclusively-created
   cgroups, and reports fixed cleanup errors. It never kills unknown cgroup
   members, signals process groups, changes permissions recursively, migrates
   children back into unrelated cgroups, or discards unresolved resources.
   Keep the domain, reactor and caller-owned child handles through cleanup.
   Any cleanup error is a final failure, including command failure followed
   by evidence that the command nevertheless took effect.

   Intent, intent acknowledgment, pinned PID, migration attempt/observation,
   rule attempt/command return/confirmed installation, bind acknowledgment,
   terminal state and cleanup are distinct retained fields. Acknowledgment
   means all reply bytes were written locally, not remote application receipt.
   Actual continuation and final kernel evidence remain required.
   This is not privileged-tampering resistance.

   assignment_attempted means a GROUP reply was queued; assignment_written
   means all its bytes were written locally. migration_attempted then means
   self-migration is POSSIBLE, not that a child write was proved. move_reply
   records the complete received frame, independently of observed_members and
   migrated. Lost/invalid replies retain the pin/group and sample membership
   without installing a rule. Cleanup closes pending transactions before
   concrete pidfd termination. Only owned empty groups/exact rules are removed;
   unknown members remain an explicit cleanup failure.

Callable future-CI controls
--------------------------
Call:
       regression(existing_deadline, fresh_epoch)

fresh_epoch(deadline) is the supervisor's explicit calibration adapter. Before
each case it establishes a fresh EXCLUSIVE PRE-REAL-WINDOW audit epoch with
exactly calibration_rules(), zero counters, and existing IPv6 protections.
It must not run after the real owner window begins. This module neither
resets nor weakens the real audit. The driver verifies the actual initial
schema/counters itself.

Controls own their listener, incremental service, synthetic Python actors,
traps, receipts, retained outcomes and cleanup. They do not require Rust probe
wiring or an undeclared callback attribute. Actor registration sockets stay
open through complete responses. Ordinary actor termination requires STOP,
BYE, stdout EOF and exact exit 0. Partial-progress controls deliberately request
domain-owned pidfd SIGKILL and require exact -SIGKILL. Any unexpected exit,
including an early exit 0 or nonzero exit, fails. Failure cleanup may force
remaining actors, but cannot convert the failed control into success.

Coverage:
- valid dynamic registration followed by live INTENT/BIND and kernel delivery;
- INTENT before independent registration, wrong sender/phase/allocation,
  zero/oversized lengths, length mismatch, uppercase hex and deliberate
  truncated EOF, followed by an otherwise valid baseline;
- registered wrong destination/port, UDP/TCP DNS attribution, each followed by
  an intended positive emission;
- configured same-destination escape, stripped proxy with no independent
  allocation, unregistered leaf, claimed owner PID and borrowed live child PID,
  each paired with a valid registration/binding/classification baseline;
- injected post-migration, pre-rule, ambiguous post-rule-command and pre-ack
  failures, exact retained progress, intentional forced outcome, exact rule and
  empty-group cleanup;
- self-write followed by lost or invalid MOVED, and MOVED without self-write:
  exact denial/EOF, retained actual membership, no rule attempt, intentional
  forced termination and terminal cleanup. Lost-reply calibration alone
  half-closes after the assignment/self-write; normal clients never do.
- every existing positive actor uses the same GROUP/self-write/MOVED/final-OK
  implementation as direct_child_gate, not a supervisor migration shortcut;
- rejection of unvalidated and superseded count inputs.

These are synthetic mechanism controls, not stock transport receipts. Frame
calibration does not claim an accepted filesystem path of exactly MAX_PATH
bytes or actual mixed-scenario integration. Fault injection exercises the
specified partial states, not every possible kernel failure.

ControlFailure.run retains every epoch, actor, process handle, domain, record,
snapshot and unresolved resource. Successful reports describe only the
synthetic controls actually run in that future CI invocation.

Import performs no probes. Linux cgroup v2, pidfds, bounded readable proc data
and usable xt_cgroup --path fail closed when explicitly exercised in CI.
No dependencies, guard/baseline changes or larger deadlines are introduced.
"""

import itertools
import os
import re
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


MAX_PATH = 2048
MAX_PAYLOAD = 4 * MAX_PATH + 2
MAX_PEERS = 64
MAX_SNAPSHOTS = 256
CHAIN = 'PT_OWNER'
PHASES = ('legacy-start', 'supplied-positive-start')
DNS = (
    ('-p', 'udp', '--dport', '53', '-j', 'RETURN'),
    ('-p', 'tcp', '--dport', '53', '-j', 'RETURN'),
)
TAIL = (
    ('!', '-d', '127.0.0.1/32', '-j', 'RETURN'),
    ('-j', 'RETURN'),
)
WIRE_REASONS = frozenset((
    'frame-bound', 'frame-eof', 'frame-trailing',
    'intent-header', 'intent-bound', 'intent-frame', 'intent-length',
    'intent-owner', 'intent-allocation', 'intent-phase', 'intent-group-failed',
    'bind-frame', 'bind-owner', 'bind-pid', 'bind-parent', 'bind-uid', 'bind-executable',
    'bind-managed', 'bind-configured-proxy', 'bind-state-bound',
    'bind-no-intent', 'bind-intent-ack', 'bind-consumed',
    'bind-group-populated', 'bind-migration', 'bind-rule-command',
    'bind-rule-unconfirmed', 'bind-membership',
    'channel-family', 'channel-address', 'channel-tuple', 'channel-owner',
    'canonical-path', 'directory', 'process-not-live', 'process-race',
    'injected-migration-failure', 'registration-unavailable',
    'bind-assignment', 'bind-move-frame', 'bind-move-eof',
    'bind-move-invalid', 'bind-membership',
))


class Denied(RuntimeError):
    pass


class ControlFailure(Denied):
    def __init__(self, run, cleanup_errors):
        super().__init__('direct-domain-control-failed')
        self.run = run
        self.cleanup_errors = tuple(cleanup_errors)


def require(value, reason):
    if not value:
        raise Denied(reason)


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, 'budget-exhausted')
    return value


def bounded(path, limit):
    with open(path, 'rb') as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, 'file-bound')
    return data


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path,
            'canonical-path')
    require(path.is_dir() and not path.is_symlink(), 'directory')
    return path


def identity(pid, *, self_owner=False):
    require(type(pid) is int
            and (pid > 1
                 or (self_owner and pid == 1 and pid == os.getpid())),
            'pid-invalid')
    data = bounded(f'/proc/{pid}/stat', 16384)
    end = data.rfind(b')')
    require(end > 0, 'process-record')
    fields = data[end + 2:].split()
    require(len(fields) >= 20 and fields[19].isdigit(), 'process-record')
    return int(fields[19])


def process_status(pid):
    text = bounded(f'/proc/{pid}/status', 16384).decode('ascii')
    parent = re.search(r'^PPid:\s+(\d+)$', text, re.MULTILINE)
    uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$',
                    text, re.MULTILINE)
    require(parent is not None and uid is not None, 'process-status')
    return int(parent.group(1)), tuple(int(value) for value in uid.groups())


def environment(pid):
    result = {}
    for field in bounded(f'/proc/{pid}/environ', 131072).split(b'\0'):
        if not field:
            continue
        require(b'=' in field, 'environment-format')
        key, value = field.split(b'=', 1)
        require(key not in result, 'environment-duplicate')
        result[key] = value
    return result


def membership(pid):
    rows = bounded(f'/proc/{pid}/cgroup', 4096).decode('ascii').splitlines()
    require(len(rows) == 1 and rows[0].startswith('0::/'),
            'cgroup-membership')
    value = rows[0][3:]
    require('..' not in Path(value).parts, 'cgroup-membership')
    return value


def socket_owned(connection, pid):
    require(connection.family == socket.AF_INET, 'channel-family')

    def endpoint(address):
        require(address[0] == '127.0.0.1', 'channel-address')
        return (socket.inet_aton(address[0])[::-1].hex().upper()
                + f':{address[1]:04X}')

    source = endpoint(connection.getpeername())
    destination = endpoint(connection.getsockname())
    rows = bounded('/proc/net/tcp', 1024 * 1024).decode('ascii').splitlines()
    require(0 < len(rows) <= 8192, 'tcp-bound')
    matches = []
    for row in rows[1:]:
        fields = row.split()
        require(len(fields) > 9, 'tcp-format')
        if (fields[1], fields[2], fields[3]) == (source, destination, '01'):
            matches.append(fields[9])
    require(len(matches) == 1 and matches[0].isdigit(), 'channel-tuple')
    target = f'socket:[{matches[0]}]'
    with os.scandir(f'/proc/{pid}/fd') as entries:
        paths = list(itertools.islice(entries, 257))
    require(len(paths) <= 256, 'descriptor-bound')
    found = False
    for entry in paths:
        try:
            found = found or os.readlink(entry.path) == target
        except FileNotFoundError:
            continue
    require(found, 'channel-owner')


class Pin:
    def __init__(self, pid, *, self_owner=False):
        self.pid = pid
        self.self_owner = self_owner
        self.start = identity(pid, self_owner=self.self_owner)
        self.fd = os.pidfd_open(pid, 0)
        try:
            require(identity(pid, self_owner=self.self_owner) == self.start
                    and self.live(), 'process-race')
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def live(self):
        if self.fd is None:
            return False
        with selectors.DefaultSelector() as selector:
            selector.register(self.fd, selectors.EVENT_READ)
            return not selector.select(0)

    def check(self):
        require(self.live()
                and identity(self.pid, self_owner=self.self_owner) == self.start,
                'process-not-live')

    def kill(self):
        if self.live():
            signal.pidfd_send_signal(self.fd, signal.SIGKILL)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


@dataclass(frozen=True)
class Allocation:
    owner: int
    request: int
    identity: int
    reserved_sequence: int
    assigned_sequence: int
    slot: int
    allocated: Path
    phase: str
    disabled: bool
    registry: int = 0


@dataclass(frozen=True)
class Snapshot:
    issuer: object
    generation: int
    schema: tuple
    data: tuple
    direct: tuple

    def chain(self, name):
        for key, rows in self.data:
            if key == name:
                return rows
        raise Denied('snapshot-chain-missing')


class Record:
    def __init__(self, allocation, leaf, group):
        self.allocation = allocation
        self.leaf = leaf
        self.group = group
        self.relative = group.relative_to('/sys/fs/cgroup').as_posix()
        self.created = False
        self.intent = True
        self.intent_ack = False
        self.pin = None
        self.pid = None
        self.original_group = None
        self.migration_attempted = False
        self.migrated = None
        self.assignment_attempted = False
        self.assignment_written = False
        self.move_reply = None
        self.observed_members = None
        self.initial_validated = False
        self.rule_attempted = False
        self.rule_command_ok = False
        self.installed = False
        self.installed_ever = False
        self.bind_ack = False
        self.terminal = False
        self.group_removed = False
        self.failure = None

    def fail(self, reason):
        self.failure = self.failure or reason


def calibration_rules():
    return {
        'INPUT': [],
        'FORWARD': [],
        'OUTPUT': [['-j', CHAIN]],
        CHAIN: [list(row) for row in DNS + TAIL],
    }


def freeze_schema(schema):
    return tuple((name, tuple(tuple(row) for row in rows))
                 for name, rows in sorted(schema.items()))


from importlib.machinery import SourceFileLoader

SourceFileLoader(
    __name__,
    str(Path(__file__).parent / "tests" / "domain" / "ownership.py"),
).exec_module(sys.modules[__name__])
SourceFileLoader(
    __name__,
    str(Path(__file__).parent / "tests" / "domain" / "reactor.py"),
).exec_module(sys.modules[__name__])

def intent_frame(allocated, leaf):
    values = [os.fsencode(allocated), os.fsencode(leaf)]
    require(all(0 < len(value) <= MAX_PATH for value in values), 'intent-bound')
    return (f'INTENT {len(values[0])} {len(values[1])}\n'.encode('ascii')
            + b' '.join(value.hex().encode('ascii') for value in values) + b'\n')


def self_migrate(group):
    group = canonical(group)
    mount = canonical(Path('/sys/fs/cgroup'))
    require(group.is_relative_to(mount)
            and group.parent.name.startswith('pt-owner-audit-')
            and re.fullmatch(r'direct-[01]', group.name) is not None,
            'gate-group')
    require(0 < len(os.fsencode(group)) <= MAX_PATH, 'gate-group-bound')
    target = group / 'cgroup.procs'
    require(target.resolve(strict=True) == target and target.is_file(),
            'gate-process-file')
    with open(target, 'w', encoding='ascii') as output:
        require(output.write('0') == 1, 'gate-self-write')


def _gate_transaction(channel, deadline, request, mode='normal'):
    def receive():
        reply = bytearray()
        while not reply.endswith(b'\n'):
            channel.settimeout(remaining(deadline))
            part = channel.recv(1)
            if not part:
                require(not reply, 'gate-incomplete-reply')
                return b''
            reply.extend(part)
            require(len(reply) <= MAX_PAYLOAD, 'gate-reply-bound')
        return bytes(reply)

    require(mode in ('normal', 'move-lost', 'move-invalid', 'move-unperformed'),
            'gate-mode')
    channel.settimeout(remaining(deadline))
    channel.sendall(request)
    first = receive()
    if not first.startswith(b'GROUP '):
        require(not first or re.fullmatch(
            rb'DENY [a-z0-9-]+\n', first) is not None, 'gate-initial-reply')
        return first
    require(request == f'BIND {os.getpid()}\n'.encode('ascii'),
            'gate-assignment-request')
    match = re.fullmatch(rb'GROUP ([0-9a-f]+)\n', first)
    require(match is not None and len(match.group(1)) % 2 == 0,
            'gate-assignment-frame')
    raw = bytes.fromhex(match.group(1).decode('ascii'))
    require(0 < len(raw) <= MAX_PATH and b'\0' not in raw,
            'gate-assignment-bound')
    group = Path(os.fsdecode(raw))
    if mode != 'move-unperformed':
        self_migrate(group)
    if mode == 'move-lost':
        channel.shutdown(socket.SHUT_WR)
    else:
        channel.settimeout(remaining(deadline))
        channel.sendall(b'INVALID\n' if mode == 'move-invalid' else b'MOVED\n')
    final = receive()
    require(not final or final == b'OK\n' or re.fullmatch(
        rb'DENY [a-z0-9-]+\n', final) is not None, 'gate-final-reply')
    return final


def direct_child_gate(address, deadline):
    require(os.getpid() > 1, 'bind-pid')
    with socket.create_connection(address, timeout=remaining(deadline)) as channel:
        reply = _gate_transaction(
            channel, deadline, f'BIND {os.getpid()}\n'.encode('ascii'))
        require(reply == b'OK\n', 'gate-denied')


SourceFileLoader(
    __name__,
    str(Path(__file__).parent / "tests" / "domain" / "controls.py"),
).exec_module(sys.modules[__name__])
