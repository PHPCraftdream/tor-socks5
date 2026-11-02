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


class Peer:
    def __init__(self, reactor, sock):
        self.reactor = reactor
        self.sock = sock
        self.buffer = bytearray()
        self.output = bytearray()
        self.intent_sizes = None
        self.record = None
        self.bind_pending = False
        self.ack = None
        self.close_after = True
        self.closed = False
        self.state = None
        self._written = None
        self.exclusive_line = None

    def reply(self, data, close=True, ack=None, *, _written=None):
        require(not self.closed and not self.output and 0 < len(data) <= 8192,
                'reply-bound')
        require(self._written is None
                and (_written is None or callable(_written)), 'reply-callback')
        self.output.extend(data)
        self.close_after, self.ack = close, ack
        self._written = _written
        self.reactor.watch(self.sock, self.service, selectors.EVENT_WRITE)

    def deny(self, reason):
        if reason not in WIRE_REASONS:
            reason = 'registration-invalid'
        self.reactor.domain.denials.append(reason)
        self.reactor.domain.touch()
        if self.record is not None:
            self.record.fail('registration-reply-failed')
        self.reply(b'DENY ' + reason.encode('ascii') + b'\n')

    def service(self, mask):
        try:
            if mask & selectors.EVENT_WRITE:
                try:
                    sent = self.sock.send(self.output)
                except BlockingIOError:
                    return
                require(sent > 0, 'reply-closed')
                del self.output[:sent]
                if self.output:
                    return
                if self.ack is not None:
                    record, kind = self.ack
                    self.reactor.domain.acknowledge(record, kind)
                    self.ack = None
                if self._written is not None:
                    written = self._written
                    self._written = None
                    written()
                if self.close_after:
                    self.close()
                else:
                    self.reactor.watch(
                        self.sock, self.service, selectors.EVENT_READ)
                return
            try:
                data = self.sock.recv(4096)
            except BlockingIOError:
                return
            if not data:
                if self.bind_pending:
                    self.reactor.domain.observe_migration(self.record)
                    self.close()
                elif self.buffer or self.intent_sizes is not None:
                    self.deny('frame-eof')
                else:
                    self.close()
                return
            self.buffer.extend(data)
            require(len(self.buffer) <= MAX_PAYLOAD + 128, 'frame-bound')
            while not self.closed and not self.output and b'\n' in self.buffer:
                at = self.buffer.index(b'\n') + 1
                line = bytes(self.buffer[:at])
                del self.buffer[:at]
                require(len(line) <= (
                    MAX_PAYLOAD if self.intent_sizes is not None else 128),
                    'frame-bound')
                if (self.bind_pending or self.intent_sizes is not None
                        or line.startswith(b'BIND')):
                    require(not self.buffer, 'frame-trailing')
                if self.exclusive_line is not None:
                    self.exclusive_line(self, line)
                    handled = True
                else:
                    handled = self.reactor.domain.handle(
                        self, line, self.reactor.phase())
                if not handled:
                    require(self.reactor.on_line is not None, 'protocol-unknown')
                    self.reactor.on_line(self, line)
            if not self.output and not self.closed:
                limit = MAX_PAYLOAD if self.intent_sizes is not None else 128
                require(len(self.buffer) < limit, 'frame-bound')
        except Denied as failure:
            if mask & selectors.EVENT_WRITE:
                self.close()
            elif not self.closed and not self.output:
                self.deny(str(failure))
            else:
                self.close()
        except (OSError, ValueError, UnicodeError):
            if mask & selectors.EVENT_WRITE:
                self.close()
            elif not self.closed and not self.output:
                self.deny('registration-unavailable')
            else:
                self.close()

    def close(self):
        if self.closed:
            return
        self._written = None
        if self.bind_pending and self.record is not None and not self.record.bind_ack:
            self.reactor.domain.observe_migration(self.record)
            self.record.fail('bind-transaction-incomplete')
            self.reactor.domain.touch()
        if self.ack is not None and self.record is not None:
            self.record.fail('ack-not-written')
            self.reactor.domain.touch()
        self.closed = True
        self.reactor.unwatch(self.sock)
        self.reactor.peers.pop(self.sock, None)
        self.sock.close()
        if self.reactor.on_close is not None:
            self.reactor.on_close(self)


class Reactor:
    def __init__(self, deadline, listener, domain, on_line=None, on_close=None,
                 phase=lambda: PHASES[0]):
        require(deadline == domain.deadline, 'reactor-budget')
        self.deadline = deadline
        self.listener = listener
        self.domain = domain
        self.on_line, self.on_close, self.phase = on_line, on_close, phase
        self.selector = selectors.DefaultSelector()
        self.peers = {}
        self.pins = {}
        self.closed = False
        listener.setblocking(False)
        self.watch(listener, self.accept)

    def watch(self, fileobj, callback, events=selectors.EVENT_READ):
        require(not self.closed, 'reactor-closed')
        try:
            self.selector.modify(fileobj, events, callback)
        except KeyError:
            self.selector.register(fileobj, events, callback)

    def unwatch(self, fileobj):
        if self.closed:
            return
        try:
            self.selector.unregister(fileobj)
        except KeyError:
            return

    def accept(self, mask):
        try:
            connection, _ = self.listener.accept()
        except BlockingIOError:
            return
        if len(self.peers) >= MAX_PEERS:
            connection.close()
            raise Denied('peer-bound')
        connection.setblocking(False)
        peer = Peer(self, connection)
        self.peers[connection] = peer
        self.watch(connection, peer.service)

    def track_pin(self, pin, callback):
        require(pin.fd is not None and pin.fd not in self.pins, 'pin-duplicate')
        fd = pin.fd
        self.pins[fd] = (pin, callback)

        def terminal(mask):
            self.unwatch(fd)
            self.pins.pop(fd, None)
            callback()

        self.watch(fd, terminal)

    def untrack_pin(self, pin):
        if pin.fd is not None:
            self.unwatch(pin.fd)
            self.pins.pop(pin.fd, None)

    def step(self, *, deadline=None):
        end = self.deadline if deadline is None else deadline
        require(end == self.deadline or (self.domain.ended
                and end == self.domain.cleanup_deadline), 'reactor-cleanup-budget')
        events = self.selector.select(remaining(end))
        require(events, 'budget-exhausted')
        for key, mask in events:
            try:
                current = self.selector.get_key(key.fd)
            except KeyError:
                continue
            if current.data is key.data:
                key.data(mask)

    def until(self, predicate, *, deadline=None):
        while not predicate():
            self.step(deadline=deadline)

    def exchange(self, frame, truncated=False):
        require(0 < len(frame) <= MAX_PAYLOAD + 128, 'exchange-bound')
        connection = socket.create_connection(
            self.listener.getsockname(), timeout=remaining(self.deadline))
        response = bytearray()
        done = False
        try:
            connection.settimeout(remaining(self.deadline))
            connection.sendall(frame)
            if truncated:
                connection.shutdown(socket.SHUT_WR)
            connection.setblocking(False)

            def receive(mask):
                nonlocal done
                try:
                    data = connection.recv(128)
                except BlockingIOError:
                    return
                response.extend(data)
                require(len(response) <= 128, 'exchange-reply-bound')
                done = not data or b'\n' in response

            self.watch(connection, receive)
            self.until(lambda: done)
            require(response.endswith(b'\n') and response.count(b'\n') == 1,
                    'exchange-incomplete-response')
            return bytes(response)
        finally:
            self.unwatch(connection)
            connection.close()

    def close(self):
        if self.closed:
            return
        for peer in list(self.peers.values()):
            peer.close()
        self.selector.close()
        self.closed = True


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
