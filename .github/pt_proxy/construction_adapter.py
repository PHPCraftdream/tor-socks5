"""Bounded authenticated construction evidence, not stock transport proof.

The trusted test-private owner exports actual producer facts and status.
Local response completion and remote acceptance receipt are distinct states.
"""

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path


VERSION = 2
HEADER = struct.Struct("!BBBQQQQQBBHH")
STATUS = struct.Struct("!BBBQQQB")
PROGRESS = struct.Struct("!QBBB")

OPEN = ord("O")
RESERVED = ord("R")
ASSIGNED = ord("S")
GLOBAL = ord("G")
FAILED = ord("F")
END = ord("X")
FINISH = ord("Z")
EVENTS = frozenset((RESERVED, ASSIGNED, GLOBAL, FAILED))
OUTCOMES = frozenset((RESERVED, GLOBAL, FAILED))

MAX_PATH = 2048
MAX_EVENTS = 64
MAX_REGISTRIES = 16
MAX_CHUNK = 48
MAX_BODY = HEADER.size + 2 * MAX_PATH + STATUS.size + MAX_EVENTS * PROGRESS.size
MAX_TRANSACTIONS = MAX_REGISTRIES * (MAX_EVENTS + 2) + 1

FAILURES = (
    None,
    "construction export acknowledgement cancelled",
    "construction export unavailable",
    "construction export deadline",
    "construction export journal dropped",
    "construction export invalid evidence",
    "construction export delivery failed",
    "construction export acknowledgement deadline",
    "construction export acknowledgement lost",
    "construction export acknowledgement mismatch",
    "construction export acknowledgement rejected",
    "construction export admission evidence missing",
    "construction export incomplete",
)
FAILURE_CODES = {value: index for index, value in enumerate(FAILURES)}


@dataclass(frozen=True)
class ItemStatus:
    sequence: int
    queued: bool
    acknowledged: bool
    failure: int


@dataclass(frozen=True)
class ProducerStatus:
    installed: bool
    closed: bool
    failure: int
    journal_count: int
    dropped: int
    creation_attempts: int
    progress: tuple


@dataclass(frozen=True)
class Fact:
    operation: int
    phase: int
    registry: int
    sequence: int = 0
    request: int = 0
    identity: int = 0
    slot: int = 0
    disabled: bool = False
    effective: object = None
    base: bytes = b""
    allocated: bytes = b""
    status: object = None


@dataclass
class Context:
    registry: int
    phase: str
    events: list = field(default_factory=list)
    outcomes: dict = field(default_factory=dict)
    assignments: dict = field(default_factory=dict)
    base: object = None
    ended: bool = False
    status: object = None
    successful: bool = False


@dataclass(eq=False)
class Receipt:
    allocation: object
    context: Context
    fact: Fact
    transaction: int
    ready: bool = False


@dataclass
class Transaction:
    number: int
    size: int
    body: bytearray = field(default_factory=bytearray)
    fact: object = None
    receipt: object = None
    accepted: bool = False
    accept_written: bool = False
    remote_confirmed: bool = False
    response_queued: bool = False
    response_written: bool = False


def failure_code(reason):
    return FAILURE_CODES[reason]


def encode(fact):
    effective = 2 if fact.effective is None else int(fact.effective)
    body = HEADER.pack(
        VERSION, fact.operation, fact.phase, fact.registry, fact.sequence,
        fact.request, fact.identity, fact.slot, int(fact.disabled), effective,
        len(fact.base), len(fact.allocated),
    ) + fact.base + fact.allocated
    if fact.status is not None:
        status = fact.status
        body += STATUS.pack(
            int(status.installed), int(status.closed), status.failure,
            status.journal_count, status.dropped, status.creation_attempts,
            len(status.progress),
        )
        for item in status.progress:
            body += PROGRESS.pack(
                item.sequence, int(item.queued),
                int(item.acknowledged), item.failure,
            )
    return body


def decode(body):
    if not HEADER.size <= len(body) <= MAX_BODY:
        raise ValueError("evidence-body-bound")
    values = HEADER.unpack(body[:HEADER.size])
    version, operation, phase, registry, sequence, request, identity, slot, \
        disabled, effective, base_size, allocated_size = values
    if (
        version != VERSION
        or operation not in EVENTS | {OPEN, END, FINISH}
        or phase not in (0, 1)
        or disabled not in (0, 1)
        or effective not in (0, 1, 2)
        or base_size > MAX_PATH
        or allocated_size > MAX_PATH
    ):
        raise ValueError("evidence-body-format")
    end = HEADER.size + base_size + allocated_size
    if end > len(body):
        raise ValueError("evidence-body-format")
    base = bytes(body[HEADER.size:HEADER.size + base_size])
    allocated = bytes(body[HEADER.size + base_size:end])
    if b"\0" in base or b"\0" in allocated:
        raise ValueError("evidence-path-nul")
    status = None
    if operation == END:
        if len(body) < end + STATUS.size:
            raise ValueError("evidence-status-format")
        installed, closed, failure, count, dropped, attempts, length = \
            STATUS.unpack(body[end:end + STATUS.size])
        end += STATUS.size
        if (
            installed not in (0, 1) or closed not in (0, 1)
            or failure >= len(FAILURES) or count > MAX_EVENTS
            or length > MAX_EVENTS
            or len(body) != end + length * PROGRESS.size
        ):
            raise ValueError("evidence-status-format")
        progress = []
        for _ in range(length):
            seq, queued, ack, reason = PROGRESS.unpack(
                body[end:end + PROGRESS.size])
            end += PROGRESS.size
            if queued not in (0, 1) or ack not in (0, 1) \
                    or reason >= len(FAILURES):
                raise ValueError("evidence-status-format")
            progress.append(ItemStatus(seq, bool(queued), bool(ack), reason))
        status = ProducerStatus(
            bool(installed), bool(closed), failure, count, dropped, attempts,
            tuple(progress),
        )
    elif len(body) != end:
        raise ValueError("evidence-body-trailing")
    return Fact(
        operation, phase, registry, sequence, request, identity, slot,
        bool(disabled), None if effective == 2 else bool(effective),
        base, allocated, status,
    )


class ConstructionAdapter:
    def __init__(self, dd, domain, phase):
        dd.require(callable(phase), "evidence-phase-callback")
        self.dd = dd
        self.domain = domain
        self.phase = phase
        self.peer = None
        self.owner_start = None
        self.contexts = {}
        self.transactions = []
        self.receipts = {}
        self.pending = None
        self.registering = None
        self.finished = False
        self.protocol_errors = []
        self.producer_failures = []
        self.previous_line = None
        self.previous_close = None
        self.attached = False

    def attach(self, reactor):
        self.dd.require(
            not self.attached
            and reactor.domain is self.domain
            and reactor.deadline == self.domain.deadline
            and self.domain.allocation_ready is None,
            "evidence-attach",
        )
        self.previous_line = reactor.on_line
        self.previous_close = reactor.on_close
        reactor.on_line = self.on_line
        reactor.on_close = self.on_close
        self.domain.verify_allocation = self.verify_allocation
        self.domain.allocation_ready = self.allocation_ready
        self.attached = True

    def _require(self, value, reason):
        if not value:
            raise self.dd.Denied(reason)

    def _fail(self, reason):
        if reason not in self.protocol_errors:
            self.protocol_errors.append(reason)
        self._domain_failure()

    def _domain_failure(self):
        if "construction-evidence-failed" not in self.domain.errors:
            self.domain.errors.append("construction-evidence-failed")
        self.domain.touch()

    def _authenticate(self, peer):
        self._require(
            self.domain.owner is not None and not self.domain.ended,
            "evidence-owner-lifecycle",
        )
        self.domain.owner.check()
        self.dd.socket_owned(peer.sock, self.domain.owner.pid)
        if self.peer is None:
            self.peer = peer
            self.owner_start = self.domain.owner.start
            peer.exclusive_line = self.on_line
        self._require(
            peer is self.peer and not peer.closed
            and self.owner_start == self.domain.owner.start,
            "evidence-owner-stream",
        )

    def _budget(self):
        self.dd.remaining(self.domain.deadline)

    def _reply(self, peer, text, written, close=False):
        self._budget()
        transaction = self.pending
        owner = self.domain.owner
        owner_start = self.owner_start
        connection = peer.sock

        def completed():
            try:
                self._budget()
                self._require(
                    peer is self.peer and not peer.closed
                    and peer.sock is connection
                    and self.pending is transaction
                    and self.domain.owner is owner
                    and owner is not None
                    and owner.start == owner_start == self.owner_start
                    and not self.protocol_errors
                    and not self.finished,
                    "evidence-response-context",
                )
                written()
            except self.dd.Denied as failure:
                self._fail(str(failure))
                raise
            except (OSError, ValueError, UnicodeError):
                self._fail("evidence-response-completion")
                raise self.dd.Denied("evidence-response-completion") from None

        peer.reply(text.encode("ascii"), close=close, _written=completed)

    def on_line(self, peer, line):
        if not line.startswith(b"CE "):
            if peer is self.peer:
                self._fail("evidence-unexpected-stream-frame")
                raise self.dd.Denied("evidence-unexpected-stream-frame")
            self._require(self.previous_line is not None, "evidence-unknown-frame")
            return self.previous_line(peer, line)
        try:
            self._budget()
            self._require(
                not self.protocol_errors and not self.finished,
                "evidence-stream-unavailable",
            )
            self._require(
                type(line) is bytes and len(line) <= 128
                and line.endswith(b"\n") and line.count(b"\n") == 1
                and not peer.buffer,
                "evidence-line-format",
            )
            self._authenticate(peer)
            self._line(peer, line)
        except self.dd.Denied as failure:
            self._fail(str(failure))
            raise
        except (OSError, ValueError, UnicodeError, struct.error):
            self._fail("evidence-invalid")
            raise self.dd.Denied("evidence-invalid") from None

    def _line(self, peer, line):
        match = re.fullmatch(
            rb"CE START ([1-9][0-9]{0,3}) ([1-9][0-9]{0,3})\n", line)
        if match is not None:
            number, size = map(int, match.groups())
            self._require(
                self.pending is None
                and number == len(self.transactions) + 1
                and number <= MAX_TRANSACTIONS
                and HEADER.size <= size <= MAX_BODY,
                "evidence-start",
            )
            item = Transaction(number, size)
            self.transactions.append(item)
            self.pending = item
            self._reply(peer, f"CE READY {number}\n", lambda: None)
            return

        item = self.pending
        self._require(item is not None, "evidence-no-transaction")

        match = re.fullmatch(
            rb"CE DATA ([1-9][0-9]{0,3}) ([0-9]{1,4}) ([0-9a-f]{2,96})\n",
            line,
        )
        if match is not None:
            number, offset = map(int, match.groups()[:2])
            raw = match.group(3)
            self._require(
                not item.accepted and number == item.number
                and offset == len(item.body) and len(raw) % 2 == 0,
                "evidence-fragment-order",
            )
            data = bytes.fromhex(raw.decode("ascii"))
            self._require(
                0 < len(data) <= MAX_CHUNK
                and len(item.body) + len(data) <= item.size,
                "evidence-fragment-bound",
            )
            item.body.extend(data)
            self._reply(
                peer, f"CE NEXT {number} {len(item.body)}\n", lambda: None)
            return

        match = re.fullmatch(rb"CE COMMIT ([1-9][0-9]{0,3})\n", line)
        if match is not None:
            number = int(match.group(1))
            self._require(
                number == item.number and not item.accepted
                and len(item.body) == item.size,
                "evidence-commit",
            )
            item.fact = decode(item.body)
            item.receipt = self._accept(item.fact, number)
            item.accepted = True

            def accepted_written():
                item.accept_written = True

            self._reply(peer, f"CE ACCEPT {number}\n", accepted_written)
            return

        match = re.fullmatch(rb"CE CONFIRM ([1-9][0-9]{0,3})\n", line)
        self._require(match is not None, "evidence-command")
        number = int(match.group(1))
        self._require(
            number == item.number and item.accepted
            and item.accept_written and not item.remote_confirmed
            and not item.response_queued,
            "evidence-confirm",
        )
        item.remote_confirmed = True
        item.response_queued = True
        terminal = item.fact.operation == FINISH

        def confirmed_written():
            item.response_written = True
            if item.receipt is not None:
                item.receipt.ready = True
            self.pending = None
            if terminal:
                self.finished = True

        self._reply(
            peer, f"CE CONFIRMED {number}\n", confirmed_written,
            close=terminal,
        )

    def _empty(self, fact):
        return (
            fact.sequence == 0 and fact.request == 0 and fact.identity == 0
            and fact.slot == 0 and not fact.disabled
            and fact.effective is None and not fact.base and not fact.allocated
        )

    def _context(self, fact):
        context = self.contexts.get(fact.registry)
        self._require(context is not None and not context.ended,
                      "evidence-context")
        self._require(
            context.phase == self.domain.phases[fact.phase]
            and self.phase() == context.phase,
            "evidence-context-phase",
        )
        return context

    def _accept(self, fact, transaction):
        self._require(fact.phase < len(self.domain.phases), "evidence-phase")
        if fact.operation == OPEN:
            self._require(
                fact.registry > 0 and fact.registry not in self.contexts
                and len(self.contexts) < MAX_REGISTRIES
                and self._empty(fact) and fact.status is None
                and self.phase() == self.domain.phases[fact.phase],
                "evidence-context-open",
            )
            self.contexts[fact.registry] = Context(
                fact.registry, self.domain.phases[fact.phase])
            return None
        if fact.operation == FINISH:
            self._require(
                fact.registry == 0 and self._empty(fact)
                and fact.status is None and self.contexts
                and all(context.ended for context in self.contexts.values()),
                "evidence-stream-finish",
            )
            return None

        context = self._context(fact)
        if fact.operation == END:
            self._require(self._empty(fact), "evidence-context-end")
            self._terminal(context, fact.status)
            return None

        self._require(
            fact.operation in EVENTS and fact.status is None
            and len(context.events) < MAX_EVENTS
            and fact.sequence == len(context.events) + 1,
            "evidence-event-order",
        )
        self._require(
            not fact.disabled or fact.effective is not False
            or fact.operation == FAILED,
            "evidence-disabled-contradiction",
        )
        if fact.operation in OUTCOMES:
            self._require(fact.request not in context.outcomes,
                          "evidence-request-replay")
            self._require(
                fact.slot == 0 and not fact.base and not fact.allocated,
                "evidence-selection-shape",
            )
            if fact.operation == RESERVED:
                self._require(
                    fact.identity > 0 and fact.effective is not None,
                    "evidence-reservation",
                )
            else:
                self._require(
                    fact.identity == 0
                    and ((fact.operation == GLOBAL and fact.effective is not None)
                         or (fact.operation == FAILED and fact.effective is None)),
                    "evidence-selection-outcome",
                )
            context.outcomes[fact.request] = fact
            receipt = None
        else:
            receipt = self._assignment(context, fact, transaction)
        context.events.append(fact)
        return receipt

    def _assignment(self, context, fact, transaction):
        reserved = context.outcomes.get(fact.request)
        self._require(
            reserved is not None and reserved.operation == RESERVED
            and reserved.identity == fact.identity
            and reserved.disabled == fact.disabled
            and reserved.effective == fact.effective
            and fact.identity not in context.assignments
            and 1 <= fact.slot <= 15 and fact.effective is not None
            and fact.base and fact.allocated,
            "evidence-assignment-correlation",
        )
        base = self.dd.canonical(Path(os.fsdecode(fact.base)))
        allocated = self.dd.canonical(Path(os.fsdecode(fact.allocated)))
        self._require(
            os.fsencode(base) == fact.base
            and os.fsencode(allocated) == fact.allocated
            and allocated == base / "owners-v1" / str(fact.slot)
            and allocated.stat().st_uid == os.geteuid(),
            "evidence-assignment-path",
        )
        if context.base is None:
            self._require(
                not any(old is not context and old.base == base
                        for old in self.contexts.values()),
                "evidence-context-root-conflict",
            )
            context.base = base
        self._require(context.base == base, "evidence-context-root")
        self._require(
            not any(
                old.allocated == fact.allocated
                for candidate in self.contexts.values()
                for old in candidate.assignments.values()
            ),
            "evidence-allocation-conflict",
        )
        context.assignments[fact.identity] = fact
        if not fact.disabled:
            return None
        self._require(fact.effective is True, "evidence-disabled-required")
        allocation = self.dd.Allocation(
            self.domain.owner.pid, fact.request, fact.identity,
            reserved.sequence, fact.sequence, fact.slot, allocated,
            context.phase, True, registry=context.registry,
        )
        receipt = Receipt(allocation, context, fact, transaction)
        self.receipts[receipt] = receipt
        self.registering = receipt
        try:
            self._require(
                self.domain.register_allocation(receipt) is allocation,
                "evidence-registration-result",
            )
        finally:
            self.registering = None
        return receipt

    def _terminal(self, context, status):
        self._require(status is not None, "evidence-status-missing")
        progress = status.progress
        self._require(
            status.installed
            and len(context.events) <= len(progress) <= status.journal_count
            and all(item.sequence == index
                    for index, item in enumerate(progress, start=1)),
            "evidence-status-correlation",
        )
        for item in progress:
            self._require(
                not item.acknowledged or (item.queued and item.failure == 0),
                "evidence-status-progress",
            )
            if item.sequence <= len(context.events):
                self._require(item.queued, "evidence-status-delivery")
        successful = (
            status.closed and status.failure == 0 and status.dropped == 0
            and status.journal_count == len(context.events) == len(progress)
            and status.creation_attempts == len(context.assignments)
            and all(item.queued and item.acknowledged and item.failure == 0
                    for item in progress)
        )
        self._require(
            successful or status.failure != 0,
            "evidence-status-unreported-failure",
        )
        context.status = status
        context.successful = successful
        context.ended = True
        if not successful:
            self.producer_failures.append(context.registry)
            self._domain_failure()

    def verify_allocation(self, owner, start, binary, evidence):
        self._budget()
        self._require(
            not self.protocol_errors and not self.producer_failures
            and type(evidence) is Receipt
            and evidence in self.receipts
            and self.receipts[evidence] is evidence
            and (self.registering is evidence or evidence.ready)
            and self.peer is not None and not self.peer.closed,
            "evidence-verifier-receipt",
        )
        self.domain.owner.check()
        self.dd.socket_owned(self.peer.sock, self.domain.owner.pid)
        self._require(
            owner == self.domain.owner.pid
            and start == self.domain.owner.start == self.owner_start
            and binary == self.domain.binary
            and evidence.context is self.contexts[evidence.context.registry]
            and evidence.context.assignments[evidence.fact.identity]
                is evidence.fact,
            "evidence-verifier-origin",
        )
        return evidence.allocation

    def allocation_ready(self, allocation):
        try:
            self._budget()
            self._require(
                not self.protocol_errors and not self.producer_failures
                and not self.finished and self.pending is None,
                "evidence-not-live",
            )
            matches = [receipt for receipt in self.receipts
                       if receipt.allocation is allocation]
            self._require(len(matches) == 1, "evidence-ready-receipt")
            receipt = matches[0]
            self._require(
                receipt.ready and not receipt.context.ended,
                "evidence-not-confirmed",
            )
            return self.verify_allocation(
                self.domain.owner.pid, self.domain.owner.start,
                self.domain.binary, receipt,
            ) is allocation
        except (self.dd.Denied, OSError, ValueError, UnicodeError):
            return False

    def on_close(self, peer):
        if peer is self.peer:
            terminal_written = (
                self.finished and self.pending is None and self.transactions
                and self.transactions[-1].fact is not None
                and self.transactions[-1].fact.operation == FINISH
                and self.transactions[-1].response_written
            )
            if not terminal_written:
                self._fail("evidence-stream-disconnected")
        if self.previous_close is not None:
            self.previous_close(peer)

    def reconcile(self):
        return bool(
            self.finished and self.pending is None
            and not self.protocol_errors and not self.producer_failures
            and self.contexts
            and all(context.ended and context.successful
                    for context in self.contexts.values())
            and all(
                item.accepted and item.accept_written
                and item.remote_confirmed and item.response_written
                for item in self.transactions
            )
            and all(receipt.ready for receipt in self.receipts)
        )

    def failure_snapshot(self):
        return {
            "protocol_errors": tuple(self.protocol_errors),
            "producer_failures": tuple(self.producer_failures),
            "finished": self.finished,
            "pending": None if self.pending is None else self.pending.number,
            "transactions": tuple(
                (item.number, item.accepted, item.accept_written,
                 item.remote_confirmed, item.response_queued,
                 item.response_written)
                for item in self.transactions
            ),
            "contexts": tuple(
                (number, context.phase, tuple(context.events),
                 context.status, context.ended, context.successful)
                for number, context in sorted(self.contexts.items())
            ),
        }
