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


