def build():
    class Wire:
        def __init__(self, response, receive=None):
            self.response = bytearray(response)
            self.sent = bytearray()
            self.closed = False
            self.endpoint = None
            self.receive = receive

        def settimeout(self, value):
            require(0 < value <= 0.05, "mechanism-socket-budget")

        def connect(self, endpoint):
            self.endpoint = endpoint

        def getpeername(self):
            return self.endpoint

        def send(self, payload):
            count = min(3, len(payload))
            self.sent.extend(payload[:count])
            return count

        def recv(self, count):
            if self.receive is not None:
                return self.receive(count)
            result = bytes(self.response[:min(count, 2)])
            del self.response[:len(result)]
            return result

        def close(self):
            self.closed = True

        def fileno(self):
            return -1 if self.closed else 1
    class Fixture(unittest.TestCase):
        def node(self, index=0, module=c, node_class=Node):
            deadline = time.monotonic() + 60
            relay = SimpleNamespace(
                deadline=deadline,
                fingerprint="%040X" % (index + 1),
            )
            material = SimpleNamespace(
                deadline=deadline,
                metadata={
                    "v3_identity_fingerprint": "%040X" % (index + 101)
                },
            )
            node = node_class(
                "/fixture/tor", deadline, relay, material, index
            )
            node.or_port = 21001 + index * 2
            node.dir_port = 21002 + index * 2
            return node

        def body(self, node, role="exit", port=23456, key=7):
            ed = encoded(bytes([key]) * 32)
            ntor = encoded(bytes([key + 1]) * 32)
            policy = (
                b"accept *:" + str(port).encode("ascii")
                + b"\nreject *:*\n"
                if role == "exit" else b"reject *:*\n"
            )
            return (
                b"router " + node.name.encode("ascii")
                + b" " + node.address.encode("ascii") + b" "
                + str(node.or_port).encode("ascii") + b" 0 "
                + str(node.dir_port).encode("ascii") + b"\n"
                b"fingerprint "
                + node.relay.fingerprint.encode("ascii") + b"\n"
                b"master-key-ed25519 " + ed + b"\n"
                b"ntor-onion-key " + ntor + b"\n"
                + policy
                + b"router-signature\n-----BEGIN SIGNATURE-----\n"
                b"bWVjaGFuaXNtLW9ubHk=\n-----END SIGNATURE-----\n"
            )

        def md(self, role="exit", port=23456, key=7):
            return (
                b"onion-key\nntor-onion-key "
                + encoded(bytes([key + 1]) * 32) + b"\n"
                b"id ed25519 " + encoded(bytes([key]) * 32) + b"\n"
                + (
                    b"p accept " + str(port).encode("ascii") + b"\n"
                    if role == "exit" else b""
                )
            )

        def process(self):
            process = mock.Mock(returncode=None)
            process.poll.side_effect = lambda: process.returncode
            process.terminate.side_effect = lambda: setattr(
                process, "returncode", -15
            )
            process.wait.side_effect = lambda **kwargs: process.returncode
            return process

        @contextmanager
        def fixture(self, operation_seconds=60):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + operation_seconds,
            )
            state = {
                "documents": {}, "overrides": {},
                "status": 400, "reason": REJECTION,
                "posts": [], "after_post": None,
                "ns_digests": {}, "md_digests": {},
                "md_flavor": b"microdesc",
                "md_period": 86400,
            }
            try:
                network.target = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                network.reservations.append(network.target)
                network.target.bind(("127.0.0.1", 0))
                network.target.listen(1)
                network.target_port = network.target.getsockname()[1]
                for index in range(3):
                    node = self.node(index)
                    node.deadline = network.deadline
                    node.relay.deadline = network.deadline
                    node.materials.deadline = network.deadline
                    network.nodes.append(node)
                    node._temp = tempfile.TemporaryDirectory(
                        prefix="producer-central-"
                    )
                    node.data = Path(node._temp.name)
                    node._log = tempfile.TemporaryFile()
                    node.process = self.process()
                    node.config_path = node.data / "torrc"
                    node._config_bytes = b"mechanism-only-config\n"
                    node.config_path.write_bytes(node._config_bytes)
                    node._identity_and_listeners = mock.Mock(
                        return_value=(node.address, node.dir_port)
                    )
                    network.active.append(node)
                state["descriptors"] = [
                    self.body(
                        node, ROLES[index], network.target_port,
                        key=7 + index * 2,
                    )
                    for index, node in enumerate(network.nodes)
                ]
                state["microdescriptors"] = [
                    self.md(
                        ROLES[index], network.target_port,
                        key=7 + index * 2,
                    )
                    for index in range(3)
                ]

                def date(value):
                    return datetime.fromtimestamp(
                        value, timezone.utc
                    ).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ).encode("ascii")

                def document(micro):
                    period = state["md_period"] if micro else 86400
                    flavor = (
                        b" " + state["md_flavor"] if micro else b""
                    )
                    body = (
                        b"network-status-version 3" + flavor + b"\n"
                        b"vote-status consensus\nvalid-after "
                        + date(period) + b"\nfresh-until "
                        + date(period + c.INTERVAL) + b"\nvalid-until "
                        + date(period + c.INTERVAL * c.VALID_INTERVALS) + b"\nvoting-delay 20 20\n"
                    )
                    for index, node in enumerate(network.nodes):
                        body += (
                            b"dir-source " + node.name.encode("ascii")
                            + b" " + node.identity.encode("ascii")
                            + b" " + node.address.encode("ascii")
                            + b" " + node.address.encode("ascii") + b" "
                            + str(node.dir_port).encode("ascii")
                            + b" " + str(node.or_port).encode("ascii")
                            + b"\nvote-digest "
                            + ("%040X" % (index + 1)).encode("ascii")
                            + b"\n"
                        )
                    for index, node in enumerate(network.nodes):
                        identity = encoded(bytes.fromhex(
                            node.relay.fingerprint
                        ))
                        digest = state["ns_digests"].get(
                            index,
                            descriptor(
                                state["descriptors"][index], node,
                                ROLES[index], network.target_port,
                            )[0],
                        )
                        md_digest = state["md_digests"].get(
                            index,
                            hashlib.sha256(
                                state["microdescriptors"][index]
                            ).digest(),
                        )
                        body += (
                            b"r " + node.name.encode("ascii")
                            + b" " + identity
                            + (b"" if micro else b" " + encoded(digest))
                            + b" " + date(86400)
                            + b" " + node.address.encode("ascii") + b" "
                            + str(node.or_port).encode("ascii")
                            + b" " + str(node.dir_port).encode("ascii")
                            + b"\n"
                        )
                        if micro:
                            body += b"m " + encoded(md_digest) + b"\n"
                        body += (
                            b"s Fast Running Valid"
                            + (
                                b" Guard" if index == 0
                                else b" Exit" if index == 2 else b""
                            )
                            + b"\npr Link=1-5 Relay=1-4\n"
                            b"w Bandwidth=100\n"
                        )
                    body += b"directory-footer\n"
                    for node in network.nodes[:2]:
                        body += (
                            b"directory-signature "
                            + (b"sha256 " if micro else b"")
                            + node.identity.encode("ascii")
                            + b" " + b"F" * 40 + b"\n"
                            b"-----BEGIN SIGNATURE-----\n"
                            b"bWVjaGFuaXNtLW9ubHk=\n"
                            b"-----END SIGNATURE-----\n"
                        )
                    return body

                def rebuild():
                    network.baseline = document(False)
                    network.metadata = c.consensus_metadata(
                        network.baseline, network.nodes, 86401
                    )
                    md_consensus = document(True)
                    documents = {
                        b"/tor/status-vote/current/consensus":
                            network.baseline,
                        b"/tor/status-vote/current/consensus-microdesc":
                            md_consensus,
                    }
                    for index, node in enumerate(network.nodes):
                        desc = state["descriptors"][index]
                        actual = descriptor(
                            desc, node, ROLES[index],
                            network.target_port,
                        )[0]
                        selected = state["ns_digests"].get(index, actual)
                        documents[
                            b"/tor/server/d/"
                            + selected.hex().upper().encode("ascii")
                        ] = desc
                        documents[
                            b"/tor/server/fp/"
                            + node.relay.fingerprint.encode("ascii")
                        ] = desc
                        md_body = state["microdescriptors"][index]
                        selected_md = state["md_digests"].get(
                            index, hashlib.sha256(md_body).digest()
                        )
                        documents[
                            b"/tor/micro/d/" + encoded(selected_md)
                        ] = md_body
                        (node.data / "cached-consensus").write_bytes(
                            network.baseline
                        )
                        (
                            node.data / "cached-microdesc-consensus"
                        ).write_bytes(md_consensus)
                        ed = field(
                            desc, rb"^master-key-ed25519 (\S+)$"
                        )
                        (
                            node.data / "fingerprint-ed25519"
                        ).write_bytes(
                            node.name.encode("ascii") + b" " + ed + b"\n"
                        )
                    state["documents"] = documents

                state["rebuild"] = rebuild
                rebuild()

                def exchange(node, index, path, payload=None):
                    if payload is not None:
                        self.assertEqual(path, b"/tor/")
                        if payload.startswith(b"\xef\xbb\xbf"):
                            self.assertEqual(
                                payload,
                                b"\xef\xbb\xbf" + network.packet[2][1],
                            )
                            state["posts"].append(index)
                            node._last_reason = state["reason"]
                            if state["after_post"] is not None:
                                state["after_post"](index)
                            return state["status"], b""
                        latest_path = (
                            b"/tor/server/fp/"
                            + node.relay.fingerprint.encode("ascii")
                        )
                        latest = state["documents"][latest_path]
                        trailer = b"\n-----END SIGNATURE-----"
                        prefix, separator, suffix = latest.partition(trailer)
                        self.assertTrue(separator)
                        self.assertTrue(suffix)
                        self.assertEqual(suffix.replace(b"\n", b""), b"")
                        canonical = prefix + separator + b"\n"
                        self.assertIn(payload, (latest, canonical))
                        state.setdefault("generation_posts", []).append(index)
                        status = state.get("generation_status", 200)
                        rejected_ntor = state.get("rejected_generation_ntor")
                        if rejected_ntor is not None:
                            submitted_ntor = re.findall(
                                rb"^ntor-onion-key (\S+)$",
                                payload,
                                re.MULTILINE,
                            )
                            self.assertEqual(len(submitted_ntor), 1)
                            if submitted_ntor[0] == rejected_ntor:
                                status = 400
                        state.setdefault("generation_submissions", []).append((
                            index,
                            node.relay.fingerprint,
                            payload,
                            status,
                        ))
                        node._last_reason = (
                            b"Descriptor accepted" if status == 200
                            else b"Mechanism admission rejected"
                        )
                        if status == 200:
                            marker = b"\nrouter-signature\n"
                            self.assertEqual(payload.count(marker), 1)
                            signed = payload[
                                :payload.index(marker) + len(marker)
                            ]
                            digest = hashlib.sha1(signed).hexdigest().upper()
                            if state.get("generation_cache", True):
                                state["documents"][
                                    b"/tor/server/d/" + digest.encode("ascii")
                                ] = canonical
                        return status, b""
                    override = state["overrides"].get((index, path))
                    if override is not None:
                        return override
                    body = state["documents"].get(path)
                    return (404, b"") if body is None else (200, body)

                for index, node in enumerate(network.nodes):
                    node._exchange = mock.Mock(
                        side_effect=lambda path, payload=None,
                        owner=node, position=index: exchange(
                            owner, position, path, payload
                        )
                    )
                with mock.patch.object(time, "time", return_value=86401):
                    yield network, state
            finally:
                network.close()

    return Wire, Fixture
