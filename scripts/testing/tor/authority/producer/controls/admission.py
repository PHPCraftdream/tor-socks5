def build():
    class Controls(Base):
        def test_central_descriptor_and_identity_counterfactuals(self):
            for variant in (
                "missing", "disagreement", "selected-digest",
                "owned-descriptor", "owned-ed", "identity",
                "policy", "role", "bandwidth",
            ):
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        node = network.nodes[0]
                        row = rows(network.baseline)[
                            node.relay.fingerprint
                        ]
                        path = (
                            b"/tor/server/d/"
                            + row["digest"].hex().upper().encode("ascii")
                        )
                        label = None
                        if variant == "missing":
                            state["overrides"][(1, path)] = (404, b"")
                            label = "producer-admitted-descriptor"
                        elif variant == "disagreement":
                            state["overrides"][(1, path)] = (
                                200, state["descriptors"][1]
                            )
                            label = "producer-descriptor-disagreement"
                        elif variant == "selected-digest":
                            state["ns_digests"][0] = bytes([99]) * 20
                            state["rebuild"]()
                            label = "producer-descriptor-digest"
                        elif variant == "owned-descriptor":
                            state["overrides"][(
                                0, b"/tor/server/fp/"
                                + node.relay.fingerprint.encode("ascii")
                            )] = (200, state["descriptors"][1])
                            label = "producer-descriptor-router"
                        elif variant == "owned-ed":
                            (
                                node.data / "fingerprint-ed25519"
                            ).write_bytes(b"changed\n")
                            label = "producer-owned-ed25519"
                        elif variant in ("identity", "policy"):
                            body = state["descriptors"][0]
                            if variant == "identity":
                                body = body.replace(
                                    node.relay.fingerprint.encode("ascii"),
                                    b"F" * 40,
                                )
                                label = "producer-descriptor-identity"
                            else:
                                body = body.replace(
                                    b"reject *:*", b"accept *:*"
                                )
                                label = "producer-port-only-policy"
                            state["documents"][path] = body
                        else:
                            old = (
                                b"s Fast Running Valid Guard"
                                if variant == "role"
                                else b"w Bandwidth=100"
                            )
                            new = (
                                b"s Fast Running Valid Exit"
                                if variant == "role"
                                else b"w Bandwidth=0"
                            )
                            network.baseline = (
                                network.baseline.replace(old, new, 1)
                            )
                            state["documents"][
                                b"/tor/status-vote/current/consensus"
                            ] = network.baseline
                            for receiver in network.nodes:
                                (
                                    receiver.data / "cached-consensus"
                                ).write_bytes(network.baseline)
                            md_path = (
                                b"/tor/status-vote/current/"
                                b"consensus-microdesc"
                            )
                            md = state["documents"][md_path].replace(
                                old, new, 1
                            )
                            state["documents"][md_path] = md
                            for receiver in network.nodes:
                                (
                                    receiver.data
                                    / "cached-microdesc-consensus"
                                ).write_bytes(md)
                            label = (
                                "producer-role-binding"
                                if variant == "role"
                                else "producer-zero-bandwidth"
                            )
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.prove()

        def test_central_latest_generation_parser_terminal_framing(self):
            with self.fixture() as (network, state):
                selected = tuple(state["descriptors"])
                selected_md = tuple(state["microdescriptors"])
                expected = []
                for index, node in enumerate(network.nodes):
                    latest_path = (
                        b"/tor/server/fp/"
                        + node.relay.fingerprint.encode("ascii")
                    )
                    canonical = selected[index].replace(
                        b"\nrouter-signature\n",
                        b"\nuptime 2\nrouter-signature\n",
                        1,
                    )
                    generated = canonical + b"\n"
                    self.assertNotEqual(generated, canonical)
                    digest = descriptor(
                        canonical, node, ROLES[index], network.target_port
                    )[0]
                    self.assertEqual(
                        descriptor(
                            generated, node, ROLES[index],
                            network.target_port,
                        )[0],
                        digest,
                    )
                    digest_path = (
                        b"/tor/server/d/"
                        + digest.hex().upper().encode("ascii")
                    )
                    self.assertNotIn(digest_path, state["documents"])
                    state["documents"][latest_path] = generated
                    expected.append((digest_path, canonical))

                self.assertEqual(
                    network.prove(), "owned-three-relay-producer"
                )
                self.assertEqual(state["generation_posts"], [0, 1, 2])
                self.assertEqual(
                    state["generation_submissions"],
                    [
                        (
                            index,
                            node.relay.fingerprint,
                            expected[index][1],
                            200,
                        )
                        for index, node in enumerate(network.nodes)
                    ],
                )
                for index, entry in enumerate(network.packet):
                    self.assertEqual(entry[1], selected[index])
                    self.assertEqual(entry[3], selected_md[index])
                    path, canonical = expected[index]
                    self.assertEqual(state["documents"][path], canonical)
                    self.assertNotEqual(canonical, selected[index])

        def test_central_latest_generation_200_without_retention_fails(self):
            with self.fixture() as (network, state):
                state["generation_cache"] = False
                node = network.nodes[0]
                latest_path = (
                    b"/tor/server/fp/"
                    + node.relay.fingerprint.encode("ascii")
                )
                canonical = state["documents"][latest_path].replace(
                    b"\nrouter-signature\n",
                    b"\nuptime 2\nrouter-signature\n",
                    1,
                )
                state["documents"][latest_path] = canonical + b"\n"
                digest = descriptor(
                    canonical, node, ROLES[0], network.target_port
                )[0]
                digest_path = (
                    b"/tor/server/d/"
                    + digest.hex().upper().encode("ascii")
                )
                self.assertNotIn(digest_path, state["documents"])
                with self.assertRaisesRegex(
                    ProducerError, "^producer-owned-admitted$"
                ):
                    network.prove()
                self.assertIsNone(network.packet)
                self.assertEqual(state["generation_posts"], [0])
                self.assertEqual(
                    state["generation_submissions"],
                    [(0, node.relay.fingerprint, canonical, 200)],
                )
                self.assertNotIn(digest_path, state["documents"])

        def test_central_latest_generation_is_not_selected_generation(self):
            with self.fixture() as (network, state):
                selected = tuple(state["descriptors"])
                selected_md = tuple(state["microdescriptors"])
                selected_paths = []
                latest_paths = []
                latest_bodies = []
                for index, node in enumerate(network.nodes):
                    original = selected[index]
                    marker = b"\nrouter-signature\n"
                    signed_end = original.index(marker) + len(marker)
                    expected_selected = hashlib.sha1(
                        original[:signed_end]
                    ).digest()
                    selected_row = rows(network.baseline)[
                        node.relay.fingerprint
                    ]
                    self.assertEqual(
                        selected_row["digest"], expected_selected
                    )
                    selected_paths.append(
                        b"/tor/server/d/"
                        + expected_selected.hex().upper().encode("ascii")
                    )
                    latest = original.replace(
                        b"\nrouter-signature\n",
                        b"\npublished 1970-01-02 00:00:02\n"
                        b"uptime 2\n"
                        b"bandwidth 1000000 2000000 300000\n"
                        b"router-signature\n",
                        1,
                    )
                    if index == 2:
                        old_ntor = encoded(bytes([12]) * 32)
                        rotated_ntor = encoded(bytes([43]) * 32)
                        self.assertEqual(
                            latest.count(b"ntor-onion-key " + old_ntor + b"\n"),
                            1,
                        )
                        latest = latest.replace(
                            b"ntor-onion-key " + old_ntor + b"\n",
                            b"ntor-onion-key " + rotated_ntor + b"\n",
                            1,
                        )
                        self.assertNotEqual(old_ntor, rotated_ntor)
                    latest_signed_end = (
                        latest.index(marker) + len(marker)
                    )
                    expected_latest = hashlib.sha1(
                        latest[:latest_signed_end]
                    ).digest()
                    self.assertNotEqual(latest, original)
                    self.assertNotEqual(
                        expected_latest, expected_selected
                    )
                    latest_path = (
                        b"/tor/server/fp/"
                        + node.relay.fingerprint.encode("ascii")
                    )
                    state["documents"][latest_path] = latest
                    latest_bodies.append(latest)
                    latest_paths.append((
                        b"/tor/server/d/"
                        + expected_latest.hex().upper().encode("ascii"),
                        latest,
                    ))
                self.assertEqual(
                    network.prove(), "owned-three-relay-producer"
                )
                self.assertEqual(
                    state["generation_posts"], [0, 1, 2]
                )
                self.assertEqual(
                    state["generation_submissions"],
                    [
                        (
                            index,
                            node.relay.fingerprint,
                            latest_bodies[index],
                            200,
                        )
                        for index, node in enumerate(network.nodes)
                    ],
                )
                for index, entry in enumerate(network.packet):
                    self.assertEqual(entry[0], selected_paths[index])
                    self.assertEqual(entry[1], selected[index])
                    self.assertEqual(entry[3], selected_md[index])
                    self.assertEqual(
                        state["documents"][entry[0]], selected[index]
                    )
                    latest_path, latest = latest_paths[index]
                    self.assertEqual(
                        state["documents"][latest_path], latest
                    )
                self.assertEqual(
                    network.producer_negative(),
                    "bom-descriptor-admission-rejected",
                )
                self.assertEqual(state["posts"], [0, 1, 2])

        def test_central_latest_generation_rejects_invalid_witnesses(self):
            cases = (
                ("http", "producer-owned-http"),
                ("owner", "producer-descriptor-identity"),
                ("ed", "producer-owned-ed25519"),
                ("ntor", "producer-owned-admission"),
                ("endpoint", "producer-descriptor-router"),
                ("policy", "producer-port-only-policy"),
                ("algorithm", "producer-field"),
                ("admission", "producer-owned-admission"),
                ("cache", "producer-owned-admitted"),
            )
            for variant, label in cases:
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        node = network.nodes[2]
                        path = (
                            b"/tor/server/fp/"
                            + node.relay.fingerprint.encode("ascii")
                        )
                        body = state["documents"][path]
                        mutated = None
                        if variant == "http":
                            state["overrides"][(2, path)] = (404, b"")
                        elif variant == "owner":
                            state["documents"][path] = body.replace(
                                node.relay.fingerprint.encode("ascii"),
                                b"F" * 40,
                            )
                        elif variant == "ed":
                            state["documents"][path] = body.replace(
                                encoded(bytes([11]) * 32),
                                encoded(bytes([41]) * 32),
                            )
                        elif variant == "ntor":
                            original_ntor = encoded(bytes([12]) * 32)
                            rejected_ntor = encoded(bytes([42]) * 32)
                            original_line = (
                                b"ntor-onion-key " + original_ntor + b"\n"
                            )
                            rejected_line = (
                                b"ntor-onion-key " + rejected_ntor + b"\n"
                            )
                            self.assertEqual(body.count(original_line), 1)
                            mutated = body.replace(
                                original_line, rejected_line, 1
                            )
                            self.assertNotEqual(mutated, body)
                            self.assertEqual(
                                mutated.count(rejected_line), 1
                            )
                            state["documents"][path] = mutated
                            state["rejected_generation_ntor"] = rejected_ntor
                        elif variant == "endpoint":
                            state["documents"][path] = body.replace(
                                b"127.0.0.1", b"127.0.0.2", 1
                            )
                        elif variant == "policy":
                            state["documents"][path] = body.replace(
                                b"reject *:*", b"accept *:*"
                            )
                        elif variant == "algorithm":
                            state["documents"][path] = body.replace(
                                b"master-key-ed25519 ",
                                b"master-key-unsupported ",
                            )
                        elif variant == "admission":
                            state["generation_status"] = 400
                        else:
                            state["generation_cache"] = False
                            state["documents"][path] = body.replace(
                                b"\nrouter-signature\n",
                                b"\nuptime 2\nrouter-signature\n",
                                1,
                            )
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.prove()
                        self.assertIsNone(network.packet)
                        if variant == "ntor":
                            self.assertNotIn(
                                "generation_status", state
                            )
                            self.assertEqual(
                                state["generation_posts"], [0, 1, 2]
                            )
                            self.assertEqual(
                                state["generation_submissions"],
                                [
                                    (
                                        0,
                                        network.nodes[0].relay.fingerprint,
                                        state["descriptors"][0],
                                        200,
                                    ),
                                    (
                                        1,
                                        network.nodes[1].relay.fingerprint,
                                        state["descriptors"][1],
                                        200,
                                    ),
                                    (
                                        2,
                                        node.relay.fingerprint,
                                        mutated,
                                        400,
                                    ),
                                ],
                            )
                            selected_path = (
                                b"/tor/server/d/"
                                + rows(network.baseline)[
                                    node.relay.fingerprint
                                ]["digest"].hex().upper().encode("ascii")
                            )
                            self.assertEqual(
                                state["documents"][selected_path],
                                state["descriptors"][2],
                            )

        def test_central_microdescriptor_counterfactuals(self):
            for variant in (
                "selected-digest", "missing", "bytes", "keys",
                "policy", "cache", "flavor", "period",
            ):
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        label = None
                        if variant == "selected-digest":
                            state["md_digests"][2] = bytes([77]) * 32
                            state["rebuild"]()
                            label = "producer-microdescriptor-digest"
                        elif variant in ("keys", "policy"):
                            body = state["microdescriptors"][2]
                            if variant == "keys":
                                body = body.replace(
                                    encoded(bytes([12]) * 32),
                                    encoded(bytes([44]) * 32),
                                )
                                label = "producer-microdescriptor-keys"
                            else:
                                body = re.sub(
                                    rb"(?m)^p accept [0-9]+\n",
                                    b"", body,
                                )
                                label = "producer-microdescriptor-policy"
                            state["microdescriptors"][2] = body
                            state["rebuild"]()
                        elif variant == "cache":
                            (
                                network.nodes[1].data
                                / "cached-microdesc-consensus"
                            ).write_bytes(b"changed\n")
                            label = "producer-md-cache"
                        elif variant == "flavor":
                            state["md_flavor"] = b"ns"
                            state["rebuild"]()
                            label = "producer-md-flavor"
                        elif variant == "period":
                            state["md_period"] = 86401
                            state["rebuild"]()
                            label = "producer-md-period"
                        else:
                            digest = hashlib.sha256(
                                state["microdescriptors"][2]
                            ).digest()
                            path = b"/tor/micro/d/" + encoded(digest)
                            state["overrides"][(1, path)] = (
                                (404, b"") if variant == "missing"
                                else (200, b"changed\n")
                            )
                            label = (
                                "producer-served-microdescriptor"
                                if variant == "missing"
                                else "producer-microdescriptor-digest"
                            )
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.prove()

        def test_central_negative_counterfactuals(self):
            for variant in (
                "status", "reason", "descriptor",
                "microdescriptor", "consensus", "cache",
            ):
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        network.prove()
                        label = "producer-specific-admission-negative"
                        if variant == "status":
                            state["status"] = 200
                        elif variant == "reason":
                            state["reason"] = b"Bad request"
                        else:
                            def change(index):
                                if variant == "descriptor":
                                    state["documents"][
                                        network.packet[0][0]
                                    ] = b"changed\n"
                                elif variant == "microdescriptor":
                                    state["documents"][
                                        network.packet[0][2]
                                    ] = b"changed\n"
                                elif variant == "consensus":
                                    state["documents"][
                                        b"/tor/status-vote/current/consensus"
                                    ] = b"changed\n"
                                else:
                                    (
                                        network.nodes[index].data
                                        / "cached-consensus"
                                    ).write_bytes(b"changed\n")
                            state["after_post"] = change
                            label = {
                                "descriptor":
                                    "producer-negative-descriptor-changed",
                                "microdescriptor":
                                    "producer-negative-md-changed",
                                "consensus":
                                    "producer-negative-consensus-changed",
                                "cache":
                                    "producer-negative-consensus-changed",
                            }[variant]
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.producer_negative()
                        self.assertFalse(network.admission_checked)

        def test_post_wire_partial_io_and_private_reason(self):
            with self.node() as node:
                wire = Wire(
                    b"HTTP/1.0 400 " + REJECTION
                    + b"\r\nContent-Length: 0\r\n\r\n"
                )
                body = b"router mechanism-only\n"
                payload = b"\xef\xbb\xbf" + body
                with mock.patch.object(
                    node, "_identity_and_listeners",
                    return_value=("127.0.0.1", node.dir_port),
                ):
                    with mock.patch.object(
                        c.socket, "socket", return_value=wire
                    ):
                        node.reject_bom(body)
                self.assertEqual(
                    bytes(wire.sent),
                    b"POST /tor/ HTTP/1.0\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Accept-Encoding: identity\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: "
                    + str(len(payload)).encode("ascii")
                    + b"\r\n\r\n" + payload,
                )
                self.assertEqual(node._last_reason, REJECTION)
                self.assertTrue(wire.closed)

        def test_get_wire_allowlist_and_request_bounds(self):
            with self.node() as node:
                wire = Wire(b"HTTP/1.0 200 OK\r\n\r\nbody")
                path = b"/tor/status-vote/current/consensus"
                with mock.patch.object(
                    node, "_identity_and_listeners",
                    return_value=("127.0.0.1", node.dir_port),
                ):
                    with mock.patch.object(
                        c.socket, "socket", return_value=wire
                    ):
                        self.assertEqual(
                            node.request(path), (200, b"body")
                        )
                self.assertEqual(
                    bytes(wire.sent),
                    b"GET " + path + b" HTTP/1.0\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Accept-Encoding: identity\r\n"
                    b"Connection: close\r\n\r\n",
                )
                self.assertTrue(wire.closed)
                with mock.patch.object(c.socket, "socket") as create:
                    with self.assertRaises(c.ConsensusError):
                        node.request(b"/arbitrary")
                    with self.assertRaises(c.ConsensusError):
                        node._exchange(b"/tor/", b"x" * (LIMIT + 1))
                    with self.assertRaises(ProducerError):
                        node.reject_bom(
                            b"router " + b"x" * (LIMIT - 9)
                        )
                    create.assert_not_called()

        def test_actual_post_cancellation_unwinds_owned_resources(self):
            isolated = load_copy()
            cls = implementation(isolated)
            network = cls(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            node = self.node(
                module=isolated, node_class=cls.node_type
            )
            node.deadline = network.deadline
            network.nodes.append(node)
            network.active.append(node)
            node._temp = tempfile.TemporaryDirectory(
                prefix="producer-post-cancel-"
            )
            root = Path(node._temp.name)
            node.data = root
            node._log = tempfile.TemporaryFile()
            log = node._log
            control, peer = socket.socketpair()
            node._socket = control
            process = self.process()
            node.process = process
            events = []

            def retained():
                self.assertTrue(root.is_dir())
                self.assertFalse(log.closed)

            def receive(count):
                retained()
                events.append("cancel")
                isolated.a.s.cancelled = True
                raise socket.timeout()

            wire = Wire(b"", receive=receive)

            def terminate():
                retained()
                self.assertEqual(control.fileno(), -1)
                self.assertTrue(wire.closed)
                events.append("term")
                process.returncode = -15

            def wait(*, timeout):
                self.assertGreaterEqual(timeout, 0)
                if node._closed:
                    self.assertFalse(root.exists())
                    self.assertTrue(log.closed)
                else:
                    retained()
                if events[-1] == "term":
                    events.append("reap")
                return process.returncode

            process.terminate.side_effect = terminate
            process.wait.side_effect = wait
            try:
                with mock.patch.object(
                    node, "_identity_and_listeners",
                    return_value=("127.0.0.1", node.dir_port),
                ):
                    with mock.patch.object(
                        isolated.socket, "socket", return_value=wire
                    ):
                        with self.assertRaises(isolated.a.s.Cancelled):
                            with network:
                                node.reject_bom(
                                    b"router mechanism-only\n"
                                )
                self.assertEqual(
                    events, ["cancel", "term", "reap"]
                )
                self.assertTrue(isolated.a.s.cancelled)
                self.assertFalse(root.exists())
                self.assertTrue(log.closed)
                self.assertEqual(control.fileno(), -1)
                self.assertTrue(wire.closed)
            finally:
                peer.close()
                if not network.closed:
                    process.returncode = -15
                    network.close()

    return Controls
