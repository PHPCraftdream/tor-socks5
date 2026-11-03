def build():
    class Controls(Base):
        def test_descriptor_good_and_owned_identity(self):
            node = self.node()
            body = self.body(node)
            descriptor(body, node, "exit", 23456)
            changed = SimpleNamespace(
                name=node.name, address=node.address,
                or_port=node.or_port, dir_port=node.dir_port,
                relay=SimpleNamespace(fingerprint="F" * 40),
            )
            with self.assertRaisesRegex(
                ProducerError, "^producer-descriptor-identity$"
            ):
                descriptor(body, changed, "exit", 23456)

        def test_descriptor_router_endpoint_binding(self):
            for index, address in enumerate((
                "127.0.0.2", "127.0.0.3", "127.0.0.4"
            )):
                with self.node(index) as node:
                    self.assertEqual(node.address, address)
                    body = self.body(node)
                    descriptor(body, node, "exit", 23456)
                    for replacement in (
                        b"127.0.0.1",
                        ("127.0.0.%d" % (2 + (index + 1) % 3)).encode(
                            "ascii"
                        ),
                    ):
                        changed = body.replace(
                            node.address.encode("ascii"), replacement, 1
                        )
                        self.assertNotEqual(changed, body)
                        with self.assertRaisesRegex(
                            ProducerError, "^producer-descriptor-router$"
                        ):
                            descriptor(changed, node, "exit", 23456)
                    changed = body.replace(
                        str(node.or_port).encode("ascii"), b"29999", 1
                    )
                    self.assertNotEqual(changed, body)
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-descriptor-router$"
                    ):
                        descriptor(changed, node, "exit", 23456)
                    values = {
                        b"process/pid": b"27",
                        b"fingerprint": node.relay.fingerprint.encode("ascii"),
                        b"net/listeners/or": (
                            '"%s:%d"' % (address, node.or_port)
                        ).encode("ascii"),
                        b"net/listeners/dir": (
                            '"%s:%d"' % (address, node.dir_port)
                        ).encode("ascii"),
                    }
                    with mock.patch.object(
                        node, "process", SimpleNamespace(pid=27)
                    ):
                        with mock.patch.object(
                            node, "_info", side_effect=values.__getitem__
                        ):
                            self.assertEqual(
                                node._identity_and_listeners(),
                                (address, node.dir_port),
                            )
                            for key, label in (
                                (b"process/pid", "owned-process"),
                                (b"fingerprint", "relay-identity"),
                                (b"net/listeners/or", "owned-listener"),
                                (b"net/listeners/dir", "owned-listener"),
                            ):
                                original = values[key]
                                values[key] = (
                                    b"28" if key == b"process/pid"
                                    else b"F" * 40 if key == b"fingerprint"
                                    else original.replace(
                                        address.encode("ascii"),
                                        b"127.0.0.1", 1,
                                    )
                                )
                                try:
                                    with self.assertRaisesRegex(
                                        c.a.StartupError, "^" + label + "$"
                                    ):
                                        node._identity_and_listeners()
                                finally:
                                    values[key] = original

        def test_port_only_policy_rejects_host_only_and_extra_ports(self):
            node = self.node()
            body = self.body(node)
            for changed in (
                body.replace(
                    b"accept *:23456", b"accept 127.0.0.1:23456"
                ),
                body.replace(
                    b"accept *:23456", b"accept *:23456-23457"
                ),
                body.replace(b"reject *:*", b"accept *:*"),
                body.replace(b"accept *:23456\n", b""),
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-port-only-policy$"
                ):
                    descriptor(changed, node, "exit", 23456)

        def test_nonexit_rejects_exit_permission(self):
            node = self.node()
            descriptor(
                self.body(node, "middle"), node, "middle", 23456
            )
            with self.assertRaisesRegex(
                ProducerError, "^producer-port-only-policy$"
            ):
                descriptor(self.body(node), node, "middle", 23456)

        def test_family_and_ipv6_are_rejected(self):
            node = self.node()
            body = self.body(node)
            for extra, label in (
                (b"family $AAAA\n", "producer-descriptor-family"),
                (
                    b"ipv6-policy accept 23456\n",
                    "producer-ipv6-policy",
                ),
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^" + label + "$"
                ):
                    descriptor(body + extra, node, "exit", 23456)

        def test_microdescriptor_good_and_digest_mutation(self):
            body = self.md()
            digest = hashlib.sha256(body).digest()
            ed = encoded(bytes([7]) * 32)
            ntor = encoded(bytes([8]) * 32)
            microdescriptor(body, digest, ed, ntor, "exit", 23456)
            with self.assertRaisesRegex(
                ProducerError, "^producer-microdescriptor-digest$"
            ):
                microdescriptor(
                    body + b"\n", digest, ed, ntor, "exit", 23456
                )

        def test_microdescriptor_key_binding(self):
            body = self.md()
            digest = hashlib.sha256(body).digest()
            ed = encoded(bytes([7]) * 32)
            ntor = encoded(bytes([8]) * 32)
            for expected_ed, expected_ntor in (
                (ntor, ntor), (ed, ed),
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-microdescriptor-keys$"
                ):
                    microdescriptor(
                        body, digest, expected_ed, expected_ntor,
                        "exit", 23456,
                    )

        def test_forced_exit_reject_all_is_not_usable(self):
            body = self.md("middle")
            with self.assertRaisesRegex(
                ProducerError, "^producer-microdescriptor-policy$"
            ):
                microdescriptor(
                    body, hashlib.sha256(body).digest(),
                    encoded(bytes([7]) * 32),
                    encoded(bytes([8]) * 32), "exit", 23456,
                )

        def test_role_and_bandwidth_mutants(self):
            node = self.node()
            good = {
                "name": b"localA",
                "address": node.address.encode("ascii"),
                "or": b"21001", "dir": b"21002",
                "flags": {b"Running", b"Valid", b"Fast", b"Guard"},
                "bandwidth": 1,
                "protocols": b"Link=1-5 Relay=1-4",
                "md": bytes([1]) * 32,
            }
            check_row(good, node, "guard", True)
            for address in (b"127.0.0.1", b"127.0.0.3"):
                changed = dict(good, address=address)
                for micro in (False, True):
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-router-binding$"
                    ):
                        check_row(changed, node, "guard", micro)
            for key, value in (
                ("flags", {b"Running", b"Valid", b"Guard"}),
                ("flags", good["flags"] | {b"Exit"}),
                ("flags", good["flags"] | {b"BadExit"}),
                ("bandwidth", 0),
                ("md", None),
            ):
                changed = dict(good)
                changed[key] = value
                with self.assertRaises(ProducerError):
                    check_row(changed, node, "guard", True)

        def test_rows_duplicate_and_flavor_binding(self):
            line = (
                b"r localA " + encoded(bytes(20)) + b" "
                + encoded(bytes([1]) * 20)
                + b" 2026-01-01 00:00:00 127.0.0.1 21001 21002\n"
            )
            self.assertEqual(len(rows(line)), 1)
            with self.assertRaisesRegex(
                ProducerError, "^producer-duplicate-router$"
            ):
                rows(line + line)
            with self.assertRaisesRegex(
                ProducerError, "^producer-router$"
            ):
                rows(line, micro=True)

        def test_target_owned_before_actual_generation_cancel(self):
            isolated = load_copy()
            network = implementation(isolated)(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            process = self.process()
            witness = {}

            def launch(argv, **kwargs):
                owner = network.materials[0]
                witness["root"] = Path(owner._temp.name)
                witness["stream"] = owner._input
                witness["target"] = network.target
                self.assertIn(
                    network.target, network.reservations
                )
                self.assertTrue(witness["root"].is_dir())
                self.assertFalse(witness["stream"].closed)
                self.assertEqual(owner.deadline, network.deadline)
                return process

            def wait(*, timeout):
                self.assertGreaterEqual(timeout, 0)
                if process.returncode is None:
                    isolated.a.m.cancelled = True
                    isolated.a.s.cancelled = True
                    raise subprocess.TimeoutExpired(
                        "mechanism-only", timeout
                    )
                return process.returncode

            process.wait.side_effect = wait
            try:
                with mock.patch.object(
                    isolated.a.m.subprocess, "Popen",
                    side_effect=launch,
                ):
                    with self.assertRaises(isolated.a.m.Cancelled):
                        with network:
                            network.start()
                self.assertTrue(isolated.a.m.cancelled)
                self.assertTrue(isolated.a.s.cancelled)
                self.assertTrue(network.closed)
                self.assertEqual(witness["target"].fileno(), -1)
                self.assertFalse(witness["root"].exists())
                self.assertTrue(witness["stream"].closed)
                self.assertEqual(process.returncode, -15)
            finally:
                if not network.closed:
                    process.returncode = -15
                    network.close()

        def test_target_unreaped_owner_retains_resources(self):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            target = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            network.target = target
            network.reservations.append(target)
            target.bind(("127.0.0.1", 0))
            target.listen(1)
            process = mock.Mock(returncode=None)
            process.poll.return_value = None
            process.wait.side_effect = subprocess.TimeoutExpired(
                "mechanism-only", 0
            )
            owner = SimpleNamespace(
                process=process, close=mock.Mock(),
                _socket=None, _http=None,
            )
            network.nodes.append(owner)
            try:
                with self.assertRaises(c.a.s.CleanupError):
                    network.close()
                self.assertGreaterEqual(target.fileno(), 0)
                owner.close.assert_not_called()
                self.assertFalse(network.closed)
            finally:
                process.returncode = -9
                process.poll.return_value = -9
                process.wait.side_effect = None
                process.wait.return_value = -9
                network.close()
                self.assertEqual(target.fileno(), -1)

        def test_actual_configuration_keeps_generated_bindings(self):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            with tempfile.TemporaryDirectory(
                prefix="producer-config-"
            ) as root_name:
                root = Path(root_name)
                candidates = []
                try:
                    for index in range(3):
                        relay_root = root / ("relay" + str(index))
                        (relay_root / "keys").mkdir(parents=True)
                        (
                            relay_root / "keys" / "secret_id_key"
                        ).write_bytes(b"mechanism-relay")
                        material_root = root / (
                            "material" + str(index)
                        )
                        material_root.mkdir()
                        for name, body in (
                            (
                                "authority_certificate",
                                b"mechanism-certificate\n",
                            ),
                            (
                                "authority_signing_key",
                                b"mechanism-online",
                            ),
                            (
                                "authority_identity_key",
                                b"mechanism-offline",
                            ),
                        ):
                            (material_root / name).write_bytes(body)
                        node = self.node(index)
                        node.deadline = network.deadline
                        node.relay.deadline = network.deadline
                        node.materials.deadline = network.deadline
                        node.relay.data = relay_root
                        node.relay._closed = False
                        node.relay.process = SimpleNamespace(
                            returncode=0
                        )
                        node.materials._closed = False
                        node.materials.process = SimpleNamespace(
                            returncode=0
                        )
                        node.materials._check_file = (
                            lambda name, base=material_root: base / name
                        )
                        node.role = ROLES[index]
                        node.target_port = 23456
                        node.candidates = []
                        network.nodes.append(node)
                        for kind in range(2):
                            candidate = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM
                            )
                            candidates.append(candidate)
                            candidate.bind(("127.0.0.1", 0))
                            node.candidates.append(candidate)
                        node.or_port, node.dir_port = [
                            item.getsockname()[1]
                            for item in node.candidates
                        ]
                    for index, node in enumerate(network.nodes):
                        node.peers = network.nodes
                        data = root / ("online" + str(index))
                        data.mkdir()
                        with mock.patch.object(
                            c.a.m, "certificate_metadata",
                            return_value=node.materials.metadata,
                        ):
                            node._write_config(
                                str(data),
                                str(root / ("control" + str(index))),
                                str(root / ("cookie" + str(index))),
                                str(root / ("torrc" + str(index))),
                            )
                        text = node.config_path.read_text(
                            encoding="utf-8"
                        )
                        expected_address = (
                            "127.0.0.2", "127.0.0.3", "127.0.0.4"
                        )[index]
                        self.assertEqual(node.address, expected_address)
                        for line in (
                            "Address " + expected_address,
                            "ORPort " + expected_address + ":"
                            + str(node.or_port),
                            "DirPort " + expected_address + ":"
                            + str(node.dir_port),
                        ):
                            self.assertEqual(
                                text.splitlines().count(line), 1
                            )
                        expected_authorities = [
                            "DirAuthority " + peer.name
                            + " orport=" + str(peer.or_port)
                            + " v3ident=" + peer.identity
                            + " " + peer.address + ":" + str(peer.dir_port)
                            + " " + peer.relay.fingerprint
                            for peer in network.nodes
                        ]
                        self.assertEqual(
                            [
                                line for line in text.splitlines()
                                if line.startswith("DirAuthority ")
                            ],
                            expected_authorities,
                        )
                        self.assertTrue(all(
                            item.getsockname()[0] == "127.0.0.1"
                            for item in node.candidates
                        ))
                        self.assertNotIn("Address 127.0.0.1\n", text)
                        self.assertNotIn("ORPort 127.0.0.1:", text)
                        self.assertNotIn("DirPort 127.0.0.1:", text)
                        self.assertIn(
                            "TestingDirAuthVoteGuard $"
                            + network.nodes[0].relay.fingerprint
                            + "\n", text,
                        )
                        self.assertIn(
                            "TestingDirAuthVoteExit $"
                            + network.nodes[2].relay.fingerprint
                            + "\n", text,
                        )
                        self.assertEqual(
                            text.count("DirAuthority "), 3
                        )
                        self.assertEqual(
                            "ExitRelay 1\n" in text, index == 2
                        )
                        self.assertEqual(
                            "ExitPolicy accept *4:23456\n" in text,
                            index == 2,
                        )
                        self.assertIn("IPv6Exit 0\n", text)
                        self.assertIn(
                            "ServerDNSDetectHijacking 0\n", text
                        )
                        self.assertEqual(
                            text.count(
                                "CircuitsAvailableTimeout 60 seconds\n"
                            ),
                            1,
                        )
                        for line in (
                            "DisableNetwork 0\n",
                            "PublishServerDescriptor 1\n",
                            "SocksPort 0\n",
                            "DirCache 1\n",
                        ):
                            self.assertEqual(text.count(line), 1)
                        self.assertNotIn(
                            "__DisablePredictedCircuits", text
                        )
                        self.assertEqual(
                            (
                                data / "producer-resolv.conf"
                            ).read_bytes(),
                            b"nameserver 127.0.0.1\n",
                        )
                        self.assertFalse(
                            (
                                data / "keys"
                                / "authority_identity_key"
                            ).exists()
                        )
                        self.assertEqual(
                            node._config_bytes,
                            node.config_path.read_bytes(),
                        )
                finally:
                    for node in network.nodes:
                        node.close()
                    for candidate in candidates:
                        candidate.close()

        def test_artifact_allowlist_before_exchange(self):
            owner = SimpleNamespace(
                _exchange=mock.Mock(return_value=(200, b"body"))
            )
            for path in (
                b"/arbitrary",
                b"/tor/server/fp/" + b"A" * 39,
                b"/tor/micro/d/" + b"A" * 44,
                b"/tor/status-vote/current/consensus-microdesc/extra",
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-request-path$"
                ):
                    Node.artifact(owner, path)
            owner._exchange.assert_not_called()
            path = b"/tor/server/fp/" + b"A" * 40
            self.assertEqual(
                Node.artifact(owner, path), (200, b"body")
            )
            owner._exchange.assert_called_once_with(path)

        def test_bom_negative_checks_exact_reason(self):
            owner = SimpleNamespace(
                _last_reason=REJECTION,
                _exchange=mock.Mock(return_value=(400, b"")),
            )
            Node.reject_bom(owner, b"router mechanism-only\n")
            self.assertEqual(
                owner._exchange.call_args,
                mock.call(
                    b"/tor/",
                    b"\xef\xbb\xbfrouter mechanism-only\n",
                ),
            )
            for status, reason in (
                (200, REJECTION), (400, b"Bad request"),
            ):
                owner._last_reason = reason
                owner._exchange.return_value = (status, b"")
                with self.assertRaisesRegex(
                    ProducerError,
                    "^producer-specific-admission-negative$",
                ):
                    Node.reject_bom(
                        owner, b"router mechanism-only\n"
                    )

        def test_central_good_proof_and_admission_negative(self):
            with self.fixture() as (network, state):
                self.assertEqual(
                    [node.address for node in network.nodes],
                    ["127.0.0.2", "127.0.0.3", "127.0.0.4"],
                )
                original = network.baseline
                for node in network.nodes:
                    source = next(
                        line for line in original.splitlines()
                        if line.startswith(
                            b"dir-source " + node.name.encode("ascii") + b" "
                        )
                    )
                    for column in (3, 4):
                        for replacement in (
                            b"127.0.0.1",
                            network.nodes[
                                (network.nodes.index(node) + 1) % 3
                            ].address.encode("ascii"),
                        ):
                            fields = source.split(b" ")
                            fields[column] = replacement
                            changed = original.replace(
                                source + b"\n",
                                b" ".join(fields) + b"\n", 1,
                            )
                            self.assertNotEqual(changed, original)
                            with self.assertRaisesRegex(
                                c.ConsensusError, "^consensus-binding$"
                            ):
                                c.consensus_metadata(
                                    changed, network.nodes, 86401
                                )
                self.assertEqual(
                    network.prove(), "owned-three-relay-producer"
                )
                self.assertEqual(len(network.packet), 3)
                self.assertEqual(
                    network.producer_negative(),
                    "bom-descriptor-admission-rejected",
                )
                self.assertEqual(state["posts"], [0, 1, 2])
                self.assertTrue(network.admission_checked)
                for node in network.nodes:
                    self.assertEqual(
                        node._identity_and_listeners.call_count, 2
                    )

    return Controls
