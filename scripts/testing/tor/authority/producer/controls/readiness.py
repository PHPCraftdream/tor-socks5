def build():
    class Controls(Base):
        @contextmanager
        def readiness_fixture(self):
            with self.fixture(operation_seconds=600) as (network, state):
                original_ns = network.baseline
                md_path = (
                    b"/tor/status-vote/current/consensus-microdesc"
                )
                original_md = state["documents"][md_path]
                clock = {
                    "wall": 86551.0,
                    "mono": time.monotonic(),
                }
                original_deadline = network.deadline

                def date(value):
                    return datetime.fromtimestamp(
                        value, timezone.utc
                    ).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ).encode("ascii")

                def render(body, period, zero=False, weights=False):
                    values = {
                        b"valid-after": date(period),
                        b"fresh-until": date(period + c.INTERVAL),
                        b"valid-until": date(period + c.INTERVAL * c.VALID_INTERVALS),
                    }
                    result = re.sub(
                        rb"(?m)^(valid-after|fresh-until|valid-until) "
                        rb"[^\n]+$",
                        lambda match: (
                            match[1] + b" " + values[match[1]]
                        ),
                        body,
                    )
                    if zero:
                        result = result.replace(
                            b"w Bandwidth=100", b"w Bandwidth=0"
                        )
                    if weights:
                        result = result.replace(
                            b"directory-footer\n",
                            b"directory-footer\n"
                            + state["readiness_weights"],
                            1,
                        )
                    self.assertEqual(
                        c.stamp(result, b"valid-after"), period
                    )
                    self.assertEqual(
                        c.stamp(result, b"fresh-until"), period + c.INTERVAL
                    )
                    self.assertEqual(
                        c.stamp(result, b"valid-until"), period + c.INTERVAL * c.VALID_INTERVALS
                    )
                    return result

                state["readiness_weights"] = (
                    b"bandwidth-weights "
                    b"Wbd=0 Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 "
                    b"Web=10000 Wed=0 Wee=10000 Weg=0 Wem=10000 "
                    b"Wgb=10000 Wgd=0 Wgg=10000 Wgm=10000 "
                    b"Wmb=10000 Wmd=0 Wme=0 Wmg=0 Wmm=10000\n"
                )

                def publish(
                    period, zero=False, install_baseline=False,
                    weights=False,
                ):
                    ns = render(original_ns, period, zero, weights)
                    md = render(original_md, period, zero, weights)
                    state["documents"][
                        b"/tor/status-vote/current/consensus"
                    ] = ns
                    state["documents"][md_path] = md
                    entries = c.sources(ns)
                    for index, node in enumerate(network.nodes):
                        (
                            node.data / "cached-consensus"
                        ).write_bytes(ns)
                        (
                            node.data / "cached-microdesc-consensus"
                        ).write_bytes(md)
                        node.certificate = (
                            b"mechanism-certificate-"
                            + str(index).encode("ascii") + b"\n"
                        )
                        vote = (
                            b"network-status-version 3\n"
                            b"vote-status vote\n"
                            b"valid-after " + date(period) + b"\n"
                            + node.certificate
                            + b"dir-source "
                            + node.name.encode("ascii")
                            + b" " + node.identity.encode("ascii")
                            + b" 127.0.0.1 127.0.0.1 "
                            + str(node.dir_port).encode("ascii")
                            + b" " + str(node.or_port).encode("ascii")
                            + b"\ndirectory-signature "
                            + node.identity.encode("ascii")
                            + b" " + b"F" * 40 + b"\n"
                            b"-----BEGIN SIGNATURE-----\n"
                            b"bWVjaGFuaXNtLW9ubHk=\n"
                            b"-----END SIGNATURE-----\n"
                        )
                        state["documents"][
                            b"/tor/status-vote/current/d/"
                            + entries[node.identity][1]
                        ] = vote
                        state["overrides"][(
                            index,
                            b"/tor/status-vote/current/authority",
                        )] = (200, vote)
                    if install_baseline:
                        network.baseline = ns
                        network.metadata = c.consensus_metadata(
                            ns, network.nodes, clock["wall"]
                        )
                    return ns, md

                state["readiness_render"] = render
                state["readiness_publish"] = publish
                state["readiness_clock"] = clock
                state["readiness_deadline"] = original_deadline
                with mock.patch.object(
                    time, "time", side_effect=lambda: clock["wall"]
                ):
                    with mock.patch.object(
                        time, "monotonic",
                        side_effect=lambda: clock["mono"],
                    ):
                        publish(
                            86550, zero=True, install_baseline=True
                        )
                        yield network, state
                        self.assertEqual(
                            network.deadline, original_deadline
                        )

        def test_initial_zero_is_complete_inspection_not_success(self):
            with self.readiness_fixture() as (network, state):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-zero-bandwidth$"
                ):
                    network.prove(inspect_initial=True)
                self.assertIsNone(network.packet)
                self.assertEqual(
                    state["generation_posts"], [0, 1, 2]
                )
                (
                    network.nodes[2].data / "fingerprint-ed25519"
                ).write_bytes(b"changed\n")
                with self.assertRaisesRegex(
                    ProducerError, "^producer-owned-ed25519$"
                ):
                    network.prove(inspect_initial=True)
            with self.readiness_fixture() as (network, state):
                path = b"/tor/status-vote/current/consensus"
                body = state["documents"][path].replace(
                    b"w Bandwidth=0\n", b"", 1
                )
                network.baseline = body
                state["documents"][path] = body
                for node in network.nodes:
                    (
                        node.data / "cached-consensus"
                    ).write_bytes(body)
                with mock.patch.object(network, "pause") as pause:
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-missing-bandwidth$"
                    ):
                        network.await_ready()
                    pause.assert_not_called()
                self.assertIsNone(network.packet)

        def test_readiness_delayed_generations_fit_private_grid(self):
            starts = tuple(86400 + phase for phase in range(120))
            starts += (172799, 172800, 172801)
            for start in starts:
                with self.subTest(start=start):
                    with self.readiness_fixture() as (network, state):
                        clock = state["readiness_clock"]
                        original_mono = clock["mono"]
                        deadline = network.deadline
                        first = c.period_after(start, 120, 0)
                        clock["wall"] = first + 1
                        clock["mono"] = original_mono + first + 1 - start
                        state["readiness_publish"](
                            first, zero=True, install_baseline=True
                        )
                        periods = []
                        original_positive = c.Network.positive

                        def advance():
                            network.check()
                            self.assertIsNone(network.packet)
                            self.assertLess(len(periods), 2)
                            period = c.next_round(network.metadata)
                            delta = period + 1 - clock["wall"]
                            self.assertGreater(delta, 0)
                            clock["wall"] += delta
                            clock["mono"] += delta
                            periods.append(period)
                            state["readiness_publish"](
                                period, zero=len(periods) == 1
                            )

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ):
                            with mock.patch.object(
                                c.Network, "positive",
                                autospec=True,
                                side_effect=original_positive,
                            ) as positive:
                                self.assertEqual(
                                    network.await_ready(),
                                    "owned-three-relay-producer",
                                )
                        self.assertEqual(
                            periods, [first + 120, first + 240]
                        )
                        self.assertEqual(positive.call_count, 2)
                        self.assertEqual(network.metadata[0], periods[-1])
                        self.assertIsNotNone(network.packet)
                        boundary = c.next_round(network.metadata)
                        self.assertEqual(boundary, first + 360)
                        self.assertLess(
                            clock["mono"] + boundary - clock["wall"],
                            deadline,
                        )
                        self.assertEqual(network.deadline, deadline)
                        self.assertEqual(
                            network.producer_negative(),
                            "bom-descriptor-admission-rejected",
                        )


        def test_readiness_requires_new_verified_generation(self):
            with self.readiness_fixture() as (network, state):
                clock = state["readiness_clock"]
                events = []
                original_positive = c.Network.positive

                def advance():
                    network.check()
                    self.assertEqual(events, [])
                    clock["wall"] += 90
                    clock["mono"] += 90
                    state["readiness_publish"](86640)
                    events.append("published")

                with mock.patch.object(
                    network, "pause", side_effect=advance
                ):
                    with mock.patch.object(
                        c.Network, "positive",
                        autospec=True,
                        side_effect=original_positive,
                    ) as positive:
                        self.assertEqual(
                            network.await_ready(),
                            "owned-three-relay-producer",
                        )
                positive.assert_called_once_with(network)
                self.assertEqual(events, ["published"])
                self.assertEqual(network.metadata[0], 86640)
                self.assertEqual(
                    c.next_round(network.metadata), 86760
                )
                self.assertIsNotNone(network.packet)
                self.assertEqual(
                    network.deadline,
                    state["readiness_deadline"],
                )
                self.assertLess(
                    clock["mono"] + 86760 - clock["wall"],
                    network.deadline,
                )
                self.assertEqual(
                    network.producer_negative(),
                    "bom-descriptor-admission-rejected",
                )

        def test_readiness_cache_failures_are_not_retried(self):
            cases = (
                ("missing", "producer-readiness-cache-missing"),
                ("same-period", "producer-readiness-same-period"),
                ("regression", "producer-readiness-regression"),
                ("disagreement", "producer-readiness-unexpected-period"),
            )
            for variant, label in cases:
                with self.subTest(category=variant):
                    with self.readiness_fixture() as (network, state):
                        events = []

                        def advance():
                            network.check()
                            self.assertEqual(events, [])
                            events.append("changed")
                            render = state["readiness_render"]
                            for index, node in enumerate(network.nodes):
                                path = node.data / "cached-consensus"
                                body = path.read_bytes()
                                if variant == "missing" and index == 0:
                                    path.unlink()
                                elif variant == "same-period" and index == 0:
                                    path.write_bytes(body + b"\n")
                                elif variant == "regression" and index == 0:
                                    path.write_bytes(render(body, 86400))
                                elif variant == "disagreement":
                                    path.write_bytes(render(
                                        body, 86640 + index * c.INTERVAL
                                    ))

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ):
                            with self.assertRaisesRegex(
                                ProducerError, "^" + label + "$"
                            ):
                                network.await_ready()
                        self.assertEqual(events, ["changed"])
                        self.assertIsNone(network.packet)

        def test_staggered_future_cache_is_validated_before_waiting(self):
            variants = (
                "validity", "voter", "signature", "router",
                "weight-value", "weight-range", "weight-duplicate",
                "weight-missing", "weight-order", "weight-unknown",
                "weight-line-duplicate", "footer-junk",
            )
            for variant in variants:
                with self.subTest(category=variant):
                    with self.readiness_fixture() as (network, state):
                        old = network.baseline
                        events = []

                        def advance():
                            network.check()
                            self.assertEqual(events, [])
                            events.append("published-one")
                            body = state["readiness_render"](
                                old, 86640, weights=True
                            )
                            weights = state["readiness_weights"]
                            if variant == "validity":
                                body = re.sub(
                                    rb"(?m)^fresh-until [^\n]+$",
                                    b"fresh-until 1970-01-02 00:04:00",
                                    body,
                                )
                            elif variant == "voter":
                                body = body.replace(
                                    network.nodes[1].identity.encode("ascii"),
                                    b"E" * 40,
                                )
                            elif variant == "signature":
                                body = body.replace(
                                    b"-----END SIGNATURE-----",
                                    b"-----END INVALID-----", 1,
                                )
                            elif variant == "router":
                                body = body.replace(
                                    b"pr Link=1-5 Relay=1-4",
                                    b"pr Link=1-5", 1,
                                )
                            elif variant == "weight-value":
                                body = body.replace(
                                    b"Wbd=0", b"Wbd=invalid", 1
                                )
                            elif variant == "weight-range":
                                body = body.replace(
                                    b"Wbd=0", b"Wbd=2147483648", 1
                                )
                            elif variant == "weight-duplicate":
                                body = body.replace(
                                    b"Wbe=0", b"Wbd=0", 1
                                )
                            elif variant == "weight-missing":
                                body = body.replace(b" Wbe=0", b"", 1)
                            elif variant == "weight-order":
                                body = body.replace(
                                    b"Wbd=0 Wbe=0", b"Wbe=0 Wbd=0", 1
                                )
                            elif variant == "weight-unknown":
                                body = body.replace(
                                    b"Wbe=0", b"Wxx=0", 1
                                )
                            elif variant == "weight-line-duplicate":
                                body = body.replace(
                                    weights, weights + weights, 1
                                )
                            else:
                                body = body.replace(
                                    weights, weights + b"unknown-footer 1\n",
                                    1,
                                )
                            (
                                network.nodes[0].data
                                / "cached-consensus"
                            ).write_bytes(body)
                            self.assertEqual(
                                state["readiness_clock"]["wall"], 86551
                            )
                            self.assertTrue(all(
                                node.cached() == old
                                for node in network.nodes[1:]
                            ))

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ) as pause:
                            with mock.patch.object(
                                c.Network, "positive"
                            ) as positive:
                                error_type, label = {
                                    "validity": (
                                        c.ConsensusError, "consensus-not-current"
                                    ),
                                    "voter": (
                                        c.ConsensusError, "consensus-voters"
                                    ),
                                    "router": (
                                        ProducerError, "producer-router-protocols"
                                    ),
                                }.get(variant, (
                                    ProducerError, "producer-readiness-framing"
                                ))
                                with self.assertRaisesRegex(
                                    error_type, "^" + label + "$"
                                ):
                                    network.await_ready()
                        self.assertEqual(pause.call_count, 1)
                        positive.assert_not_called()
                        self.assertEqual(events, ["published-one"])
                        self.assertIsNone(network.packet)

        def test_legitimate_staggered_future_generation_progresses(self):
            for weights in (False, True):
                with self.subTest(weights=weights):
                    with self.readiness_fixture() as (network, state):
                        old = network.baseline
                        clock = state["readiness_clock"]
                        events = []
                        original_positive = c.Network.positive

                        def advance():
                            network.check()
                            if not events:
                                (
                                    network.nodes[0].data
                                    / "cached-consensus"
                                ).write_bytes(
                                    state["readiness_render"](
                                        old, 86640, weights=weights
                                    )
                                )
                                events.append("one-future")
                            elif events == ["one-future"]:
                                self.assertEqual(clock["wall"], 86551)
                                self.assertIsNone(network.packet)
                                state["readiness_publish"](
                                    86640, weights=weights
                                )
                                events.append("all-future")
                            elif events == ["one-future", "all-future"]:
                                self.assertIsNone(network.packet)
                                clock["wall"] += 90
                                clock["mono"] += 90
                                events.append("current")
                            else:
                                self.fail("unexpected-readiness-pause")

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ):
                            with mock.patch.object(
                                c.Network, "positive",
                                autospec=True,
                                side_effect=original_positive,
                            ) as positive:
                                self.assertEqual(
                                    network.await_ready(),
                                    "owned-three-relay-producer",
                                )
                        self.assertEqual(
                            events,
                            ["one-future", "all-future", "current"],
                        )
                        positive.assert_called_once_with(network)
                        self.assertEqual(network.metadata[0], 86640)
                        self.assertIsNotNone(network.packet)
                        self.assertEqual(
                            network.deadline,
                            state["readiness_deadline"],
                        )

        def test_readiness_hard_error_and_budget_are_not_retried(self):
            with self.readiness_fixture() as (network, state):
                node = network.nodes[0]
                digest = rows(network.baseline)[
                    node.relay.fingerprint
                ]["digest"]
                path = (
                    b"/tor/server/d/"
                    + digest.hex().upper().encode("ascii")
                )
                state["overrides"][(1, path)] = (404, b"")
                with mock.patch.object(network, "pause") as pause:
                    with self.assertRaisesRegex(
                        ProducerError,
                        "^producer-admitted-descriptor$",
                    ):
                        network.await_ready()
                    pause.assert_not_called()
            with self.fixture() as (network, state):
                with mock.patch.object(network, "pause") as pause:
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-readiness-budget$"
                    ):
                        network.await_ready()
                    pause.assert_not_called()
                self.assertIsNone(network.packet)

        def test_unchanged_zero_exhausts_original_deadline(self):
            isolated = load_copy()
            isolated_case = controls(isolated)(
                "test_initial_zero_is_complete_inspection_not_success"
            )
            with isolated_case.readiness_fixture() as (network, state):
                deadline = network.deadline
                clock = state["readiness_clock"]
                start_mono = clock["mono"]
                start_wall = clock["wall"]
                baseline = network.baseline
                roots = [node.data for node in network.nodes]
                streams = [node._log for node in network.nodes]
                processes = [node.process for node in network.nodes]
                target = network.target
                passes = []
                events = []

                def retained():
                    self.assertTrue(all(root.is_dir() for root in roots))
                    self.assertTrue(all(
                        not stream.closed for stream in streams
                    ))
                    self.assertGreaterEqual(target.fileno(), 0)

                for index, process in enumerate(processes):
                    def terminate(p=process, position=index):
                        retained()
                        events.append(("term", position))
                        p.returncode = -15

                    process.terminate.side_effect = terminate

                def advance():
                    retained()
                    self.assertIsNone(network.packet)
                    self.assertEqual(network.deadline, deadline)
                    self.assertTrue(all(
                        node.cached() == baseline
                        for node in network.nodes
                    ))
                    passes.append(len(passes) + 1)
                    self.assertLessEqual(len(passes), 4)
                    elapsed = (
                        deadline - start_mono
                    ) * len(passes) / 4
                    clock["mono"] = (
                        deadline if len(passes) == 4
                        else start_mono + elapsed
                    )
                    clock["wall"] = start_wall + elapsed
                    network.check()

                with mock.patch.object(
                    network, "pause", side_effect=advance
                ):
                    with mock.patch.object(
                        isolated.Network, "positive"
                    ) as positive:
                        with self.assertRaises(
                            isolated.a.s.DeadlineExceeded
                        ):
                            with network:
                                network.await_ready()
                positive.assert_not_called()
                self.assertEqual(passes, [1, 2, 3, 4])
                self.assertEqual(
                    events, [("term", 0), ("term", 1), ("term", 2)]
                )
                self.assertEqual(network.deadline, deadline)
                self.assertIsNone(network.packet)
                self.assertTrue(network.closed)
                self.assertTrue(all(
                    process.returncode == -15 for process in processes
                ))
                self.assertTrue(all(
                    not root.exists() for root in roots
                ))
                self.assertTrue(all(
                    stream.closed for stream in streams
                ))
                self.assertEqual(target.fileno(), -1)
                self.assertFalse(isolated.a.s.cancelled)

        def test_readiness_wait_cancel_and_deadline_release_owners(self):
            for variant in ("cancel", "deadline"):
                with self.subTest(category=variant):
                    isolated = load_copy()
                    isolated_case = controls(isolated)(
                        "test_initial_zero_is_complete_inspection_not_success"
                    )
                    with isolated_case.readiness_fixture() as (
                        network, state
                    ):
                        clock = state["readiness_clock"]
                        roots = [node.data for node in network.nodes]
                        streams = [node._log for node in network.nodes]
                        processes = [node.process for node in network.nodes]
                        target = network.target
                        events = []

                        def retained():
                            self.assertTrue(all(
                                root.is_dir() for root in roots
                            ))
                            self.assertTrue(all(
                                not stream.closed for stream in streams
                            ))
                            self.assertGreaterEqual(target.fileno(), 0)

                        for index, process in enumerate(processes):
                            def terminate(p=process, position=index):
                                retained()
                                events.append(("term", position))
                                p.returncode = -15

                            process.terminate.side_effect = terminate

                        def interrupt():
                            retained()
                            self.assertIsNone(network.packet)
                            events.append(("interrupt", variant))
                            if variant == "cancel":
                                isolated.a.s.cancelled = True
                            else:
                                clock["mono"] = network.deadline
                            network.check()

                        expected = (
                            isolated.a.s.Cancelled
                            if variant == "cancel"
                            else isolated.a.s.DeadlineExceeded
                        )
                        with mock.patch.object(
                            network, "pause", side_effect=interrupt
                        ):
                            with self.assertRaises(expected):
                                with network:
                                    network.await_ready()
                        self.assertEqual(
                            events,
                            [
                                ("interrupt", variant),
                                ("term", 0), ("term", 1), ("term", 2),
                            ],
                        )
                        self.assertTrue(network.closed)
                        self.assertTrue(all(
                            process.returncode == -15
                            for process in processes
                        ))
                        self.assertTrue(all(
                            not root.exists() for root in roots
                        ))
                        self.assertTrue(all(
                            stream.closed for stream in streams
                        ))
                        self.assertEqual(target.fileno(), -1)
                        if variant == "cancel":
                            self.assertTrue(isolated.a.s.cancelled)

        def test_live_sequence_uses_actual_producer_methods(self):
            with self.fixture(operation_seconds=600) as (network, state):
                events = []
                actual_prove = network.await_ready
                actual_negative = network.producer_negative
                network.start = mock.Mock(
                    side_effect=lambda: events.append("start")
                )

                def positive():
                    events.append("consensus")
                    return "three-authority-consensus"

                def prove():
                    events.append("producer")
                    return actual_prove()

                def admission():
                    events.append("admission")
                    return actual_negative()

                def quorum():
                    self.assertIsNotNone(network.packet)
                    self.assertTrue(network.admission_checked)
                    self.assertEqual(state["posts"], [0, 1, 2])
                    self.assertTrue(all(
                        node.process.returncode is None
                        for node in network.nodes
                    ))
                    events.append("quorum")
                    return "one-of-three-vote-quorum-rejected"

                network.positive = mock.Mock(side_effect=positive)
                network.await_ready = mock.Mock(side_effect=prove)
                network.producer_negative = mock.Mock(
                    side_effect=admission
                )
                network.negative = mock.Mock(side_effect=quorum)
                run_live(network, c)
                self.assertEqual(
                    events,
                    ["start", "consensus", "producer",
                     "admission", "quorum"],
                )
                network.start.assert_called_once_with()
                network.await_ready.assert_called_once_with()
                network.producer_negative.assert_called_once_with()
                network.negative.assert_called_once_with()
                self.assertTrue(network.closed)
                self.assertEqual(network.target.fileno(), -1)

    return Controls
