PRODUCER_FAILURE_GATES = frozenset("""
producer-field producer-base64 producer-router producer-duplicate-router
producer-flags producer-md-line producer-bandwidth producer-protocols
producer-router-limit producer-router-binding producer-router-eligibility
producer-role-binding producer-zero-bandwidth producer-router-protocols
producer-missing-md producer-descriptor producer-descriptor-router
producer-descriptor-identity producer-descriptor-family
producer-port-only-policy producer-ipv6-policy producer-descriptor-signature
producer-microdescriptor-digest producer-microdescriptor-keys
producer-microdescriptor-family producer-microdescriptor-policy
producer-microdescriptor-ipv6 producer-topology producer-baseline-config
producer-request-path producer-negative-input
producer-specific-admission-negative producer-single-use
producer-target-listener producer-good-baseline producer-config-changed
producer-ns-metadata producer-distinct-identities producer-ns-membership
producer-ns-baseline producer-md-consensus producer-md-cache
producer-md-flavor producer-md-period producer-md-disagreement
producer-md-membership producer-flavor-flags producer-admitted-descriptor
producer-descriptor-disagreement producer-descriptor-digest
producer-owned-descriptor producer-owned-ed25519
producer-owned-http producer-owned-admission producer-owned-admitted
producer-served-microdescriptor producer-microdescriptor-disagreement
producer-negative-descriptor-changed producer-negative-md-changed
producer-negative-consensus-changed producer-consensus-not-executed
producer-positive-not-executed producer-negative-not-executed
producer-quorum-not-executed producer-target-unreleased
producer-missing-bandwidth producer-readiness-single-use
producer-readiness-budget producer-readiness-cache-missing
producer-readiness-regression producer-readiness-same-period
producer-readiness-disagreement producer-readiness-not-advanced
producer-readiness-unexpected-period producer-readiness-framing
""".split())

CONSENSUS_FAILURE_GATES = frozenset("""
document-field schedule-input consensus-interval quorum-window-missed
document-version document-signature document-source duplicate-source
document-vote-digest document-type consensus-not-current consensus-delays
consensus-voters consensus-binding consensus-signers vote-type vote-period
vote-identity vote-binding vote-certificate file-limit topology-unprepared
baseline-config baseline-authority-config request-path request-limit
http-peer http-limit http-header http-status http-framing http-length
listener-changed cached-empty invalid-deadline single-use
independent-identities candidate-ports loaded-certificate consensus-http
consensus-disagreement daemon-current-consensus origin-vote participating-vote
good-baseline baseline-config-changed removed-voters-not-reaped next-vote-http
minority-vote-changed log-truncated rotated-vote-http quorum-admitted-votes
minority-pending-consensus minority-published-consensus quorum-config-changed
child-unreaped stream-unreleased directory-unreleased socket-unreleased
""".split())

FAILURE_STAGES = frozenset({
    "prepare", "launch", "consensus", "votes", "quorum",
    "producer", "producer-negative", "producer-readiness",
})


def report_runtime_failure(error, stage):
    if type(stage) is not str or stage not in FAILURE_STAGES:
        stage = "prepare"
    error_type = type(error)
    categories = {
        p.ProducerError: "producer",
        c.ConsensusError: "consensus",
        c.a.StartupError: "startup",
        c.a.s.ChildExit: "child-exit",
        c.a.s.ProtocolError: "protocol",
        c.a.s.AuthError: "authentication",
        FileNotFoundError: "file-missing",
        PermissionError: "permission",
        OSError: "os",
        ValueError: "value",
        TypeError: "type",
        KeyError: "key",
        AttributeError: "attribute",
    }
    category = categories.get(error_type, "unknown")
    gate = "unknown"
    allowed = (
        PRODUCER_FAILURE_GATES if error_type is p.ProducerError
        else CONSENSUS_FAILURE_GATES if error_type is c.ConsensusError
        else None
    )
    if allowed is not None:
        arguments = error.args
        if (
            type(arguments) is tuple
            and len(arguments) == 1
            and type(arguments[0]) is str
            and len(arguments[0]) <= 96
            and arguments[0] in allowed
        ):
            gate = arguments[0]
    print("Tor authority consensus failed: " + stage, file=sys.stderr)
    print(
        "Tor authority failure detail:"
        + " type=" + category
        + " gate=" + gate,
        file=sys.stderr,
    )
    return 1


class DiagnosticControls(unittest.TestCase):
    def capture_failure(self, error, stage="producer"):
        output = io.StringIO()
        with mock.patch.object(sys, "stderr", output):
            status = report_runtime_failure(error, stage)
        self.assertEqual(status, 1)
        return output.getvalue()

    def test_genuine_failed_gates_have_fixed_labels(self):
        row = {
            "name": b"localA",
            "address": b"127.0.0.1",
            "or": b"21001",
            "dir": b"21002",
            "flags": {b"Running", b"Valid", b"Guard"},
            "bandwidth": 1,
            "protocols": b"Link=1-5 Relay=1-4",
            "md": bytes(32),
        }
        node = SimpleNamespace(
            name="localA", or_port=21001, dir_port=21002,
        )
        with self.assertRaises(p.ProducerError) as producer_failure:
            p.check_row(row, node, "guard", True)
        self.assertEqual(
            self.capture_failure(producer_failure.exception),
            "Tor authority consensus failed: producer\n"
            "Tor authority failure detail:"
            " type=producer gate=producer-router-eligibility\n",
        )
        with self.assertRaises(c.ConsensusError) as consensus_failure:
            c.require_window(100, 60)
        self.assertEqual(
            self.capture_failure(consensus_failure.exception),
            "Tor authority consensus failed: producer\n"
            "Tor authority failure detail:"
            " type=consensus gate=quorum-window-missed\n",
        )

        for label in (
            "producer-owned-http",
            "producer-owned-admission",
            "producer-owned-admitted",
            "producer-missing-bandwidth",
            "producer-readiness-budget",
            "producer-readiness-unexpected-period",
            "producer-readiness-framing",
        ):
            with self.subTest(category=label):
                with self.assertRaises(p.ProducerError) as failure:
                    p.require(False, label)
                self.assertEqual(
                    self.capture_failure(failure.exception),
                    "Tor authority consensus failed: producer\n"
                    "Tor authority failure detail:"
                    " type=producer gate=" + label + "\n",
                )

    def test_unknown_and_private_payloads_are_not_formatted(self):
        calls = []

        class PrivateValue:
            def __str__(self):
                calls.append("value-str")
                raise AssertionError("private-value-formatted")

            def __repr__(self):
                calls.append("value-repr")
                raise AssertionError("private-value-formatted")

        class PrivateFailure(Exception):
            def __str__(self):
                calls.append("error-str")
                raise AssertionError("private-error-formatted")

            def __repr__(self):
                calls.append("error-repr")
                raise AssertionError("private-error-formatted")

        class ProducerSubclass(p.ProducerError):
            pass

        for error, category in (
            (p.ProducerError("private-path-or-key"), "producer"),
            (p.ProducerError("producer-field", "private"), "producer"),
            (p.ProducerError(PrivateValue()), "producer"),
            (p.ProducerError("x" * 97), "producer"),
            (c.ConsensusError("producer-field"), "consensus"),
            (PrivateFailure(PrivateValue()), "unknown"),
            (ProducerSubclass("producer-field"), "unknown"),
            (FileNotFoundError("private-path-or-key"), "file-missing"),
        ):
            with self.subTest(category=category):
                self.assertEqual(
                    self.capture_failure(error, PrivateValue()),
                    "Tor authority consensus failed: prepare\n"
                    "Tor authority failure detail:"
                    + " type=" + category + " gate=unknown\n",
                )
        self.assertEqual(calls, [])

    def test_main_failure_status_and_special_handlers_are_preserved(self):
        cases = (
            (
                p.ProducerError("producer-md-cache"),
                1,
                "Tor authority consensus failed: producer\n"
                "Tor authority failure detail:"
                " type=producer gate=producer-md-cache\n",
            ),
            (
                c.ConsensusError("quorum-window-missed"),
                1,
                "Tor authority consensus failed: producer\n"
                "Tor authority failure detail:"
                " type=consensus gate=quorum-window-missed\n",
            ),
            (
                c.a.s.Cancelled("private"),
                143,
                "Tor authority consensus cancelled\n",
            ),
            (
                c.a.m.Cancelled("private"),
                143,
                "Tor authority consensus cancelled\n",
            ),
            (
                c.a.s.DeadlineExceeded("private"),
                1,
                "Tor authority consensus deadline\n",
            ),
            (
                c.a.m.DeadlineExceeded("private"),
                1,
                "Tor authority consensus deadline\n",
            ),
            (
                c.a.s.CleanupError("private"),
                1,
                "Tor authority consensus cleanup\n",
            ),
            (
                c.a.m.CleanupError("private"),
                1,
                "Tor authority consensus cleanup\n",
            ),
        )
        for error, expected_status, expected_error in cases:
            with self.subTest(category=type(error)):
                network = SimpleNamespace(stage="producer")
                output = io.StringIO()
                errors = io.StringIO()
                results = [
                    SimpleNamespace(
                        testsRun=15, wasSuccessful=lambda: True,
                    ),
                    SimpleNamespace(
                        testsRun=3, wasSuccessful=lambda: True,
                    ),
                ]
                runner = mock.Mock()
                runner.run.side_effect = results
                environment = {
                    "GITHUB_ACTIONS": "true",
                    "TOR_REAL_ISOLATED": "yes",
                    "TOR_REAL_DEADLINE": str(time.monotonic() + 60),
                    "TOR_REAL_BINARY": "/fixture/tor",
                    "TOR_REAL_GENCERT_BINARY": "/fixture/gencert",
                }
                with mock.patch.dict(os.environ, environment):
                    with mock.patch.object(
                        unittest, "TextTestRunner", return_value=runner,
                    ):
                        with mock.patch.object(
                            signal, "signal", return_value=None,
                        ):
                            with mock.patch.object(
                                p, "run_controls",
                                return_value=(True, ()),
                            ) as producer_controls:
                                with mock.patch.object(
                                    p, "implementation",
                                    return_value=mock.Mock(
                                        return_value=network,
                                    ),
                                ):
                                    with mock.patch.object(
                                        p, "run_live", side_effect=error,
                                    ) as operation:
                                        with mock.patch.object(
                                            sys, "stdout", output,
                                        ):
                                            with mock.patch.object(
                                                sys, "stderr", errors,
                                            ):
                                                status = main()
                self.assertEqual(status, expected_status)
                self.assertEqual(errors.getvalue(), expected_error)
                self.assertEqual(runner.run.call_count, 2)
                producer_controls.assert_called_once_with(c)
                operation.assert_called_once_with(network, c)
                self.assertNotIn(
                    "Tor owned guard middle exit producer controls passed",
                    output.getvalue(),
                )
                self.assertNotIn(
                    "Tor one-of-three vote quorum rejection controls passed",
                    output.getvalue(),
                )

