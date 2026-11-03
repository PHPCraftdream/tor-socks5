def controls(c):
    Network = implementation(c)
    Node = Network.node_type
    Wire = None
    Base = None
    for filename in (
        "fixture.py", "descriptors.py", "admission.py", "readiness.py",
    ):
        path = Path(__file__).with_name("controls") / filename
        spec = importlib.util.spec_from_file_location(
            "producer_" + filename[:-3] + "_controls", path
        )
        module = importlib.util.module_from_spec(spec)
        module.__dict__.update({
            name: value for name, value in globals().items()
            if not name.startswith("__")
        })
        module.c = c
        module.Network = Network
        module.Node = Node
        if Wire is not None:
            module.Wire = Wire
        if Base is not None:
            module.Base = Base
        spec.loader.exec_module(module)
        if filename == "fixture.py":
            Wire, Base = module.build()
        else:
            Base = module.build()
    return Base


def run_controls(c):
    case = controls(c)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    allowed = set(unittest.defaultTestLoader.getTestCaseNames(case))
    failures = []
    for category, entries in (
        ("FAIL", result.failures), ("ERROR", result.errors)
    ):
        for test, traceback in entries:
            actual = getattr(test, "test_case", test)
            name = getattr(actual, "_testMethodName", None)
            identity = (
                "ProducerControls." + name
                if type(actual) is case and name in allowed
                else "<unknown-test>"
            )
            failures.append(category + " " + identity)
    return (
        result.testsRun == 36 and result.wasSuccessful(),
        tuple(failures),
    )


_STREAM_CONTROL_METHODS = (
    (
        "stream.py",
        "StreamWire",
        (
            "test_actual_dispatcher_fixed_labels_and_privacy",
            "test_early_exit_and_missing_done",
            "test_eof_before_verified_is_retained_without_ack",
            "test_eof_requires_reply_shutdown_and_live_child",
            "test_fragmented_receipt_and_invalid_frames",
            "test_helper_mutation_cannot_erase_independent_anchor",
            "test_partial_write_and_shutdown_order",
            "test_real_unix_credentials_and_wrong_pid",
            "test_receipts_cannot_replace_target_witnesses",
            "test_session_failed_close_is_once_retained_and_not_released",
            "test_shutdown_error_is_not_terminal_success",
            "test_wrong_request_and_suffix_fail",
        ),
    ),
    (
        "stream_lifecycle.py",
        "StreamLifecycle",
        (
            "test_actual_classifier_rejects_other_live_node_pid",
            "test_actual_full_run_and_entry_order",
            "test_main_stream_controls_boundary_uses_actual_dispatcher",
            "test_original_deadline_and_cancel_during_selector_supervision",
            "test_popen_retained_before_post_spawn_cancellation",
            "test_real_early_exit_and_no_done_do_not_reach_quorum",
            "test_real_exit_proof_and_independent_guard_counterfactuals",
            "test_remaining_uses_original_deadline_without_guard_mock",
            "test_unreaped_cleanup_retains_dependencies_and_finalizers",
        ),
    ),
)

_STREAM_CONTROL_IDENTITIES = frozenset(
    prefix + "." + method
    for filename, prefix, methods in _STREAM_CONTROL_METHODS
    for method in methods
)


def _stream_control_identity(test, registry):
    record = registry.get(id(test))
    if record is None or record[0] is not test:
        return "<unknown-test>"
    identity = record[1]
    if type(identity) is not str:
        return "<unknown-test>"
    if identity not in _STREAM_CONTROL_IDENTITIES:
        return "<unknown-test>"
    return identity


class _StreamControlResult(unittest.TestResult):
    def __init__(self, registry):
        super().__init__()
        self.registry = registry
        self.events = []

    def record(self, category, test, err):
        identity = _stream_control_identity(test, self.registry)
        error = None
        if (
            type(err) is tuple
            and len(err) == 3
            and isinstance(err[1], BaseException)
        ):
            error = err[1]
        self.events.append((category, identity, error))
        if category == "FAIL":
            self.failures.append((test, "<suppressed>"))
        else:
            self.errors.append((test, "<suppressed>"))

    def addFailure(self, test, err):
        self.record("FAIL", test, err)

    def addError(self, test, err):
        self.record("ERROR", test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            category = (
                "FAIL"
                if type(err) is tuple
                and len(err) == 3
                and err[0] is AssertionError
                else "ERROR"
            )
            self.record(category, test, err)


def _run_stream_control_suite(suite, registry, expected, report):
    result = _StreamControlResult(registry)
    suite.run(result)
    for category, identity, error in result.events:
        print(
            "Tor owned stream mechanism "
            + category + " " + identity,
            file=_stream.w.sys.stderr,
        )
        report(
            error
            if error is not None
            else _stream.StreamError("stream-controls"),
            "stream-controls",
        )
    valid = (
        result.testsRun == expected
        and len(registry) == expected
        and result.wasSuccessful()
        and not result.skipped
        and not result.expectedFailures
        and not result.unexpectedSuccesses
    )
    if not valid and not result.events:
        print(
            "Tor owned stream mechanism ERROR <unknown-test>",
            file=_stream.w.sys.stderr,
        )
        report(_stream.StreamError("stream-controls"), "stream-controls")
    return valid


def run_stream_controls(c, deadline, report):
    suite = unittest.TestSuite()
    registry = {}
    expected = 0
    for filename, prefix, methods in _STREAM_CONTROL_METHODS:
        path = Path(__file__).with_name("controls") / filename
        spec = importlib.util.spec_from_file_location(
            "producer_controls_" + filename.replace(".", "_"), path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        case = module.build(c, _stream, globals(), deadline, report)
        discovered = tuple(
            unittest.defaultTestLoader.getTestCaseNames(case)
        )
        if discovered != methods:
            print(
                "Tor owned stream mechanism ERROR <unknown-test>",
                file=_stream.w.sys.stderr,
            )
            report(_stream.StreamError("stream-controls"), "stream-controls")
            return False
        for method in methods:
            test = case(method)
            identity = prefix + "." + method
            registry[id(test)] = (test, identity)
            suite.addTest(test)
        expected += len(methods)
    return _run_stream_control_suite(
        suite, registry, expected, report
    )
