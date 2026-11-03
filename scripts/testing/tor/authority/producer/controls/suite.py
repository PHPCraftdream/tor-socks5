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


def run_stream_controls(c, deadline, report):
    suite = unittest.TestSuite()
    expected = 0
    for filename, count in (
        ("stream.py", 12),
        ("stream_lifecycle.py", 9),
    ):
        path = Path(__file__).with_name("controls") / filename
        spec = importlib.util.spec_from_file_location(
            "producer_controls_" + filename.replace(".", "_"), path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        case = module.build(c, _stream, globals(), deadline, report)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
        expected += count
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    return result.testsRun == expected and result.wasSuccessful()
