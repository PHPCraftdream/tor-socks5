def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("TOR_REAL_ISOLATED") != "yes"
    ):
        print("Tor authority consensus requires isolated CI", file=sys.stderr)
        return 1
    try:
        deadline = float(os.environ["TOR_REAL_DEADLINE"])
        binary = os.environ["TOR_REAL_BINARY"]
        gencert = os.environ["TOR_REAL_GENCERT_BINARY"]
        stream_binary = os.environ["TOR_REAL_STREAM_BINARY"]
        if (
            not math.isfinite(deadline)
            or deadline <= time.monotonic()
            or not os.path.isabs(stream_binary)
            or not Path(stream_binary).is_file()
        ):
            raise ValueError()
    except (KeyError, ValueError):
        print("Tor authority consensus invalid operation input", file=sys.stderr)
        return 1
    previous = {
        sig: signal.signal(sig, cancel)
        for sig in (signal.SIGTERM, signal.SIGINT)
    }
    network = None
    operation_stage = "prepare"
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        if result.testsRun != 16 or not result.wasSuccessful():
            print("Tor authority consensus mechanism controls failed",
                  file=sys.stderr)
            report_failures(result)
            return 1
        print("Tor authority consensus mechanism controls passed: 16")
        diagnostic_suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            DiagnosticControls
        )
        diagnostic_result = unittest.TextTestRunner(
            stream=io.StringIO()
        ).run(diagnostic_suite)
        if (
            diagnostic_result.testsRun != 3
            or not diagnostic_result.wasSuccessful()
        ):
            print(
                "Tor authority failure diagnostic controls failed",
                file=sys.stderr,
            )
            return 1
        print("Tor authority failure diagnostic controls passed: 3")
        producer_ok, producer_failures = p.run_controls(c)
        if not producer_ok:
            print("Tor relay producer mechanism controls failed",
                  file=sys.stderr)
            for failure in producer_failures:
                print(failure, file=sys.stderr)
            return 1
        print("Tor relay producer mechanism controls passed: 36")
        operation_stage = "stream-controls"
        if not p.run_stream_controls(c, deadline, report_runtime_failure):
            print(
                "Tor owned stream mechanism controls failed",
                file=sys.stderr,
            )
            return 1
        print("Tor owned stream mechanism controls passed: 21")
        operation_stage = "prepare"
        network = p.implementation(c)(binary, gencert, deadline)
        p.run_stream_live(network, c, stream_binary)
        print("Tor three-authority current consensus controls passed: 1")
        print("Tor one-of-three vote quorum rejection controls passed: 1")
        print("Tor owned guard middle exit producer controls passed: 1")
        print("Tor BOM descriptor admission rejection controls passed: 1")
        print("Tor owned stream positive controls passed: 1")
        return 0
    except (c.a.s.Cancelled, c.a.m.Cancelled):
        print("Tor authority consensus cancelled", file=sys.stderr)
        return 143
    except (c.a.s.DeadlineExceeded, c.a.m.DeadlineExceeded):
        print("Tor authority consensus deadline", file=sys.stderr)
        return 1
    except (c.a.s.CleanupError, c.a.m.CleanupError):
        print("Tor authority consensus cleanup", file=sys.stderr)
        return 1
    except Exception as error:
        stage = network.stage if network is not None else operation_stage
        return report_runtime_failure(error, stage)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
