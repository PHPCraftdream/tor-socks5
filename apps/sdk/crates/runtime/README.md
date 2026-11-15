# tor-socks5-runtime

The internal runtime module tree of the `tor-socks5` proxy binary — Tor bootstrap setup, bridge maintenance (ranking, channel probes, candidate pooling), bridge store writing, circuit verification, warming, fetch merging, conn health counters and the Tor watchdog — moved as-is out of the binary (SDK-6, docs/plans/sdk-coverage-plan.md). Behavior-neutral: the binary links this crate and keeps its own CLI/server/commands code.

Not published: the release artifact is the single `tor-socks5` package; consumers take the facade by git. The public surface is minimal until the API steps SDK-7/8/9 open it up.

The `test-seams` feature is dev-only: it is enabled solely through consumers' dev-dependencies so tests in other crates can drive the same internal seams the binary's tests use (R10). Never enable it in default/full builds.
