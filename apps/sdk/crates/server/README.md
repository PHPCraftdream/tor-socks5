# tor-socks5-server

The internal server module tree of the `tor-socks5` proxy binary — the SOCKS5/HTTP CONNECT listener and accept loop, the egress selection (Tor branch, pre pools, owner clients, upstream SOCKS5 relay), the DNS wiring, the startup helpers and the Tor-owner watchdogs and bridge producers around them — moved as-is out of the binary (SDK-10, docs/plans/sdk-coverage-plan.md). Behavior-neutral: the binary links this crate and keeps its own CLI/process/commands code.

Not published: the release artifact is the single `tor-socks5` package; consumers take the facade by git. Until the API step (SDK-11), only what the binary itself consumes is public, marked `#[doc(hidden)]`: `run_server`/`ServerArgs` (driven by the host's process layer) and the `route` pool validation used by the `bridges` CLI.

Behind the default `onion-service` feature, the crate shells configured onion services out to the `tor-socks5-onion` host (SDK-5); a build without the feature only warns at startup when enabled services are configured.

The `test-seams` feature is dev-only: it is enabled solely through consumers' dev-dependencies so tests in other crates can drive the same internal seams the binary's tests use (R10). Never enable it in default/full builds.
