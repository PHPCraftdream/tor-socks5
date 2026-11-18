# tor-socks5-server

`tor-socks5-server` contains the internal server tree moved from the proxy binary (SDK-10): SOCKS5/HTTP CONNECT listeners, egress selection, DNS wiring, Tor-owner watchdogs, bridge producers, and onion-service startup. The SDK-11 embedding API is available through the `tor-socks5` facade's `server` feature; the host still owns process initialization and CLI/OS integration.

## Embedded server API

Build a `Config` in the host and pass it to `Server::builder`. The builder accepts an optional associated config path, an optional Arti `ObservationSink`, upstream SOCKS5 settings, an explicit `no_upstream` override, a DNS startup policy, and a caller-owned `CancellationToken`. `start().await` waits for the server's ready point (SOCKS listeners bound and accepting connections); with the default `DnsStartupPolicy::Required`, at least one configured DNS UDP/TCP pair must also bind first. DNS binding skips unavailable pairs (`AddrInUse`, `PermissionDenied`, or `AddrNotAvailable`, the latter queued for retry); `ServerError::Bind` is returned only if no pair binds. `Running` addresses contain only successfully bound sockets. `DnsStartupPolicy::Background` retains the proxy CLI's legacy optional-DNS behavior: DNS starts in the background and bind failure does not fail SOCKS startup. Startup does not wait for an upstream proxy to connect or validate it. Startup and runtime failures are typed `ServerError`s, including `AlreadyRunning`, config/recovery/bind/startup/runtime, cancellation, and task failures.

```rust,no_run
use tor_socks5::config::Config;
use tor_socks5::server::Server;

# async fn run(config_path: Option<std::path::PathBuf>) -> Result<(), tor_socks5::server::ServerError> {
let config = Config {
    listen: vec!["127.0.0.1:0".into()],
    ..Config::default()
};
let server = Server::builder(config)
    .config_path(config_path)
    // Optional: .observation_sink(tor_socks5::runtime::ObservationSink::new())
    .upstream(Some("127.0.0.1:9050".into()), None, None)
    .no_upstream(false)
    // SDK default is Required; the CLI explicitly selects Background.
    .dns_startup_policy(tor_socks5::server::DnsStartupPolicy::Required)
    .start()
    .await?;

let mut status = server.subscribe();
let ready_status = server.status(); // Running includes actual SOCKS and DNS socket addresses
server.shutdown().await?;
# let _ = (status, ready_status);
# Ok(())
# }
```

Use `ServerHandle::shutdown().await` to request graceful cancellation and join cleanup, or `wait().await` to join natural termination without requesting cancellation. `token()` returns a clone of the shutdown token; callers that want to pass their own token to `.cancellation_token(...)` need a direct `tokio-util` dependency (with its `rt` feature). `status()` returns the latest lifecycle snapshot; `subscribe()` gives a Tokio `watch::Receiver<ServerStatus>` with `Starting`, `Running`, `Stopping`, and `Stopped` states. `Running`, `Stopping`, and `Stopped` carry actual bound socket addresses (the last known addresses are retained at stop). DNS UDP and TCP sockets are listed separately and can therefore appear as duplicate `SocketAddr` values; the status vector does not encode protocol. A watch is a latest-value snapshot, not an event stream: intermediate lifecycle changes may be coalesced.

Dropping a handle requests cancellation only: it does not block, spawn cleanup, or abort the supervised worker. Retain the handle and explicitly call `shutdown().await` or `wait().await` when the host needs to know the cleanup attempt has finished and receive its result. Settings/global-init/owner recovery uses explicit deadlines; producer and handler joins have their own budgets (normal producer grace is 120 seconds). The final blocking-worker join has a five-second timeout. Closing the bridge-store writer is awaited without a deadline. `Stopped` means that attempt completed (successfully or with an error; `ServerError::Cleanup` preserves a secondary cleanup failure), not that every task handle was provably joined; timed-out handles remain retained in process slots for recovery by the next start.

There is one live server per process. `start()` obtains an RAII admission reservation before recovery begins; a concurrent attempt returns `ServerError::AlreadyRunning` without running recovery. The reservation remains held through worker cleanup and is released on every exit path, including startup failure and cancellation, so sequential stop-then-start is supported. Runs that allocate owner storage are additionally limited by the process-lifetime quarantine described below.

Owner storage has a process-lifetime quarantine of 15 slots. Each run that allocates an owner-storage slot consumes one slot, which is not released before process exit; repeated runs using owner storage can exhaust the limit.

The library does not load the config file: the host loads `Config` and may pass its source path via `config_path`. Process-wide tracing/subscriber setup, rustls crypto-provider installation, child-process binding, `NO_COLOR` handling, OS signal registration, and CLI/service management remain host responsibilities.

## Internal compatibility surface

The server implementation tree and `run_server` are internal, not part of the SDK API. At the crate root, the only `#[doc(hidden)]` compatibility export is `reject_unsupported_pool`, used by the binary's `bridges` CLI; it is not the server API.

Behind the default `onion-service` feature, configured onion services are hosted through `tor-socks5-onion`; builds without that feature retain the startup warning when services are configured.

The crate is not published: the release artifact is the single `tor-socks5` package, and consumers use its facade by git.
