# tor-socks5-proto

Internal shared authentication adapter for the CLI and Android hosts. The library
name remains `socks5_proto`; this workspace package is not published separately.

All SOCKS5 and HTTP CONNECT detection, framing, authentication responses, and
final replies belong to `resocks5_net::server`. There is no local parser, reply
encoder, `ConnectRequest`, or legacy compatibility API.

```rust,no_run
use resocks5_net::server::{Reply, ServerError};
use socks5_proto::accept;
use tokio::time::{Duration, Instant};

# async fn example(mut sock: tokio::net::TcpStream) -> Result<(), ServerError> {
let deadline = Instant::now() + Duration::from_secs(30);
let request = accept(&mut sock, deadline, None).await?;
// No real egress in this example: never report Established for an unconnected target.
request.reply(&mut sock, Reply::UpstreamUnavailable).await?;
# Ok(())
# }
```

A real host applies policy and opens egress before replying `Established`, then
forwards `take_pipeline()` exactly once before unread client bytes. The adapter
never dials or sends final tunnel success itself.

`accept<S>(&mut S, tokio::time::Instant, Option<Arc<dyn PasswordVerifier>>)`
returns `Result<IncomingRequest, ServerError>` directly using SDK types.
`S: AsyncRead + AsyncWrite + Unpin`. `Some(verifier)` enables passwords and
**disables anonymous access**; `None` enables anonymous access and disables
passwords. `PasswordVerifier::verify(&self, username: &str, password: &str) -> bool`
is an open, object-safe host port; keep concrete auth-store implementations in the
hosts. The adapter moves SDK-owned credentials into an awaited `spawn_blocking`.
Panic/join failure rejects authentication (with unwinding, not panic=abort).

## Deadline and admission contract

Supply one absolute 30-second deadline from the host's handshake start; it covers detection,
framing, and verification without renewal. Expired entry does not poll I/O or
verification. **Discard the socket and any buffered wrapper on every error,
timeout, or cancellation**: partial framing cannot be resumed.

Both current hosts have 256-connection caps. Those permits do not bound work
surviving handshake cancellation, so the adapter also has one process-wide gate
for **256 queued or running blocking verifications**, matching the host cap and
shared across listeners and verifier instances. At the current host KDF's 5 MiB
per verification this budgets 1280 MiB of KDF memory, excluding overhead; custom
verifiers must bound their own
memory and duration. Full admission rejects the newest attempt immediately via
SDK authentication failure framing, with no verifier invocation or wait queue.
The permit moves into the blocking closure and survives deadline/cancellation
until the closure exits. A deadline stops waiting, not verification or persistence;
host connection admission and verifier-side bounded work remain necessary.

The adapter logs no credentials. SDK credentials redact Debug, but SDK errors and
request identity can contain usernames: hosts must not indiscriminately log them.
Credentials travel in plaintext unless the host provides transport protection.

`is_onion(host: &str) -> bool` retains the final-label, case-insensitive predicate
with trailing-dot tolerance. Pass a parsed host, **not** `request.target()` with its
port. It is not validation of a hidden-service address.

The CLI applies account policy using the SDK request's authenticated username;
JNI applies the global destination policy. Both hosts accept SOCKS5 and HTTP
CONNECT on the same port; ordinary HTTP forwarding is not supported.

## SDK replies

Use `IncomingRequest::reply` and SDK `Reply` only. `Established` is success,
`Forbidden` is policy refusal (SOCKS REP 2 / HTTP 403), and `GeneralFailure`
is Tor egress failure (SOCKS REP 1 / HTTP 502). `UpstreamUnavailable` is SOCKS
REP 4 / HTTP 502; `Overloaded` means admission overload (SOCKS REP 1 / HTTP 503),
not an egress failure. Do not write raw response bytes or misuse `Overloaded`.

## Static-only test changes

Adapter tests cover auth capability mapping, acceptance/rejection/panic, exact
credential forwarding and identity, blocking-thread offload, no premature success,
HTTP pipeline ownership, expired and non-renewed deadlines, full admission, and
permit retention after cancellation/deadline. Gate tests use isolated semaphores
through the same private implementation, not mutable global test state.

Intended mutation controls (not executed): flip capability flags; ignore verifier
false/join failure; drop credentials/identity/pipeline; invoke verification on the
async worker; renew/ignore the supplied deadline; remove admission; keep the permit
outside the blocking closure. Each should break its corresponding observable
assertions. Parser-specific conformance stays upstream.
