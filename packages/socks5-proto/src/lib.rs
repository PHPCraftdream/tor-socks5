//! Shared host authentication adapter for resocks5-net inbound framing.
//! Protocol detection, parsing, authentication responses, and tunnel replies are
//! exclusively owned by the SDK. This crate never resolves or dials a target.
#![warn(missing_docs)]

use std::sync::{Arc, OnceLock};

use resocks5_net::server::{self, Credentials, IncomingRequest, ServerError, ServerOptions};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio::time::Instant;

// Both hosts cap connections at 256, but cancellation releases their connection
// permits while blocking verification may still run. Independently cap queued +
// running verifications process-wide at 256, matching the host connection cap
// (1280 MiB for the current 5 MiB KDF, excluding overhead). Custom verifiers must
// bound their own memory and duration.
const MAX_BLOCKING_VERIFICATIONS: usize = 256;

fn verification_slots() -> Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_BLOCKING_VERIFICATIONS))))
}

/// Host-owned credential store; no dependency on the application's auth store.
pub trait PasswordVerifier: Send + Sync {
    /// Verify the submitted UTF-8 credentials without normalization, at most once
    /// per handshake, on the blocking pool. Return false for every rejection.
    /// Implementations must bound work, avoid logging credentials, and use their
    /// credential backend's secure comparison. Cancellation cannot stop this call
    /// or roll back persistence it performs. An unwinding panic fails closed;
    /// a host built with panic=abort instead terminates the process.
    fn verify(&self, username: &str, password: &str) -> bool;
}

/// Accept an authenticated, unresolved SOCKS5 or HTTP CONNECT request.
///
/// `Some` requires passwords and disables anonymous access; `None` does the
/// inverse. The supplied absolute deadline covers every SDK phase, including
/// waiting for verification to finish, and is never renewed by this adapter.
/// An expired deadline does not poll the stream or invoke the verifier.
/// Saturated verification admission fails closed through SDK authentication
/// failure framing; it is not a host tunnel `Reply::Overloaded` outcome.
/// No final tunnel success is sent: use `IncomingRequest::reply` after egress.
///
/// cancel-safe: NO — SDK reads and writes can be partial. On error, deadline,
/// or cancellation, discard the stream and any buffered wrapper. Already queued
/// or running blocking work deliberately survives cancellation, retaining its
/// admission permit until the closure exits. Hosts still need connection caps.
pub async fn accept<S>(
    stream: &mut S,
    deadline: Instant,
    auth: Option<Arc<dyn PasswordVerifier>>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_with_slots(stream, deadline, auth, verification_slots()).await
}

// cancel-safe: NO — same terminal stream contract as accept. The gate parameter
// permits isolated tests of the production path without changing global state.
async fn accept_with_slots<S>(
    stream: &mut S,
    deadline: Instant,
    auth: Option<Arc<dyn PasswordVerifier>>,
    slots: Arc<Semaphore>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let password = auth.is_some();
    let options = ServerOptions::new(deadline, !password, password);
    server::accept(
        stream,
        &options,
        move |credentials: Credentials| async move {
            let Some(verifier) = auth else {
                return false;
            };
            // Drop-newest admission: never build an attacker-sized wait queue.
            let Ok(permit) = slots.try_acquire_owned() else {
                return false;
            };
            // Await normally; fire-and-forget: detached by design ONLY if the SDK
            // deadline or host cancellation drops this await. Blocking work cannot
            // be aborted; its owned permit remains captured even while queued.
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                verifier.verify(credentials.username(), credentials.password())
            })
            .await
            .unwrap_or(false)
        },
    )
    .await
}

/// Match a host's final `.onion` label case-insensitively, tolerating trailing
/// FQDN dots. Pass the host, not an authority containing a port. This is a
/// routing-policy predicate, not validation of a Tor hidden-service address.
#[must_use]
pub fn is_onion(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    matches!(host.rsplit_once('.'), Some((_, tld)) if tld.eq_ignore_ascii_case("onion"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use resocks5_net::server::Protocol;
    use std::future::Future;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    const CONNECT: &[u8] = &[5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
    const AUTH: &[u8] = &[
        1, 5, b'a', b'l', b'i', b'c', b'e', 6, b'p', b'u', b'b', b'l', b'i', b'c',
    ];

    struct RecordingVerifier {
        calls: Mutex<Vec<(String, String)>>,
        accepted: bool,
        panic: bool,
        worker: Mutex<Option<std::thread::ThreadId>>,
    }

    impl PasswordVerifier for RecordingVerifier {
        fn verify(&self, username: &str, password: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push((username.into(), password.into()));
            *self.worker.lock().unwrap() = Some(std::thread::current().id());
            // Intentional test-only unwinding panic exercises fail-closed join handling.
            assert!(!self.panic, "test verifier panic");
            self.accepted
        }
    }

    fn recorder(accepted: bool, panic: bool) -> Arc<RecordingVerifier> {
        Arc::new(RecordingVerifier {
            calls: Mutex::new(Vec::new()),
            accepted,
            panic,
            worker: Mutex::new(None),
        })
    }

    // Fixtures are public test data, not secret comparisons or cryptography.
    #[tokio::test]
    async fn password_result_identity_and_blocking_thread_are_preserved() {
        for (accepted, panic) in [(true, false), (false, false), (true, true)] {
            let verifier = recorder(accepted, panic);
            let (mut server, mut client) = duplex(256);
            client.write_all(&[5, 2, 0, 2]).await.unwrap();
            client.write_all(AUTH).await.unwrap();
            client.write_all(CONNECT).await.unwrap();
            let result = accept(
                &mut server,
                Instant::now() + Duration::from_secs(30),
                Some(verifier.clone()),
            )
            .await;
            drop(server);
            let mut replies = Vec::new();
            client.read_to_end(&mut replies).await.unwrap();
            if accepted && !panic {
                let request = result.unwrap();
                assert_eq!(request.username(), Some("alice"));
                assert_eq!(request.target(), "1.2.3.4:80");
                assert_eq!(replies, [5, 2, 1, 0]); // no premature tunnel success
            } else {
                assert!(matches!(result, Err(ServerError::Authentication(_))));
                assert_eq!(replies, [5, 2, 1, 1]);
            }
            assert_eq!(
                *verifier.calls.lock().unwrap(),
                [("alice".into(), "public".into())]
            );
            assert_ne!(
                *verifier.worker.lock().unwrap(),
                Some(std::thread::current().id())
            );
        }
    }

    #[tokio::test]
    async fn capability_matrix_has_no_anonymous_downgrade() {
        for (configured, method, succeeds) in
            [(true, 0, false), (false, 2, false), (false, 0, true)]
        {
            let verifier = recorder(true, false);
            let auth = configured.then(|| verifier.clone() as Arc<dyn PasswordVerifier>);
            let (mut server, mut client) = duplex(256);
            client.write_all(&[5, 1, method]).await.unwrap();
            client.write_all(CONNECT).await.unwrap();
            let result = accept(&mut server, Instant::now() + Duration::from_secs(30), auth).await;
            drop(server);
            let mut replies = Vec::new();
            client.read_to_end(&mut replies).await.unwrap();
            if succeeds {
                assert_eq!(result.unwrap().username(), None);
                assert_eq!(replies, [5, 0]);
            } else {
                assert!(matches!(result, Err(ServerError::Authentication(_))));
                assert_eq!(replies, [5, 255]);
            }
            assert!(verifier.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn http_adapter_preserves_identity_and_pipeline() {
        let verifier = recorder(true, false);
        let (mut server, mut client) = duplex(1024);
        client.write_all(b"CONNECT example.onion:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHVibGlj\r\n\r\npayload").await.unwrap();
        let mut request = accept(
            &mut server,
            Instant::now() + Duration::from_secs(30),
            Some(verifier.clone()),
        )
        .await
        .unwrap();
        assert_eq!(request.protocol(), Protocol::Http);
        assert_eq!(request.target(), "example.onion:443");
        assert_eq!(request.username(), Some("alice"));
        assert_eq!(request.take_pipeline(), b"payload");
        assert!(request.take_pipeline().is_empty());
        assert_eq!(
            *verifier.calls.lock().unwrap(),
            [("alice".into(), "public".into())]
        );
        drop(server);
        let mut replies = Vec::new();
        client.read_to_end(&mut replies).await.unwrap();
        assert!(replies.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn supplied_expired_deadline_does_not_consume_ready_input() {
        let verifier = recorder(true, false);
        let (mut server, mut client) = duplex(256);
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.write_all(AUTH).await.unwrap();
        let result = accept(&mut server, Instant::now(), Some(verifier.clone())).await;
        assert!(matches!(result, Err(ServerError::Deadline)));
        let mut first = [0];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [5]);
        assert!(verifier.calls.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn partial_progress_does_not_renew_supplied_deadline() {
        let (mut server, mut client) = duplex(256);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut accepting = Box::pin(accept(&mut server, deadline, None));
        client.write_all(&[5]).await.unwrap();
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                accepting.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        tokio::time::advance(Duration::from_secs(9)).await;
        client.write_all(&[1, 0]).await.unwrap();
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                accepting.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(accepting.await, Err(ServerError::Deadline)));
        assert_eq!(Instant::now(), deadline);
    }

    struct HeldVerifier {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl PasswordVerifier for HeldVerifier {
        fn verify(&self, _: &str, _: &str) -> bool {
            self.started
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            // Blocking-pool test fixture only: release is explicitly signalled.
            self.release.lock().unwrap().recv().unwrap();
            true
        }
    }

    #[tokio::test]
    async fn cancellation_retains_gate_until_blocking_verification_exits() {
        use std::future::Future;
        let slots = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let verifier = Arc::new(HeldVerifier {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
        });
        let (mut server, mut client) = duplex(256);
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.write_all(AUTH).await.unwrap();
        let mut accepting = Box::pin(accept_with_slots(
            &mut server,
            Instant::now() + Duration::from_secs(30),
            Some(verifier),
            slots.clone(),
        ));
        let pending = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(accepting.as_mut().poll(cx).is_pending())
        })
        .await;
        started_rx.await.unwrap();
        drop(accepting);
        let retained = slots.available_permits();
        release_tx.send(()).unwrap(); // always unblock before assertions
        let permit = slots.acquire().await.unwrap();
        assert!(pending);
        assert_eq!(retained, 0);
        drop(permit);
    }

    #[tokio::test]
    async fn deadline_retains_gate_until_blocking_verification_exits() {
        let slots = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let verifier = Arc::new(HeldVerifier {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
        });
        let (mut server, mut client) = duplex(256);
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.write_all(AUTH).await.unwrap();
        // Freeze only after the OS-thread acknowledgement, avoiding virtual-time
        // auto-advance racing the blocking worker's startup.
        let mut accepting = Box::pin(accept_with_slots(
            &mut server,
            Instant::now() + Duration::from_secs(30),
            Some(verifier),
            slots.clone(),
        ));
        std::future::poll_fn(|cx| {
            let _ = accepting.as_mut().poll(cx);
            std::task::Poll::Ready(())
        })
        .await;
        started_rx.await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        let result = accepting.await;
        let retained = slots.available_permits();
        release_tx.send(()).unwrap();
        tokio::time::resume();
        let permit = slots.acquire().await.unwrap();
        assert!(matches!(result, Err(ServerError::Deadline)));
        assert_eq!(retained, 0);
        drop(permit);
    }

    #[tokio::test]
    async fn http_capabilities_reject_missing_or_unconfigured_credentials() {
        for configured in [true, false] {
            let verifier = recorder(true, false);
            let auth = configured.then(|| verifier.clone() as Arc<dyn PasswordVerifier>);
            let (mut server, mut client) = duplex(1024);
            let input: &[u8] = if configured {
                b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"
            } else {
                b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHVibGlj\r\n\r\n"
            };
            client.write_all(input).await.unwrap();
            let result = accept(&mut server, Instant::now() + Duration::from_secs(30), auth).await;
            drop(server);
            let mut replies = Vec::new();
            client.read_to_end(&mut replies).await.unwrap();
            assert!(matches!(result, Err(ServerError::Authentication(_))));
            assert!(replies.starts_with(b"HTTP/1.1 407 "));
            assert!(verifier.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn saturated_gate_rejects_without_invoking_verifier() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.acquire().await.unwrap();
        let verifier = recorder(true, false);
        let (mut server, mut client) = duplex(256);
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.write_all(AUTH).await.unwrap();
        let result = accept_with_slots(
            &mut server,
            Instant::now() + Duration::from_secs(30),
            Some(verifier.clone()),
            slots.clone(),
        )
        .await;
        drop(server);
        let mut replies = Vec::new();
        client.read_to_end(&mut replies).await.unwrap();
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(replies, [5, 2, 1, 1]);
        assert!(verifier.calls.lock().unwrap().is_empty());
        drop(held);
    }

    #[test]
    fn onion_policy_matches_only_final_label() {
        for host in ["example.onion", "sub.example.ONION", "example.onion."] {
            assert!(is_onion(host));
        }
        for host in [
            "onion",
            "example.com",
            "foo.onion.evil.com",
            "1.2.3.4",
            "example.onion:443",
        ] {
            assert!(!is_onion(host));
        }
    }
}
