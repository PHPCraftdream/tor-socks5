use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

struct TrackedProof {
    identity: &'static str,
    drops: Arc<AtomicUsize>,
    dropped: Option<oneshot::Sender<()>>,
}

impl Drop for TrackedProof {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(sender) = self.dropped.take() {
            // При тайм-ауте уведомление уже не нужно.
            let _ = sender.send(());
        }
    }
}

struct IsolationVerifier {
    started: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    dropped: Mutex<Option<oneshot::Sender<()>>>,
    drops: Arc<AtomicUsize>,
}

impl ProofVerifier for IsolationVerifier {
    type Proof = TrackedProof;

    fn verify_proof(&self, username: &str, _: &str) -> Option<Self::Proof> {
        let (identity, dropped) = match username {
            "alice" => {
                self.started
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                // Ограниченное ожидание не оставит рабочий поток зависшим.
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .ok()?;
                ("alice", self.dropped.lock().unwrap().take())
            }
            "bob" => ("bob", None),
            _ => return None,
        };
        Some(TrackedProof {
            identity,
            drops: Arc::clone(&self.drops),
            dropped,
        })
    }

    fn username<'a>(&self, proof: &'a Self::Proof) -> &'a str {
        proof.identity
    }
}

/// cancel-safe: NO — после частичной записи нужно отбросить оба конца.
async fn write_handshake(client: &mut tokio::io::DuplexStream, http: bool, alice: bool) {
    if http {
        let header = if alice {
            "YWxpY2U6cHVibGlj"
        } else {
            "Ym9iOnB1YmxpYw=="
        };
        client.write_all(format!("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {header}\r\n\r\n").as_bytes()).await.unwrap();
    } else {
        client.write_all(b"\x05\x01\x02\x01").await.unwrap();
        if alice {
            client.write_all(b"\x05alice").await.unwrap();
        } else {
            client.write_all(b"\x03bob").await.unwrap();
        }
        client
            .write_all(b"\x06public\x05\x01\x00\x01\x01\x02\x03\x04\x00\x50")
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn cancelled_verification_cannot_contaminate_next_handshake() {
    // При тайм-ауте оба конца и отправитель разблокировки удаляются.
    tokio::time::timeout(Duration::from_secs(5), async {
        for http in [false, true] {
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
            let (dropped_tx, dropped_rx) = oneshot::channel();
            let drops = Arc::new(AtomicUsize::new(0));
            let verifier = Arc::new(IsolationVerifier {
                started: Mutex::new(Some(started_tx)),
                release: Mutex::new(release_rx),
                dropped: Mutex::new(Some(dropped_tx)),
                drops: Arc::clone(&drops),
            });
            let (mut server, mut client) = duplex(1024);
            write_handshake(&mut client, http, true).await;
            let mut accepting = Box::pin(accept_verified(
                &mut server,
                Instant::now() + Duration::from_secs(30),
                Some(Arc::clone(&verifier)),
            ));
            std::future::poll_fn(|cx| {
                assert!(accepting.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            started_rx.await.unwrap();
            drop(accepting);
            drop(server);
            drop(client);
            assert_eq!(drops.load(Ordering::SeqCst), 0);

            let (mut next_server, mut next_client) = duplex(1024);
            write_handshake(&mut next_client, http, false).await;
            let (request, proof) = accept_verified(
                &mut next_server,
                Instant::now() + Duration::from_secs(30),
                Some(verifier),
            )
            .await
            .unwrap()
            .into_parts();
            assert_eq!(request.username(), Some("bob"));
            let proof = proof.unwrap();
            assert_eq!(proof.identity, "bob");
            drop(proof);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            release_tx.send(()).unwrap();
            dropped_rx.await.unwrap();
            assert_eq!(drops.load(Ordering::SeqCst), 2);
        }
    })
    .await
    .expect("cancellation isolation exceeded 5 seconds");
}

struct Verifier {
    mismatch: bool,
    panic: bool,
}
impl ProofVerifier for Verifier {
    type Proof = String;
    fn verify_proof(&self, username: &str, password: &str) -> Option<String> {
        assert!(!self.panic);
        (password == "public").then(|| {
            if self.mismatch {
                "other".into()
            } else {
                username.into()
            }
        })
    }
    fn username<'a>(&self, proof: &'a String) -> &'a str {
        proof
    }
}

#[tokio::test]
async fn socks_and_http_return_only_matching_proofs() {
    for http in [false, true] {
        for (mismatch, panic, password_ok) in [
            (false, false, true),
            (true, false, true),
            (false, true, true),
            (false, false, false),
        ] {
            let (mut server, mut client) = duplex(1024);
            if http {
                let header = if password_ok {
                    "YWxpY2U6cHVibGlj"
                } else {
                    "YWxpY2U6d3Jvbmc="
                };
                client.write_all(format!("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {header}\r\n\r\n").as_bytes()).await.unwrap();
            } else {
                client
                    .write_all(&[5, 1, 2, 1, 5, b'a', b'l', b'i', b'c', b'e'])
                    .await
                    .unwrap();
                if password_ok {
                    client.write_all(b"\x06public").await.unwrap();
                } else {
                    client.write_all(b"\x05wrong").await.unwrap();
                }
                client
                    .write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
                    .await
                    .unwrap();
            }
            let result = accept_verified(
                &mut server,
                Instant::now() + Duration::from_secs(5),
                Some(Arc::new(Verifier { mismatch, panic })),
            )
            .await;
            if !mismatch && !panic && password_ok {
                let (request, proof) = result.unwrap().into_parts();
                assert_eq!(request.username(), Some("alice"));
                assert_eq!(proof.as_deref(), Some("alice"));
            } else {
                assert!(result.is_err());
            }
        }
    }
}

struct DropTrackingVerifier {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl ProofVerifier for DropTrackingVerifier {
    type Proof = TrackedProof;

    fn verify_proof(&self, username: &str, password: &str) -> Option<Self::Proof> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!((username, password), ("alice", "public"));
        Some(TrackedProof {
            identity: "alice",
            drops: Arc::clone(&self.drops),
            dropped: None,
        })
    }

    fn username<'a>(&self, proof: &'a Self::Proof) -> &'a str {
        proof.identity
    }
}

#[tokio::test]
async fn incomplete_and_expired_never_return_proof() {
    let (mut server, mut client) = duplex(256);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let verifier = Arc::new(DropTrackingVerifier {
        calls: Arc::clone(&calls),
        drops: Arc::clone(&drops),
    });
    let (result, ()) = tokio::join!(
        accept_verified(
            &mut server,
            Instant::now() + Duration::from_secs(5),
            Some(verifier),
        ),
        async {
            client.write_all(b"\x05\x01\x02").await.unwrap();
            let mut reply = [0; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 2]);
            client.write_all(b"\x01\x05alice\x06public").await.unwrap();
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [1, 0]);
            client.write_all(b"\x05\x01\x00\x01\x01").await.unwrap();
            client.shutdown().await.unwrap();
        }
    );
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let (mut server, _client) = duplex(256);
    assert!(accept_verified(
        &mut server,
        Instant::now(),
        Some(Arc::new(Verifier {
            mismatch: false,
            panic: false
        }))
    )
    .await
    .is_err());
}
