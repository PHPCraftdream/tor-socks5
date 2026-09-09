//! Multi-origin redirect tests over an in-memory TLS loopback. TEST-ONLY:
//! the client side uses a `dangerous()` verifier that accepts any server
//! certificate, and the throwaway self-signed ED25519 key below is embedded
//! in test code (standard loopback practice). The real fetch path keeps full
//! webpki-roots verification — see `tls_config()`.
//!
//! Handshake signature verification stays REAL: the verifier delegates to
//! the ring provider's signature verification algorithms.

use super::*;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// Throwaway self-signed ED25519 cert, CN=loopback.test. Never used outside
/// this module's in-memory loopback.
const LOOPBACK_CERT_B64: &str = "MIIBJTCB2KADAgECAhQVSI8AVC6vAjqZ4jhMF2q57wBFoDAFBgMrZXAwGDEWMBQGA1UEAwwNbG9vcGJhY2sudGVzdDAgFw0yNjA5MDgyMzA2MzFaGA8yMTI2MDgxNTIzMDYzMVowGDEWMBQGA1UEAwwNbG9vcGJhY2sudGVzdDAqMAUGAytlcAMhAJ9726wAZAJt3a3Bv3ad+ObsMh+dqXLfQZNoUxX4HY84ozIwMDAdBgNVHQ4EFgQUQcoUaivG5PYb6jVz7V1tNFa/oKQwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBAPAqpkCC9/K55caCPpeZwfKhSqG/1rGQaekl26XguQF0QxXitqo21IR7wz1IY8uzLhL4Cl/9WxNiQBHTTAngD";
const LOOPBACK_KEY_B64: &str = "MC4CAQAwBQYDK2VwBCIEIADmlskGbt55dMziA72MzYuqJJGmafIls+PF/QEp0j0l";

fn decode(b64: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    STANDARD.decode(b64).expect("valid base64")
}

/// TEST-ONLY verifier: accepts any certificate presented over the in-memory
/// loopback, but keeps handshake signature verification real via the ring
/// provider.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn test_client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS13 supported");
    Arc::new(
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth(),
    )
}

struct OriginScript {
    acceptor: tokio_rustls::TlsAcceptor,
    responses: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

/// In-memory TLS server pool: one origin per (host, port), each scripted
/// with the sequence of raw HTTP responses to serve, one per request.
pub(super) struct TestServer {
    origins: HashMap<(String, u16), OriginScript>,
    requests: Arc<Mutex<Vec<(String, u16, String)>>>,
}

impl TestServer {
    fn new() -> Self {
        Self {
            origins: HashMap::new(),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_origin(&mut self, host: &str, port: u16, responses: Vec<String>) {
        // Single throwaway cert/key reused for every origin: the test client
        // accepts any certificate anyway.
        let certs = vec![CertificateDer::from(decode(LOOPBACK_CERT_B64))];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode(LOOPBACK_KEY_B64)));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("valid test cert/key");
        self.origins.insert(
            (host.to_string(), port),
            OriginScript {
                acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
                responses: Arc::new(Mutex::new(
                    responses.into_iter().map(String::into_bytes).collect(),
                )),
            },
        );
    }

    fn requests(&self) -> MutexGuard<'_, Vec<(String, u16, String)>> {
        self.requests.lock().expect("requests log lock")
    }

    pub(super) async fn connect(&self, host: &str, port: u16) -> Result<BoxedIo, FetchError> {
        let script = self
            .origins
            .get(&(host.to_string(), port))
            .ok_or_else(|| FetchError::Http(format!("unexpected test origin {host}:{port}")))?;
        let (client_half, server_half) = tokio::io::duplex(64 * 1024);

        let acceptor = script.acceptor.clone();
        let responses = script.responses.clone();
        let requests = self.requests.clone();
        let host = host.to_string();
        tokio::spawn(async move {
            let mut tls = match acceptor.accept(server_half).await {
                Ok(tls) => tls,
                Err(_) => return,
            };
            // Read one GET request: no body, so headers-end is request-end.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match tls.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            requests.lock().expect("requests log lock").push((
                host,
                port,
                String::from_utf8_lossy(&buf).to_string(),
            ));
            let next = responses.lock().expect("responses lock").pop_front();
            if let Some(resp) = next {
                use tokio::io::AsyncWriteExt;
                let _ = tls.write_all(&resp).await;
                let _ = tls.flush().await;
            }
            // Dropping `tls` closes the connection, which the fetch loop
            // treats as end-of-body.
        });

        Ok(Box::pin(client_half) as BoxedIo)
    }
}

async fn run_fetch(srv: &TestServer, url: &str, allow_cross: bool) -> Result<String, FetchError> {
    let headers = vec!["Authorization: Bearer tok".to_string()];
    let cookies = vec!["sid=abc".to_string()];
    tokio::time::timeout(
        Duration::from_secs(10),
        super::fetch_one_inner(
            &super::Connector::Test(srv),
            url,
            test_client_config(),
            1024 * 1024,
            &headers,
            &cookies,
            allow_cross,
        ),
    )
    .await
    .expect("fetch must not hang")
}

fn ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn redirect(loc: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\n\r\n")
}

#[tokio::test]
async fn redirect_to_new_origin_drops_credentials() {
    let mut srv = TestServer::new();
    srv.add_origin("a.test", 443, vec![redirect("https://b.test/next")]);
    srv.add_origin("b.test", 443, vec![ok("bridges")]);

    let body = run_fetch(&srv, "https://a.test/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 2);
    let (h0, p0, req0) = &log[0];
    assert_eq!((h0.as_str(), *p0), ("a.test", 443));
    assert!(req0.contains("Authorization: Bearer tok\r\n"));
    assert!(req0.contains("Cookie: sid=abc\r\n"));
    let (h1, p1, req1) = &log[1];
    assert_eq!((h1.as_str(), *p1), ("b.test", 443));
    assert!(req1.contains("Host: b.test\r\n"));
    assert!(!req1.contains("Authorization:"));
    assert!(!req1.contains("Cookie:"));
}

#[tokio::test]
async fn redirect_same_host_other_port_drops_credentials() {
    let mut srv = TestServer::new();
    srv.add_origin("a.test", 443, vec![redirect("https://a.test:8443/x")]);
    srv.add_origin("a.test", 8443, vec![ok("bridges")]);

    let body = run_fetch(&srv, "https://a.test/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 2);
    assert!(log[0].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[0].2.contains("Cookie: sid=abc\r\n"));
    assert!(log[1].2.contains("GET /x "));
    // Host header carries the explicit port — the fetch loop's request
    // builder uses the preformatted host_header from the parsed URL.
    assert!(log[1].2.contains("Host: a.test:8443\r\n"));
    assert!(!log[1].2.contains("Host: a.test\r\n"));
    assert!(!log[1].2.contains("Authorization:"));
    assert!(!log[1].2.contains("Cookie:"));
}

#[tokio::test]
async fn direct_fetch_explicit_port_host_header() {
    let mut srv = TestServer::new();
    srv.add_origin("a.test", 8443, vec![ok("bridges")]);

    let body = run_fetch(&srv, "https://a.test:8443/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 1);
    assert_eq!((log[0].0.as_str(), log[0].1), ("a.test", 8443));
    assert!(log[0].2.contains("Host: a.test:8443\r\n"));
    assert!(!log[0].2.contains("Host: a.test\r\n"));
}

#[tokio::test]
async fn ipv6_explicit_port_dial_and_host_header() {
    let mut srv = TestServer::new();
    srv.add_origin("::1", 8443, vec![redirect("/next"), ok("bridges")]);

    let body = run_fetch(&srv, "https://[::1]:8443/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 2);
    // Dial host has NO brackets — a bracketed form would miss the origin
    // lookup and the fetch would fail with "unexpected test origin".
    assert_eq!(log[0].0, "::1");
    assert_eq!(log[0].1, 8443);
    assert!(log[0].2.contains("Host: [::1]:8443\r\n"));
    // Each logged entry exists only after a successful TLS handshake, so
    // these prove ServerName accepted the unbracketed dial host.
    assert_eq!(log[1].0, "::1");
    assert_eq!(log[1].1, 8443);
    // Relative-redirect reconstruction rebuilt a valid bracketed authority
    // with the explicit port.
    assert!(log[1].2.contains("Host: [::1]:8443\r\n"));
    // Same origin per dial_host+port: credentials survive both hops.
    assert!(log[0].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[0].2.contains("Cookie: sid=abc\r\n"));
    assert!(log[1].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[1].2.contains("Cookie: sid=abc\r\n"));
}

#[tokio::test]
async fn ipv6_default_port_host_header_has_no_port() {
    let mut srv = TestServer::new();
    srv.add_origin("::1", 443, vec![ok("bridges")]);

    let body = run_fetch(&srv, "https://[::1]/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].0, "::1");
    assert_eq!(log[0].1, 443);
    assert!(log[0].2.contains("Host: [::1]\r\n"));
    assert!(!log[0].2.contains("Host: [::1]:443"));
}

#[tokio::test]
async fn relative_redirect_keeps_credentials() {
    let mut srv = TestServer::new();
    srv.add_origin("a.test", 443, vec![redirect("/next"), ok("bridges")]);

    let body = run_fetch(&srv, "https://a.test/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 2);
    assert!(log[0].2.contains("GET /bridges "));
    assert!(log[0].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[1].2.contains("GET /next "));
    assert!(log[1].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[1].2.contains("Cookie: sid=abc\r\n"));
}

#[tokio::test]
async fn cross_origin_then_relative_still_drops_credentials() {
    let mut srv = TestServer::new();
    srv.add_origin("a.test", 443, vec![redirect("https://b.test/x")]);
    srv.add_origin("b.test", 443, vec![redirect("/y"), ok("bridges")]);

    let body = run_fetch(&srv, "https://a.test/bridges", false)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 3);
    assert!(log[0].2.contains("Authorization: Bearer tok\r\n"));
    // Hop 1: cross-origin absolute redirect — credentials dropped.
    assert!(log[1].2.contains("GET /x "));
    assert!(!log[1].2.contains("Authorization:"));
    assert!(!log[1].2.contains("Cookie:"));
    // Hop 2: relative redirect on the *new* origin stays credential-free —
    // the boundary is the original origin, not the previous hop.
    assert!(log[2].2.contains("GET /y "));
    assert!(!log[2].2.contains("Authorization:"));
    assert!(!log[2].2.contains("Cookie:"));
}

#[tokio::test]
async fn allow_flag_forwards_credentials_cross_origin() {
    let mut srv = TestServer::new();
    srv.add_origin("a.test", 443, vec![redirect("https://b.test/next")]);
    srv.add_origin("b.test", 443, vec![ok("bridges")]);

    let body = run_fetch(&srv, "https://a.test/bridges", true)
        .await
        .expect("fetch succeeds");
    assert_eq!(body, "bridges");

    let log = srv.requests();
    assert_eq!(log.len(), 2);
    assert!(log[0].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[0].2.contains("Cookie: sid=abc\r\n"));
    // Explicit opt-in: the cross-origin hop carries the credentials.
    assert!(log[1].2.contains("Authorization: Bearer tok\r\n"));
    assert!(log[1].2.contains("Cookie: sid=abc\r\n"));
}
