//! Behavioral regressions for the local directory body patches.
// tor-socks5 local patch: body_regressions
use super::*;
use tor_rtmock::{MockRuntime, io::stream_pair};

/// Progress resets the deadline even beyond the old total budget.
// tor-socks5 local patch: body_progress_regression
#[test]
fn body_progress_resets_idle_timeout() {
    MockRuntime::test_with_various(|rt| async move {
        let (reader, mut writer) = stream_pair();
        let mut output = Vec::new();
        {
            let read = read_and_decompress(&rt, reader, 100, &mut output);
            futures::pin_mut!(read);
            assert!(futures::poll!(&mut read).is_pending());
            for byte in b"abc" {
                rt.advance_by(Duration::from_secs(60)).await;
                assert!(futures::poll!(&mut read).is_pending());
                writer.write_all(&[*byte]).await.expect("write body byte");
                assert!(futures::poll!(&mut read).is_pending());
            }
            writer.close().await.expect("close body");
            read.await.expect("progressing body completes");
        }
        assert_eq!(output, b"abc");
    });
}

/// A stall survives 89 seconds and fails after the 90-second bound.
// tor-socks5 local patch: body_idle_regression
#[test]
fn body_idle_timeout() {
    MockRuntime::test_with_various(|rt| async move {
        let (reader, _held_open) = stream_pair();
        let mut output = Vec::new();
        {
            let read = read_and_decompress(&rt, reader, 100, &mut output);
            futures::pin_mut!(read);
            assert!(futures::poll!(&mut read).is_pending());
            rt.advance_by(Duration::from_secs(89)).await;
            assert!(futures::poll!(&mut read).is_pending());
            rt.advance_by(Duration::from_secs(2)).await;
            assert!(matches!(read.await, Err(RequestError::DirTimeout)));
        }
        assert!(output.is_empty());
    });
}

/// Header stalls retain their independent ten-second total timeout.
// tor-socks5 local patch: header_timeout_regression
#[test]
fn stalled_headers_timeout_independently() {
    MockRuntime::test_with_various(|rt| async move {
        let (reader, mut writer) = stream_pair();
        let mut reader = BufReader::new(reader);
        let read = read_headers(&rt, &mut reader);
        futures::pin_mut!(read);
        assert!(futures::poll!(&mut read).is_pending());
        rt.advance_by(Duration::from_secs(6)).await;
        writer
            .write_all(b"HTTP/1.0 200 OK\r\n")
            .await
            .expect("partial headers");
        assert!(futures::poll!(&mut read).is_pending());
        rt.advance_by(Duration::from_secs(5)).await;
        assert!(matches!(read.await, Err(RequestError::DirTimeout)));
    });
}

/// Declared wire length ends identity and compressed bodies without EOF.
// tor-socks5 local patch: bounded_body_regression
#[test]
fn content_length_completes_on_open_connection() {
    MockRuntime::test_with_various(|rt| async move {
        let member = hex::decode("789cf3cf4b5548cb2cce500829cf8730825253200ca79c52881c00e5970c88")
            .expect("zlib fixture");
        for (encoding, body, expected) in [
            ("identity", b"abc".as_slice(), b"abc".as_slice()),
            (
                "deflate",
                member.as_slice(),
                b"One fish Two fish Red fish Blue fish".as_slice(),
            ),
        ] {
            let (mut client, mut server) = stream_pair();
            let headers = format!(
                "HTTP/1.0 200 OK\r\ncontent-length: {}\r\nContent-Encoding: {encoding}\r\n\r\n",
                body.len()
            );
            server.write_all(headers.as_bytes()).await.expect("headers");
            server.write_all(body).await.expect("body");
            server
                .write_all(b"not part of this body")
                .await
                .expect("trailing bytes");
            let req: request::MicrodescRequest = vec![[9; 32]].into_iter().collect();
            let response = rt
                .timeout(
                    Duration::from_secs(1),
                    send_request(&rt, &req, &mut client, None),
                )
                .await
                .expect("must not wait for EOF")
                .expect("response");
            assert!(!response.is_partial());
            assert!(response.error().is_none());
            assert_eq!(response.output_unchecked(), expected);
        }
    });
}

/// EOF before declared wire length fails even after a complete compressed member.
// tor-socks5 local patch: truncated_body_regression
#[test]
fn content_length_early_eof() {
    use tor_error::{ErrorKind, HasKind};
    let member = hex::decode("789cf3cf4b5548cb2cce500829cf8730825253200ca79c52881c00e5970c88")
        .expect("fixture");
    for (encoding, body) in [
        ("identity", b"abc".as_slice()),
        ("deflate", member.as_slice()),
    ] {
        for count in [1, 2] {
            let req: request::MicrodescRequest = vec![[9; 32]; count].into_iter().collect();
            let mut text = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nContent-Encoding: {encoding}\r\n\r\n",
                body.len() + 7
            )
            .into_bytes();
            text.extend_from_slice(body);
            let (response, request) = super::test::run_download_test(req, &text);
            assert!(request.is_ok());
            let error = if count == 1 {
                let error = response.expect_err("single-object truncation fails");
                assert!(error.should_retire_circ());
                match error {
                    Error::RequestFailed(e) => e.error,
                    other => panic!("unexpected error: {other:?}"),
                }
            } else {
                let response = response.expect("partial response");
                assert!(response.is_partial());
                response.error().expect("partial error").clone()
            };
            assert!(matches!(error, RequestError::TruncatedBody(7)), "{error:?}");
            assert_eq!(error.kind(), ErrorKind::TorProtocolViolation);
            assert!(error.should_retire_circ());
            #[cfg(any(feature = "hs-client", feature = "hs-service"))]
            assert!(error.should_report_as_suspicious_if_anon());
        }
    }
}

/// Preserve the old regression's oracle: only the first member belongs to this HTTP body.
// tor-socks5 local patch: old_undercount_regression
#[test]
fn test_content_length_undercount_truncates_silently() {
    let member = hex::decode("789cf3cf4b5548cb2cce500829cf8730825253200ca79c52881c00e5970c88")
        .expect("fixture");
    let mut text = format!(
        "HTTP/1.0 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: {}\r\n\r\n",
        member.len()
    )
    .into_bytes();
    text.extend_from_slice(&member);
    text.extend_from_slice(&member);
    let req: request::MicrodescRequest = vec![[9; 32]; 2].into_iter().collect();
    let (response, request) = super::test::run_download_test(req, &text);
    assert!(request.is_ok());
    assert_eq!(
        response.expect("bounded response").output_unchecked(),
        b"One fish Two fish Red fish Blue fish"
    );
}
