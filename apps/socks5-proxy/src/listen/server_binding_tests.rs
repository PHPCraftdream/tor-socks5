use super::*;

#[test]
fn only_local_availability_errors_are_skippable() {
    for kind in [
        ErrorKind::AddrInUse,
        ErrorKind::PermissionDenied,
        ErrorKind::AddrNotAvailable,
    ] {
        assert!(skippable(kind), "{kind:?}");
    }
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::Other,
        ErrorKind::Interrupted,
        ErrorKind::TimedOut,
        ErrorKind::ConnectionRefused,
        ErrorKind::Unsupported,
    ] {
        assert!(!skippable(kind), "{kind:?}");
    }
}

#[tokio::test]
async fn empty_addresses_report_empty_reasons() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let error = bind_listeners(&[]).await.unwrap_err().to_string();
        assert!(error.contains("no listen addresses configured"), "{error}");
        assert!(error.contains("addresses/reasons: []"), "{error}");
    })
    .await
    .expect("empty bind must finish");
}

#[tokio::test]
async fn invalid_address_is_hard_error_with_original_context() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let error = bind_listeners(&["not-a-socket-address".into(), "127.0.0.1:0".into()])
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "failed to bind not-a-socket-address");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            ErrorKind::InvalidInput
        );
    })
    .await
    .expect("invalid bind must finish");
}

#[tokio::test]
async fn all_occupied_errors_list_every_address_and_os_reason() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses = [
            first.local_addr().unwrap().to_string(),
            second.local_addr().unwrap().to_string(),
        ];
        let error = bind_listeners(&addresses).await.unwrap_err().to_string();
        assert!(
            error.contains("no SOCKS5 listen addresses could be bound"),
            "{error}"
        );
        for address in &addresses {
            let reason = error
                .split("; ")
                .find(|reason| reason.contains(address))
                .unwrap();
            assert!(
                reason.contains("AddrInUse") || reason.contains("PermissionDenied"),
                "{reason}"
            );
            assert!(reason.contains("os error"), "{reason}");
        }
        // The original owners remain alive, including after the all-skipped error.
        for listener in [&first, &second] {
            let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (_accepted, _) = listener.accept().await.unwrap();
            drop(client);
        }
    })
    .await
    .expect("occupied bind must finish");
}
