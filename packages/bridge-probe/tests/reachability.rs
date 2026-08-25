use std::time::Duration;

use bridge_probe::{probe_all, Outcome};
use tokio::net::TcpListener;

#[tokio::test]
async fn local_tcp_probe_reports_live_bridge_and_skips_documentation_address() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind local listener");
    let live_addr = listener.local_addr().expect("listener address");
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let live: bridge_line::BridgeLine =
        format!("obfs4 {live_addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0")
            .parse()
            .expect("live bridge syntax");
    // A plain bridge on a 2001:db8::/32 ORPort is a real documentation
    // placeholder. (A webtunnel line with the same ORPort is legitimate — its
    // endpoint lives in url= — and is covered by the unit tests.)
    let documentation: bridge_line::BridgeLine =
        "obfs4 [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
            .parse()
            .expect("documentation bridge syntax");

    let reports = probe_all(vec![live, documentation], Duration::from_secs(1)).await;
    accept_task.await.expect("accept task");

    assert_eq!(reports.len(), 2);
    assert!(reports.iter().any(|report| report.is_reachable()));
    assert!(reports.iter().any(|report| {
        matches!(&report.outcome, Outcome::Unreachable { reason } if reason.contains("documentation"))
    }));
}
