use std::process::Stdio;
use std::time::Duration;

#[tokio::test]
async fn library_entrypoint_preserves_host_policy() {
    const CHILD: &str = "LYREBIRD_EMBEDDING_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let _guard = safelog::disable_safe_logging().unwrap();
        lyrebird::run_from_env().await.unwrap();
        assert_eq!(
            format!("{}", safelog::sensitive("host-policy")),
            "host-policy"
        );
        return;
    }

    let state = std::env::temp_dir().join(format!("lyrebird-embedding-{}", std::process::id()));
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "library_entrypoint_preserves_host_policy",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("TOR_PT_STATE_LOCATION", &state)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", "unsupported-test-transport")
        .env_remove("TOR_PT_SERVER_TRANSPORTS")
        .env_remove("TOR_PT_PROXY")
        .env_remove("TOR_PT_EXIT_ON_STDIN_CLOSE")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("embedded runner must finish without listeners")
        .unwrap();
    let _ = std::fs::remove_dir_all(&state);
    assert!(
        output.status.success(),
        "embedded runner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("CMETHOD-ERROR unsupported-test-transport"));
    assert!(stdout.contains("CMETHODS DONE"));
}
