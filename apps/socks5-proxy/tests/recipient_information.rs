//! Контракт встроенных сведений о лицензиях и исходниках.
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn run(args: &[&str], dir: &std::path::Path) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    let stdout = tempfile::tempfile().expect("stdout file");
    let stderr = tempfile::tempfile().expect("stderr file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_socks5-proxy"))
        .args(args)
        .current_dir(dir)
        .env_remove("TOR_PT_MANAGED_TRANSPORT_VER")
        .env("TOR_SOCKS5_CONFIG", dir.join("missing").join("config"))
        .stdout(Stdio::from(stdout.try_clone().expect("clone stdout")))
        .stderr(Stdio::from(stderr.try_clone().expect("clone stderr")))
        .spawn()
        .expect("spawn binary");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("information command did not exit");
        }
        thread::sleep(Duration::from_millis(50));
    };
    use std::io::{Read, Seek, SeekFrom};
    let read = |mut file: fs::File| {
        file.seek(SeekFrom::Start(0)).expect("rewind output");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read output");
        bytes
    };
    (status, read(stdout), read(stderr))
}

#[test]
fn information_options_emit_exact_embedded_bytes_without_startup() {
    let dir = tempfile::tempdir().expect("temporary directory");
    for (flag, expected) in [
        (
            "--licenses",
            &include_bytes!(concat!(env!("OUT_DIR"), "/notices.txt"))[..],
        ),
        (
            "--source-info",
            &include_bytes!(concat!(env!("OUT_DIR"), "/source-info.txt"))[..],
        ),
    ] {
        let (status, stdout, stderr) = run(&["--config", "missing/config", flag], dir.path());
        assert!(
            status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, expected, "{flag}");
        assert!(
            stderr.is_empty(),
            "{flag}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(!expected.is_empty());
        assert!(fs::read_dir(dir.path())
            .expect("read directory")
            .next()
            .is_none());
    }
}

#[test]
fn information_options_conflict() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (status, stdout, stderr) = run(&["--licenses", "--source-info"], dir.path());
    assert!(!status.success());
    assert!(stdout.is_empty());
    let error = String::from_utf8(stderr).expect("UTF-8 error");
    assert!(error.contains("--licenses"));
    assert!(error.contains("--source-info"));
}

#[test]
fn help_lists_information_options() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (status, stdout, _) = run(&["--help"], dir.path());
    assert!(status.success());
    let help = String::from_utf8(stdout).expect("UTF-8 help");
    assert!(help.contains("--licenses"));
    assert!(help.contains("--source-info"));
}
