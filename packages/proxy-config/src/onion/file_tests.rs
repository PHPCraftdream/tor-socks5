use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Config, IdentityKey, OnionServiceEntry, OnionServicePort};

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-onion-file-{}-{}-{tag}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn address(fill: char) -> String {
    format!("{}.onion", fill.to_string().repeat(56))
}

fn entry(nickname: &str, address: Option<String>, key: Option<&str>) -> OnionServiceEntry {
    OnionServiceEntry {
        nickname: nickname.to_owned(),
        enabled: true,
        address,
        key: key.map(|key| IdentityKey::new(key).unwrap()),
        circuit_hops: 4,
        ports: vec![OnionServicePort {
            onion_port: 80,
            target: "127.0.0.1:8080".to_owned(),
        }],
    }
}

#[test]
fn onion_path_uses_config_dir_and_stem() {
    let path = Config::onion_path(std::path::Path::new("some/dir/node.ktav"));
    assert_eq!(
        path,
        std::path::Path::new("some/dir").join("node.onion.ktav")
    );
    assert_eq!(
        Config::onion_path(std::path::Path::new("tor-socks5.ktav")),
        std::path::Path::new("").join("tor-socks5.onion.ktav")
    );
}

#[test]
fn a_missing_file_means_no_services() {
    let dir = tmp_dir("missing");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, "listen: 127.0.0.1:1080\n").unwrap();
    let config = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(config.onion_services.is_empty());
    assert!(!Config::onion_path(&path).exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn services_roundtrip_with_key_and_address_through_the_file() {
    let dir = tmp_dir("roundtrip");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, "listen: 127.0.0.1:1080\n").unwrap();
    let services = vec![
        entry("web", Some(address('a')), Some("c2VjcmV0")),
        entry("api", None, None),
    ];
    Config::write_onion_services(&path, &services).unwrap();

    let text = fs::read_to_string(Config::onion_path(&path)).unwrap();
    assert!(text.contains("key: c2VjcmV0"), "{text}");
    assert!(
        text.contains(&format!("address: {}", address('a'))),
        "{text}"
    );
    let config = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert_eq!(config.onion_services, services);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_main_config_does_not_carry_the_services() {
    let dir = tmp_dir("main");
    let path = dir.join("tor-socks5.ktav");
    let config = Config {
        onion_services: vec![entry("web", None, None)],
        ..Default::default()
    };
    config.write(&path).unwrap();
    let main = fs::read_to_string(&path).unwrap();
    assert!(!main.contains("onion_services"), "{main}");
    assert!(!main.contains("nickname"), "{main}");
    assert!(fs::read_to_string(Config::onion_path(&path))
        .unwrap()
        .contains("nickname: web"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn no_services_means_no_onion_file_on_write() {
    let dir = tmp_dir("none");
    let path = dir.join("tor-socks5.ktav");
    Config::default().write(&path).unwrap();
    assert!(!Config::onion_path(&path).exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_key_is_redacted_in_debug_output() {
    let service = entry("web", None, Some("c2VjcmV0"));
    let shown = format!("{service:?}");
    assert!(!shown.contains("c2VjcmV0"), "{shown}");
    assert!(shown.contains("redacted"), "{shown}");
}

#[test]
fn an_invalid_file_is_reported_with_its_path() {
    let dir = tmp_dir("invalid");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, "listen: 127.0.0.1:1080\n").unwrap();
    fs::write(
        Config::onion_path(&path),
        "services: [\n\t{\n\t\tnickname: web\n\t\taddress: not-an-address\n\t\tports: [ 80=127.0.0.1:8080 ]\n\t}\n]\n",
    )
    .unwrap();
    let error = format!("{:#}", Config::read_onion_services(&path).unwrap_err());
    assert!(error.contains("tor-socks5.onion.ktav"), "{error}");
    assert!(error.contains("services[0].address"), "{error}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn update_applies_the_change_and_returns_its_result() {
    let dir = tmp_dir("update");
    let path = dir.join("tor-socks5.ktav");
    Config::write_onion_services(&path, &[entry("web", None, None)]).unwrap();
    let count = Config::update_onion_services(&path, |services| {
        services.push(entry("api", None, None));
        Ok(services.len())
    })
    .unwrap();
    assert_eq!(count, 2);
    let stored = Config::read_onion_services(&path).unwrap();
    assert_eq!(
        stored
            .iter()
            .map(|s| s.nickname.as_str())
            .collect::<Vec<_>>(),
        ["web", "api"]
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn update_leaves_the_file_alone_when_the_result_is_invalid() {
    let dir = tmp_dir("rejected");
    let path = dir.join("tor-socks5.ktav");
    Config::write_onion_services(&path, &[entry("web", None, None)]).unwrap();
    let before = fs::read_to_string(Config::onion_path(&path)).unwrap();

    // Two services with one nickname are not a valid document.
    let error = Config::update_onion_services(&path, |services| {
        services.push(entry("web", None, None));
        Ok(())
    })
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("duplicate nickname"),
        "{error:#}"
    );
    // A failing change writes nothing either.
    let failed: anyhow::Result<()> =
        Config::update_onion_services(&path, |_| anyhow::bail!("not today"));
    assert!(failed.is_err());
    assert_eq!(
        fs::read_to_string(Config::onion_path(&path)).unwrap(),
        before
    );
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn the_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir("mode");
    let path = dir.join("tor-socks5.ktav");
    Config::write_onion_services(&path, &[entry("web", None, Some("c2VjcmV0"))]).unwrap();
    let mode = fs::metadata(Config::onion_path(&path))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let _ = fs::remove_dir_all(&dir);
}
