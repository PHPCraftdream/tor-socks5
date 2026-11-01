use super::*;
use std::path::PathBuf;

#[test]
fn bootstrap_raw_guard_rejects_pre_pt_config_before_construction() {
    // stock-прокси пропускает PT: raw-конфигурация собирается локально,
    // без создания клиента и без сети.
    let mut settings = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "127.0.0.9:1087".parse().unwrap(),
            None,
        )),
        pt_binary: Some(std::env::current_exe().unwrap()),
        stock_pt_proxy: true,
        extra_pt_protocols: vec!["obfs4".to_owned()],
        ..Default::default()
    };
    // build_config подключает PT только при наличии моста; используем валидную obfs4-строку.
    settings.bridges = vec![
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap(),
    ];
    let pre_pt_config = build_config(&settings).expect("stock pre-PT config builds");
    assert!(!pre_pt_config.transports().is_empty());
    assert!(pre_pt_config.channel().outbound_proxy().is_some());
    let error =
        pre_endpoint::checked_raw(pre_pt_config).expect_err("raw pre-PT one-shot must fail closed");
    assert!(error.to_string().contains("bootstrap_raw"));

    // plain-pre без PT сохраняет прежнее поведение raw-конструктора.
    let plain = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "127.0.0.9:1087".parse().unwrap(),
            None,
        )),
        ..Default::default()
    };
    let plain_config = build_config(&plain).expect("plain pre config builds");
    assert!(pre_endpoint::checked_raw(plain_config).is_ok());

    // без pre — прежнее поведение полностью сохранено.
    assert!(pre_endpoint::checked_raw(TorClientConfig::default()).is_ok());
}

#[test]
fn stock_pt_pre_guard_accepts_supported_and_rejects_untrusted() {
    let endpoint = Socks5PreEndpoint::new("127.0.0.1:1080".parse().unwrap(), None);
    let mut settings = Settings {
        pre_endpoint: Some(endpoint),
        pt_binary: Some(std::env::current_exe().unwrap()),
        stock_pt_proxy: true,
        ..Default::default()
    };
    settings.bridges = vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap()];
    for protocols in [vec!["obfs4"], vec!["webtunnel"], vec!["obfs4", "webtunnel"]] {
        settings.extra_pt_protocols = protocols.into_iter().map(str::to_owned).collect();
        assert!(
            pre_endpoint::configure_pre_endpoint(&mut TorClientConfig::builder(), &settings)
                .is_ok()
        );
    }
    for bridge in [
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0",
        "webtunnel 192.0.2.2:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/x ver=0.0.3",
    ] {
        let mut mixed = settings.clone();
        mixed.bridges.push(bridge.parse().unwrap());
        assert!(pre_endpoint::configure_pre_endpoint(&mut TorClientConfig::builder(), &mixed).is_ok());
    }
    settings.stock_pt_proxy = false;
    assert!(settings.validate_stock_pt_proxy().is_err());
    settings.stock_pt_proxy = true;
    settings.extra_pt_protocols.push("unknownpt".into());
    assert!(settings.validate_stock_pt_proxy().is_err());
    settings.extra_pt_protocols.pop();
    settings.pt_binary = Some(PathBuf::from("external-pt"));
    assert!(settings.validate_stock_pt_proxy().is_err());
}
