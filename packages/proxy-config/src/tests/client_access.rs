use super::*;

#[test]
fn client_access_defaults_allow_everything() {
    // Старый конфиг без новых ключей сохраняет поведение: и SOCKS5-, и
    // DNS-слушатель разрешают всех (`*`); оба экземпляра независимы.
    let src = "listen: 127.0.0.1:1080\n";
    let cfg: Config = ktav::from_str(src).expect("old config remains valid");
    assert_eq!(cfg.security.client_access.allowed_clients.as_str(), "*");
    assert_eq!(cfg.dns_server.client_access.allowed_clients.as_str(), "*");
    assert!(cfg
        .security
        .client_access
        .allowed_clients
        .allows("10.0.0.1".parse().unwrap()));
    assert!(cfg
        .dns_server
        .client_access
        .allowed_clients
        .allows("10.0.0.1".parse().unwrap()));
}

#[test]
fn client_access_values_are_independent_per_listener() {
    let src = "listen: 127.0.0.1:1080\n\
               security.client_access.allowed_clients: 127.*\n\
               dns_server.client_access.allowed_clients: 192.168.*\n";
    let cfg: Config = ktav::from_str(src).expect("ktav parses client_access keys");
    assert!(cfg
        .security
        .client_access
        .allowed_clients
        .allows("127.8.8.8".parse().unwrap()));
    assert!(!cfg
        .security
        .client_access
        .allowed_clients
        .allows("192.168.1.1".parse().unwrap()));
    assert!(cfg
        .dns_server
        .client_access
        .allowed_clients
        .allows("192.168.44.3".parse().unwrap()));
    assert!(!cfg
        .dns_server
        .client_access
        .allowed_clients
        .allows("127.0.0.1".parse().unwrap()));

    // Обе орфографии независимо проходят round-trip через Ktav.
    let serialized = ktav::to_string(&cfg).expect("serialize");
    let restored: Config = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(
        restored.security.client_access.allowed_clients.as_str(),
        "127.*"
    );
    assert_eq!(
        restored.dns_server.client_access.allowed_clients.as_str(),
        "192.168.*"
    );
}

#[test]
fn client_access_explicit_empty_string_is_a_load_error() {
    // Сначала доказываем, что валидный dotted-ключ парсится и даёт ожидаемую
    // политику, — чтобы ошибка пустого значения была именно ACL-валидацией,
    // а не случайной синтаксической ошибкой.
    let valid = "listen: 127.0.0.1:1080\n\
                 security.client_access.allowed_clients: 127.*\n";
    let cfg: Config = ktav::from_str(valid).expect("valid dotted-key config parses");
    assert_eq!(cfg.security.client_access.allowed_clients.as_str(), "127.*");
    assert!(cfg
        .security
        .client_access
        .allowed_clients
        .allows("127.5.5.5".parse().unwrap()));

    // `key::` — literal-string маркер ktav: явно пустое значение обязано
    // отвергаться при загрузке, а не молча означать «наследовать» или
    // «запретить всем».
    for key in [
        "security.client_access.allowed_clients",
        "dns_server.client_access.allowed_clients",
    ] {
        let src = format!("listen: 127.0.0.1:1080\n{key}::\n");
        let error = ktav::from_str::<Config>(&src).unwrap_err().to_string();
        assert!(
            error.contains("list is empty"),
            "ожидался отказ ACL для {key}, получено: {error}"
        );
    }
}

#[test]
fn client_access_invalid_value_is_a_load_error() {
    // `192.168.1*` смешивает цифры и `*` в одном октете — отвергается
    // энергично, до старта слушателя.
    let src = "listen: 127.0.0.1:1080\nsecurity.client_access.allowed_clients: 192.168.1*\n";
    assert!(
        ktav::from_str::<Config>(src).is_err(),
        "invalid allowed_clients must be rejected at parse time"
    );
    let src = "listen: 127.0.0.1:1080\ndns_server.client_access.allowed_clients: localhost\n";
    assert!(
        ktav::from_str::<Config>(src).is_err(),
        "hostname in allowed_clients must be rejected at parse time"
    );
}

#[test]
fn security_config_clone_keeps_distinct_policies_per_listener() {
    // SecurityConfig/Clone/PartialEq/Eq на реальном клоне: клона с РАЗНЫМИ
    // явными политиками двух слушателей каждый слушатель продолжает
    // применять свою собственную.
    let cfg = Config {
        security: SecurityConfig {
            client_access: ClientAccessConfig {
                allowed_clients: "127.*".parse().expect("valid allow-list"),
            },
            ..Default::default()
        },
        dns_server: DnsServerConfig {
            client_access: ClientAccessConfig {
                allowed_clients: "192.168.*".parse().expect("valid allow-list"),
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let clone = cfg.clone();
    assert_eq!(cfg.security.client_access, clone.security.client_access);
    assert_eq!(cfg.dns_server.client_access, clone.dns_server.client_access);
    // Клонированный security пускает только 127.*, dns_server — только 192.168.*.
    assert!(clone
        .security
        .client_access
        .allowed_clients
        .allows("127.5.5.5".parse().unwrap()));
    assert!(!clone
        .security
        .client_access
        .allowed_clients
        .allows("192.168.1.1".parse().unwrap()));
    assert!(clone
        .dns_server
        .client_access
        .allowed_clients
        .allows("192.168.44.3".parse().unwrap()));
    assert!(!clone
        .dns_server
        .client_access
        .allowed_clients
        .allows("127.0.0.1".parse().unwrap()));
}
