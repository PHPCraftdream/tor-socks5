//! Тесты грамматики, сопоставления и serde-контракта `AllowedClients`.
//!
//! Разбор проверяется через `ktav::from_str` там, где важна поверхность
//! serde/Ktav, и через `FromStr` для чистой грамматики; оба пути идут
//! через один парсер, поэтому невалидный список не может дойти до
//! `allows`.

use std::net::IpAddr;
use std::str::FromStr;

use super::AllowedClients;

fn allows_str(list: &str, peer: &str) -> bool {
    let acl: AllowedClients = list
        .parse()
        .unwrap_or_else(|e| panic!("list {list:?} must parse: {e}"));
    let peer: IpAddr = peer.parse().expect("peer is a valid IP literal");
    acl.allows(peer)
}

fn denies_str(list: &str, peer: &str) -> bool {
    !allows_str(list, peer)
}

fn rejects(list: &str) {
    assert!(
        AllowedClients::from_str(list).is_err(),
        "list {list:?} must be rejected"
    );
}

#[test]
fn default_is_allow_all() {
    let acl = AllowedClients::default();
    assert_eq!(acl.as_str(), "*");
    assert!(acl.allows("127.0.0.1".parse().unwrap()));
    assert!(acl.allows("10.0.0.1".parse().unwrap()));
    assert!(acl.allows("2001:db8::1".parse().unwrap()));
    assert!(acl.allows("::ffff:10.0.0.1".parse().unwrap()));
}

#[test]
fn star_allows_everything() {
    assert!(allows_str("*", "127.0.0.1"));
    assert!(allows_str("*", "8.8.8.8"));
    assert!(allows_str("*", "fe80::1"));
    assert!(allows_str("*", "::ffff:8.8.8.8"));
}

#[test]
fn star_does_not_short_circuit_validation() {
    rejects("* , invalid");
    rejects("*, 192.168.1*");
    rejects("*,");
}

#[test]
fn exact_ipv4() {
    assert!(allows_str("192.168.1.5", "192.168.1.5"));
    assert!(denies_str("192.168.1.5", "192.168.1.6"));
    assert!(denies_str("192.168.1.5", "10.0.0.1"));
}

#[test]
fn exact_ipv6_compressed_and_expanded_are_the_same_rule() {
    let expanded: AllowedClients = "2001:db8:0:0:0:0:0:1".parse().unwrap();
    assert!(expanded.allows("2001:db8::1".parse().unwrap()));
    let compressed: AllowedClients = "2001:db8::1".parse().unwrap();
    assert!(compressed.allows("2001:db8:0:0:0:0:0:1".parse().unwrap()));
    assert!(denies_str("2001:db8::1", "2001:db8::2"));
}

#[test]
fn exact_mapped_address_normalizes() {
    // Правило и пир — один и тот же адрес ::ffff:127.0.0.1 в двух
    // записях; нормализация не должна ломать сопоставление.
    assert!(allows_str("::ffff:127.0.0.1", "::ffff:127.0.0.1"));
    assert!(allows_str("::ffff:127.0.0.1", "127.0.0.1"));
    assert!(denies_str("::ffff:127.0.0.1", "::ffff:127.0.0.2"));
}

#[test]
fn ipv4_compatible_ipv6_is_not_mapped() {
    // "::10.0.0.1" разбирается std как обычный IPv6-адрес (без префикса
    // ffffff): v4-правило не должно совпадать, точное v6-правило — должно.
    assert!(denies_str("10.0.0.1", "::10.0.0.1"));
    assert!(allows_str("::10.0.0.1", "::10.0.0.1"));
    assert!(denies_str("::10.0.0.1", "10.0.0.1"));
}

#[test]
fn loopback_rule() {
    let list = "loopback";
    assert!(allows_str(list, "127.0.0.1"));
    assert!(allows_str(list, "127.2.3.4"));
    assert!(allows_str(list, "::1"));
    // Mapped-loopback пир сначала нормализуется в 127.0.0.1.
    assert!(allows_str(list, "::ffff:127.0.0.1"));
    assert!(denies_str(list, "10.0.0.1"));
    assert!(denies_str(list, "192.168.1.1"));
    assert!(denies_str(list, "fe80::1"));
    assert!(denies_str(list, "::2"));
}

#[test]
fn loopback_is_case_sensitive() {
    rejects("Loopback");
    rejects("LOOPBACK");
}

#[test]
fn loopback_tokens_can_repeat() {
    let acl: AllowedClients = "loopback,loopback".parse().expect("duplicates allowed");
    assert!(acl.allows("127.0.0.1".parse().unwrap()));
    assert!(acl.allows("::1".parse().unwrap()));
    assert!(!acl.allows("10.0.0.1".parse().unwrap()));
}

#[test]
fn duplicates_are_allowed_without_dedup() {
    let acl: AllowedClients = "1.2.3.4,1.2.3.4".parse().expect("duplicates allowed");
    assert!(acl.allows("1.2.3.4".parse().unwrap()));
}

#[test]
fn ipv4_wildcard_full_mask() {
    assert!(allows_str("192.168.*.*", "192.168.0.0"));
    assert!(allows_str("192.168.*.*", "192.168.255.255"));
    assert!(denies_str("192.168.*.*", "192.169.0.1"));
    assert!(denies_str("192.168.*.*", "10.168.0.1"));
}

#[test]
fn ipv4_wildcard_shorthand() {
    // Поведенческая эквивалентность `192.168.*` и `192.168.*.*`:
    // одинаковые позитивы и негативы.
    assert!(allows_str("192.168.*", "192.168.44.3"));
    assert!(allows_str("192.168.*", "192.168.0.0"));
    assert!(denies_str("192.168.*", "192.169.0.1"));
    assert!(denies_str("192.168.*", "10.168.0.1"));
    assert!(allows_str("192.168.*.*", "192.168.44.3"));
    assert!(allows_str("192.168.*.*", "192.168.0.0"));
    assert!(denies_str("192.168.*.*", "192.169.0.1"));
    assert!(denies_str("192.168.*.*", "10.168.0.1"));
    // Исходная орфография shorthand сохраняется.
    let acl: AllowedClients = "192.168.*".parse().unwrap();
    assert_eq!(acl.as_str(), "192.168.*");
    assert!(allows_str("127.*", "127.0.0.1"));
    assert!(allows_str("127.*", "127.255.255.255"));
    // Привязка: не должно перетекать в соседние префиксы.
    assert!(denies_str("127.*", "128.0.0.1"));
    assert!(denies_str("127.*", "12.7.0.1"));
}

#[test]
fn ipv4_wildcard_last_octet_only() {
    assert!(allows_str("192.168.1.*", "192.168.1.200"));
    assert!(denies_str("192.168.1.*", "192.168.2.1"));
}

#[test]
fn ipv4_wildcard_leading_zeros_rejected() {
    rejects("192.168.01.*");
    rejects("192.168.1.01");
    // Сам "0" — единственная допустимая форма нуля с ведущими нулями.
    assert!(allows_str("192.168.0.0", "192.168.0.0"));
}

#[test]
fn ipv4_wildcard_shorthand_requires_terminal_star() {
    rejects("127.1");
    rejects("192.168.1");
}

#[test]
fn ipv4_wildcard_component_errors() {
    rejects("192.168.1.2.3");
    rejects("192.168.1.256");
    rejects("192.168.1*");
    rejects("192.168.1.**");
    rejects("1.2.3.-1");
    rejects("1.2.3.+1");
    rejects("1.2.3.0x1");
    rejects("1.2.3.4.5");
}

#[test]
fn ipv6_wildcard_prefix_and_terminal_star_are_distinct() {
    // "2001:db8::*": первые 6 hextet'ов фиксированы (включая нули),
    // последний — любой.
    assert!(allows_str("2001:db8::*", "2001:db8:0:0:0:0:0:1"));
    assert!(denies_str("2001:db8::*", "2001:db8:1:0:0:0:0:1"));
    // "2001:db8:*": первые 2 фиксированы, весь хвост — любой.
    assert!(allows_str("2001:db8:*", "2001:db8:1:2:3:4:5:6"));
    assert!(denies_str("2001:db8:*", "2001:db7:1:2:3:4:5:6"));
}

#[test]
fn ipv6_wildcard_full_8_group_mask() {
    assert!(allows_str("2001:db8:1:2:3:4:*:*", "2001:db8:1:2:3:4:5:6"));
    assert!(denies_str("2001:db8:1:2:3:4:*:*", "2001:db8:1:2:3:5:5:6"));
}

#[test]
fn ipv6_wildcard_expanded_and_compressed_peers_match() {
    let acl: AllowedClients = "2001:db8:1:2:3:4:*:*".parse().unwrap();
    assert!(acl.allows("2001:db8:1:2:3:4:ffff:ffff".parse().unwrap()));
    // Тот же пир в сжатой форме должен вести себя идентично.
    assert!(acl.allows("2001:db8:1:2:3:4:0:0".parse().unwrap()));
}

#[test]
fn double_colon_alone_is_exact_unspecified() {
    assert!(allows_str("::", "::"));
    assert!(denies_str("::", "::1"));
}

#[test]
fn ipv6_wildcard_parse_errors() {
    rejects("2001:db8:::1");
    rejects("1:2::3::4");
    rejects("1:2:3:4:5:6:7:8:9");
    rejects("1:2:3:4:5:6:7:1ffff");
    rejects("1:2:3:4:5:6:7:1*2");
    // Сокращённая форма без `::` не в начале.
    rejects("1:2:3");
    rejects("::1:2:3:4:5:6:7:8");
}

#[test]
fn mapped_wildcard_matches_v4_and_mapped_peers() {
    let list = "::ffff:192.168.*.*";
    assert!(allows_str(list, "::ffff:192.168.1.5"));
    assert!(allows_str(list, "192.168.1.5"));
    assert!(denies_str(list, "::ffff:10.0.0.1"));
    assert!(denies_str(list, "fe80::1"));
}

#[test]
fn full_hextet_mapped_wildcard_is_the_same_rule() {
    let list = "0:0:0:0:0:ffff:192.168.*.*";
    assert!(allows_str(list, "::ffff:192.168.1.5"));
    assert!(allows_str(list, "192.168.1.5"));
    assert!(denies_str(list, "::ffff:10.0.0.1"));
}

#[test]
fn non_mapped_v6_wildcard_never_matches_ipv4_peer() {
    // Первые 6 hextet'ов — не ровно ::ffff:, поэтому это чистая IPv6-маска
    // и не должна совпадать с IPv4-пирами.
    let list = "2001:db8:*:*:*:*:*:*";
    assert!(allows_str(list, "2001:db8:1:2:3:4:5:6"));
    assert!(denies_str(list, "192.168.1.1"));
    assert!(denies_str(list, "::ffff:192.168.1.1"));
}

#[test]
fn parse_errors() {
    rejects("");
    rejects("   ");
    rejects("a,,b");
    rejects(",* ");
    rejects("*,");
    rejects("192.168.0.0/16");
    rejects("localhost");
    rejects("example.com");
    rejects("127.0.0.1:1080");
    rejects("fe80::1%eth0");
    rejects("-1");
    rejects("+1");
    rejects("0x1");
    rejects("01");
}

#[test]
fn error_message_names_the_token() {
    let err = "192.168.1*".parse::<AllowedClients>().unwrap_err();
    let text = err.to_string();
    assert!(text.contains("192.168.1*"), "message: {text}");
    assert!(text.contains("allowed_clients"), "message: {text}");
}

#[test]
fn ktav_roundtrip_preserves_source_and_behaviour() {
    let acl: AllowedClients = ktav::from_str("192.168.*").expect("ktav parses");
    assert_eq!(acl.as_str(), "192.168.*");
    let text = ktav::to_string(&acl).expect("ktav serialises");
    assert!(text.contains("192.168.*"), "serialised: {text}");
    let restored: AllowedClients = ktav::from_str(&text).expect("ktav reparses");
    assert_eq!(restored, acl);
    assert!(restored.allows("192.168.9.9".parse().unwrap()));
    assert!(!restored.allows("10.0.0.1".parse().unwrap()));
}

#[test]
fn ktav_default_when_key_absent() {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Section {
        allowed_clients: AllowedClients,
    }
    // Пустой документ (или без ключа) должен дать `*`.
    let section: Section = ktav::from_str("").expect("empty ktav document");
    assert_eq!(section.allowed_clients.as_str(), "*");
    assert!(section.allowed_clients.allows("8.8.8.8".parse().unwrap()));
}

#[test]
fn ktav_explicit_empty_string_is_an_error() {
    // Пустая скалярная строка должна падать на ACL-валидации (пустой список),
    // а не на случайной синтаксической ошибке.
    use serde::de::value::StrDeserializer;
    use serde::Deserialize as _;
    let de = StrDeserializer::<serde::de::value::Error>::new("");
    let err = AllowedClients::deserialize(de).unwrap_err();
    assert!(
        err.to_string().contains("allowed_clients") || err.to_string().contains("list is empty"),
        "ошибка должна указывать на ACL-валидацию: {err}"
    );
}

#[test]
fn mapped_dotted_tail_per_octet_wildcards_do_not_collapse() {
    // `::ffff:192.*.1.*`: wildcards пооктетно, а не цельной маской префикса.
    assert!(allows_str("::ffff:192.*.1.*", "192.2.1.3"));
    assert!(allows_str("::ffff:192.*.1.*", "::ffff:192.2.1.3"));
    assert!(denies_str("::ffff:192.*.1.*", "193.2.1.3"));
    assert!(denies_str("::ffff:192.*.1.*", "192.2.2.3"));
}

#[test]
fn mapped_dotted_tail_leading_wildcard() {
    // `::ffff:*.168.*.5`: wildcard в старшем октете тоже сохраняется пооктетно.
    assert!(allows_str("::ffff:*.168.*.5", "10.168.7.5"));
    assert!(denies_str("::ffff:*.168.*.5", "10.169.7.5"));
    assert!(denies_str("::ffff:*.168.*.5", "10.168.7.6"));
}

#[test]
fn mapped_compressed_and_full_dotted_forms_are_identical() {
    // `::ffff:192.168.*.*` и `0:0:0:0:0:ffff:192.168.*.*` — одно правило.
    let compressed = "::ffff:192.168.*.*";
    let full = "0:0:0:0:0:ffff:192.168.*.*";
    assert!(allows_str(compressed, "192.168.1.5"));
    assert!(allows_str(full, "192.168.1.5"));
    assert!(denies_str(compressed, "192.169.1.5"));
    assert!(denies_str(full, "192.169.1.5"));
}

#[test]
fn true_full_hextet_mapped_wildcard() {
    // Полный hextet-форма `0:0:0:0:0:ffff:c0a8:*`: c0a8 == 192.168, хвост —
    // wildcard-октеты; по-прежнему IPv4-правило.
    assert!(allows_str("0:0:0:0:0:ffff:c0a8:*", "192.168.7.7"));
    assert!(denies_str("0:0:0:0:0:ffff:c0a8:*", "192.169.7.7"));
}

#[test]
fn same_peer_compressed_and_expanded_spellings_both_allowed() {
    // Правило `2001:db8::1` и один и тот же пир в двух орфографиях:
    // развёрнутой `2001:db8:0:0:0:0:0:1` и сжатой `2001:db8::1`.
    assert!(allows_str("2001:db8::1", "2001:db8:0:0:0:0:0:1"));
    assert!(allows_str("2001:db8::1", "2001:db8::1"));
}

#[test]
fn dotted_tail_with_non_mapped_prefix_is_rejected() {
    // Префикс `::1:` — не точный `::ffff:`, точечный хвост запрещён.
    rejects("::1:2.3.4.*");
}

#[test]
fn serde_serializes_the_source_string() {
    let acl: AllowedClients = " 127.*, ::1 ".parse().expect("parses");
    // Источник хранится дословно (с исходными пробелами);
    // сериализация пишет ровно эту строку.
    let text = ktav::to_string(&acl).expect("serialises");
    assert!(text.contains("127.*, ::1"), "serialised: {text}");
}
