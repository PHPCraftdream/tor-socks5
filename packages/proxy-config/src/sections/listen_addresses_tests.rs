use super::expand_entry;
use crate::Config;

const KEYS: [&str; 2] = ["listen", "dns_server.listen"];

fn addresses<'a>(config: &'a Config, key: &str) -> &'a [String] {
    if key == "listen" {
        &config.listen
    } else {
        &config.dns_server.listen
    }
}

fn source(key: &str, entries: &[&str], list: bool) -> String {
    if list {
        let entries = entries
            .iter()
            .map(|entry| format!("    :: {entry}\n"))
            .collect::<String>();
        format!("{key}: [\n{entries}]\n")
    } else {
        format!("{key}:: {}\n", entries[0])
    }
}

#[test]
fn parser_expands_all_hosts_with_the_final_port() {
    for (entry, expected) in [
        ("host1,host2:1080", vec!["host1:1080", "host2:1080"]),
        (
            " 127.0.0.1 , localhost , 192.0.2.1:65535 ",
            vec!["127.0.0.1:65535", "localhost:65535", "192.0.2.1:65535"],
        ),
        ("host1,host2:1", vec!["host1:1", "host2:1"]),
    ] {
        assert_eq!(expand_entry(entry).unwrap(), expected, "{entry}");
    }
}

#[test]
fn parser_preserves_every_ordinary_entry_including_port_zero() {
    for entry in [
        "127.0.0.1:0",
        "[::1]:0",
        "localhost:1080",
        "::1:0",
        "",
        " legacy ",
    ] {
        assert_eq!(expand_entry(entry).unwrap(), vec![entry], "{entry}");
    }
}

#[test]
fn both_keys_expand_scalar_and_list_shorthand() {
    for key in KEYS {
        for list in [false, true] {
            let config: Config =
                ktav::from_str(&source(key, &["127.0.0.1,localhost:1080"], list)).unwrap();
            assert_eq!(
                addresses(&config, key),
                ["127.0.0.1:1080", "localhost:1080"]
            );
        }
        // Unquoted scalar shorthand remains valid Ktav too.
        let config: Config = ktav::from_str(&format!("{key}: host1,host2:15353\n")).unwrap();
        assert_eq!(addresses(&config, key), ["host1:15353", "host2:15353"]);
    }
}

#[test]
fn both_keys_support_bracketed_ipv6_and_mixed_hosts() {
    for key in KEYS {
        for list in [false, true] {
            for (entry, expected) in [
                (
                    "[::1],[2001:db8::1]:15353",
                    vec!["[::1]:15353", "[2001:db8::1]:15353"],
                ),
                ("127.0.0.1,[::1]:1080", vec!["127.0.0.1:1080", "[::1]:1080"]),
                ("[::1],localhost:1080", vec!["[::1]:1080", "localhost:1080"]),
            ] {
                let config: Config = ktav::from_str(&source(key, &[entry], list)).unwrap();
                assert_eq!(addresses(&config, key), expected, "{key}: {entry}");
            }
        }
    }
}

#[test]
fn both_keys_preserve_ordinary_scalar_and_list_entries() {
    for key in KEYS {
        for entry in ["127.0.0.1:0", "[::1]:0", "localhost:1080"] {
            for list in [false, true] {
                let config: Config = ktav::from_str(&source(key, &[entry], list)).unwrap();
                assert_eq!(addresses(&config, key), [entry]);
            }
        }
        let config: Config = ktav::from_str(&source(key, &[], true)).unwrap();
        assert!(addresses(&config, key).is_empty());
    }
}

#[test]
fn shorthand_errors_name_the_original_entry_for_both_keys_and_forms() {
    for (entry, reason) in [
        (",host:1080", "empty host"),
        ("host,:1080", "empty host"),
        ("host,,other:1080", "empty host"),
        ("host,   :1080", "empty host"),
        ("host,other", "missing shared port"),
        ("host,other:", "missing shared port"),
        ("host,other:0", "not zero"),
        ("host,other:abc", "numeric"),
        ("host,other:+1080", "numeric"),
        ("host,other:-1", "numeric"),
        ("host,other:65536", "1..=65535"),
        ("host,other:99999999999999999999999", "1..=65535"),
        ("::1,host:1080", "bracketed"),
        ("host,::1:1080", "bracketed"),
        ("2001:db8::1,::2:1080", "bracketed"),
        ("host:1080,other:1080", "cannot include ports"),
        ("[::1,host:1080", "bracketed"),
        ("host,[::1:1080", "bracketed"),
        ("[invalid],host:1080", "invalid bracketed IPv6"),
        ("[],host:1080", "invalid bracketed IPv6"),
        ("two hosts,other:1080", "whitespace"),
    ] {
        let error = expand_entry(entry).unwrap_err();
        assert!(error.contains(entry), "{error}");
        assert!(error.contains(reason), "{error}");
        for key in KEYS {
            for list in [false, true] {
                let error = ktav::from_str::<Config>(&source(key, &[entry], list))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains(entry), "{key}: {error}");
                assert!(error.contains(reason), "{key}: {error}");
            }
        }
    }
}

#[test]
fn deduplication_keeps_first_after_expansion_across_entries() {
    for key in KEYS {
        let entries = [
            "localhost:1080",
            "127.0.0.1,localhost,127.0.0.1:1080",
            "[::1],localhost:1080",
            "127.0.0.1:1080",
            "localhost:1081",
            "localhost:1080",
        ];
        let config: Config = ktav::from_str(&source(key, &entries, true)).unwrap();
        assert_eq!(
            addresses(&config, key),
            [
                "localhost:1080",
                "127.0.0.1:1080",
                "[::1]:1080",
                "localhost:1081"
            ]
        );
        let config: Config = ktav::from_str(&source(key, &["host,host:1080"], false)).unwrap();
        assert_eq!(addresses(&config, key), ["host:1080"]);
    }
}

#[test]
fn expanded_lists_serialize_and_round_trip_for_both_keys() {
    // Generated boundary ports supplement independent expected expansion vectors.
    for port in [1, 53, 1080, 15353, 65535] {
        for list in [false, true] {
            let entry = format!("localhost,[::1],localhost:{port}");
            let input = format!(
                "{}{}",
                source("listen", &[&entry], list),
                source("dns_server.listen", &[&entry], list)
            );
            let config: Config = ktav::from_str(&input).unwrap();
            let expected = vec![format!("localhost:{port}"), format!("[::1]:{port}")];
            assert_eq!(config.listen, expected);
            assert_eq!(config.dns_server.listen, expected);
            let serialized = ktav::to_string(&config).unwrap();
            assert!(!serialized.contains(&entry), "{serialized}");
            assert!(serialized.contains("listen: ["), "{serialized}");
            let reparsed: Config = ktav::from_str(&serialized).unwrap();
            assert_eq!(reparsed.listen, expected);
            assert_eq!(reparsed.dns_server.listen, expected);
        }
    }
}
