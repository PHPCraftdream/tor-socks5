use serde::{Deserialize, Serialize};

/// Tor circuit configuration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TorConfig {
    /// Desired circuit length; only 2 or 3 are permitted. Default `3`.
    #[serde(deserialize_with = "circuit_hops")]
    pub circuit_hops: u8,
}

fn circuit_hops<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u8::deserialize(deserializer).map_err(|_| {
        serde::de::Error::custom("tor.circuit_hops must be an integer; permitted values are 2 or 3")
    })?;
    if matches!(value, 2 | 3) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("tor.circuit_hops must be 2 or 3"))
    }
}

impl Default for TorConfig {
    fn default() -> Self {
        Self { circuit_hops: 3 }
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    #[test]
    fn tor_circuit_hops_defaults_without_or_with_empty_tor_section() {
        let omitted: Config =
            ktav::from_str("listen: 127.0.0.1:1080\n").expect("omitted tor section parses");
        assert_eq!(omitted.tor.circuit_hops, 3);
        let empty_tor: Config =
            ktav::from_str("tor: {}\n").expect("empty tor section parses as defaults");
        assert_eq!(empty_tor.tor.circuit_hops, 3);
    }

    #[test]
    fn tor_circuit_hops_defaults_to_three_and_accepts_two_or_three() {
        assert_eq!(Config::default().tor.circuit_hops, 3);
        for (value, expected) in [("2", 2), ("3", 3)] {
            let cfg: Config = ktav::from_str(&format!("tor.circuit_hops: {value}\n"))
                .expect("valid circuit_hops parses");
            assert_eq!(cfg.tor.circuit_hops, expected);
        }
    }

    #[test]
    fn tor_circuit_hops_rejects_invalid_values_and_non_integer_types() {
        for value in ["0", "1", "4", "255", "-1", "256", "\"3\""] {
            let err = ktav::from_str::<Config>(&format!("tor.circuit_hops: {value}\n"))
                .expect_err("invalid circuit_hops must fail");
            let message = format!("{err:#}");
            assert!(message.contains("circuit_hops"), "{message}");
            assert!(message.contains("tor"), "{message}");
            assert!(message.contains("2") && message.contains("3"), "{message}");
        }
    }

    #[test]
    fn tor_circuit_hops_roundtrips_through_write() {
        let dir =
            std::env::temp_dir().join(format!("tor-circuit-hops-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("tor-socks5.ktav");
        let mut cfg = Config::default();
        cfg.tor.circuit_hops = 2;
        cfg.write(&path).expect("write");
        let loaded = Config::load_with_override(Some(&path))
            .expect("load")
            .into_config();
        assert_eq!(loaded.tor.circuit_hops, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
