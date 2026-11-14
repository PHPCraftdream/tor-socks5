//! Tests for the `tor.guard_spread` net-param override, split out of
//! `tests.rs` (file line limit).

use super::*;

#[test]
fn guard_spread_default_is_one_and_adds_no_override() {
    let settings = Settings::default();
    assert_eq!(settings.guard_spread, 1);
    assert!(settings.is_default());
    assert!(guard_spread_override(1).is_none());
    let mut builder = TorClientConfig::builder();
    apply_guard_spread(&mut builder, 1);
    assert!(
        !builder
            .override_net_params()
            .contains_key(GUARD_SPREAD_NET_PARAM),
        "the default spread must not add an override"
    );
}

#[test]
fn guard_spread_override_map_contains_the_entry_for_two_and_three() {
    for spread in [2, 3] {
        let mut builder = TorClientConfig::builder();
        apply_guard_spread(&mut builder, spread);
        assert_eq!(
            builder.override_net_params().get(GUARD_SPREAD_NET_PARAM),
            Some(&i32::from(spread)),
            "guard_spread {spread} must set {GUARD_SPREAD_NET_PARAM}"
        );
        let settings = Settings {
            guard_spread: spread,
            ..Default::default()
        };
        assert!(!settings.is_default());
        assert!(build_config(&settings).is_ok());
    }
}

#[test]
fn build_config_rejects_invalid_guard_spread() {
    for spread in [0, 4, u8::MAX] {
        let settings = Settings {
            guard_spread: spread,
            ..Default::default()
        };
        let error = build_config(&settings).expect_err("invalid guard_spread rejected");
        assert!(error.to_string().contains("guard_spread"), "{error}");
    }
}
