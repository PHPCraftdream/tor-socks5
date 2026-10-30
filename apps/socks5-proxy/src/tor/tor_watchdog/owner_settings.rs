use super::*;

/// Создаёт ограниченный шаблон владельца без сетевых операций.
/// Вызывающий код обязан проверить эффективный upstream с учётом CLI и задать pre endpoint.
pub(crate) fn restricted_owner_settings(
    cfg: &Config,
    config_path: Option<&Path>,
) -> Result<Settings> {
    restricted_owner_settings_with_override(
        cfg,
        config_path,
        std::env::var_os("TOR_PT_BINARY").as_deref(),
    )
}

fn restricted_owner_settings_with_override(
    cfg: &Config,
    config_path: Option<&Path>,
    pt_override: Option<&std::ffi::OsStr>,
) -> Result<Settings> {
    if cfg.dns_server.enabled || cfg.onion_services.iter().any(|service| service.enabled) {
        bail!("pre_socks5 is incompatible with DNS listener, onion services, or upstream egress");
    }
    if cfg.bridges.use_seeds || cfg.bridges.auto_fetch {
        bail!("pre_socks5 requires bridges.use_seeds and bridges.auto_fetch to be disabled");
    }
    if cfg.warm_pool.enabled {
        bail!("pre_socks5 is incompatible with warm_pool.enabled");
    }
    for line in &cfg.bridges.lines {
        if !line.starts_with(bridge_probe::DNS_HINT_PREFIX) {
            let bridge: BridgeLine = line.parse().context("parsing configured bridge")?;
            if bridge
                .transport
                .as_deref()
                .is_some_and(|p| !matches!(p, "obfs4" | "webtunnel"))
            {
                bail!("pre_socks5 does not support pluggable transport bridges with unknown protocols");
            }
        }
    }
    let bridges = cfg
        .bridges
        .parsed()
        .context("parsing bridges from config")?
        .bridges;
    if bridges.is_empty() {
        bail!("pre_socks5 requires at least one explicitly configured usable plain bridge");
    }
    let needs_pt = bridges.iter().any(|b| b.transport.is_some());
    let override_path = pt_binary_override_from(pt_override);
    let pt_binary = if needs_pt {
        Some(match &override_path {
            Some(path) => path.clone(),
            None => std::env::current_exe().context("resolving current_exe for PT")?,
        })
    } else {
        None
    };
    let settings = Settings {
        bridges,
        state_dir: Some(arti_base_dir(config_path)),
        pre_endpoint: None,
        pt_binary,
        stock_pt_proxy: needs_pt && override_path.is_none(),
        extra_pt_protocols: Vec::new(),
        obfs4_iat_mode: cfg.bridges.iat_mode_override(),
        ..settings_for_config(cfg)
    };
    settings.validate_stock_pt_proxy()?;
    Ok(settings)
}

/// Проверяет отличающиеся действующие pre-маршруты до сетевых операций.
/// Прямому альтернативному маршруту шаблон не нужен; вызывающий код обязан
/// проверить эффективный upstream с учётом CLI и сохранить шаблон для перезагрузки.
pub(crate) fn validate_owner_routes(
    cfg: &Config,
    users: &auth::UsersConfig,
    config_path: Option<&Path>,
) -> Result<Option<Settings>> {
    let global = proxy_config::resolve_endpoint(cfg.pre_socks5.as_ref(), None);
    if users
        .users
        .iter()
        .filter(|user| user.is_enabled)
        .any(|user| {
            let effective =
                proxy_config::resolve_endpoint(cfg.pre_socks5.as_ref(), user.pre_socks5.as_ref());
            effective.is_some() && effective != global
        })
    {
        return restricted_owner_settings(cfg, config_path).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_external_override_rejected_for_pt_but_plain_is_unchanged() {
        let mut cfg = Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        let external = std::ffi::OsStr::new("external-pt");
        cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
        let plain = restricted_owner_settings_with_override(&cfg, None, Some(external)).unwrap();
        assert!(plain.pt_binary.is_none());
        assert!(!plain.stock_pt_proxy);
        cfg.bridges.lines.push(
            "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0".into(),
        );
        assert!(restricted_owner_settings_with_override(&cfg, None, Some(external)).is_err());
        let current = std::env::current_exe().unwrap();
        assert!(
            restricted_owner_settings_with_override(&cfg, None, Some(current.as_os_str())).is_err()
        );
        let stock = restricted_owner_settings_with_override(&cfg, None, None).unwrap();
        assert!(stock.stock_pt_proxy);
        assert_eq!(stock.pt_binary, Some(current));
    }

    #[test]
    fn restricted_owner_rejects_unknown_raw_transport_before_filtering() {
        let mut cfg = Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        cfg.bridges.lines = vec![
            "8.8.8.8:443 1111111111111111111111111111111111111111".into(),
            "unknownpt [2001:db8::20]:443 2222222222222222222222222222222222222222".into(),
        ];
        assert!(restricted_owner_settings(&cfg, None).is_err());
    }

    #[test]
    fn restricted_owner_template_rejects_unusable_bridges() {
        let mut cfg = Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        cfg.bridges.lines.clear();
        assert!(restricted_owner_settings(&cfg, None).is_err());
        cfg.bridges.lines.push("not a bridge".into());
        assert!(restricted_owner_settings(&cfg, None).is_err());

        let filtered = "[2001:db8::20]:443 2222222222222222222222222222222222222222";
        assert!(filtered.parse::<BridgeLine>().is_ok());
        cfg.bridges.lines = vec![filtered.into()];
        let parsed = cfg.bridges.parsed().unwrap();
        assert!(parsed.bridges.is_empty());
        assert_eq!(parsed.rejected, 1);
        assert!(restricted_owner_settings(&cfg, None).is_err());

        let accepted = [
            "192.0.2.20:443 2222222222222222222222222222222222222222",
            "8.8.8.8:443 3333333333333333333333333333333333333333",
            "[2606:4700:4700::1111]:443 4444444444444444444444444444444444444444",
        ];
        let expected: Vec<BridgeLine> = accepted.iter().map(|line| line.parse().unwrap()).collect();
        for (line, bridge) in accepted.iter().zip(&expected) {
            cfg.bridges.lines = vec![(*line).into()];
            assert_eq!(
                restricted_owner_settings(&cfg, None).unwrap().bridges,
                vec![bridge.clone()]
            );
        }
        cfg.bridges.lines = std::iter::once(filtered)
            .chain(accepted.iter().copied())
            .map(String::from)
            .collect();
        assert_eq!(
            restricted_owner_settings(&cfg, None).unwrap().bridges,
            expected
        );
    }
}
