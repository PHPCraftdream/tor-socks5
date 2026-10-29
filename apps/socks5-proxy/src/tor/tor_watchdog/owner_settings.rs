use super::*;

/// Создаёт ограниченный шаблон владельца без сетевых операций.
/// Вызывающий код обязан проверить эффективный upstream с учётом CLI и задать pre endpoint.
pub(crate) fn restricted_owner_settings(
    cfg: &Config,
    config_path: Option<&Path>,
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
            if bridge.transport.is_some() {
                bail!("pre_socks5 does not support pluggable transport bridges");
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
    Ok(Settings {
        bridges,
        state_dir: Some(arti_base_dir(config_path)),
        pre_endpoint: None,
        pt_binary: None,
        extra_pt_protocols: Vec::new(),
        ..settings_for_config(cfg)
    })
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
    fn restricted_owner_template_rejects_unusable_bridges() {
        let mut cfg = Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        cfg.bridges.lines.clear();
        assert!(restricted_owner_settings(&cfg, None).is_err());
        cfg.bridges
            .lines
            .push("192.0.2.20:443 2222222222222222222222222222222222222222".into());
        assert!(restricted_owner_settings(&cfg, None).is_err());
    }
}
