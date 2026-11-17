use super::*;

/// Создаёт ограниченный шаблон владельца без сетевых операций.
/// Вызывающий код обязан проверить эффективный upstream с учётом CLI и задать pre endpoint.
pub fn restricted_owner_settings(
    cfg: &Config,
    config_path: &Path,
    pt: &crate::pt::PtBinary,
) -> Result<Settings> {
    restricted_owner_settings_with_policy(cfg, config_path, pt)
}

fn restricted_owner_settings_with_policy(
    cfg: &Config,
    config_path: &Path,
    pt: &crate::pt::PtBinary,
) -> Result<Settings> {
    restricted_owner_settings_with_override(
        cfg,
        config_path,
        std::env::var_os("TOR_PT_BINARY").as_deref(),
        pt,
    )
}

fn restricted_owner_settings_with_override(
    cfg: &Config,
    config_path: &Path,
    pt_override: Option<&std::ffi::OsStr>,
    pt: &crate::pt::PtBinary,
) -> Result<Settings> {
    if cfg.dns_server.enabled || cfg.onion_services.iter().any(|service| service.enabled) {
        bail!("pre_proxies is incompatible with DNS listener, onion services, or upstream egress");
    }
    if cfg.bridges.use_seeds || cfg.bridges.auto_fetch {
        bail!("pre_proxies requires bridges.use_seeds and bridges.auto_fetch to be disabled");
    }
    if cfg.warm_pool.enabled {
        bail!("pre_proxies is incompatible with warm_pool.enabled");
    }
    for line in &cfg.bridges.lines {
        if !line.starts_with(bridge_probe::DNS_HINT_PREFIX) {
            let bridge: BridgeLine = line.parse().context("parsing configured bridge")?;
            if bridge
                .transport
                .as_deref()
                .is_some_and(|p| !matches!(p, "obfs4" | "webtunnel"))
            {
                bail!("pre_proxies does not support pluggable transport bridges with unknown protocols");
            }
        }
    }
    let bridges = cfg
        .bridges
        .parsed()
        .context("parsing bridges from config")?
        .bridges;
    if bridges.is_empty() {
        bail!("pre_proxies requires at least one explicitly configured usable bridge");
    }
    let needs_pt = bridges.iter().any(|b| b.transport.is_some());
    let override_path = match pt {
        crate::pt::PtBinary::Explicit(_) => None,
        crate::pt::PtBinary::Environment => crate::pt::pt_binary_override_from(pt_override),
    };
    let explicit = matches!(pt, crate::pt::PtBinary::Explicit(_));
    let pt_binary = if needs_pt {
        Some(match pt {
            // Shared helper: same info! line and SDK14 test observer as the
            // main `build_tor_settings` resolution.
            crate::pt::PtBinary::Explicit(_) => crate::pt::resolve_pt_binary(pt)?,
            crate::pt::PtBinary::Environment => {
                // Same resolution as `tor_setup` (shared info! lines and
                // test observer) when the injected override is the real
                // process env; a synthetic override keeps the test seam
                // deterministic without touching the process env.
                let env_var = std::env::var_os("TOR_PT_BINARY");
                let env_now = env_var.as_deref();
                if pt_override == env_now {
                    crate::pt::resolve_pt_binary(pt)?
                } else {
                    match &override_path {
                        Some(path) => path.clone(),
                        None => std::env::current_exe().context("resolving current_exe for PT")?,
                    }
                }
            }
        })
    } else {
        None
    };
    let settings = Settings {
        bridges,
        state_dir: Some(arti_base_dir(config_path)),
        pre_endpoint: None,
        pt_binary,
        stock_pt_proxy: needs_pt && !explicit && override_path.is_none(),
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
pub fn validate_owner_routes(
    cfg: &Config,
    users: &auth::UsersConfig,
    config_path: &Path,
    pt: &crate::pt::PtBinary,
) -> Result<Option<Settings>> {
    let global = cfg.pre_proxies.clone();
    if users
        .users
        .iter()
        .filter(|user| user.is_enabled)
        .any(|user| {
            let effective =
                proxy_config::resolve_pool(cfg.pre_proxies.as_ref(), user.pre_proxies.as_ref());
            effective.is_some() && effective != global
        })
    {
        return restricted_owner_settings(cfg, config_path, pt).map(Some);
    }
    Ok(None)
}

/// How long each pre pool member gets to answer the startup handshake check.
const ANCHOR_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Picks the pre pool member the main Tor client bootstraps through: the first
/// one in configuration order that answers a direct handshake check.
///
/// A pool of one member is taken as it is, so a dead proxy still shows up as a
/// bootstrap failure. Only the member's position is logged, never its address.
pub(super) async fn select_anchor(
    pool: &proxy_config::ProxyPool,
) -> Result<&proxy_config::Socks5Endpoint> {
    if let Some(only) = pool.sole_member() {
        return Ok(only);
    }
    let deadline = std::time::Instant::now() + ANCHOR_PROBE_TIMEOUT;
    let answers = futures::future::join_all(pool.members().iter().map(|member| async move {
        match route_pool::proxy_config(member) {
            Ok(proxy) => {
                arti_wrapper::probe_proxy_direct(&proxy, deadline).await
                    == arti_wrapper::ProxyProbe::Alive
            }
            Err(_) => false,
        }
    }))
    .await;
    match answers.iter().position(|alive| *alive) {
        Some(index) => {
            info!(
                member = index,
                "main Tor client uses this pre proxy pool member"
            );
            Ok(&pool.members()[index])
        }
        None => bail!("no pre_proxies member answered the startup handshake check"),
    }
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
        let plain = restricted_owner_settings_with_override(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            Some(external),
            &crate::pt::PtBinary::Environment,
        )
        .unwrap();
        assert!(plain.pt_binary.is_none());
        assert!(!plain.stock_pt_proxy);
        cfg.bridges.lines.push(
            "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0".into(),
        );
        assert!(restricted_owner_settings_with_override(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            Some(external),
            &crate::pt::PtBinary::Environment
        )
        .is_err());
        let current = std::env::current_exe().unwrap();
        assert!(restricted_owner_settings_with_override(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            Some(current.as_os_str()),
            &crate::pt::PtBinary::Environment
        )
        .is_err());
        let stock = restricted_owner_settings_with_override(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            None,
            &crate::pt::PtBinary::Environment,
        )
        .unwrap();
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
        assert!(restricted_owner_settings(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            &crate::pt::PtBinary::Environment
        )
        .is_err());
    }

    #[test]
    fn restricted_owner_template_rejects_unusable_bridges() {
        let mut cfg = Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        cfg.bridges.lines.clear();
        assert!(restricted_owner_settings(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            &crate::pt::PtBinary::Environment
        )
        .is_err());
        cfg.bridges.lines.push("not a bridge".into());
        assert!(restricted_owner_settings(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            &crate::pt::PtBinary::Environment
        )
        .is_err());

        let filtered = "[2001:db8::20]:443 2222222222222222222222222222222222222222";
        assert!(filtered.parse::<BridgeLine>().is_ok());
        cfg.bridges.lines = vec![filtered.into()];
        let parsed = cfg.bridges.parsed().unwrap();
        assert!(parsed.bridges.is_empty());
        assert_eq!(parsed.rejected, 1);
        assert!(restricted_owner_settings(
            &cfg,
            std::path::Path::new("tor-socks5.ktav"),
            &crate::pt::PtBinary::Environment
        )
        .is_err());

        let accepted = [
            "192.0.2.20:443 2222222222222222222222222222222222222222",
            "8.8.8.8:443 3333333333333333333333333333333333333333",
            "[2606:4700:4700::1111]:443 4444444444444444444444444444444444444444",
        ];
        let expected: Vec<BridgeLine> = accepted.iter().map(|line| line.parse().unwrap()).collect();
        for (line, bridge) in accepted.iter().zip(&expected) {
            cfg.bridges.lines = vec![(*line).into()];
            assert_eq!(
                restricted_owner_settings(
                    &cfg,
                    std::path::Path::new("tor-socks5.ktav"),
                    &crate::pt::PtBinary::Environment
                )
                .unwrap()
                .bridges,
                vec![bridge.clone()]
            );
        }
        cfg.bridges.lines = std::iter::once(filtered)
            .chain(accepted.iter().copied())
            .map(String::from)
            .collect();
        assert_eq!(
            restricted_owner_settings(
                &cfg,
                std::path::Path::new("tor-socks5.ktav"),
                &crate::pt::PtBinary::Environment
            )
            .unwrap()
            .bridges,
            expected
        );
    }

    /// H11 acceptance: the owner template resolves the PT binary through the
    /// shared `pt::resolve_pt_binary` (same info! lines and SDK14 test
    /// observer as `build_tor_settings`). An explicit policy resolves the
    /// host's PT executable but is rejected for the pre route (PT routing
    /// through a pre proxy is only guaranteed with the stock proxy); the
    /// default `Environment` policy keeps the pre-H11 behaviour (current
    /// process executable, stock PT proxy).
    #[tokio::test]
    async fn pt_policy_resolves_via_shared_helper_and_reports_to_sdk14_observer() {
        let mut cfg = Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        cfg.bridges.lines = vec![
            "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0".into(),
        ];

        // Explicit policy: the resolution goes through the shared helper (the
        // observer sees the host's own PT executable), but the pre-route
        // template still rejects it: PT routing through a pre proxy is only
        // guaranteed with the bundled stock proxy.
        let helper = std::path::PathBuf::from("host-pt-helper");
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let error = crate::pt::SDK14_PT_OBSERVER
            .scope(("owner-settings", tx), async {
                restricted_owner_settings(
                    &cfg,
                    std::path::Path::new("tor-socks5.ktav"),
                    &crate::pt::PtBinary::Explicit(helper.clone()),
                )
                .expect_err("explicit PT must not pass the pre-route stock guarantee")
            })
            .await;
        assert!(error.to_string().contains("cannot guarantee routing"));
        assert_eq!(rx.recv().await, Some(("owner-settings", helper)));

        // Environment policy: unchanged resolution, still reported.
        let exe = std::env::current_exe().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let settings = crate::pt::SDK14_PT_OBSERVER
            .scope(("owner-settings", tx), async {
                restricted_owner_settings(
                    &cfg,
                    std::path::Path::new("tor-socks5.ktav"),
                    &crate::pt::PtBinary::Environment,
                )
                .unwrap()
            })
            .await;
        assert_eq!(settings.pt_binary, Some(exe.clone()));
        assert!(settings.stock_pt_proxy);
        assert_eq!(rx.recv().await, Some(("owner-settings", exe)));
    }
}
