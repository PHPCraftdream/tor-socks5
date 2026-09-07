use super::*;

pub(super) fn refresh_sources_failure(outcomes: &[bridge_fetcher::FetchOutcome]) -> Option<String> {
    if outcomes.is_empty() || outcomes.iter().all(|outcome| outcome.error.is_some()) {
        let details = outcomes
            .iter()
            .map(|outcome| {
                format!(
                    "{}: {}",
                    outcome.label,
                    outcome.error.as_deref().unwrap_or("source task failed")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(if details.is_empty() {
            "all configured bridge sources failed".to_owned()
        } else {
            format!("all configured bridge sources failed: {details}")
        })
    } else {
        None
    }
}

/// JNI entry point: `nativeRefreshBridges(String configPath)`
///
/// Fetches fresh bridge lines from `configPath`'s `bridges.sources` over the
/// **currently running** engine's live `TorTunnel` (see
/// [`engine::get_current_tunnel`]) and returns them newline-joined, one
/// `BridgeLine` per line, ready to append to `bridges.lines` on the Kotlin
/// side. Returns an empty string (not an error) if no sources are configured
/// or none of them yielded anything usable.
///
/// This is a one-shot refresh, not a background/keep-alive task: it must be
/// called again by Kotlin whenever a fresh list is wanted. It intentionally
/// does *not* touch the running engine's own bridge set or config file --
/// `bridge_fetcher::fetch_all` has no path that doesn't require an
/// already-live Tor circuit, so this can only ever help populate bridges for
/// the *next* start (or a future retry), never the current bootstrap.
///
/// - **Threading:** Blocks the calling thread for up to the fetch timeout
///   (30s) -- call off the Android main thread.
/// - **Error Signaling:** Throws `java.lang.IllegalStateException` if the
///   engine isn't currently `On` (no live tunnel to fetch through),
///   `java.lang.RuntimeException` if `configPath` can't be read/parsed, or if
///   every configured source fails to fetch.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeRefreshBridges(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: String = env
            .get_string(&config_path)
            .inspect_err(|_| {
                env.throw_new(
                    "java/lang/IllegalArgumentException",
                    "configPath is null or invalid",
                )
                .ok();
            })?
            .into();

        let Some(tunnel) = engine::get_current_tunnel() else {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "engine is not running; bridges can only be refreshed over a live Tor circuit",
            );
            return Err(anyhow::anyhow!("engine not running"));
        };

        let loaded = Config::load_with_override(Some(std::path::Path::new(&config_path_str)))
            .with_context(|| format!("loading config from {}", config_path_str))
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;
        let cfg = match &loaded {
            Loaded::FromFile { config, .. } => config,
            Loaded::Defaults(config) => config,
        };

        let sources: Vec<bridge_fetcher::Source> = cfg
            .bridges
            .sources
            .iter()
            .map(|s| bridge_fetcher::Source {
                label: s.label.clone(),
                url: s.url.clone(),
                headers: s.headers.clone(),
                cookies: s.cookies.clone(),
            })
            .collect();

        if sources.is_empty() {
            return env.new_string("").map(|s| s.into_raw()).map_err(|e| {
                error!("failed to create Java string for empty bridge refresh: {e}");
                anyhow::anyhow!(e)
            });
        }

        let max_body_bytes = cfg.bridges.max_body_mib.saturating_mul(1024 * 1024);

        // A fresh, minimal runtime for this one-shot blocking call -- the
        // engine's own multi-worker runtime lives on the engine thread's
        // stack and isn't reachable from here (this JNI call runs on
        // whatever thread Kotlin invoked it from).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                let msg = format!("failed to create refresh runtime: {e}");
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                anyhow::anyhow!(msg)
            })?;

        let (fetched, outcomes) = rt.block_on(bridge_fetcher::fetch_all(
            &tunnel,
            &sources,
            Duration::from_secs(30),
            max_body_bytes,
        ));

        for outcome in &outcomes {
            if let Some(err) = &outcome.error {
                tracing::warn!(label = %outcome.label, error = %err, "bridge source failed");
            } else {
                info!(
                    label = %outcome.label,
                    bridges = outcome.bridges_extracted,
                    "bridge source OK"
                );
            }
        }

        // An empty result is normally a valid "no new bridges" response, but
        // it is misleading when every source failed. Surface that distinction
        // to Kotlin so the UI can report a refresh failure instead of silently
        // claiming that no new bridges exist.
        if let Some(message) = refresh_sources_failure(&outcomes) {
            let _ = env.throw_new("java/lang/RuntimeException", &message);
            return Err(anyhow::anyhow!(message));
        }

        let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
        info!(unique = unique.len(), duplicates, "bridge refresh complete");

        let joined = unique
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for refreshed bridges: {e}");
            anyhow::anyhow!(e)
        })
    }));

    match result {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeProbeBridgeTransport(String configPath, String transport)`
///
/// An on-demand reachability probe over raw sockets -- unlike `nativeRefreshBridges`, this needs
/// no live Tor connection, the same way the bootstrap-time probe in `engine::engine_async` runs
/// before any circuit exists. Filters `configPath`'s configured bridges to `transport`
/// (`"obfs4"`/`"webtunnel"`; an empty string probes every configured bridge), probes them, and
/// persists the outcome to the same health store every other probe round writes to -- a manual
/// check from the UI improves the *next* connect's ranking exactly like the automatic rounds do.
///
/// Returns `"<alive>|<total>|<unmeasured>"`, or throws on a config error.
///
/// - **Threading:** Blocks the calling thread for the probe's duration (a per-bridge timeout of a
///   few seconds times however many candidates match `transport`) -- call off the Android main
///   thread, same convention as `nativeRefreshBridges`.
/// - **Error Signaling:** Throws `java.lang.IllegalArgumentException` if `configPath` is invalid,
///   `java.lang.RuntimeException` if the config or its bridge lines can't be parsed.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeProbeBridgeTransport(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    transport: JString,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: String = env
            .get_string(&config_path)
            .inspect_err(|_| {
                env.throw_new(
                    "java/lang/IllegalArgumentException",
                    "configPath is null or invalid",
                )
                .ok();
            })?
            .into();
        let transport_str: String = env
            .get_string(&transport)
            .map(|s| s.into())
            .unwrap_or_default();

        let loaded = Config::load_with_override(Some(std::path::Path::new(&config_path_str)))
            .with_context(|| format!("loading config from {}", config_path_str))
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;
        let cfg = match &loaded {
            Loaded::FromFile { config, .. } => config,
            Loaded::Defaults(config) => config,
        };

        let parsed = cfg.bridges.parsed().map_err(|e| {
            let msg = format!("{:#}", e);
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            e
        })?;
        // "plain" is the Kotlin side's label for a bridge line with no pluggable transport at
        // all (BridgeLine::transport == None) -- not a literal transport name to match against.
        let candidates: Vec<bridge_line::BridgeLine> = parsed
            .bridges
            .into_iter()
            .filter(|b| match transport_str.as_str() {
                "" => true,
                "plain" => b.transport.is_none(),
                t => b.transport.as_deref() == Some(t),
            })
            .collect();
        let total = candidates.len();

        let bridge_health = engine::BridgeHealthContext {
            config_path: Some(std::path::PathBuf::from(&config_path_str)),
            bridges_cfg: cfg.bridges.clone(),
            resolver_policy: cfg.dns.resolver_policy(),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                let msg = format!("failed to create probe runtime: {e}");
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                anyhow::anyhow!(msg)
            })?;

        let mut round = rt.block_on(bridge_probe::probe_round_with_policy(
            candidates.clone(),
            Duration::from_secs(5),
            bridge_health.resolver_policy,
        ));
        let alive = round.alive.len();
        let unmeasured = round.unmeasured.len();
        engine::persist_and_rank_probe(&candidates, &mut round, &bridge_health);

        info!(
            transport = %transport_str,
            alive,
            total,
            unmeasured,
            "on-demand bridge probe complete"
        );

        env.new_string(format!("{alive}|{total}|{unmeasured}"))
            .map(|s| s.into_raw())
            .map_err(|e| {
                error!("failed to create Java string for probe result: {e}");
                anyhow::anyhow!(e)
            })
    }));

    match result {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeGetDnsHints(String bridgeLines) -> String`
///
/// `bridgeLines` is newline-joined bridge-line strings -- typically the same
/// slice `ShareBridgesBottomSheet` is about to export. For each bridge whose
/// target is a hostname (currently: webtunnel bridges using `url=`, not
/// `addr=`), looks up the best DNS answer this process currently knows
/// (fresh, stale-but-recent, or persisted from a previous run -- see
/// `bridge_probe::best_known_answer`) and, if one exists, formats it as a
/// `# xorbot:dns ...` directive line.
///
/// Returns the directive lines newline-joined (empty string if none apply),
/// ready to be appended verbatim to the same list of strings being exported
/// -- `proxy_config::BridgesConfig::parsed` recognises and diverts these on
/// the importing side, scoped to only the bridges imported alongside them
/// (see that function's doc for why the scope check matters).
///
/// Reads only in-process state (no file I/O, no `configPath`): the DNS
/// caches this draws from are process-wide, not per-config.
///
/// - **Threading:** Cheap -- no network access, just cache lookups. Safe to
///   call from the main thread.
/// - **Error Signaling:** Does not throw. An unparseable bridge line is
///   simply skipped (not every bridge needs a hint); a Java string
///   allocation failure returns `null`.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetDnsHints(
    mut env: JNIEnv,
    _class: JClass,
    bridge_lines: JString,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let lines_str: String = env
            .get_string(&bridge_lines)
            .map(|s| s.into())
            .unwrap_or_default();
        env.new_string(dns_hints_for_lines(&lines_str))
            .map(|s| s.into_raw())
            .map_err(|e| {
                error!("failed to create Java string for DNS hints: {e}");
                anyhow::anyhow!(e)
            })
    }));

    match result {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// Pure glue behind [`nativeGetDnsHints`], factored out so it can be unit
/// tested without a JVM: parse each bridge line, keep only the (deduplicated)
/// hostnames that actually need DNS resolution, look up the best known
/// answer for each, and format whatever exists as directive lines.
pub(super) fn dns_hints_for_lines(lines_str: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    lines_str
        .lines()
        .filter_map(|line| line.parse::<bridge_line::BridgeLine>().ok())
        .filter_map(|bridge| bridge_probe::dns_hostname_of(&bridge))
        .filter(|host| seen.insert(host.clone()))
        .filter_map(|host| bridge_probe::best_known_answer(&host))
        .map(|hint| bridge_probe::format_dns_hint_line(&hint))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Bound on how long one candidate's throwaway bootstrap may take. Generous
/// on purpose: with a warm, shared cache (the common case -- see
/// `verify_bridges_blocking`) this finishes in the time of one PT handshake
/// and directory-descriptor fetch, but a cold cache or a genuinely slow
/// bridge needs real patience (see `arti-wrapper::build_config`'s own
/// comments on why aggressive timeouts break slow obfs4/webtunnel bridges).
pub(super) const VERIFY_BRIDGE_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);
/// Deliberately *not* `engine::LIVE_PROBE_TIMEOUT` (20s): that bound is for
/// the main connection's already-warm guard, whose descriptor and circuits
/// are long since built. This probe's circuit is the client's first-ever
/// contact with the candidate bridge, and `wait_bootstrapped()` above
/// returns as soon as the *shared* cache's consensus looks fresh -- it does
/// not wait for this specific bridge's own descriptor. That fetch (see
/// `vendor/tor-dirmgr/src/bridgedesc.rs`'s 30s timeout, raised there after
/// `docs/known-issues/android-bridge-bootstrap-regression.md`) plus the
/// actual PT/circuit build both land inside this probe's budget, not
/// bootstrap's, so it must clear 30s with real headroom -- and a single
/// failed descriptor fetch is routine, not fatal: `tor_dirmgr::bridgedesc`
/// retries on its own schedule, and the live engine's own logs show real,
/// currently-working bridges failing a fetch attempt before a later retry
/// succeeds. A short budget cuts the check off before that retry lands.
pub(super) const VERIFY_BRIDGE_PROBE_TIMEOUT: Duration = Duration::from_secs(180);
