use super::*;

/// Bootstrap one bridge set while retaining a handle for the stall watchdog.
///
/// Returns `Ok(None)` when Android requested stop. The returned tunnel is
/// owned by the caller; all spawned watchdog work is aborted before this
/// future resolves. The timeout intentionally cancels only the wait future,
/// then drops the tunnel, so the next attempt gets a fresh Arti client and
/// state-dir lifecycle.
///
/// cancel-safe: NO — cancelling this future drops the in-flight tunnel and
/// aborts its bootstrap attempt; callers use that behaviour for stop/retry.
pub(super) async fn bootstrap_tunnel_attempt(
    settings: arti_wrapper::Settings,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
    callback: BootstrapEventCallback,
) -> Result<Option<TorTunnel>> {
    info!(
        bridges = settings.bridges.len(),
        "bootstrapping Tor client..."
    );
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).context("creating Tor client")?;
    tunnel.forward_bootstrap_events(callback.clone());
    let stall_handle = tokio::spawn(bootstrap_stall_watchdog(tunnel.clone(), callback));

    let result = tokio::select! {
        biased;
        changed = stop_rx.changed() => {
            stall_handle.abort();
            info!(changed = changed.is_ok(), "received stop signal while bootstrapping");
            drop(tunnel);
            return Ok(None);
        }
        result = tokio::time::timeout(
            BOOTSTRAP_ATTEMPT_TIMEOUT,
            tunnel.wait_bootstrapped(),
        ) => result,
    };
    stall_handle.abort();

    match result {
        Ok(Ok(())) => Ok(Some(tunnel)),
        Ok(Err(error)) => {
            drop(tunnel);
            Err(error).context("failed to bootstrap Tor")
        }
        Err(_) => {
            warn!(
                timeout_secs = BOOTSTRAP_ATTEMPT_TIMEOUT.as_secs(),
                "Tor bootstrap attempt timed out; releasing bridge slice"
            );
            if let Err(error) = tunnel.terminate_all_channels() {
                debug!(error = %error, "failed to terminate channels after bootstrap timeout");
            }
            drop(tunnel);
            Err(anyhow::anyhow!(
                "Tor bootstrap attempt timed out after {BOOTSTRAP_ATTEMPT_TIMEOUT:?}"
            ))
        }
    }
}

/// How often [`stall_watchdog`] probes connectivity once the tunnel is live.
pub(super) const WATCHDOG_PROBE_INTERVAL: Duration = Duration::from_secs(45);
/// Per-probe timeout -- generous enough that a slow-but-alive circuit isn't
/// mistaken for a dead one.
pub(super) const WATCHDOG_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Consecutive probe failures before forcing a channel rebuild.
pub(super) const WATCHDOG_FAILURES_BEFORE_RESET: u32 = 3;
/// Minimum time between two rebuild attempts, so a genuinely blocked network
/// doesn't get hammered with resets that can't help it.
pub(super) const WATCHDOG_RESET_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// The first readiness signal must include a real end-to-end circuit probe.
/// A plain TCP bridge probe can succeed while DPI kills the obfs4 stream, and
/// cached arti state can otherwise make `wait_bootstrapped` look healthy.
// pub(crate): also the reachability bar `lib.rs`'s nativeVerifyBridges holds
// scanned candidate bridges to -- one canonical "does this actually carry
// Tor traffic" target, not a duplicated literal.
pub(crate) const LIVE_PROBE_TARGET: &str = "check.torproject.org";
pub(crate) const LIVE_PROBE_PORT: u16 = 443;
pub(super) const LIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
pub(super) const LIVE_PROBE_ATTEMPTS: u32 = 3;
pub(super) const LIVE_PROBE_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Bound each parallel PT/channel warm-up so a dead bridge cannot hold the
/// rotation pool open indefinitely.
pub(super) const WARM_BRIDGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Per-bridge timeout for the periodic re-probe, matching the bootstrap-time
/// probe in `engine_async`.
pub(super) const BRIDGE_REPROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for the whole auto-fetch-from-sources call, matching
/// `nativeRefreshBridges`'s manual equivalent (`lib.rs`).
pub(super) const AUTO_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// How often [`bootstrap_stall_watchdog`] checks bootstrap progress.
pub(super) const BOOTSTRAP_STALL_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// How long the bootstrap percentage can stay unchanged before this forces a channel reset.
pub(super) const BOOTSTRAP_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Verify that arti can establish a usable circuit before advertising
/// `EngineStatus::On`/`BootstrapEvent::Ready` to Android.
///
/// cancel-safe: NO — cancelling the timeout aborts an in-flight Tor connect;
/// this is intentional because a stop signal must not wait for a dead circuit.
pub(super) async fn verify_live_circuit(
    tunnel: &TorTunnel,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
    callback: &BootstrapEventCallback,
) -> Result<bool> {
    if *stop_rx.borrow() {
        return Ok(false);
    }

    for attempt in 1..=LIVE_PROBE_ATTEMPTS {
        let probe = tokio::select! {
            biased;
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return Ok(false);
                }
                continue;
            }
            result = tokio::time::timeout(
                LIVE_PROBE_TIMEOUT,
                tunnel.connect(LIVE_PROBE_TARGET, LIVE_PROBE_PORT),
            ) => result,
        };

        match probe {
            Ok(Ok(stream)) => {
                drop(stream);
                return Ok(true);
            }
            Ok(Err(error)) => {
                let reason = error.to_string();
                callback(BootstrapEvent::Blocked(format!(
                    "Tor bootstrapped, but live circuits are not working yet (attempt {attempt}/{LIVE_PROBE_ATTEMPTS}): {reason}"
                )));
            }
            Err(_) => {
                callback(BootstrapEvent::Blocked(format!(
                    "Tor bootstrapped, but live circuits are not working yet (attempt {attempt}/{LIVE_PROBE_ATTEMPTS}): probe timed out after {LIVE_PROBE_TIMEOUT:?}"
                )));
            }
        }

        if attempt < LIVE_PROBE_ATTEMPTS {
            if let Err(error) = tunnel.terminate_all_channels() {
                warn!(error = %error, "live circuit probe failed; channel rotation was unavailable");
            } else {
                info!(
                    attempt,
                    "rotated Tor channels after failed live circuit probe"
                );
            }

            let changed = tokio::time::sleep(LIVE_PROBE_RETRY_DELAY);
            tokio::pin!(changed);
            tokio::select! {
                biased;
                result = stop_rx.changed() => {
                    if result.is_err() || *stop_rx.borrow() {
                        return Ok(false);
                    }
                }
                _ = &mut changed => {}
            }
        }
    }

    Err(anyhow::anyhow!(
        "Tor bootstrap completed, but no live circuit passed the connectivity probe after {LIVE_PROBE_ATTEMPTS} attempts; refusing to report Connected"
    ))
}

/// Open a channel to every candidate concurrently and return successful
/// bridges ordered by measured warm-up latency. The first element is the best
/// immediate rotation candidate; the remainder stay available as fallbacks.
///
/// cancel-safe: NO — dropping this future aborts the in-flight warm-up set;
/// callers use that behaviour when Android requests stop during bootstrap.
pub(super) async fn warm_bridge_pool(tunnel: TorTunnel, bridges: Vec<BridgeLine>) -> WarmPool {
    let bridges = bridges.into_iter().take(MAX_WARM_BRIDGES);
    let total = bridges.len();
    let mut tasks = tokio::task::JoinSet::new();
    for bridge in bridges {
        let tunnel = tunnel.clone();
        tasks.spawn(async move {
            let started = Instant::now();
            match tokio::time::timeout(WARM_BRIDGE_TIMEOUT, tunnel.warm_bridge(&bridge)).await {
                Ok(Ok(())) => WarmOutcome::Warm(bridge, started.elapsed()),
                Ok(Err(error)) => {
                    let rendered = format!("{error:#}");
                    if is_permanent_bridge_failure(&rendered) {
                        warn!(
                            bridge = %bridge.addr,
                            error = %rendered,
                            "bridge is permanently unusable; retiring it"
                        );
                        WarmOutcome::Retired(bridge)
                    } else {
                        debug!(bridge = %bridge.addr, error = %rendered, "bridge warm-up failed");
                        WarmOutcome::Failed
                    }
                }
                Err(_) => {
                    debug!(
                        bridge = %bridge.addr,
                        timeout = ?WARM_BRIDGE_TIMEOUT,
                        "bridge warm-up timed out"
                    );
                    WarmOutcome::Failed
                }
            }
        });
    }

    let mut warmed = Vec::new();
    let mut retired = Vec::new();
    let mut completed = 0usize;
    let mut failed = 0usize;
    while let Some(result) = tasks.join_next().await {
        completed += 1;
        match result {
            Ok(WarmOutcome::Warm(bridge, elapsed)) => warmed.push((bridge, elapsed)),
            Ok(WarmOutcome::Retired(bridge)) => {
                retired.push(bridge);
                failed += 1;
            }
            Ok(WarmOutcome::Failed) => failed += 1,
            Err(error) => {
                debug!(error = %error, "parallel bridge warm-up task failed");
                failed += 1;
            }
        }
        info!(
            active = total.saturating_sub(completed),
            completed,
            successful = warmed.len(),
            failed,
            "parallel bridge warm-up progress"
        );
    }
    warmed.sort_by_key(|(_, elapsed)| *elapsed);
    info!(
        active = 0,
        completed,
        successful = warmed.len(),
        retired = retired.len(),
        failed,
        "parallel bridge warm-up finished"
    );
    WarmPool { warmed, retired }
}

/// What one bridge's warm-up attempt established.
pub(super) enum WarmOutcome {
    /// A channel opened; the bridge is proven usable and timed.
    Warm(BridgeLine, Duration),
    /// The bridge answered but can never work as configured — retire it.
    Retired(BridgeLine),
    /// Transient failure or timeout; the bridge keeps its place in the pool.
    Failed,
}

/// Result of warming a set of bridges.
pub(crate) struct WarmPool {
    /// Bridges that opened a channel, fastest first.
    pub warmed: Vec<(BridgeLine, Duration)>,
    /// Bridges whose failure was a verdict rather than bad luck.
    pub retired: Vec<BridgeLine>,
}

/// Whether a warm-up error means the bridge line itself is wrong, rather than
/// the network being uncooperative.
///
/// An identity mismatch is the case that matters in practice: the relay behind
/// the endpoint presents a different key than the fingerprint in the bridge
/// line, so the line is stale and no retry can fix it. Public webtunnel lists
/// carry many of these, and they are invisible to reachability probing --
/// the fronting web server answers perfectly, which is exactly why they
/// otherwise keep ranking well and crowding out working bridges.
///
/// Matching on the rendered message is deliberate: arti surfaces this as an
/// opaque `HandshakeProto` string, with no typed variant to match on.
pub(super) fn is_permanent_bridge_failure(rendered_error: &str) -> bool {
    rendered_error.contains("does not match target")
}

/// Runs alongside `wait_bootstrapped()` (spawned right before it, aborted right after it
/// resolves either way). Bootstrap has no built-in stall detection: if every currently-tried
/// bridge fails at the PT/TLS layer (deeper than the plain TCP reachability probe already run
/// before bootstrap started), arti can sit retrying the same small pool indefinitely at a
/// fixed percentage. Polls the global `EngineStatus` (the same one `nativeGetStatus` reads)
/// every [`BOOTSTRAP_STALL_CHECK_INTERVAL`]; if the percentage hasn't moved for
/// [`BOOTSTRAP_STALL_TIMEOUT`], calls [`TorTunnel::terminate_all_channels`] to force arti to
/// drop its dead channels and retry fresh ones, and reports it via `BootstrapEvent::Blocked`
/// (already surfaced to the user as a log line on the Kotlin side) so a stall is visible
/// instead of just a frozen percentage.
pub(super) async fn bootstrap_stall_watchdog(tunnel: TorTunnel, callback: BootstrapEventCallback) {
    let mut last_percent: Option<u8> = None;
    let mut last_change = Instant::now();
    loop {
        tokio::time::sleep(BOOTSTRAP_STALL_CHECK_INTERVAL).await;
        let current_percent = match crate::get_status()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            EngineStatus::Starting(pct) => pct,
            _ => return, // no longer bootstrapping (ready, stopped, or errored)
        };
        if last_percent != Some(current_percent) {
            last_percent = Some(current_percent);
            last_change = Instant::now();
            continue;
        }
        if last_change.elapsed() < BOOTSTRAP_STALL_TIMEOUT {
            continue;
        }
        warn!(
            percent = current_percent,
            stalled_for_secs = last_change.elapsed().as_secs(),
            "bootstrap stalled, forcing a channel reset"
        );
        callback(BootstrapEvent::Blocked(format!(
            "stalled at {current_percent}% for {}s, retrying with fresh channels",
            last_change.elapsed().as_secs()
        )));
        if let Err(e) = tunnel.terminate_all_channels() {
            warn!(error = %e, "bootstrap watchdog: terminate_all_channels failed");
        }
        last_change = Instant::now();
    }
}

/// Background task, spawned once the tunnel reaches `On`, with three independent jobs on
/// their own cadences:
///
/// 1. Every [`WATCHDOG_PROBE_INTERVAL`], probes Tor Project's own connectivity-check endpoint
///    through the tunnel (the same target Tor Browser itself uses for this). After
///    [`WATCHDOG_FAILURES_BEFORE_RESET`] consecutive failures it calls
///    [`TorTunnel::terminate_all_channels`] to force arti to rebuild its channels, giving the
///    guard/circuit managers a clean slate -- mirrors the CLI daemon's `tor_watchdog.rs`,
///    scoped down to a single canary target instead of replaying real traffic history
///    (Android's accept loop doesn't track per-connection success/failure the way the CLI's
///    `TorHealth` does).
/// 2. Every `bridge_health.bridges_cfg.recheck_interval_mins` minutes (`0` disables this and
///    job 3 entirely, deliberately far longer than [`WATCHDOG_PROBE_INTERVAL`] -- bridges have
///    their own flood protection, and re-probing the same set too often risks tripping it, see
///    `arti-wrapper`'s `build_config` doc for the earlier incident that taught this fork to be
///    conservative here), re-probes `bridges` for reachability and persists the outcome via
///    [`persist_and_rank_probe`] -- the same store `engine_async` writes to at bootstrap. This
///    session's already-chosen bridge/circuit is unaffected; the point is keeping the
///    persisted ranking fresh so the *next* connect starts from the genuinely fastest known
///    bridge (docs/circuit-speed-plan.md's Tier 1) instead of whatever was fastest whenever
///    bootstrap last probed.
/// 3. Immediately after job 2, if the reachable count fell below
///    `bridge_health.bridges_cfg.min_alive` and `auto_fetch` is enabled, fetches fresh
///    candidates from `bridges_cfg.sources` over this *already-live* tunnel -- the same fetch
///    `nativeRefreshBridges` does on a manual tap, just triggered automatically instead of only
///    from the menu (docs/android-bridge-freshness-plan.md's Phase 2). Newly found bridges are
///    handed to Kotlin via [`take_auto_fetched_bridges`]/`nativeTakeAutoFetchedBridges`, mirroring
///    [`take_pruned_bridges`]'s pattern -- this task has no access to `Prefs.bridgesList`, only
///    Kotlin does.
///
/// Exits when `stop_rx` fires.
pub(super) async fn stall_watchdog(
    tunnel: TorTunnel,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    bridges: Vec<BridgeLine>,
    bridge_health: BridgeHealthContext,
    pt_binary: Option<PathBuf>,
) {
    let mut consecutive_failures = 0u32;
    let mut last_reset: Option<Instant> = None;
    // Bootstrap already probed once, but a thin pool should be refreshed shortly after the
    // first successful connection. Waiting a full hour here made `auto_fetch` effectively
    // invisible on Android, especially after a fresh install with only a few seed bridges.
    let mut first_bridge_reprobe = true;
    let mut last_bridge_reprobe = Instant::now();
    let mut auto_fetch_round: u32 = 0;
    let reprobe_interval = Duration::from_secs(
        bridge_health
            .bridges_cfg
            .recheck_interval_mins
            .saturating_mul(60),
    );

    // The confirmed-warm rotation pool, fastest first, and the top-up round's own state.
    // Starts empty: see the spawn site's comment for why that beats guessing.
    let mut rotation_bridges: Vec<(BridgeLine, Duration)> = Vec::new();
    // Candidates that failed to warm this session. Nothing demotes a merely-reachable bridge
    // in the health store just because opening a channel to it failed -- reachability and
    // warm success are different questions, see `usable_for_tor`'s webtunnel note for why the
    // gap can be large -- so without this a bridge stuck failing PT/Tor handshake would be
    // re-selected and re-attempted by every single top-up round for the life of the connection.
    let mut warm_session_failed: HashSet<String> = HashSet::new();
    // Due immediately: the first top-up round runs on this loop's first tick rather than
    // waiting a full `WARM_TOPUP_INTERVAL` on top of `WATCHDOG_PROBE_INTERVAL`.
    let mut last_topup = Instant::now()
        .checked_sub(WARM_TOPUP_INTERVAL)
        .unwrap_or_else(Instant::now);
    // Same "due immediately" reasoning as `last_topup`, but the store itself already tracks
    // per-bridge staleness (`BridgeStore::needing_circuit_verification`'s `max_age`) -- this
    // only paces how often a *tick* happens, not which bridges within it are actually checked.
    let mut last_circuit_verify = Instant::now()
        .checked_sub(CIRCUIT_VERIFY_INTERVAL)
        .unwrap_or_else(Instant::now);

    loop {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => return,
            _ = tokio::time::sleep(WATCHDOG_PROBE_INTERVAL) => {}
        }
        if *stop_rx.borrow() {
            return;
        }

        // Cheap, unconditional per-tick housekeeping: keep the on-disk DNS fallback
        // fresh so a future cold start (possibly with DNS fully blocked from the
        // first moment) has something recent to fall back to, not just whatever
        // was known the last time this file happened to get written.
        if let Err(error) = bridge_probe::save_persisted_dns_cache(&dns_cache_path(
            bridge_health.config_path.as_deref(),
        )) {
            warn!(error = %error, "could not persist DNS fallback cache");
        }

        // Runs before the reachability re-probe below on purpose: that re-probe walks the
        // *entire* configured pool (thousands of bridges) and, on this loop's first tick, is
        // forced regardless of `recheck_interval_mins` -- with webtunnel's up-to-27s-per-bridge
        // worst case, a full sweep can take minutes. Running the top-up after it would delay a
        // connection's very first top-up round by however long that sweep takes, defeating the
        // point of "proactively". The health store already has plenty of history from earlier
        // rounds and earlier sessions for `select_active_probe_bridges` to draw on immediately.
        if last_topup.elapsed() >= WARM_TOPUP_INTERVAL {
            last_topup = Instant::now();
            let active = rotation_bridges.len();
            let batch_size = if active < TARGET_WARM_POOL_SIZE {
                WARM_TOPUP_BATCH
            } else {
                WARM_REFRESH_BATCH
            };

            let already_active: HashSet<String> = rotation_bridges
                .iter()
                .map(|(bridge, _)| bridge.to_string())
                .collect();
            // Respect the transport preference the same way the bootstrap-time probe pool
            // does. Without this, ranking-by-reachability over the unfiltered configured pool
            // hands most of every batch to whichever transport is largest and most TCP-reachable
            // -- typically obfs4 -- even on a network where obfs4 is blocked at the flow-shape
            // layer and every one of those attempts is doomed before it starts, starving the
            // transport the user actually asked for of its share of each round's batch.
            let preferred = preferred_transport_bridges(&bridges, &bridge_health);
            let batch: Vec<BridgeLine> = select_active_probe_bridges(&preferred, &bridge_health)
                .into_iter()
                .filter(|bridge| {
                    let text = bridge.to_string();
                    !already_active.contains(&text) && !warm_session_failed.contains(&text)
                })
                .take(batch_size)
                .collect();

            if !batch.is_empty() {
                info!(
                    count = batch.len(),
                    active,
                    target = TARGET_WARM_POOL_SIZE,
                    "warm pool: attempting new candidates"
                );
                let pool = tokio::select! {
                    biased;
                    _ = stop_rx.changed() => return,
                    pool = warm_bridge_pool(tunnel.clone(), batch.clone()) => pool,
                };
                persist_warm_results(&pool, &bridge_health);

                let warmed_keys: HashSet<String> =
                    pool.warmed.iter().map(|(b, _)| b.to_string()).collect();
                for bridge in &batch {
                    let text = bridge.to_string();
                    if !warmed_keys.contains(&text) {
                        warm_session_failed.insert(text);
                    }
                }
                let retired_keys: HashSet<String> =
                    pool.retired.iter().map(|b| b.to_string()).collect();
                rotation_bridges.retain(|(bridge, _)| !retired_keys.contains(&bridge.to_string()));

                let newly_warmed = pool.warmed.len();
                rotation_bridges.extend(pool.warmed);
                // Fastest first; a full pool sheds its slowest members here, which is how a
                // newly-discovered fast bridge displaces an already-active slow one.
                rotation_bridges.sort_by_key(|(_, latency)| *latency);
                if rotation_bridges.len() > TARGET_WARM_POOL_SIZE {
                    let dropped = rotation_bridges.split_off(TARGET_WARM_POOL_SIZE);
                    for (bridge, latency) in &dropped {
                        debug!(
                            bridge = %bridge.addr,
                            latency_ms = latency.as_millis() as u64,
                            "warm pool: dropped in favour of a faster bridge"
                        );
                    }
                }

                crate::set_active_bridges(
                    bridge_health.config_path.as_deref(),
                    &rotation_bridges
                        .iter()
                        .map(|(bridge, _)| bridge.clone())
                        .collect::<Vec<_>>(),
                );
                info!(
                    active = rotation_bridges.len(),
                    target = TARGET_WARM_POOL_SIZE,
                    newly_warmed,
                    "warm pool: rotation updated"
                );
            }
        }

        // Background circuit-verify tick: the standard this whole app now holds bridges to
        // ("reachable" means a live circuit actually reached the open internet, not merely a
        // TCP handshake or an open channel) applied to a slow trickle of the pool, not just the
        // QR-scan flow's user-initiated checks. See `docs/design/real-connectivity-bridge-
        // verification.md` for why this can't simply replace the TCP reprobe above: a full
        // check costs a real Tor circuit per bridge, not a local socket.
        if last_circuit_verify.elapsed() >= CIRCUIT_VERIFY_INTERVAL {
            last_circuit_verify = Instant::now();
            let store_path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
            let due = match BridgeStore::load(store_path) {
                Ok(store) => store.needing_circuit_verification(
                    OffsetDateTime::now_utc(),
                    CIRCUIT_VERIFY_MAX_AGE,
                    CIRCUIT_VERIFY_BATCH,
                    // android ranks the whole pool; no active-set restriction here
                    |_| true,
                ),
                Err(error) => {
                    warn!(error = %error, "circuit-verify: failed to load bridge store");
                    Vec::new()
                }
            };

            if !due.is_empty() {
                info!(count = due.len(), "circuit-verify: checking due bridges");
                let live_cache_dir = bridge_health
                    .config_path
                    .as_deref()
                    .map(crate::arti_cache_dir)
                    .unwrap_or_else(|| std::path::PathBuf::from("arti-data/cache"));
                let scratch_base = bridge_health
                    .config_path
                    .as_deref()
                    .map(|p| {
                        crate::scratch_dir(p, &format!("circuit-verify-{}", std::process::id()))
                    })
                    .unwrap_or_else(|| {
                        std::path::PathBuf::from(format!(
                            "verify-scratch/circuit-verify-{}",
                            std::process::id()
                        ))
                    });
                let verify_pt_binary = pt_binary.clone();
                let verify_health = bridge_health.clone();
                tokio::spawn(async move {
                    // `verify_bridges_sequential` blocks its calling thread (it builds and
                    // drives its own throwaway tokio runtimes internally, one per bridge) --
                    // `spawn_blocking` moves it off this runtime's async worker threads, the
                    // same reason `nativeVerifyBridges` runs it on a dedicated OS thread rather
                    // than as a plain async task.
                    let results = tokio::task::spawn_blocking(move || {
                        let mut results = Vec::new();
                        crate::verify_bridges_sequential(
                            &live_cache_dir,
                            &scratch_base,
                            due,
                            verify_pt_binary,
                            CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT,
                            CIRCUIT_VERIFY_PROBE_TIMEOUT,
                            |bridge, result| results.push((bridge.clone(), result.is_ok())),
                        );
                        let _ = std::fs::remove_dir_all(&scratch_base);
                        results
                    })
                    .await
                    .unwrap_or_default();

                    let verified = results.iter().filter(|(_, ok)| *ok).count();
                    info!(
                        checked = results.len(),
                        verified, "circuit-verify: tick complete"
                    );
                    persist_circuit_verify_results(&results, &verify_health);
                });
            }
        }

        let should_reprobe = !reprobe_interval.is_zero()
            && (first_bridge_reprobe || last_bridge_reprobe.elapsed() >= reprobe_interval);
        if !bridges.is_empty() && should_reprobe {
            // Bumped synchronously, before the spawn: this guards against starting a second
            // sweep while one is still running, not against the loop moving on without waiting
            // for this one -- moving on is the fix, not a race to prevent.
            first_bridge_reprobe = false;
            last_bridge_reprobe = Instant::now();
            auto_fetch_round = auto_fetch_round.wrapping_add(1);

            let reprobe_tunnel = tunnel.clone();
            let reprobe_bridges = bridges.clone();
            let reprobe_health = bridge_health.clone();
            let mut reprobe_stop_rx = stop_rx.clone();
            let this_round = auto_fetch_round;
            // Spawned rather than awaited inline: a full sweep of the configured pool (thousands
            // of bridges, some with multi-second timeouts) previously blocked this entire loop --
            // including the warm-pool top-up and the liveness check below -- for as long as the
            // sweep took. Measured on a phone: still running 7+ minutes after the connection came
            // up, during which the top-up round that should fire every WARM_TOPUP_INTERVAL never
            // got a second chance to run. Neither the top-up cadence nor the liveness check has
            // any reason to wait on this; only the health store needs the result, and that's
            // written from inside the spawned task itself.
            tokio::spawn(async move {
                if *reprobe_stop_rx.borrow() {
                    return;
                }
                let mut round = tokio::select! {
                    biased;
                    _ = reprobe_stop_rx.changed() => return,
                    round = bridge_probe::probe_round_with_policy(reprobe_bridges.clone(), BRIDGE_REPROBE_TIMEOUT, reprobe_health.resolver_policy) => round,
                };
                persist_and_rank_probe(&reprobe_bridges, &mut round, &reprobe_health);
                let alive = std::mem::take(&mut round.alive);
                debug!(
                    alive = alive.len(),
                    total = reprobe_bridges.len(),
                    "watchdog: periodic bridge re-probe complete"
                );

                if alive.len() < reprobe_health.bridges_cfg.min_alive
                    && reprobe_health.bridges_cfg.auto_fetch
                    && !reprobe_health.bridges_cfg.sources.is_empty()
                {
                    let barren = barren_sources(&reprobe_health, this_round);
                    let sources: Vec<bridge_fetcher::Source> = reprobe_health
                        .bridges_cfg
                        .sources
                        .iter()
                        .filter(|s| !barren.contains(&s.label))
                        .map(|s| bridge_fetcher::Source {
                            label: s.label.clone(),
                            url: s.url.clone(),
                            headers: s.headers.clone(),
                            cookies: s.cookies.clone(),
                            allow_credentials_cross_origin: s.allow_credentials_cross_origin,
                        })
                        .collect();
                    let max_body_bytes = reprobe_health
                        .bridges_cfg
                        .max_body_mib
                        .saturating_mul(1024 * 1024);
                    info!(
                        alive = alive.len(),
                        min_alive = reprobe_health.bridges_cfg.min_alive,
                        "watchdog: alive bridge pool is thin, auto-fetching more"
                    );
                    let (fetched, outcomes) = tokio::select! {
                        biased;
                        _ = reprobe_stop_rx.changed() => return,
                        result = bridge_fetcher::fetch_all(&reprobe_tunnel, &sources, AUTO_FETCH_TIMEOUT, max_body_bytes) => result,
                    };
                    for outcome in &outcomes {
                        if let Some(err) = &outcome.error {
                            warn!(label = %outcome.label, error = %err, "watchdog: bridge auto-fetch source failed");
                        } else {
                            info!(
                                label = %outcome.label,
                                bridges = outcome.bridges_extracted,
                                "watchdog: bridge auto-fetch source OK"
                            );
                        }
                    }
                    persist_bridge_sources(&outcomes, &reprobe_health);
                    let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
                    info!(
                        unique = unique.len(),
                        duplicates, "watchdog: bridge auto-fetch complete"
                    );
                    record_auto_fetched_bridges(unique);
                }
            });
        }

        let probe = tokio::time::timeout(
            WATCHDOG_PROBE_TIMEOUT,
            tunnel.connect("check.torproject.org", 443),
        )
        .await;

        if matches!(probe, Ok(Ok(_))) {
            consecutive_failures = 0;
            continue;
        }

        consecutive_failures += 1;
        debug!(consecutive_failures, "watchdog: connectivity probe failed");
        if consecutive_failures < WATCHDOG_FAILURES_BEFORE_RESET {
            continue;
        }

        let now = Instant::now();
        let cooled_down = last_reset
            .map(|t| now.duration_since(t) >= WATCHDOG_RESET_COOLDOWN)
            .unwrap_or(true);
        if !cooled_down {
            continue;
        }

        warn!(
            consecutive_failures,
            "watchdog: forcing channel rebuild after sustained stall"
        );
        // A sustained stall is what a network change looks like from in here,
        // and the DNS cache plus the DoH provider scores both describe the
        // network we were on, not the one we may now be on.
        bridge_probe::flush_dns_cache();
        if let Err(e) = tunnel.terminate_all_channels() {
            warn!(error = %e, "watchdog: terminate_all_channels failed");
        } else {
            let candidates: Vec<BridgeLine> = if rotation_bridges.is_empty() {
                bridges.clone()
            } else {
                rotation_bridges.iter().map(|(b, _)| b.clone()).collect()
            };
            let pool = tokio::select! {
                biased;
                _ = stop_rx.changed() => return,
                pool = warm_bridge_pool(tunnel.clone(), candidates) => pool,
            };
            // Persist even when nothing warmed: a round that only retired stale
            // bridges is still progress worth keeping.
            persist_warm_results(&pool, &bridge_health);
            if !pool.retired.is_empty() {
                let retired: HashSet<String> = pool.retired.iter().map(|b| b.to_string()).collect();
                rotation_bridges.retain(|(b, _)| !retired.contains(&b.to_string()));
            }
            if !pool.warmed.is_empty() {
                rotation_bridges = pool.warmed;
                crate::set_active_bridges(
                    bridge_health.config_path.as_deref(),
                    &rotation_bridges
                        .iter()
                        .map(|(bridge, _)| bridge.clone())
                        .collect::<Vec<_>>(),
                );
                info!(
                    warmed = rotation_bridges.len(),
                    retired = pool.retired.len(),
                    "watchdog: rebuilt parallel bridge rotation pool"
                );
            }
        }
        last_reset = Some(now);
        consecutive_failures = 0;
    }
}
