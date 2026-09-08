use super::*;

use anyhow::bail;

/// Absolute deadline for the entire SOCKS5 handshake: method negotiation,
/// RFC 1929 USER/PASS auth (including the Argon2 verify) and the CONNECT
/// request. Armed once when the handshake starts and never renewed — a
/// client trickling valid bytes one at a time still hits it. On expiry the
/// client socket is dropped and the connection task exits, releasing its
/// `MAX_CONCURRENT_CONNECTIONS` permit.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Narrow the startup pool to the user's preferred transport, if they set one.
///
/// Blocking is transport-specific: a network that fingerprints obfs4 and kills
/// its streams routinely lets webtunnel through untouched, since webtunnel is
/// ordinary HTTPS to a real web server. Honouring the preference here — before
/// the health ranking — keeps the choice meaningful even when the background
/// pool is dominated by the other transport.
///
/// A preference rather than a filter, but only in one direction: matching
/// nothing falls back to the full list, since asking for a transport the pool
/// does not contain should not amount to asking for nothing. A preference whose
/// bridges all turn out to be dead is deliberately *not* rescued — which
/// transport a network actually permits is what the setting exists to reveal,
/// so that failure is reported rather than papered over.
pub(super) fn preferred_transport_bridges(
    configured: &[BridgeLine],
    bridge_health: &BridgeHealthContext,
) -> Vec<BridgeLine> {
    let Some(preferred) = bridge_health.bridges_cfg.preferred_transport() else {
        return configured.to_vec();
    };
    let matching: Vec<BridgeLine> = configured
        .iter()
        .filter(|bridge| bridge.transport.as_deref() == Some(preferred))
        .cloned()
        .collect();
    if matching.is_empty() {
        warn!(
            preferred,
            configured = configured.len(),
            "no bridge uses the preferred transport; using the full pool"
        );
        return configured.to_vec();
    }
    info!(
        preferred,
        matching = matching.len(),
        configured = configured.len(),
        "restricted startup pool to the preferred transport"
    );
    matching
}

/// Choose the small, latency-sensitive startup pool from the persisted bridge ranking.
///
/// `configured` is intentionally not reduced here: the watchdog still owns the complete
/// imported list and uses it as the background discovery/re-probe pool. A missing or stale
/// health store falls back to the first bounded slice; the caller performs a full probe only
/// when that slice produces no reachable bridge.
pub(super) fn select_active_probe_bridges(
    configured: &[BridgeLine],
    bridge_health: &BridgeHealthContext,
) -> Vec<BridgeLine> {
    let store_path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let store = BridgeStore::load(store_path).ok();

    // Drop retired bridges before anything else looks at the list. They are
    // reachable by construction -- a retirement means the endpoint answers but
    // the relay's identity does not match the line -- so every reachability
    // check votes for them, and the short-pool shortcut below would hand them
    // straight back. Keep them if that would leave nothing at all: a pool of
    // known-bad bridges is still a better starting point than an empty one.
    let usable: Vec<BridgeLine> = match &store {
        Some(store) => {
            let live: Vec<BridgeLine> = configured
                .iter()
                .filter(|bridge| !store.is_retired(bridge))
                .cloned()
                .collect();
            if live.is_empty() {
                warn!(
                    configured = configured.len(),
                    "every configured bridge has been retired; using them anyway"
                );
                configured.to_vec()
            } else {
                if live.len() < configured.len() {
                    info!(
                        retired = configured.len() - live.len(),
                        remaining = live.len(),
                        "skipped retired bridges when choosing the active pool"
                    );
                }
                live
            }
        }
        None => configured.to_vec(),
    };

    if usable.len() <= MAX_ACTIVE_BRIDGES {
        return usable;
    }

    if let Some(store) = &store {
        // Ranks within `usable` rather than globally-then-intersect: see
        // `BridgeStore::healthiest_among`'s doc for why that distinction is the whole point --
        // a webtunnel-preferred `usable` ranked against the *global* top bridges would mostly
        // disappear behind a much larger obfs4 history.
        let ranked = store.healthiest_among(&usable, MAX_ACTIVE_BRIDGES);
        if !ranked.is_empty() {
            return ranked;
        }
    }

    usable.into_iter().take(MAX_ACTIVE_BRIDGES).collect()
}

/// Persist a probe round's reachability outcome to the shared bridge-health store
/// (`<config-stem>.alive-bridges.log`, same file the CLI daemon uses) and re-sort `alive` by
/// historical stability (`ok_count`, ties broken by latency) ahead of a bridge seen reachable
/// for the first time. Shared between the bootstrap-time probe in `engine_async`,
/// `stall_watchdog`'s periodic re-probe, and `nativeProbeBridgeTransport`'s on-demand probe --
/// all three need the identical persist-and-rank step, just with different cancellation/error
/// handling and triggers around the probe itself. Best-effort throughout: a missing or
/// unwritable store never fails the caller, it just forfeits the ranking boost for this round.
pub(crate) fn persist_and_rank_probe(
    all_bridges: &[BridgeLine],
    round: &mut bridge_probe::ProbeRound,
    bridge_health: &BridgeHealthContext,
) {
    // A bridge whose hostname would not resolve was never contacted, so this
    // round has nothing to say about it. Recording a failure would be recording
    // our own resolver's trouble against the bridge -- and, through the source
    // tally, against whoever supplied it.
    let measured: Vec<BridgeLine> = if round.unmeasured.is_empty() {
        all_bridges.to_vec()
    } else {
        let skip: HashSet<String> = round.unmeasured.iter().map(|b| b.to_string()).collect();
        all_bridges
            .iter()
            .filter(|b| !skip.contains(&b.to_string()))
            .cloned()
            .collect()
    };
    if !round.unmeasured.is_empty() {
        info!(
            unmeasured = round.unmeasured.len(),
            measured = measured.len(),
            "probe round left some bridges untested; their health is unchanged"
        );
    }

    let store_path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    match BridgeStore::load(store_path.clone()) {
        Ok(mut store) => {
            let now = OffsetDateTime::now_utc();
            let fail_window = Duration::from_secs(
                bridge_health
                    .bridges_cfg
                    .fail_window_mins
                    .saturating_mul(60),
            );
            let pruned = store.note_probe_round(
                &measured,
                &round.alive,
                now,
                fail_window,
                bridge_health.bridges_cfg.max_fails,
                bridge_health.bridges_cfg.max_circuit_fails,
            );
            if !pruned.is_empty() {
                info!(
                    count = pruned.len(),
                    "bridges crossed max_fails/max_circuit_fails, pruning"
                );
                record_pruned_bridges(pruned);
            }
            if let Err(e) = store.save() {
                warn!(path = %store_path.display(), error = %e, "could not persist bridge health store");
            }
            round.alive.sort_by(|(ba, la), (bb, lb)| {
                store
                    .channel_ok_count(bb)
                    .cmp(&store.channel_ok_count(ba))
                    .then_with(|| store.ok_count(bb).cmp(&store.ok_count(ba)))
                    .then_with(|| la.cmp(lb))
            });
        }
        Err(e) => {
            warn!(path = %store_path.display(), error = %e, "could not load bridge health store");
        }
    }
}

/// Path for the on-disk DNS fallback cache, next to the config file --
/// same sibling-file convention as `active_bridges_path` in `lib.rs`.
pub(super) fn dns_cache_path(config_path: Option<&std::path::Path>) -> std::path::PathBuf {
    match config_path {
        Some(cfg) => {
            let dir = cfg.parent().unwrap_or_else(|| std::path::Path::new("."));
            let stem = cfg
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tor-socks5".to_string());
            dir.join(format!("{stem}.dns-cache"))
        }
        None => std::path::PathBuf::from("tor-socks5.dns-cache"),
    }
}

/// Persist the PT-channel rotation signal without confusing it with an
/// end-to-end circuit success or a plain TCP probe.
/// A source must have offered this many bridges before its yield is judged.
/// Below it, a run of bad luck is indistinguishable from a dead collector.
pub(super) const SOURCE_MIN_SAMPLE: usize = 40;

/// How often a barren source is retried anyway. Collectors do resume, and a
/// source struck off permanently could never prove it.
pub(super) const BARREN_SOURCE_RETRY_EVERY: u32 = 6;

/// Labels of sources worth skipping this round.
///
/// Barren means "has supplied a meaningful number of bridges and not one of
/// them was ever reachable" — the state a collector reaches when it stops
/// regenerating, which no fetch-level check can see because it keeps answering
/// HTTP 200 with a full list. Skipping is periodic rather than permanent so a
/// revived collector re-earns its place on its own.
pub(super) fn barren_sources(bridge_health: &BridgeHealthContext, round: u32) -> HashSet<String> {
    if round.is_multiple_of(BARREN_SOURCE_RETRY_EVERY) {
        return HashSet::new();
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let Ok(store) = BridgeStore::load(path) else {
        return HashSet::new();
    };
    let barren: HashSet<String> = store
        .source_summary()
        .into_iter()
        .filter(|s| s.is_barren(SOURCE_MIN_SAMPLE))
        .map(|s| s.label)
        .collect();
    if !barren.is_empty() {
        info!(
            skipped = barren.len(),
            "watchdog: skipping sources that have yielded no reachable bridge"
        );
    }
    barren
}

/// Credit each source with the bridges it supplied, so a collector can later be
/// judged by what it yields rather than by whether its fetch returned 200.
pub(super) fn persist_bridge_sources(
    outcomes: &[bridge_fetcher::FetchOutcome],
    bridge_health: &BridgeHealthContext,
) {
    if outcomes.iter().all(|o| o.bridges.is_empty()) {
        return;
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "could not load bridge health store for source attribution");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for outcome in outcomes {
        for bridge in &outcome.bridges {
            store.note_source_at(bridge, &outcome.label, now);
        }
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "could not persist bridge source attribution");
    }
}

/// Outcome of [`cold_start_rescue_fetch`]: either a (possibly still empty)
/// set of newly-alive bridges, or an early exit because the caller asked to
/// stop while the rescue fetch was in flight.
pub(super) enum ColdStartRescue {
    Alive(Vec<(BridgeLine, Duration)>),
    StopRequested,
}

/// True cold start: every configured bridge (active slice and, where tried,
/// the full background pool) failed its TCP probe, and there is no
/// `TorTunnel` yet to route a normal auto-fetch through — `bridge_fetcher`'s
/// usual path requires one. Without this, a fresh install (or a health store
/// wiped by all-dead bridges) can never recover on its own: `auto_fetch`
/// exists specifically for this, but the watchdog's version of it only runs
/// after a tunnel is already up.
///
/// Fetches the configured collateral-freedom sources directly (no Tor,
/// hostnames resolved through `bridge-probe`'s DoH pool -- see
/// `bridge_fetcher::fetch_all_direct`), persists source attribution the same
/// way the watchdog's own auto-fetch does, records anything found so Kotlin
/// can persist it into the user's saved bridge list, and re-probes the
/// result before handing it back. Returns an empty `Alive` set (not an
/// error) when `auto_fetch` is disabled, no sources are configured, or the
/// rescue fetch itself turns up nothing reachable -- the caller already
/// knows how to fail on an empty set.
pub(super) async fn cold_start_rescue_fetch(
    bridge_health: &BridgeHealthContext,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> ColdStartRescue {
    if !bridge_health.bridges_cfg.auto_fetch || bridge_health.bridges_cfg.sources.is_empty() {
        return ColdStartRescue::Alive(Vec::new());
    }

    info!(
        "no configured bridge is reachable; attempting a direct (non-Tor) fetch of fresh \
         bridges before giving up"
    );

    let sources: Vec<bridge_fetcher::Source> = bridge_health
        .bridges_cfg
        .sources
        .iter()
        .map(|s| bridge_fetcher::Source {
            label: s.label.clone(),
            url: s.url.clone(),
            headers: s.headers.clone(),
            cookies: s.cookies.clone(),
        })
        .collect();
    let max_body_bytes = bridge_health
        .bridges_cfg
        .max_body_mib
        .saturating_mul(1024 * 1024);

    let (fetched, outcomes) = tokio::select! {
        biased;
        _ = stop_rx.changed() => return ColdStartRescue::StopRequested,
        result = bridge_fetcher::fetch_all_direct(&sources, bridge_health.resolver_policy, AUTO_FETCH_TIMEOUT, max_body_bytes) => result,
    };
    for outcome in &outcomes {
        if let Some(err) = &outcome.error {
            warn!(label = %outcome.label, error = %err, "cold-start rescue fetch source failed");
        } else {
            info!(
                label = %outcome.label,
                bridges = outcome.bridges_extracted,
                "cold-start rescue fetch source OK"
            );
        }
    }
    persist_bridge_sources(&outcomes, bridge_health);
    let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
    info!(
        unique = unique.len(),
        duplicates, "cold-start rescue fetch complete"
    );
    if unique.is_empty() {
        return ColdStartRescue::Alive(Vec::new());
    }
    record_auto_fetched_bridges(unique.clone());

    let mut round = tokio::select! {
        biased;
        _ = stop_rx.changed() => return ColdStartRescue::StopRequested,
        round = bridge_probe::probe_round_with_policy(unique.clone(), Duration::from_secs(5), bridge_health.resolver_policy) => round,
    };
    persist_and_rank_probe(&unique, &mut round, bridge_health);
    ColdStartRescue::Alive(std::mem::take(&mut round.alive))
}

pub(super) fn persist_warm_results(pool: &WarmPool, bridge_health: &BridgeHealthContext) {
    if pool.warmed.is_empty() && pool.retired.is_empty() {
        return;
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "could not load bridge health store for warm pool");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for (bridge, _) in &pool.warmed {
        store.note_channel_success_at(bridge, now);
    }
    // Retiring is the only way a stale bridge line ever leaves the pool: it
    // stays reachable, so probing keeps voting for it, and the ranking keeps
    // promoting it.
    for bridge in &pool.retired {
        store.note_permanent_failure_at(bridge, now);
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "could not persist bridge rotation ranking");
    }
}

/// Persist the background circuit-verify tick's results. Only successes are recorded
/// (`BridgeStore::note_circuit_verified_at`) -- a failed end-to-end check does not demote the
/// bridge or bump any failure counter, it simply stays due for the next tick, since a single
/// timeout is routine (see `verify_bridges_sequential`'s doc) rather than proof the bridge is
/// actually bad.
pub(super) fn persist_circuit_verify_results(
    results: &[(BridgeLine, bool)],
    bridge_health: &BridgeHealthContext,
) {
    if results.is_empty() {
        return;
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "circuit-verify: could not load bridge health store");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for (bridge, ok) in results {
        if *ok {
            store.note_circuit_verified_at(bridge, now);
        }
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "circuit-verify: could not persist results");
    }
}

/// SOCKS5 accept loop.
///
/// Accepts connections, acquires a semaphore permit, spawns a task per connection.
/// Each task:
/// 1. Performs the SOCKS5 handshake — RFC 1929 USER/PASS when `auth_state` is
///    `Some`, otherwise legacy NO_AUTH (see [`handle_connection`]).
/// 2. Connects through Tor.
/// 3. Sends success reply.
/// 4. Bidirectionally copies data.
///
/// All errors are logged and swallowed; individual connection failures don't
/// crash the loop. Accept errors are also treated as transient and retried
/// after `ACCEPT_ERROR_BACKOFF`.
pub(super) async fn accept_loop(
    listener: &TcpListener,
    tunnel: &TorTunnel,
    permits: Arc<Semaphore>,
    policy: ConnectionPolicy,
) -> Result<()> {
    loop {
        // Accept a new connection; any accept error is treated as transient —
        // log it, back off, and retry instead of tearing down the engine.
        let (client, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "accept failed; retrying in {ACCEPT_ERROR_BACKOFF:?}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        // Acquire a permit before spawning (bounds task growth)
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");

        // Spawn a task for this connection
        let tunnel = tunnel.clone();
        let auth = policy.auth_state.clone();
        let block_onion = policy.block_onion;
        tokio::spawn(async move {
            // Permit is moved into the task and dropped on exit
            let _permit = permit;

            debug!(%peer, "new SOCKS5 connection");

            match handle_connection(client, tunnel, auth, block_onion).await {
                Ok(()) => {
                    debug!(%peer, "connection closed normally");
                }
                Err(e) => {
                    // Classify and log at appropriate level
                    let error_str = format!("{:#}", e);
                    if error_str.contains("handshake")
                        || error_str.contains("reset")
                        || error_str.contains("broken pipe")
                    {
                        debug!(%peer, error = %error_str, "connection error (client-side)");
                    } else {
                        warn!(%peer, error = %error_str, "connection error");
                    }
                }
            }
        });
    }
}

/// Handle a single SOCKS5 connection.
///
/// `auth` mirrors the CLI's behaviour (see `apps/socks5-proxy/src/server.rs`
/// and `docs/auth.md`): `Some(state)` insists on RFC 1929 USER/PASS and
/// rejects any connection with missing or incorrect credentials before a
/// Tor circuit is ever built; `None` is the legacy anonymous NO_AUTH path,
/// used only when no users are configured for this Android instance (see
/// `nativeStart`'s auth-resolution step in `lib.rs`).
pub(super) async fn handle_connection(
    mut client: TcpStream,
    tunnel: TorTunnel,
    auth: Option<Arc<AuthState>>,
    block_onion: bool,
) -> Result<()> {
    // SOCKS5 handshake: USER/PASS when `auth` is configured, NO_AUTH otherwise.
    let req = handshake_with_deadline(&mut client, auth).await?;

    if !onion_destination_allowed(&req, block_onion) {
        info!(host = %req.host, port = req.port, "rejecting onion destination by local policy");
        socks5_proto::reply(&mut client, Reply::ConnectionNotAllowed)
            .await
            .context("failed to send onion policy reply")?;
        return Ok(());
    }

    debug!(host = %req.host, port = req.port, "SOCKS5 CONNECT request");

    // Connect through Tor
    let tor_stream = tunnel
        .connect(&req.host, req.port)
        .await
        .context("Tor connect failed")?;

    debug!(host = %req.host, port = req.port, "Tor connection established");

    // Send success reply
    socks5_proto::reply(&mut client, Reply::Success)
        .await
        .context("failed to send SOCKS5 reply")?;

    // Bidirectional copy (DataStream is futures AsyncRead/Write)
    let mut tor_compat = tor_stream.compat();
    tokio::io::copy_bidirectional(&mut client, &mut tor_compat)
        .await
        .context("data relay failed")?;

    Ok(())
}

/// [`socks5_proto::handshake`] under one absolute deadline: a single
/// `tokio::time::timeout` around the whole negotiation — NOT a per-read
/// timeout, so slow byte-by-byte clients cannot extend it indefinitely.
async fn handshake_with_deadline<S>(
    stream: &mut S,
    auth: Option<Arc<AuthState>>,
) -> anyhow::Result<socks5_proto::ConnectRequest>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let handshake =
        tokio::time::timeout(HANDSHAKE_DEADLINE, socks5_proto::handshake(stream, auth)).await;
    let req = match handshake {
        Ok(res) => res,
        Err(_elapsed) => bail!("handshake deadline of {HANDSHAKE_DEADLINE:?} exceeded"),
    }
    .context("SOCKS5 handshake")?;
    Ok(req)
}

/// Apply the Android listener's global destination policy after SOCKS5
/// authentication and before any Tor stream is opened.
pub(super) fn onion_destination_allowed(
    req: &socks5_proto::ConnectRequest,
    block_onion: bool,
) -> bool {
    !block_onion || !req.is_onion()
}

/// Helper: set the global status from the engine thread.
///
/// Poisoning-tolerant (`into_inner`): a panicked holder must not brick
/// status updates forever — readers/writers share the recovery policy.
pub(super) fn set_final_status(status: EngineStatus) {
    use crate::get_status;
    *get_status().lock().unwrap_or_else(|p| p.into_inner()) = status;
}

/// The running engine's `TorTunnel`, shared with `nativeRefreshBridges`
/// (`lib.rs`) so it can fetch fresh bridge lists over the already-live
/// circuit -- `bridge_fetcher::fetch_all` requires an established
/// `TorTunnel` and has no direct (non-Tor) fetch path, so this can only
/// ever do anything while the engine is `On`. `None` whenever the engine
/// isn't in that state (not started yet, still bootstrapping, or tearing
/// down -- see the `set_current_tunnel(None)` call just before teardown in
/// `engine_async`).
pub(super) static CURRENT_TUNNEL: OnceLock<Mutex<Option<TorTunnel>>> = OnceLock::new();

pub(super) fn set_current_tunnel(tunnel: Option<TorTunnel>) {
    *CURRENT_TUNNEL
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = tunnel;
}

/// Cheap `TorTunnel` clone (see [`TorTunnel::clone`]'s use in `accept_loop`)
/// of the currently running engine's tunnel, or `None` if the engine isn't
/// `On` right now.
pub(crate) fn get_current_tunnel() -> Option<TorTunnel> {
    CURRENT_TUNNEL
        .get()?
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

/// Bridges `persist_and_rank_probe` has pruned (crossed `max_fails`/`max_circuit_fails`)
/// since the last time Kotlin drained them via `nativeTakePrunedBridges`
/// (docs/android-bridge-freshness-plan.md's Phase 1). `Prefs.bridgesList` on the Kotlin side
/// is the actual source of truth for what gets probed/bootstrapped next -- this is just the
/// handoff channel, mirroring `CURRENT_TUNNEL`'s pattern.
pub(super) static PRUNED_BRIDGES: OnceLock<Mutex<Vec<BridgeLine>>> = OnceLock::new();

pub(super) fn record_pruned_bridges(mut pruned: Vec<BridgeLine>) {
    if pruned.is_empty() {
        return;
    }
    PRUNED_BRIDGES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .append(&mut pruned);
}

/// Drain and return every bridge pruned since the last call. Called from the
/// `nativeTakePrunedBridges` JNI entry point (`lib.rs`).
pub(crate) fn take_pruned_bridges() -> Vec<BridgeLine> {
    let Some(lock) = PRUNED_BRIDGES.get() else {
        return Vec::new();
    };
    std::mem::take(&mut *lock.lock().unwrap_or_else(|p| p.into_inner()))
}

/// Bridges `stall_watchdog`'s auto-fetch has found (docs/android-bridge-freshness-plan.md's
/// Phase 2) since the last time Kotlin drained them via `nativeTakeAutoFetchedBridges`. Same
/// handoff pattern as [`PRUNED_BRIDGES`] -- `stall_watchdog` has no access to
/// `Prefs.bridgesList`, only Kotlin does.
pub(super) static AUTO_FETCHED_BRIDGES: OnceLock<Mutex<Vec<BridgeLine>>> = OnceLock::new();

pub(super) fn record_auto_fetched_bridges(mut fetched: Vec<BridgeLine>) {
    if fetched.is_empty() {
        return;
    }
    AUTO_FETCHED_BRIDGES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .append(&mut fetched);
}

/// Drain and return every bridge auto-fetched since the last call. Called from the
/// `nativeTakeAutoFetchedBridges` JNI entry point (`lib.rs`).
pub(crate) fn take_auto_fetched_bridges() -> Vec<BridgeLine> {
    let Some(lock) = AUTO_FETCHED_BRIDGES.get() else {
        return Vec::new();
    };
    std::mem::take(&mut *lock.lock().unwrap_or_else(|p| p.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{duplex, AsyncWriteExt};
    use tokio::time::sleep;

    /// Assert that `handle` is still running, then that it fails with a
    /// deadline error containing "handshake" and "deadline" after the given
    /// additional wait.
    async fn assert_deadline_error(
        handle: &mut tokio::task::JoinHandle<anyhow::Result<socks5_proto::ConnectRequest>>,
        wait_before_finish_check: Duration,
    ) {
        sleep(wait_before_finish_check).await;
        assert!(!handle.is_finished(), "handshake must still be pending");

        // Wait out the remainder of the deadline before polling completion.
        sleep(HANDSHAKE_DEADLINE).await;
        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("handshake task did not finish after the deadline")
            .expect("handshake task panicked");
        let err = result.expect_err("handshake must fail at the deadline");
        let msg = format!("{err:#}");
        assert!(msg.contains("handshake"), "error text: {msg}");
        assert!(msg.contains("deadline"), "error text: {msg}");
    }

    #[tokio::test(start_paused = true)]
    async fn silent_client_handshake_fails_at_deadline() {
        let (client, server) = duplex(64);
        let mut handle = tokio::spawn(async move {
            let mut server = server;
            handshake_with_deadline(&mut server, None).await
        });

        // Client sends nothing and keeps the stream open (never dropped).
        drop(tokio::spawn(async move {
            sleep(Duration::from_secs(3600)).await;
            drop(client);
        }));

        assert_deadline_error(&mut handle, HANDSHAKE_DEADLINE / 2).await;
    }

    #[tokio::test(start_paused = true)]
    async fn partial_handshake_header_fails_at_deadline() {
        let (mut client, server) = duplex(64);
        let mut handle = tokio::spawn(async move {
            let mut server = server;
            handshake_with_deadline(&mut server, None).await
        });

        // Client writes only the VER byte — an incomplete method-negotiation
        // header — then holds the stream open.
        tokio::spawn(async move {
            client.write_all(&[0x05]).await.ok();
            sleep(Duration::from_secs(3600)).await;
        });

        assert_deadline_error(&mut handle, HANDSHAKE_DEADLINE / 2).await;
    }

    #[tokio::test(start_paused = true)]
    async fn trickling_client_still_hits_absolute_deadline() {
        let (mut client, server) = duplex(64);
        let handle = tokio::spawn(async move {
            let mut server = server;
            handshake_with_deadline(&mut server, None).await
        });

        // Trickling client: one valid byte every 12 s (HANDSHAKE_DEADLINE *
        // 2 / 5), then holds the stream forever. If the deadline were renewed
        // per byte, the handshake would never expire.
        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05]).await.ok();
            sleep(HANDSHAKE_DEADLINE * 2 / 5).await;
            client.write_all(&[0x01]).await.ok();
            sleep(HANDSHAKE_DEADLINE * 2 / 5).await;
            client.write_all(&[0x00]).await.ok();
            sleep(Duration::from_secs(3600)).await;
        });

        // 20 s in: a renewal-per-read implementation would still be waiting
        // for the CONNECT request (last byte arrived at 24 s).
        sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
        assert!(!handle.is_finished(), "handshake must still be pending");

        // Sleep past the absolute deadline (40 s total) before polling.
        sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("handshake task did not finish after the deadline")
            .expect("handshake task panicked");
        let err = result.expect_err("handshake must fail at the absolute deadline");
        let msg = format!("{err:#}");
        assert!(msg.contains("handshake"), "error text: {msg}");
        assert!(msg.contains("deadline"), "error text: {msg}");

        client_task.abort();
    }
}
