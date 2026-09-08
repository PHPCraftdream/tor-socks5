//! Read-side queries and ranking for [`BridgeStore`]: per-bridge counters,
//! summary slices, and health-ranked bridge selection.

use super::*;

impl BridgeStore {
    /// Bridges that have actually carried a Tor channel, most recently first.
    ///
    /// Stricter than [`healthiest_bridges`](Self::healthiest_bridges), which
    /// also admits bridges that merely answered a reachability probe. For
    /// handing bridges to someone else that difference is the whole point: the
    /// recipient is typically offline at import and cannot check anything, so
    /// whatever is passed on has to be already known good rather than merely
    /// plausible. A webtunnel bridge in particular can answer probes forever
    /// while the relay behind its website is long gone.
    pub fn channel_proven_bridges(&self, limit: usize) -> Vec<BridgeLine> {
        let mut proven: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.channel_ok_count > 0 && !e.is_retired())
            .collect();
        proven.sort_by(|a, b| {
            b.last_channel_ok
                .cmp(&a.last_channel_ok)
                .then_with(|| b.channel_ok_count.cmp(&a.channel_ok_count))
        });
        proven
            .into_iter()
            .take(limit)
            .map(|e| e.bridge.clone())
            .collect()
    }

    /// What each source has actually yielded, keyed by its label.
    ///
    /// A source is judged by the bridges it supplied, not by whether its fetch
    /// succeeded — those answer different questions, and only the first one
    /// matters. A collector that has stopped regenerating keeps returning HTTP
    /// 200 with hundreds of lines indefinitely.
    pub fn source_summary(&self) -> Vec<SourceStats> {
        let mut by_source: BTreeMap<String, SourceStats> = BTreeMap::new();
        for entry in self.entries.values() {
            for label in &entry.sources {
                let stats = by_source
                    .entry(label.clone())
                    .or_insert_with(|| SourceStats {
                        label: label.clone(),
                        ..SourceStats::default()
                    });
                stats.offered += 1;
                if entry.is_retired() {
                    stats.retired += 1;
                    continue;
                }
                if entry.fails == 0 && entry.ok_count > 0 {
                    stats.alive += 1;
                }
                if entry.channel_ok_count > 0 {
                    stats.channel_proven += 1;
                }
            }
        }
        by_source.into_values().collect()
    }

    /// Sources credited with a bridge, empty when it predates attribution.
    pub fn sources_of(&self, bridge: &BridgeLine) -> Vec<String> {
        self.entries
            .get(&key_of(bridge))
            .map(|e| e.sources.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Per-transport counts and freshest timestamps, for a status display.
    ///
    /// Only covers bridges the store has seen. The configured total is not
    /// knowable here — that lives in the caller's own bridge list — and the
    /// difference between the two is itself informative: a large configured
    /// pool with few known entries means most of it has never been probed.
    pub fn transport_summary(&self) -> Vec<TransportStats> {
        let mut by_transport: BTreeMap<String, TransportStats> = BTreeMap::new();
        for entry in self.entries.values() {
            let name = entry
                .bridge
                .transport
                .clone()
                .unwrap_or_else(|| "plain".to_owned());
            let stats = by_transport
                .entry(name.clone())
                .or_insert_with(|| TransportStats {
                    transport: name,
                    ..TransportStats::default()
                });
            stats.known += 1;
            if entry.is_retired() {
                stats.retired += 1;
                // A retired bridge is excluded from the usable counts even
                // though its probe record looks perfect — that record is
                // exactly what makes it misleading.
                continue;
            }
            if entry.fails == 0 && entry.ok_count > 0 {
                stats.alive += 1;
            }
            if entry.channel_ok_count > 0 {
                stats.channel_proven += 1;
            }
            if let Some(ok) = entry.last_ok {
                stats.last_probe_ok = stats.last_probe_ok.max(Some(ok));
            }
            stats.last_channel_ok = stats.last_channel_ok.max(entry.last_channel_ok);
        }
        by_transport.into_values().collect()
    }

    /// Number of bridges with proven reachability: they answered at least
    /// one probe (`ok_count > 0`), have no failure since (`fails == 0`), and
    /// are not retired — the same predicate [`healthiest_bridges`]
    /// (Self::healthiest_bridges) filters by. Mere `fails == 0` was wrong for
    /// this method's only consumer, the stale-channel watchdog: a
    /// source-attributed entry is born with `fails == 0` without ever being
    /// probed, and a retired bridge keeps a perfect TCP record, so either
    /// would let the watchdog read "only unprobed candidates in the store"
    /// as "a bridge is reachable" and withhold the client rebuild. Surfaced
    /// for the stale-channel watchdog, which must distinguish "all circuits
    /// fail but bridges are proven reachable" (stale channels → rebuild the
    /// client) from "bridges are genuinely unreachable" (the bridge
    /// maintenance loop's own job).
    #[must_use]
    pub fn alive_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.is_proven_alive())
            .count()
    }

    /// Cumulative successful-probe count for a bridge (0 if unknown). This
    /// is the persistent stability signal used to order bridges for arti:
    /// a higher count means the bridge has proven reachable more often.
    #[must_use]
    pub fn ok_count(&self, bridge: &BridgeLine) -> u32 {
        self.entries.get(&key_of(bridge)).map_or(0, |e| e.ok_count)
    }

    /// Circuit-layer consecutive failure count for a bridge (0 if unknown).
    /// Surfaced by arti's tracing events; used to prune bridges that pass
    /// TCP probes but can't carry multi-hop traffic. Also used by the
    /// bridge-warmer (`bridge_warmer.rs`) to rank candidates for channel
    /// warming — a bridge accumulating circuit failures is deprioritized
    /// even if its TCP probes still succeed.
    #[must_use]
    pub fn circuit_fails(&self, bridge: &BridgeLine) -> u32 {
        self.entries
            .get(&key_of(bridge))
            .map_or(0, |e| e.circuit_fails)
    }

    /// When the circuit-failure counter for a bridge was last touched (bumped
    /// or reset), if the bridge is known to the store. `None` covers "not
    /// tracked here". Surfaced for the soft-failover watchdog
    /// (`apps/socks5-proxy/src/tor_watchdog.rs`), which must only signal guard
    /// failures on evidence produced by the *current* process run — a
    /// `circuit_fails` count inherited from a previous run's store file
    /// (possibly days old, per docs/plans/2026-08-28-stability-plan.md §1b)
    /// must not arm a guard-failure signal seconds after boot. Note: entries
    /// parsed from legacy store lines without a `cobs=` field carry the Unix
    /// epoch here, which naturally compares as stale.
    #[must_use]
    pub fn last_circuit_observation(&self, bridge: &BridgeLine) -> Option<OffsetDateTime> {
        self.entries
            .get(&key_of(bridge))
            .map(|e| e.last_circuit_observation)
    }

    /// Number of successful PT/channel warm-ups for a bridge.
    #[must_use]
    pub fn channel_ok_count(&self, bridge: &BridgeLine) -> u32 {
        self.entries
            .get(&key_of(bridge))
            .map_or(0, |e| e.channel_ok_count)
    }

    /// Number of times a full circuit through this bridge was proven to
    /// reach the open internet. `0` covers both "never checked" and "the
    /// bridge is not even tracked".
    #[must_use]
    pub fn verified_count(&self, bridge: &BridgeLine) -> u32 {
        self.entries
            .get(&key_of(bridge))
            .map_or(0, |e| e.verified_count)
    }

    /// When a full circuit through this bridge last reached the open
    /// internet, if ever.
    #[must_use]
    pub fn last_verified(&self, bridge: &BridgeLine) -> Option<OffsetDateTime> {
        self.entries
            .get(&key_of(bridge))
            .and_then(|e| e.last_verified)
    }

    /// Channel-proven bridges (see [`Self::channel_proven_bridges`]) that either have never
    /// passed a full end-to-end circuit verification, or whose last one is older than
    /// `max_age` -- the candidate pool for the background watchdog's slow circuit-verify tick.
    /// Ranked oldest-verified (or never-verified) first, so the tick always makes progress
    /// through the whole channel-proven pool rather than repeatedly re-checking the same few
    /// bridges. Retired bridges are excluded.
    #[must_use]
    pub fn needing_circuit_verification(
        &self,
        now: OffsetDateTime,
        max_age: Duration,
        limit: usize,
    ) -> Vec<BridgeLine> {
        let mut due: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.channel_ok_count > 0 && !e.is_retired())
            .filter(|e| match e.last_verified {
                None => true,
                Some(t) => now - t >= max_age,
            })
            .collect();
        due.sort_by_key(|e| e.last_verification_attempt.or(e.last_verified));
        due.into_iter()
            .take(limit)
            .map(|e| e.bridge.clone())
            .collect()
    }

    /// Consecutive TCP-probe failure count for a bridge (0 if unknown, which
    /// also covers "never probed"). `0` means the last probe round saw this
    /// bridge as reachable. Used by the bridge-warmer to exclude TCP-unreachable
    /// bridges from the warming pool.
    #[must_use]
    pub fn tcp_fails(&self, bridge: &BridgeLine) -> u32 {
        self.entries.get(&key_of(bridge)).map_or(0, |e| e.fails)
    }

    /// Failure count for a bridge (0 if unknown). Test/diagnostic helper.
    #[cfg(test)]
    pub(super) fn fails_of(&self, bridge: &BridgeLine) -> u32 {
        self.entries.get(&key_of(bridge)).map_or(0, |e| e.fails)
    }

    /// Bridges known reachable at the last probe round (`fails == 0`), ranked best-first by
    /// proven stability (`ok_count`, descending) then latency (ascending) -- the same ordering
    /// [`Self::note_probe_round`]'s caller applies to a freshly-probed round, read back from
    /// disk instead of requiring a new probe. A bridge with `ok_count == 0` (never yet seen
    /// reachable, even if it hasn't failed either) is excluded: absence of failure is not
    /// evidence the bridge actually works.
    #[must_use]
    pub fn healthiest_bridges(&self, limit: usize) -> Vec<BridgeLine> {
        let healthy: Vec<&Entry> = self
            .entries
            .values()
            // Retired bridges must be excluded rather than merely ranked low. A
            // retirement means the bridge answers but can never serve as
            // configured -- a stale fingerprint -- so it keeps a clean probe
            // record and an excellent latency, and any ranking that considers
            // only reachability promotes it straight back into the active pool.
            .filter(|e| e.is_proven_alive())
            .collect();
        Self::rank_and_take(healthy, limit)
    }

    /// Like [`healthiest_bridges`](Self::healthiest_bridges), but ranks only entries whose
    /// bridge appears in `candidates`, rather than the whole store.
    ///
    /// Ranking globally and then intersecting with a candidate set -- the obvious way to combine
    /// "healthiest" with "restricted to this pool" -- silently starves a small pool: a store
    /// dominated by one transport's history fills the global top `limit` before a smaller
    /// transport's own candidates are even considered, so "the healthiest of these 441 webtunnel
    /// bridges" could come back as five, not because only five are healthy, but because the rest
    /// don't outrank several thousand healthy obfs4 entries globally. Measured on a phone: this
    /// was the actual reason a webtunnel-preferred pool kept landing on a handful of bridges
    /// through every fix to the probing and warming logic above it -- all of them fed candidates
    /// through this same global-then-intersect pattern. Filtering to `candidates` first means a
    /// small pool's own best members always survive to be ranked.
    #[must_use]
    pub fn healthiest_among(&self, candidates: &[BridgeLine], limit: usize) -> Vec<BridgeLine> {
        use std::collections::HashSet;
        let allowed: HashSet<Key> = candidates.iter().map(key_of).collect();
        let healthy: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.is_proven_alive() && allowed.contains(&e.key()))
            .collect();
        Self::rank_and_take(healthy, limit)
    }

    fn rank_and_take(mut healthy: Vec<&Entry>, limit: usize) -> Vec<BridgeLine> {
        healthy.sort_by(|a, b| {
            // End-to-end verified (a real circuit reached the open internet) outranks
            // merely channel-proven, which outranks merely TCP-reachable -- the same three
            // tiers `docs/design/real-connectivity-bridge-verification.md` documents.
            b.verified_count
                .cmp(&a.verified_count)
                .then_with(|| b.last_verified.cmp(&a.last_verified))
                .then_with(|| b.channel_ok_count.cmp(&a.channel_ok_count))
                .then_with(|| b.last_channel_ok.cmp(&a.last_channel_ok))
                .then_with(|| b.ok_count.cmp(&a.ok_count))
                .then(a.last_latency.cmp(&b.last_latency))
        });
        healthy
            .into_iter()
            .take(limit)
            .map(|e| e.bridge.clone())
            .collect()
    }
}
