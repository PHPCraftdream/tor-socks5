//! Observation recording for [`BridgeStore`]: probe outcomes, circuit- and
//! channel-layer successes and failures, source attribution, and pruning of
//! dead entries.

use super::*;

impl BridgeStore {
    /// Record a successful probe: reset the failure counter and stamp the
    /// success time + latency. (Test helper; production goes through
    /// [`Self::note_probe_round`].)
    #[cfg(test)]
    pub(super) fn record(&mut self, bridge: BridgeLine, latency: Duration) {
        self.record_at(bridge, latency, OffsetDateTime::now_utc());
    }

    pub(super) fn record_at(&mut self, bridge: BridgeLine, latency: Duration, now: OffsetDateTime) {
        let key = key_of(&bridge);
        let e = self.entries.entry(key).or_insert_with(|| Entry {
            bridge: bridge.clone(),
            last_ok: None,
            last_attempt: now,
            last_latency: latency,
            fails: 0,
            ok_count: 0,
            channel_ok_count: 0,
            last_channel_ok: None,
            verified_count: 0,
            last_verified: None,
            last_verification_attempt: None,
            circuit_fails: 0,
            last_circuit_observation: now,
            sources: Default::default(),
        });
        e.bridge = bridge;
        e.last_ok = Some(now);
        e.last_attempt = now;
        e.last_latency = latency;
        e.fails = 0;
        e.ok_count = e.ok_count.saturating_add(1);
    }

    /// Apply the outcome of a probe round and prune dead bridges.
    ///
    /// `probed` is every bridge that was attempted; `alive` is the subset
    /// that responded (with latency). A reachable bridge resets to
    /// healthy; an unreachable one bumps its `fails` counter at most once
    /// per `fail_window`. Any bridge whose `fails` reaches `max_fails`
    /// **or** whose `circuit_fails` reaches `max_circuit_fails` is removed
    /// from the store and returned, so the caller can also drop it from
    /// the config.
    ///
    /// Pure w.r.t. `now` so it is unit-testable.
    pub fn note_probe_round(
        &mut self,
        probed: &[BridgeLine],
        alive: &[(BridgeLine, Duration)],
        now: OffsetDateTime,
        fail_window: Duration,
        max_fails: u32,
        max_circuit_fails: u32,
    ) -> Vec<BridgeLine> {
        use std::collections::HashSet;
        let alive_keys: HashSet<Key> = alive.iter().map(|(b, _)| key_of(b)).collect();

        for (bridge, latency) in alive {
            self.record_at(bridge.clone(), *latency, now);
        }
        for bridge in probed {
            if alive_keys.contains(&key_of(bridge)) {
                continue;
            }
            self.note_failure_at(bridge, now, fail_window);
        }

        self.prune(max_fails, max_circuit_fails)
    }

    /// Record a circuit-layer failure observed from arti's tracing events.
    /// Rate-limited: at most one bump per `window`. Returns true if the
    /// counter was incremented this call. If the bridge is unknown to the
    /// store, it is inserted with `circuit_fails = 1`.
    ///
    /// Pure w.r.t. `now` for unit testing.
    pub fn note_circuit_failure_at(
        &mut self,
        bridge: &BridgeLine,
        now: OffsetDateTime,
        window: Duration,
    ) -> bool {
        let key = key_of(bridge);
        match self.entries.get_mut(&key) {
            Some(e) => {
                if now - e.last_circuit_observation >= window {
                    e.circuit_fails = e.circuit_fails.saturating_add(1);
                    e.last_circuit_observation = now;
                    true
                } else {
                    false
                }
            }
            None => {
                self.entries.insert(
                    key,
                    Entry {
                        bridge: bridge.clone(),
                        last_ok: None,
                        last_attempt: now,
                        last_latency: Duration::ZERO,
                        fails: 0,
                        ok_count: 0,
                        channel_ok_count: 0,
                        last_channel_ok: None,
                        verified_count: 0,
                        last_verified: None,
                        last_verification_attempt: None,
                        circuit_fails: 1,
                        last_circuit_observation: now,
                        sources: Default::default(),
                    },
                );
                true
            }
        }
    }

    /// Mark a bridge as permanently unusable, regardless of the caller's
    /// failure window or threshold.
    ///
    /// Most channel failures are transient and deserve the rate-limited
    /// counting `note_circuit_failure_at` does. Some are verdicts: a relay whose
    /// identity does not match the fingerprint in the bridge line will never
    /// match it, because the line is stale rather than the relay unreachable.
    /// Counting those slowly means re-selecting a known-dead bridge for hours,
    /// and they are especially costly for webtunnel, where the endpoint stays
    /// perfectly reachable and so keeps ranking well.
    pub fn note_permanent_failure_at(&mut self, bridge: &BridgeLine, now: OffsetDateTime) {
        let key = key_of(bridge);
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            bridge: bridge.clone(),
            last_ok: None,
            last_attempt: now,
            last_latency: Duration::ZERO,
            fails: 0,
            ok_count: 0,
            channel_ok_count: 0,
            last_channel_ok: None,
            verified_count: 0,
            last_verified: None,
            last_verification_attempt: None,
            circuit_fails: 0,
            last_circuit_observation: now,
            sources: Default::default(),
        });
        entry.circuit_fails = RETIRED_CIRCUIT_FAILS;
        entry.last_circuit_observation = now;
    }

    /// Credit `source` with having offered `bridge`.
    ///
    /// Additive rather than overwriting: the same line is routinely published
    /// by several collectors, and crediting only the first would make every
    /// other one look barren for bridges it genuinely supplies. Creates a
    /// bare entry if the bridge has not been probed yet, so a source can be
    /// judged even before its bridges have been tried.
    pub fn note_source_at(&mut self, bridge: &BridgeLine, source: &str, now: OffsetDateTime) {
        let entry = self.entries.entry(key_of(bridge)).or_insert_with(|| Entry {
            bridge: bridge.clone(),
            last_ok: None,
            last_attempt: now,
            last_latency: Duration::ZERO,
            fails: 0,
            ok_count: 0,
            channel_ok_count: 0,
            last_channel_ok: None,
            verified_count: 0,
            last_verified: None,
            last_verification_attempt: None,
            circuit_fails: 0,
            last_circuit_observation: now,
            sources: Default::default(),
        });
        entry.sources.insert(source.to_owned());
    }

    /// Whether this bridge has been retired, i.e. proven unusable as configured
    /// rather than just unreliable. Callers selecting candidates should skip
    /// these: they stay reachable, so reachability-based checks keep voting for
    /// them.
    pub fn is_retired(&self, bridge: &BridgeLine) -> bool {
        self.entries
            .get(&key_of(bridge))
            .is_some_and(Entry::is_retired)
    }

    /// Whether `bridge`'s most recent probe attempt was today (UTC, by `today`'s date) and it
    /// failed (`fails > 0` -- a success would have reset it to zero). Lets a caller skip
    /// re-checking a bridge already known dead as of earlier today without waiting through its
    /// live timeout again; unknown to the store at all reads as "not known dead", not "dead".
    pub fn failed_today(&self, bridge: &BridgeLine, today: OffsetDateTime) -> bool {
        self.entries
            .get(&key_of(bridge))
            .is_some_and(|e| e.fails > 0 && e.last_attempt.date() == today.date())
    }

    /// Record a circuit-layer success observed from arti's tracing events:
    /// resets `circuit_fails` to 0 and stamps `last_circuit_observation`.
    /// No-op for an unknown bridge — circuit successes only matter for
    /// bridges we are tracking via TCP probes too.
    pub fn note_circuit_success_at(&mut self, bridge: &BridgeLine, now: OffsetDateTime) {
        if let Some(e) = self.entries.get_mut(&key_of(bridge)) {
            e.circuit_fails = 0;
            e.last_circuit_observation = now;
        }
    }

    /// Record a successful pluggable-transport channel warm-up. This is
    /// deliberately separate from TCP probe and end-to-end circuit counters:
    /// a warm channel is a strong rotation signal, but it is not proof that a
    /// multi-hop circuit can carry arbitrary traffic.
    pub fn note_channel_success_at(&mut self, bridge: &BridgeLine, now: OffsetDateTime) {
        if let Some(e) = self.entries.get_mut(&key_of(bridge)) {
            e.channel_ok_count = e.channel_ok_count.saturating_add(1);
            e.last_channel_ok = Some(now);
        }
    }

    /// Record that a full circuit through this bridge actually reached the
    /// open internet (`verify_bridge_reachable`, not merely a channel open).
    /// No-op if the bridge is not already tracked -- verification only ever
    /// runs against bridges the store already knows about (channel-proven
    /// candidates), never as a way to introduce a new entry.
    pub fn note_circuit_verified_at(&mut self, bridge: &BridgeLine, now: OffsetDateTime) {
        if let Some(e) = self.entries.get_mut(&key_of(bridge)) {
            e.verified_count = e.verified_count.saturating_add(1);
            e.last_verified = Some(now);
            e.last_verification_attempt = Some(now);
        }
    }

    /// Advance verification scheduling even when the check failed.
    pub fn note_verification_attempt_at(&mut self, bridge: &BridgeLine, now: OffsetDateTime) {
        if let Some(entry) = self.entries.get_mut(&key_of(bridge)) {
            entry.last_verification_attempt = Some(now);
        }
    }

    /// Bump the failure counter for one bridge, respecting the rate limit.
    /// Returns true if the counter was incremented this call.
    pub(super) fn note_failure_at(
        &mut self,
        bridge: &BridgeLine,
        now: OffsetDateTime,
        window: Duration,
    ) -> bool {
        let key = key_of(bridge);
        match self.entries.get_mut(&key) {
            Some(e) => {
                // Rate-limit: only one increment per `window`.
                if now - e.last_attempt >= window {
                    e.fails = e.fails.saturating_add(1);
                    e.last_attempt = now;
                    true
                } else {
                    false
                }
            }
            None => {
                // First time we see this bridge and it already failed.
                self.entries.insert(
                    key,
                    Entry {
                        bridge: bridge.clone(),
                        last_ok: None,
                        last_attempt: now,
                        last_latency: Duration::ZERO,
                        fails: 1,
                        ok_count: 0,
                        channel_ok_count: 0,
                        last_channel_ok: None,
                        verified_count: 0,
                        last_verified: None,
                        last_verification_attempt: None,
                        circuit_fails: 0,
                        last_circuit_observation: now,
                        sources: Default::default(),
                    },
                );
                true
            }
        }
    }

    /// Remove and return every bridge whose `fails` reached `max_fails`
    /// or whose `circuit_fails` reached `max_circuit_fails`.
    fn prune(&mut self, max_fails: u32, max_circuit_fails: u32) -> Vec<BridgeLine> {
        let dead: Vec<Key> = self
            .entries
            .iter()
            .filter(|(_, e)| e.fails >= max_fails || e.circuit_fails >= max_circuit_fails)
            .map(|(k, _)| k.clone())
            .collect();
        dead.into_iter()
            .filter_map(|k| self.entries.remove(&k).map(|e| e.bridge))
            .collect()
    }
}
