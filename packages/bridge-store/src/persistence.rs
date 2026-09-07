use super::*;

/// Parsed metadata-comment fields.
#[derive(Debug)]
pub(super) struct Meta {
    pub(super) last_ok: Option<OffsetDateTime>,
    pub(super) last_attempt: OffsetDateTime,
    pub(super) last_latency: Duration,
    pub(super) fails: u32,
    pub(super) ok_count: u32,
    pub(super) channel_ok_count: u32,
    pub(super) last_channel_ok: Option<OffsetDateTime>,
    pub(super) verified_count: u32,
    pub(super) last_verified: Option<OffsetDateTime>,
    pub(super) last_verification_attempt: Option<OffsetDateTime>,
    pub(super) circuit_fails: u32,
    pub(super) last_circuit_observation: OffsetDateTime,
    pub(super) sources: std::collections::BTreeSet<String>,
}

impl Default for Meta {
    fn default() -> Self {
        let epoch = OffsetDateTime::from_unix_timestamp(0).expect("epoch is valid");
        Self {
            last_ok: None,
            last_attempt: epoch,
            last_latency: Duration::ZERO,
            fails: 0,
            ok_count: 0,
            channel_ok_count: 0,
            last_channel_ok: None,
            verified_count: 0,
            last_verified: None,
            last_verification_attempt: None,
            circuit_fails: 0,
            sources: Default::default(),
            last_circuit_observation: epoch,
        }
    }
}

pub(super) fn parse_meta_comment(s: &str) -> Option<Meta> {
    // New format: `fails=N seen=M attempt=<iso> ok=<iso|-> latency=NNms`
    // plus optional `cfails=N cobs=<iso>` (active health observation).
    // Unknown tokens are ignored — forward-compatible.
    if s.starts_with("fails=") {
        let mut meta = Meta::default();
        for tok in s.split_whitespace() {
            if let Some(v) = tok.strip_prefix("fails=") {
                meta.fails = v.parse().ok()?;
            } else if let Some(v) = tok.strip_prefix("seen=") {
                meta.ok_count = v.parse().ok()?;
            } else if let Some(v) = tok.strip_prefix("attempt=") {
                meta.last_attempt = OffsetDateTime::parse(v, &Iso8601::DEFAULT).ok()?;
            } else if let Some(v) = tok.strip_prefix("ok=") {
                meta.last_ok = if v == "-" {
                    None
                } else {
                    Some(OffsetDateTime::parse(v, &Iso8601::DEFAULT).ok()?)
                };
            } else if let Some(v) = tok.strip_prefix("latency=") {
                let ms = v.strip_suffix("ms")?.parse::<u64>().ok()?;
                meta.last_latency = Duration::from_millis(ms);
            } else if let Some(v) = tok.strip_prefix("chseen=") {
                meta.channel_ok_count = v.parse().ok()?;
            } else if let Some(v) = tok.strip_prefix("chok=") {
                meta.last_channel_ok = if v == "-" {
                    None
                } else {
                    Some(OffsetDateTime::parse(v, &Iso8601::DEFAULT).ok()?)
                };
            } else if let Some(v) = tok.strip_prefix("evseen=") {
                meta.verified_count = v.parse().ok()?;
            } else if let Some(v) = tok.strip_prefix("evok=") {
                meta.last_verified = if v == "-" {
                    None
                } else {
                    Some(OffsetDateTime::parse(v, &Iso8601::DEFAULT).ok()?)
                };
            } else if let Some(v) = tok.strip_prefix("evtry=") {
                meta.last_verification_attempt =
                    Some(OffsetDateTime::parse(v, &Iso8601::DEFAULT).ok()?);
            } else if let Some(v) = tok.strip_prefix("cfails=") {
                meta.circuit_fails = v.parse().ok()?;
            } else if let Some(v) = tok.strip_prefix("cobs=") {
                meta.last_circuit_observation = OffsetDateTime::parse(v, &Iso8601::DEFAULT).ok()?;
            } else if let Some(v) = tok.strip_prefix("src=") {
                meta.sources = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
        return Some(meta);
    }

    // Legacy format: `<iso> latency=NNms` → treat as healthy at that time.
    let (when_part, rest) = s.split_once(' ')?;
    let when = OffsetDateTime::parse(when_part, &Iso8601::DEFAULT).ok()?;
    let lat_ms = rest
        .trim()
        .strip_prefix("latency=")?
        .strip_suffix("ms")?
        .parse::<u64>()
        .ok()?;
    Some(Meta {
        last_ok: Some(when),
        last_attempt: when,
        last_latency: Duration::from_millis(lat_ms),
        fails: 0,
        ok_count: 1,
        channel_ok_count: 0,
        last_channel_ok: None,
        verified_count: 0,
        last_verified: None,
        last_verification_attempt: None,
        circuit_fails: 0,
        sources: Default::default(),
        last_circuit_observation: when,
    })
}

pub(super) fn format_iso(t: OffsetDateTime) -> String {
    t.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "0000-00-00T00:00:00Z".to_string())
}
