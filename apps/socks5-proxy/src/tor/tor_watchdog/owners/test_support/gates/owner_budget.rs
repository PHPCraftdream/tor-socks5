use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, ensure, Result};
use tokio::time::Instant;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

fn upper_boottime_nanos(uptime: &str) -> Result<u128> {
    ensure!(uptime.len() <= 256, "owner uptime bound");
    let value = uptime
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("missing uptime"))?;
    let (seconds, fraction) = value
        .split_once('.')
        .ok_or_else(|| anyhow!("uptime precision"))?;
    ensure!(
        !seconds.is_empty()
            && seconds.bytes().all(|byte| byte.is_ascii_digit())
            && (1..=9).contains(&fraction.len())
            && fraction.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid uptime"
    );
    let seconds = seconds.parse::<u128>()?;
    let fractional = fraction.parse::<u128>()?;
    let precision = u32::try_from(fraction.len())?;
    let quantum = NANOS_PER_SECOND / 10_u128.pow(precision);
    // /proc/uptime truncates CLOCK_BOOTTIME. Its upper edge never grants extra time.
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|whole| {
            fractional
                .checked_mul(quantum)
                .and_then(|part| whole.checked_add(part))
        })
        .and_then(|value| value.checked_add(quantum))
        .ok_or_else(|| anyhow!("uptime overflow"))
}

fn project(absolute: u128, uptime: &str, budget_ms: u64, anchor: Instant) -> Result<Instant> {
    ensure!((1..=240_000).contains(&budget_ms), "owner budget bound");
    let remaining = absolute
        .checked_sub(upper_boottime_nanos(uptime)?)
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow!("original owner deadline expired"))?;
    ensure!(remaining <= 240_000_000_000, "owner absolute budget bound");
    let remaining = u64::try_from(remaining)?.min(budget_ms * 1_000_000);
    anchor
        .checked_add(Duration::from_nanos(remaining))
        .ok_or_else(|| anyhow!("owner deadline overflow"))
}

/// Private inherited absolute CLOCK_BOOTTIME boundary, not a fresh child duration.
/// Synchronous procfs reading is not preemptible; the external guardian is unchanged.
#[allow(
    dead_code,
    reason = "Called by harness environment entrypoints, not binary unit tests."
)]
pub(super) fn from_environment() -> Result<Option<Instant>> {
    let Some(budget) = std::env::var_os("PT_OWNER_EVIDENCE_BUDGET_MS") else {
        ensure!(
            std::env::var_os("PT_OWNER_EVIDENCE_DEADLINE_BOOTTIME_NS").is_none(),
            "incomplete owner deadline metadata"
        );
        return Ok(None);
    };
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("PT_PROXY_ISOLATED").as_deref() == Ok("yes"),
        "owner deadline requires isolated CI"
    );
    let budget = budget
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("invalid owner budget metadata"))?;
    let absolute = std::env::var("PT_OWNER_EVIDENCE_DEADLINE_BOOTTIME_NS")?.parse::<u128>()?;
    let anchor = Instant::now();
    let mut uptime = String::new();
    std::fs::File::open("/proc/uptime")?
        .take(257)
        .read_to_string(&mut uptime)?;
    Ok(Some(project(absolute, &uptime, budget, anchor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_descendant_cannot_restart_the_owner_duration() {
        let anchor = Instant::now();
        let absolute = 110 * NANOS_PER_SECOND;
        let parent = project(absolute, "100.00 0.00\n", 10_000, anchor).unwrap();
        let child = project(absolute, "108.00 0.00\n", 10_000, anchor).unwrap();
        assert_eq!(parent.duration_since(anchor), Duration::from_millis(9990));
        assert_eq!(child.duration_since(anchor), Duration::from_millis(1990));
        assert!(child < parent);
        assert!(project(absolute, "110.00 0.00\n", 10_000, anchor).is_err());
    }

    #[test]
    fn uptime_precision_is_conservative_and_checked() {
        assert_eq!(upper_boottime_nanos("1.2 0.00\n").unwrap(), 1_300_000_000);
        assert_eq!(
            upper_boottime_nanos("1.234567890 0.00\n").unwrap(),
            1_234_567_891
        );
        for invalid in ["", "1", "1.", "-1.00", "1.a0", "1.1234567890", "NaN"] {
            assert!(upper_boottime_nanos(invalid).is_err());
        }
        assert!(upper_boottime_nanos(&"9".repeat(257)).is_err());
        assert!(upper_boottime_nanos("340282366920938463463374607431768211455.00").is_err());
    }
}
