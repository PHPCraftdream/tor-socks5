//! CLI plumbing around the vanity search core (`tor-socks5-onion`): duration
//! parsing, warm-up measurement, Ctrl-C handling and stderr progress.
//! Printing stays here; the crate stays silent.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ::tor_socks5_onion::address::Keypair;
use ::tor_socks5_onion::vanity::{
    estimate, expected_attempts, measure_rate, search, worker_count, SearchOptions, SearchOutcome,
    VanityTarget,
};

/// Parse a duration: a non-negative number plus unit s|m|h; a bare number
/// means seconds. Zero and overflow are rejected.
fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    use anyhow::bail;

    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, unit) = s.split_at(split);
    if digits.is_empty() {
        bail!("invalid duration {s:?}: bad number");
    }
    let value: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration {s:?}: bad number"))?;
    let mult: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => bail!("invalid duration {s:?}: unknown unit (use s, m or h)"),
    };
    let secs = value
        .checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("invalid duration {s:?}: overflow"))?;
    if secs == 0 {
        bail!("invalid duration {s:?}: must be positive");
    }
    Ok(Duration::from_secs(secs))
}

/// Measure attempts/s over ~1s with `threads` worker threads.
fn warmup_rate(threads: usize) -> Option<f64> {
    measure_rate(threads, Duration::from_secs(1))
}

/// Spawn a detached thread that sets `cancel` on Ctrl-C.
fn spawn_ctrl_c(cancel: Arc<AtomicBool>) {
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let Ok(runtime) = runtime else {
            return;
        };
        runtime.block_on(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel.store(true, Ordering::Relaxed);
            }
        });
    });
}

/// The vanity search of `onion new --vanity`, with its estimate and progress
/// on stderr: returns the keypair found, or an error when the search timed
/// out or was interrupted (nothing is saved then).
pub(crate) fn search_for_cli(
    vanity_str: &str,
    threads: Option<usize>,
    timeout_str: Option<&str>,
) -> anyhow::Result<Keypair> {
    use anyhow::bail;

    let target = VanityTarget::new(vanity_str)?;

    // Warm-up: measure the generation rate for a rough ETA.
    let rate = warmup_rate(worker_count(threads.unwrap_or(0)));
    let expected = expected_attempts(target.prefix().len());
    let estimate = rate.map(|rate| self::estimate(target.prefix().len(), rate));
    match estimate {
        Some(eta) => eprintln!(
            "vanity search: prefix {:?} needs ~{expected} attempts; \
             measured {:.0} keys/s; mean time ~{:?} (~95% within 3x)",
            target.prefix(),
            rate.expect("estimate implies rate"),
            eta,
        ),
        None => eprintln!(
            "vanity search: prefix {:?} needs ~{expected} attempts; \
             speed could not be measured, no ETA available",
            target.prefix()
        ),
    }
    let time_limit = match timeout_str {
        Some(s) => Some(parse_duration(s)?),
        None => {
            if estimate.is_some_and(|eta| eta > Duration::from_secs(3600)) {
                bail!(
                    "expected vanity search time exceeds 1 hour; pass \
                     --timeout (e.g. --timeout 2h) to confirm"
                );
            }
            None
        }
    };

    let cancel = Arc::new(AtomicBool::new(false));
    spawn_ctrl_c(Arc::clone(&cancel));
    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    {
        let progress = Arc::clone(&progress);
        let done = Arc::clone(&done);
        let start = Instant::now();
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(10));
                if done.load(Ordering::Relaxed) {
                    break;
                }
                let attempts = progress.load(Ordering::Relaxed);
                let secs = start.elapsed().as_secs_f64().max(1e-9);
                eprintln!(
                    "vanity search: {attempts} attempts, {:.0} keys/s, elapsed {:?}",
                    attempts as f64 / secs,
                    Duration::from_secs_f64(secs),
                );
            }
        });
    }
    let outcome = match search(
        &target,
        &SearchOptions {
            threads: threads.unwrap_or(0),
            time_limit,
            cancel: Arc::clone(&cancel),
            progress: Some(Arc::clone(&progress)),
        },
    ) {
        Ok(outcome) => outcome,
        Err(e) => bail!("vanity search failed to start: {e}"),
    };
    done.store(true, Ordering::Relaxed);

    match outcome {
        SearchOutcome::Found(keypair) => Ok(keypair),
        SearchOutcome::TimedOut { attempts } => {
            eprintln!("vanity search: {attempts} attempts in total");
            bail!(
                "vanity search timed out; no key was saved \
                 (retry with a longer --timeout or a shorter prefix)"
            );
        }
        SearchOutcome::Cancelled { attempts } => {
            eprintln!("vanity search: interrupted by Ctrl-C after {attempts} attempts");
            bail!("vanity search interrupted; no key was saved");
        }
        SearchOutcome::Panicked { attempts } => {
            eprintln!("vanity search: {attempts} attempts before abort");
            bail!("vanity search aborted: a worker thread panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_units_and_rejects_nonsense() {
        for good in [("90", 90), ("90s", 90), ("30m", 1800), ("2h", 7200)] {
            assert_eq!(
                parse_duration(good.0).expect(good.0),
                Duration::from_secs(good.1),
                "{good:?}"
            );
        }
        for bad in ["", "abc", "0", "1x", "-5s", "99999999999999999999s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} must be rejected");
        }
    }
}
