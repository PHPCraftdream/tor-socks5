//! Vanity prefix search for v3 onion addresses.

use std::cmp::min;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::address::{generate, Keypair};

/// Maximum supported vanity prefix length (base32 chars).
///
/// 32^8 = 2^40 attempts: hours-to-days on commodity hardware; anything
/// longer is unrealistic.
pub const MAX_PREFIX_LEN: usize = 8;

/// Upper bound on worker threads: spawn cost and diminishing returns make
/// more pointless (also caps the executor's chosen thread count).
pub const MAX_THREADS: usize = 64;

/// Errors returned by [`VanityTarget::new`] and [`search`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VanityError {
    /// Empty prefix.
    #[error("vanity prefix must not be empty")]
    Empty,
    /// Longer than [`MAX_PREFIX_LEN`]: unreasonably expensive to search.
    #[error("vanity prefix longer than {MAX_PREFIX_LEN} chars is unrealistic")]
    TooLong(usize),
    /// A character outside the base32 alphabet (a-z, 2-7).
    #[error("invalid character {0:?}: base32 uses a-z and 2-7 (no 0, 1, 8, or 9)")]
    InvalidCharacter(char),
    /// A worker thread could not be spawned.
    #[error("failed to spawn vanity worker thread: {0}")]
    Spawn(String),
}

/// A validated vanity prefix, precompiled to a bit pattern for fast
/// comparison against the leading bits of a public key.
///
/// The first `prefix.len() * 5` bits of the base32 address body are exactly
/// the first `prefix.len() * 5` bits of the pubkey (big-endian bit order),
/// so no address formatting is needed per attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VanityTarget {
    /// Lowercased prefix (a-z2-7 only).
    prefix: String,
    /// Significant bits: `prefix.len() * 5` (<= 40).
    bits: u32,
    /// Prefix bits packed MSB-first in the low `bits` bits.
    pattern: u64,
}

impl VanityTarget {
    /// Validate and compile a vanity prefix. Case is normalized to lower.
    pub fn new(prefix: &str) -> Result<VanityTarget, VanityError> {
        let lower = prefix.to_ascii_lowercase();
        if lower.is_empty() {
            return Err(VanityError::Empty);
        }
        if lower.len() > MAX_PREFIX_LEN {
            return Err(VanityError::TooLong(lower.len()));
        }
        let mut pattern = 0u64;
        for ch in lower.chars() {
            let val = match ch {
                'a'..='z' => ch as u64 - 'a' as u64,
                '2'..='7' => ch as u64 - '2' as u64 + 26,
                _ => return Err(VanityError::InvalidCharacter(ch)),
            };
            pattern = (pattern << 5) | val;
        }
        let bits = lower.len() as u32 * 5;
        Ok(VanityTarget {
            prefix: lower,
            bits,
            pattern,
        })
    }

    /// The normalized prefix this target searches for.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// True if `pubkey`'s first `bits` bits match the prefix pattern.
    #[inline]
    fn matches(&self, pubkey: &[u8; 32]) -> bool {
        let head = u64::from_be_bytes(pubkey[..8].try_into().expect("8 bytes"));
        (head >> (64 - self.bits)) == self.pattern
    }
}

/// Expected number of key generations to find a prefix of `len` base32
/// characters: 32^len. Lengths beyond [`MAX_PREFIX_LEN`] are clamped.
#[must_use]
pub fn expected_attempts(len: usize) -> u64 {
    let len = len.min(MAX_PREFIX_LEN);
    32u64.pow(len as u32)
}

/// Rough wall-clock estimate for finding a prefix at `rate_per_sec` keys/s.
/// Non-finite or non-positive rates yield [`Duration::MAX`].
#[must_use]
pub fn estimate(prefix_len: usize, rate_per_sec: f64) -> Duration {
    let attempts = expected_attempts(prefix_len);
    if rate_per_sec <= 0.0 || rate_per_sec.is_nan() {
        return Duration::MAX;
    }
    let secs = attempts as f64 / rate_per_sec;
    Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX)
}

/// Configuration for [`search`].
#[derive(Clone)]
pub struct SearchOptions {
    /// Worker threads; 0 means `available_parallelism - 1` (min 1).
    pub threads: usize,
    /// Overall time budget; `None` searches until found or cancelled.
    pub time_limit: Option<Duration>,
    /// Cooperative cancel flag, checked between attempts.
    pub cancel: Arc<AtomicBool>,
    /// Optional shared progress counter: total attempts across workers.
    pub progress: Option<Arc<AtomicU64>>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            threads: 0,
            time_limit: None,
            cancel: Arc::new(AtomicBool::new(false)),
            progress: None,
        }
    }
}

/// Result of a vanity [`search`].
#[derive(Debug)]
pub enum SearchOutcome {
    /// A matching keypair was found.
    Found(Keypair),
    /// The time limit expired before a match.
    TimedOut {
        /// Total attempts across all threads.
        attempts: u64,
    },
    /// The cancel flag was observed before a match.
    Cancelled {
        /// Total attempts across all threads.
        attempts: u64,
    },
    /// A worker thread panicked.
    Panicked {
        /// Total attempts across all threads.
        attempts: u64,
    },
}

impl SearchOutcome {
    /// Total attempts made (0 if a key was found before counting).
    pub fn attempts(&self) -> u64 {
        match self {
            SearchOutcome::Found(_) => 0,
            SearchOutcome::TimedOut { attempts }
            | SearchOutcome::Cancelled { attempts }
            | SearchOutcome::Panicked { attempts } => *attempts,
        }
    }
}

#[cfg(test)]
static SPAWN_FAIL: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static WORKER_PANIC: AtomicBool = AtomicBool::new(false);

/// Search for a keypair whose address starts with `target`'s prefix.
///
/// Plain `std::thread` workers share an attempts counter and a stop flag;
/// the first match stops all other workers.
///
/// Returns `Err` only when a worker thread could not be spawned; a worker
/// panic instead yields [`SearchOutcome::Panicked`] after the remaining
/// workers are joined.
pub fn search(target: &VanityTarget, opts: &SearchOptions) -> Result<SearchOutcome, VanityError> {
    let threads = worker_count(opts.threads);
    let attempts = Arc::new(AtomicU64::new(0));
    // Local stop flag: set by the finder (and on deadline), ORed with the
    // caller's cancel flag in the worker loop.
    let stop = Arc::new(AtomicBool::new(opts.cancel.load(Ordering::Relaxed)));
    // checked_add: an over-large time limit must disable the deadline,
    // not panic.
    let deadline = opts.time_limit.and_then(|d| Instant::now().checked_add(d));

    let mut handles: Vec<thread::JoinHandle<Option<Keypair>>> = Vec::with_capacity(threads);
    for _ in 0..threads {
        let target = target.clone();
        // Test seams are keyed to a sentinel prefix so parallel search
        // tests are unaffected.
        #[cfg(test)]
        let spawn_seam = target.prefix() == "ababa";
        #[cfg(test)]
        let panic_seam = target.prefix() == "abab7";
        #[cfg(test)]
        if spawn_seam && SPAWN_FAIL.load(Ordering::Relaxed) {
            stop.store(true, Ordering::Relaxed);
            for handle in handles {
                let _ = handle.join();
            }
            return Err(VanityError::Spawn("spawn disabled in test".to_owned()));
        }
        let target = target.clone();
        let attempts = Arc::clone(&attempts);
        let worker_stop = Arc::clone(&stop);
        let cancel = Arc::clone(&opts.cancel);
        let progress = opts.progress.clone();
        let spawned = thread::Builder::new()
            .name("vanity-search".to_owned())
            .spawn(move || {
                let mut local = 0u64;
                loop {
                    #[cfg(test)]
                    if panic_seam && WORKER_PANIC.load(Ordering::Relaxed) {
                        panic!("worker panic seam");
                    }
                    if local.is_multiple_of(64)
                        && (worker_stop.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed))
                    {
                        break;
                    }
                    let kp = generate();
                    local += 1;
                    if target.matches(kp.pubkey()) {
                        worker_stop.store(true, Ordering::Relaxed);
                        attempts.fetch_add(local, Ordering::Relaxed);
                        if let Some(p) = &progress {
                            p.fetch_add(local, Ordering::Relaxed);
                        }
                        return Some(kp);
                    }
                    if let Some(deadline) = deadline {
                        if Instant::now() >= deadline {
                            worker_stop.store(true, Ordering::Relaxed);
                            attempts.fetch_add(local, Ordering::Relaxed);
                            if let Some(p) = &progress {
                                p.fetch_add(local, Ordering::Relaxed);
                            }
                            return None;
                        }
                    }
                }
                attempts.fetch_add(local, Ordering::Relaxed);
                if let Some(p) = &progress {
                    p.fetch_add(local, Ordering::Relaxed);
                }
                None
            });
        let handle = match spawned {
            Ok(handle) => handle,
            Err(err) => {
                stop.store(true, Ordering::Relaxed);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(VanityError::Spawn(err.to_string()));
            }
        };
        handles.push(handle);
    }

    let mut found = None;
    let mut panicked = false;
    for handle in handles {
        match handle.join() {
            Ok(Some(kp)) => found = Some(kp),
            Ok(None) => {}
            Err(_) => {
                // A worker panicked: stop the rest, keep joining.
                panicked = true;
                stop.store(true, Ordering::Relaxed);
            }
        }
    }
    let total = attempts.load(Ordering::Relaxed);
    if let Some(kp) = found {
        return Ok(SearchOutcome::Found(kp));
    }
    if panicked {
        return Ok(SearchOutcome::Panicked { attempts: total });
    }
    if opts.cancel.load(Ordering::Relaxed) {
        return Ok(SearchOutcome::Cancelled { attempts: total });
    }
    Ok(SearchOutcome::TimedOut { attempts: total })
}

/// Rough attempts/s measured by running `worker_count(threads)` generation
/// workers for `duration`.
#[must_use]
pub fn measure_rate(threads: usize, duration: Duration) -> Option<f64> {
    let threads = worker_count(threads);
    let attempts = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(threads);
    for _ in 0..threads {
        let attempts = Arc::clone(&attempts);
        let stop = Arc::clone(&stop);
        let worker_stop = Arc::clone(&stop);
        let spawned = thread::Builder::new()
            .name("vanity-rate".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    let _ = generate();
                    attempts.fetch_add(1, Ordering::Relaxed);
                }
            });
        match spawned {
            Ok(handle) => handles.push(handle),
            Err(err) => {
                stop.store(true, Ordering::Relaxed);
                for handle in handles {
                    let _ = handle.join();
                }
                eprintln!("failed to spawn rate-measurement worker thread: {err}");
                return None;
            }
        }
    }
    let start = Instant::now();
    thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.join();
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed > 0.0 {
        Some(attempts.load(Ordering::Relaxed) as f64 / elapsed)
    } else {
        None
    }
}

/// Resolve the configured thread count; 0 means all-but-one core, min 1.
/// Always clamped to [`MAX_THREADS`].
#[must_use]
pub fn worker_count(requested: usize) -> usize {
    if requested > 0 {
        return min(requested, MAX_THREADS);
    }
    let cores = thread::available_parallelism().map_or(1, |n| n.get());
    min(cores.saturating_sub(1).max(1), MAX_THREADS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{onion_address, parse_onion_address};

    fn assert_invalid(ch: char) {
        assert!(
            matches!(
                VanityTarget::new(&ch.to_string()),
                Err(VanityError::InvalidCharacter(_))
            ),
            "char {ch:?} must be rejected"
        );
    }

    #[test]
    fn target_validation_and_normalization() {
        assert_eq!(VanityTarget::new(""), Err(VanityError::Empty));
        assert_eq!(VanityTarget::new("abcdefghi"), Err(VanityError::TooLong(9)));
        // Note: 'l' IS valid base32 (a-z) and must be accepted.
        for bad in ['1', '8', '0', ' ', '9', '!'] {
            assert_invalid(bad);
        }
        // Case normalized: "ABC" and "abc" compile identically.
        let upper = VanityTarget::new("ABC").unwrap();
        let lower = VanityTarget::new("abc").unwrap();
        assert_eq!(upper.prefix(), "abc");
        assert_eq!(upper.bits, lower.bits);
        assert_eq!(upper.pattern, lower.pattern);
        // 'l' is inside the base32 alphabet, so it is accepted.
        assert!(VanityTarget::new("l").is_ok());
    }

    #[test]
    fn matches_agrees_with_address_prefix() {
        for prefix in ["a", "ab", "abc", "abcd", "z7", "2a7b", "abcdefgh"] {
            let target = VanityTarget::new(prefix).unwrap();
            // The first `bits` bits of the pubkey are the first `bits`
            // bits of the base32 body, so placing the pattern in the top
            // bits of a fresh pubkey yields a matching address.
            let mut pubkey = [0u8; 32];
            let shifted = target.pattern << (64 - target.bits);
            pubkey[..8].copy_from_slice(&shifted.to_be_bytes());
            assert!(
                target.matches(&pubkey),
                "pattern pubkey must match for {prefix}"
            );
            let addr = onion_address(&pubkey);
            assert!(addr.starts_with(prefix), "{addr} must start with {prefix}");
            assert_eq!(parse_onion_address(&addr).unwrap(), pubkey);
            // Flipping any bit inside the pattern region must not match.
            let idx = (target.bits - 1) as usize;
            let mut other = pubkey;
            other[idx / 8] ^= 1 << (7 - (idx % 8));
            assert!(!target.matches(&other));
        }
    }

    #[test]
    fn expected_attempts_values() {
        assert_eq!(expected_attempts(1), 32);
        assert_eq!(expected_attempts(8), 32u64.pow(8));
        assert_eq!(expected_attempts(8), 1u64 << 40);
    }

    /// Lengths beyond MAX_PREFIX_LEN are clamped, not asserted on.
    #[test]
    fn expected_attempts_clamps_long_input() {
        assert_eq!(expected_attempts(999), 32u64.pow(8));
    }

    #[test]
    fn estimate_values() {
        // 32 attempts at 32 keys/s = 1 second.
        assert_eq!(estimate(1, 32.0), Duration::from_secs(1));
        // Zero, negative, or NaN rate is unbounded.
        assert_eq!(estimate(1, 0.0), Duration::MAX);
        assert_eq!(estimate(2, -1.0), Duration::MAX);
        assert_eq!(estimate(1, f64::NAN), Duration::MAX);
        // Infinite rate: finite (immediate) estimate, not a panic.
        let inf = estimate(1, f64::INFINITY);
        assert!(inf < Duration::MAX);
        assert!(estimate(8, 1e6) > Duration::from_secs(1_000_000));
    }

    #[test]
    fn search_finds_short_prefix_single_thread() {
        let target = VanityTarget::new("a").unwrap();
        let opts = SearchOptions {
            threads: 1,
            time_limit: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let SearchOutcome::Found(kp) = search(&target, &opts).unwrap() else {
            panic!("1-char prefix must be found quickly");
        };
        assert!(kp.address().starts_with("a"));
        assert_eq!(
            parse_onion_address(kp.address()).expect("valid address"),
            *kp.pubkey()
        );
    }

    /// Duration::MAX overflows `Instant::now() + d`; the deadline must be
    /// disabled instead of panicking.
    #[test]
    fn search_survives_overflowing_time_limit() {
        let target = VanityTarget::new("a").unwrap();
        let opts = SearchOptions {
            threads: 1,
            time_limit: Some(Duration::MAX),
            ..Default::default()
        };
        let SearchOutcome::Found(kp) = search(&target, &opts).unwrap() else {
            panic!("1-char prefix must be found quickly");
        };
        assert!(kp.address().starts_with("a"));
    }

    #[test]
    fn search_finds_three_char_prefix_multithreaded() {
        let target = VanityTarget::new("7Z2").unwrap();
        let opts = SearchOptions {
            threads: 4,
            time_limit: Some(Duration::from_secs(120)),
            ..Default::default()
        };
        let SearchOutcome::Found(kp) = search(&target, &opts).unwrap() else {
            panic!("3-char prefix must be found with 4 threads");
        };
        assert!(kp.address().starts_with("7z2"));
        assert!(parse_onion_address(kp.address()).is_ok());
    }

    #[test]
    fn search_times_out_on_impossible_prefix() {
        // 32^8 expected attempts; 200ms cannot plausibly find it
        // (attempts/s is ~1e5-1e6, so hit probability is ~1e-7).
        let target = VanityTarget::new("abcdefgh").unwrap();
        let opts = SearchOptions {
            threads: 2,
            time_limit: Some(Duration::from_millis(200)),
            ..Default::default()
        };
        let outcome = search(&target, &opts).unwrap();
        assert!(matches!(outcome, SearchOutcome::TimedOut { attempts } if attempts > 0));
    }

    #[test]
    fn search_cancelled_before_start() {
        let target = VanityTarget::new("a").unwrap();
        let cancel = Arc::new(AtomicBool::new(true));
        let opts = SearchOptions {
            threads: 1,
            time_limit: None,
            cancel: Arc::clone(&cancel),
            ..Default::default()
        };
        let outcome = search(&target, &opts).unwrap();
        assert!(matches!(outcome, SearchOutcome::Cancelled { attempts } if attempts == 0));
    }

    #[test]
    fn search_cancelled_midway() {
        let target = VanityTarget::new("abcd2347").unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        // No time limit: the only exits are found/cancel, so the outcome
        // is deterministically Cancelled. attempts may be 0 if the worker
        // observes the cancel flag before its first attempt (heavy load).
        let opts = SearchOptions {
            threads: 1,
            time_limit: None,
            cancel: Arc::clone(&cancel),
            ..Default::default()
        };
        let flag = Arc::clone(&cancel);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::Relaxed);
        });
        let outcome = search(&target, &opts).unwrap();
        assert!(matches!(outcome, SearchOutcome::Cancelled { .. }));
    }

    /// The SPAWN_FAIL seam makes every spawn fail; search must return
    /// Err(VanityError::Spawn) after joining the workers already started.
    #[test]
    fn search_reports_spawn_failure() {
        SPAWN_FAIL.store(true, Ordering::Relaxed);
        let target = VanityTarget::new("ababa").unwrap();
        let opts = SearchOptions {
            threads: 2,
            time_limit: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let result = search(&target, &opts);
        SPAWN_FAIL.store(false, Ordering::Relaxed);
        assert!(matches!(result, Err(VanityError::Spawn(_))));
    }

    /// The WORKER_PANIC seam makes workers panic; search must join the
    /// remaining workers and return Panicked.
    #[test]
    fn search_reports_worker_panic() {
        WORKER_PANIC.store(true, Ordering::Relaxed);
        let target = VanityTarget::new("abab7").unwrap();
        let opts = SearchOptions {
            threads: 2,
            time_limit: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let result = search(&target, &opts);
        WORKER_PANIC.store(false, Ordering::Relaxed);
        assert!(matches!(result, Ok(SearchOutcome::Panicked { .. })));
    }

    #[test]
    fn worker_count_respects_zero_and_positive() {
        assert_eq!(worker_count(3), 3);
        assert_eq!(worker_count(1), 1);
        assert!(worker_count(0) >= 1);
    }

    #[test]
    fn worker_count_clamps_to_max() {
        assert_eq!(worker_count(usize::MAX), MAX_THREADS);
    }

    /// The shared progress counter receives every worker's attempts, also on
    /// the winning thread (a Found outcome leaves the counter nonzero).
    #[test]
    fn progress_counter_counts_attempts_on_found() {
        let target = VanityTarget::new("a").unwrap();
        let progress = Arc::new(AtomicU64::new(0));
        let opts = SearchOptions {
            threads: 1,
            time_limit: Some(Duration::from_secs(30)),
            progress: Some(Arc::clone(&progress)),
            ..Default::default()
        };
        let SearchOutcome::Found(_) = search(&target, &opts).unwrap() else {
            panic!("1-char prefix must be found quickly");
        };
        assert!(progress.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn measure_rate_returns_positive_rate() {
        let rate = measure_rate(1, Duration::from_millis(100));
        assert!(rate.is_some());
        assert!(rate.unwrap() > 0.0);
    }

    /// Ignored benchmark: measures attempts/s on one thread by searching an
    /// 8-char prefix with a 2s budget. Run with
    /// `cargo test -p tor-socks5-onion onion --release -- --ignored --nocapture`.
    #[test]
    #[ignore = "speed benchmark, not a correctness test"]
    fn bench_attempts_per_second() {
        let target = VanityTarget::new("abcdefgh").unwrap();
        let opts = SearchOptions {
            threads: 1,
            time_limit: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let start = Instant::now();
        let SearchOutcome::TimedOut { attempts } = search(&target, &opts).unwrap() else {
            panic!("benchmark assumes a timeout");
        };
        let elapsed = start.elapsed();
        let rate = attempts as f64 / elapsed.as_secs_f64();
        println!("attempts: {attempts} in {elapsed:?} => {rate:.0} attempts/s (1 thread)");
    }
}
