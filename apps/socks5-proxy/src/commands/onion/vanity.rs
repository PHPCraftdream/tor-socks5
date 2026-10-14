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
pub(crate) const MAX_PREFIX_LEN: usize = 8;

/// Errors returned by [`VanityTarget::new`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum VanityError {
    /// Empty prefix.
    #[error("vanity prefix must not be empty")]
    Empty,
    /// Longer than [`MAX_PREFIX_LEN`]: unreasonably expensive to search.
    #[error("vanity prefix longer than {MAX_PREFIX_LEN} chars is unrealistic")]
    TooLong(usize),
    /// A character outside the base32 alphabet (a-z, 2-7).
    #[error("invalid character {0:?}: base32 uses a-z and 2-7 (no 0, 1, 8, or 9)")]
    InvalidCharacter(char),
}

/// A validated vanity prefix, precompiled to a bit pattern for fast
/// comparison against the leading bits of a public key.
///
/// The first `prefix.len() * 5` bits of the base32 address body are exactly
/// the first `prefix.len() * 5` bits of the pubkey (big-endian bit order),
/// so no address formatting is needed per attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VanityTarget {
    /// Lowercased prefix (a-z2-7 only).
    prefix: String,
    /// Significant bits: `prefix.len() * 5` (<= 40).
    bits: u32,
    /// Prefix bits packed MSB-first in the low `bits` bits.
    pattern: u64,
}

impl VanityTarget {
    /// Validate and compile a vanity prefix. Case is normalized to lower.
    pub(crate) fn new(prefix: &str) -> Result<VanityTarget, VanityError> {
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
    pub(crate) fn prefix(&self) -> &str {
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
/// characters: 32^len.
#[must_use]
pub(crate) fn expected_attempts(len: usize) -> u64 {
    assert!(len <= MAX_PREFIX_LEN, "prefix too long");
    32u64.pow(len as u32)
}

/// Rough wall-clock estimate for finding a prefix at `rate_per_sec` keys/s.
#[must_use]
pub(crate) fn estimate(prefix_len: usize, rate_per_sec: f64) -> Duration {
    let attempts = expected_attempts(prefix_len);
    if rate_per_sec <= 0.0 {
        return Duration::MAX;
    }
    let secs = (attempts as f64 / rate_per_sec).min(u64::MAX as f64);
    Duration::from_secs_f64(secs)
}

/// Configuration for [`search`].
#[derive(Clone)]
pub(crate) struct SearchOptions {
    /// Worker threads; 0 means `available_parallelism - 1` (min 1).
    pub(crate) threads: usize,
    /// Overall time budget; `None` searches until found or cancelled.
    pub(crate) time_limit: Option<Duration>,
    /// Cooperative cancel flag, checked between attempts.
    pub(crate) cancel: Arc<AtomicBool>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            threads: 0,
            time_limit: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Result of a vanity [`search`].
#[derive(Debug)]
pub(crate) enum SearchOutcome {
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
}

impl SearchOutcome {
    /// Total attempts made (0 if a key was found before counting).
    pub(crate) fn attempts(&self) -> u64 {
        match self {
            SearchOutcome::Found(_) => 0,
            SearchOutcome::TimedOut { attempts } | SearchOutcome::Cancelled { attempts } => {
                *attempts
            }
        }
    }
}

/// Search for a keypair whose address starts with `target`'s prefix.
///
/// Plain `std::thread` workers share an attempts counter and a stop flag;
/// the first match stops all other workers.
#[must_use]
pub(crate) fn search(target: &VanityTarget, opts: &SearchOptions) -> SearchOutcome {
    let threads = worker_count(opts.threads);
    let attempts = Arc::new(AtomicU64::new(0));
    // Local stop flag: set by the finder (and on deadline), ORed with the
    // caller's cancel flag in the worker loop.
    let stop = Arc::new(AtomicBool::new(opts.cancel.load(Ordering::Relaxed)));
    let deadline = opts.time_limit.map(|d| Instant::now() + d);

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let target = target.clone();
        let attempts = Arc::clone(&attempts);
        let stop = Arc::clone(&stop);
        let cancel = Arc::clone(&opts.cancel);
        handles.push(thread::spawn(move || {
            let mut local = 0u64;
            loop {
                if local.is_multiple_of(64)
                    && (stop.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed))
                {
                    break;
                }
                let kp = generate();
                local += 1;
                if target.matches(kp.pubkey()) {
                    stop.store(true, Ordering::Relaxed);
                    attempts.fetch_add(local, Ordering::Relaxed);
                    return Some(kp);
                }
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        stop.store(true, Ordering::Relaxed);
                        attempts.fetch_add(local, Ordering::Relaxed);
                        return None;
                    }
                }
            }
            attempts.fetch_add(local, Ordering::Relaxed);
            None
        }));
    }

    let mut found = None;
    for handle in handles {
        if let Ok(Some(kp)) = handle.join() {
            found = Some(kp);
        }
    }
    let total = attempts.load(Ordering::Relaxed);
    if let Some(kp) = found {
        return SearchOutcome::Found(kp);
    }
    if opts.cancel.load(Ordering::Relaxed) {
        return SearchOutcome::Cancelled { attempts: total };
    }
    SearchOutcome::TimedOut { attempts: total }
}

/// Resolve the configured thread count; 0 means all-but-one core, min 1.
fn worker_count(requested: usize) -> usize {
    if requested > 0 {
        return requested;
    }
    let cores = thread::available_parallelism().map_or(1, |n| n.get());
    min(cores.saturating_sub(1).max(1), usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::address::{onion_address, parse_onion_address};
    use super::*;

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

    #[test]
    fn estimate_values() {
        // 32 attempts at 32 keys/s = 1 second.
        assert_eq!(estimate(1, 32.0), Duration::from_secs(1));
        // Zero or negative rate is unbounded.
        assert_eq!(estimate(1, 0.0), Duration::MAX);
        assert_eq!(estimate(2, -1.0), Duration::MAX);
        assert!(estimate(8, 1e6) > Duration::from_secs(1_000_000));
    }

    #[test]
    fn search_finds_short_prefix_single_thread() {
        let target = VanityTarget::new("a").unwrap();
        let opts = SearchOptions {
            threads: 1,
            time_limit: Some(Duration::from_secs(30)),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let outcome = search(&target, &opts);
        let SearchOutcome::Found(kp) = outcome else {
            panic!("1-char prefix must be found quickly");
        };
        assert!(kp.address().starts_with("a"));
        assert_eq!(
            parse_onion_address(kp.address()).expect("valid address"),
            *kp.pubkey()
        );
    }

    #[test]
    fn search_finds_three_char_prefix_multithreaded() {
        let target = VanityTarget::new("7Z2").unwrap();
        let opts = SearchOptions {
            threads: 4,
            time_limit: Some(Duration::from_secs(120)),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let outcome = search(&target, &opts);
        let SearchOutcome::Found(kp) = outcome else {
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
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let outcome = search(&target, &opts);
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
        };
        let outcome = search(&target, &opts);
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
        };
        let flag = Arc::clone(&cancel);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::Relaxed);
        });
        let outcome = search(&target, &opts);
        assert!(matches!(outcome, SearchOutcome::Cancelled { .. }));
    }

    #[test]
    fn worker_count_respects_zero_and_positive() {
        assert_eq!(worker_count(3), 3);
        assert_eq!(worker_count(1), 1);
        assert!(worker_count(0) >= 1);
    }

    /// Ignored benchmark: measures attempts/s on one thread by searching an
    /// 8-char prefix with a 2s budget. Run with
    /// `cargo test -p socks5-proxy onion --release -- --ignored --nocapture`.
    #[test]
    #[ignore = "speed benchmark, not a correctness test"]
    fn bench_attempts_per_second() {
        let target = VanityTarget::new("abcdefgh").unwrap();
        let opts = SearchOptions {
            threads: 1,
            time_limit: Some(Duration::from_secs(2)),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let start = Instant::now();
        let outcome = search(&target, &opts);
        let elapsed = start.elapsed();
        let SearchOutcome::TimedOut { attempts } = outcome else {
            panic!("benchmark assumes a timeout");
        };
        let rate = attempts as f64 / elapsed.as_secs_f64();
        println!("attempts: {attempts} in {elapsed:?} => {rate:.0} attempts/s (1 thread)");
    }
}
