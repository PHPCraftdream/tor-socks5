//! An internal pool object that we use to implement HsCircPool.

use web_time_compat::{Duration, Instant};

use crate::{
    AbstractTunnel,
    hspool::{HsCircStem, HsCircStemKind},
};
use rand::Rng;
use tor_basic_utils::RngExt as _;

/// A collection of circuits used to fulfil onion-service-related requests.
pub(super) struct Pool<C: AbstractTunnel> {
    /// The collection of circuits themselves, in no particular order.
    circuits: Vec<HsCircStem<C>>,

    /// The number of NAIVE elements that we would like to have in our pool.
    stem_target: usize,

    /// The number of GUARDED elements that we would like to have in our pool.
    guarded_stem_target: usize,

    /// Target number of short NAIVE circuits (zero except Disabled/2).
    short_stem_target: usize,
    /// Target number of short GUARDED circuits (zero except Disabled/2).
    short_guarded_stem_target: usize,
    /// tor-socks5 local patch: current standard service stem length
    /// (service_circuit_hops - 1). Stems of other lengths are retired when
    /// this changes.
    svc_len: usize,
    /// Set when short-target mode flips, so callers can retire old stems.
    policy_changed: bool,
    /// True if we have exhausted our pool since the last time we decided
    /// whether to change our target level.
    have_been_exhausted: bool,

    /// True if we have been under 4/5 of our target since the last time we
    /// decided whether to change it.
    have_been_under_highwater: bool,

    /// Last time when we changed our target size.
    last_changed_target: Option<Instant>,
}

/// Our default (and minimum) target NAIVE pool size.
const DEFAULT_NAIVE_STEM_TARGET: usize = 3;

/// Our default (and minimum) target GUARDED pool size.
const DEFAULT_GUARDED_STEM_TARGET: usize = 1;

/// Our maximum target NAIVE pool size.  We will never let our NAIVE target grow above this
/// value.
const MAX_NAIVE_STEM_TARGET: usize = 384;

/// Our maximum target GUARDED pool size.  We will never let our GUARDED target grow above this
/// value.
const MAX_GUARDED_STEM_TARGET: usize = 128;

/// A type of circuit we would like to launch.
///
/// [`ForLaunch::note_circ_launched`] should be called whenever a circuit
/// of this [`HsCircStemKind`] is launched, to decrement the internal target `count`.
pub(super) struct ForLaunch<'a> {
    /// The kind of circuit we want to launch.
    kind: HsCircStemKind,
    /// Actual expected stem length.
    n_hops: usize,
    /// This is a mutable reference to one of the target values from [`CircsToLaunch`];
    /// we decrement it when we have launched a circuit of this type.
    count: &'a mut usize,
    /// tor-socks5 local patch: true when this is a short (client) launch target.
    short: bool,
}

impl<'a> ForLaunch<'a> {
    /// A circuit was launched, decrement the current target for its kind.
    pub(super) fn note_circ_launched(self) {
        *self.count -= 1;
    }

    /// The stem length this launch request expects.
    pub(super) fn hops(&self) -> usize {
        self.n_hops
    }

    /// The kind of circuit we want to launch.
    pub(super) fn kind(&self) -> HsCircStemKind {
        self.kind
    }

    /// tor-socks5 local patch: true if this launch target is for short client stems.
    pub(super) fn is_short(&self) -> bool {
        self.short
    }
}

/// The circuits we need to launch.
pub(super) struct CircsToLaunch {
    /// tor-socks5 local patch: standard service stem length to launch.
    svc_len: usize,
    /// The number of NAIVE standard-length circuits to launch.
    stem_target: usize,
    /// The number of GUARDED standard-length circuits to launch.
    guarded_stem_target: usize,
    /// The number of NAIVE short-client circuits to launch.
    short_stem_target: usize,
    /// The number of GUARDED short-client circuits to launch.
    short_guarded_stem_target: usize,
    /// Diagnostic flag (pool-level state tracks the real policy); never read.
    #[allow(dead_code)]
    policy_changed: bool,
}

impl CircsToLaunch {
    /// Return a [`ForLaunch`] representing a circuit we would like to launch.
    pub(super) fn for_launch(&mut self) -> ForLaunch {
        if self.stem_target > 0 {
            ForLaunch {
                kind: HsCircStemKind::Naive,
                n_hops: self.svc_len,
                short: false,
                count: &mut self.stem_target,
            }
        } else if self.short_stem_target > 0 {
            ForLaunch {
                kind: HsCircStemKind::Naive,
                n_hops: 2,
                short: true,
                count: &mut self.short_stem_target,
            }
        } else if self.guarded_stem_target > 0 {
            ForLaunch {
                kind: HsCircStemKind::Guarded,
                n_hops: self.svc_len,
                short: false,
                count: &mut self.guarded_stem_target,
            }
        } else {
            ForLaunch {
                kind: HsCircStemKind::Guarded,
                n_hops: 2,
                short: true,
                count: &mut self.short_guarded_stem_target,
            }
        }
    }

    /// Number of NAIVE standard-length stems still needed.
    pub(super) fn stem(&self) -> usize {
        self.stem_target
    }

    /// Number of GUARDED standard-length stems still needed.
    pub(super) fn guarded_stem(&self) -> usize {
        self.guarded_stem_target
    }

    /// Number of short-length stems still needed (test-only inspector).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn short_stems(&self) -> usize {
        self.short_stem_target + self.short_guarded_stem_target
    }

    /// Total number of stems still to launch, all lengths combined.
    pub(super) fn n_to_launch(&self) -> usize {
        self.stem_target
            + self.guarded_stem_target
            + self.short_stem_target
            + self.short_guarded_stem_target
    }
}

impl<C: AbstractTunnel> Default for Pool<C> {
    fn default() -> Self {
        Self {
            circuits: Vec::new(),
            stem_target: DEFAULT_NAIVE_STEM_TARGET,
            guarded_stem_target: DEFAULT_GUARDED_STEM_TARGET,
            short_stem_target: 0,
            short_guarded_stem_target: 0,
            svc_len: 3,
            policy_changed: false,
            have_been_exhausted: false,
            have_been_under_highwater: false,
            last_changed_target: None,
        }
    }
}

impl<C: AbstractTunnel> Pool<C> {
    /// Add `circ` to this pool
    pub(super) fn insert(&mut self, circ: HsCircStem<C>) {
        self.circuits.push(circ);
    }

    /// Remove every circuit from this pool for which `f` returns false.
    pub(super) fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&HsCircStem<C>) -> bool,
    {
        self.circuits.retain(f);
    }

    /// Return true if we are very low on circuits and should build more immediately.
    pub(super) fn very_low(&self) -> bool {
        self.circuits.len() <= self.target() / 3
    }

    /// tor-socks5 local patch: set the standard service stem length and
    /// short-client targets, retiring stems that are incompatible with the
    /// new policy (wrong standard length, or wrong short/standard class).
    pub(super) fn set_policy(&mut self, svc_len: usize, short_targets: bool) {
        if self.svc_len != svc_len {
            self.svc_len = svc_len;
            // Different standard length: no existing stem is reusable.
            self.circuits.clear();
            self.policy_changed = true;
            self.have_been_exhausted = true;
            self.have_been_under_highwater = true;
        }
        let was_enabled = self.short_stem_target != 0;
        if was_enabled != short_targets {
            self.circuits
                .retain(|circ| (circ.n_hops == 2) == short_targets);
            self.policy_changed = true;
            self.have_been_exhausted = true;
            self.have_been_under_highwater = true;
        }
        self.short_stem_target = if short_targets {
            DEFAULT_NAIVE_STEM_TARGET
        } else {
            0
        };
        self.short_guarded_stem_target = if short_targets {
            DEFAULT_GUARDED_STEM_TARGET
        } else {
            0
        };
    }

    /// Take and reset the policy-changed flag.
    pub(super) fn take_policy_changed(&mut self) -> bool {
        std::mem::replace(&mut self.policy_changed, false)
    }

    /// Return the stems we would like to launch under the current policy.
    ///
    /// tor-socks5 local patch: standard-length stems are counted at the
    /// configured service stem length rather than a hardcoded 3.
    pub(super) fn circuits_to_launch(&self, short_clients: bool) -> CircsToLaunch {
        let count = |kind, hops| {
            self.circuits
                .iter()
                .filter(|c| c.kind == kind && c.n_hops == hops)
                .count()
        };
        CircsToLaunch {
            svc_len: self.svc_len,
            policy_changed: false,
            stem_target: self
                .stem_target
                .saturating_sub(count(HsCircStemKind::Naive, self.svc_len)),
            guarded_stem_target: self
                .guarded_stem_target
                .saturating_sub(count(HsCircStemKind::Guarded, self.svc_len)),
            short_stem_target: if short_clients {
                DEFAULT_NAIVE_STEM_TARGET.saturating_sub(count(HsCircStemKind::Naive, 2))
            } else {
                0
            },
            short_guarded_stem_target: if short_clients {
                DEFAULT_GUARDED_STEM_TARGET.saturating_sub(count(HsCircStemKind::Guarded, 2))
            } else {
                0
            },
        }
    }

    /// Return the total number of circuits we would like to launch.
    ///
    /// We do not discard when we are _above_ this threshold, but we do
    /// try to build when we are low.
    fn target(&self) -> usize {
        self.stem_target
            + self.guarded_stem_target
            + self.short_stem_target
            + self.short_guarded_stem_target
    }

    /// If there is any circuit in this pool for which `f`  returns true and that satisfies
    /// all of the specified [`HsCircPrefs`], return one such circuit at random, and remove
    /// it from the pool.
    ///
    /// If none of the circuits satisfy `prefs`, return a randomly selected circuit for which `f`
    /// returns true and which has exactly `expected_hops` hops.
    pub(super) fn take_one_where<R, F>(
        &mut self,
        rng: &mut R,
        f: F,
        prefs: &HsCircPrefs,
        expected_hops: usize,
    ) -> Option<HsCircStem<C>>
    where
        R: Rng,
        F: Fn(&HsCircStem<C>) -> bool,
    {
        let rv = match random_idx_where(rng, &mut self.circuits[..], |circ_stem| {
            // First, check if any circuit matches _all_ the prefs
            circ_stem.satisfies_prefs(prefs) && circ_stem.n_hops == expected_hops && f(circ_stem)
        })
        .or_else(|| {
            // Exact length is a hard eligibility condition, never a fallback preference.
            random_idx_where(rng, &mut self.circuits[..], |circ_stem| {
                circ_stem.n_hops == expected_hops && f(circ_stem)
            })
        }) {
            Some(idx) => Some(self.circuits.swap_remove(idx)),
            None => None,
        };

        if self.circuits.is_empty() {
            self.have_been_exhausted = true;
            self.have_been_under_highwater = true;
        } else if self.circuits.len() < self.target() * 4 / 5 {
            self.have_been_under_highwater = true;
        }

        rv
    }

    /// Update the target sizes for our pool.
    ///
    /// This updates our target numbers of NAIVE and GUARDED circuits.
    pub(super) fn update_target_size(&mut self, now: Instant) {
        /// Minimum amount of time that must elapse between a change and a
        /// decision to grow our pool.  We use this to control the rate of
        /// growth and make sure that we are allowing enough time for circuits
        /// to complete.
        const MIN_TIME_TO_GROW: Duration = Duration::from_secs(120);
        /// Minimum amount of time that must elapse between a target change and
        /// a decisions to shrink our target.  We use this to make sure that we
        /// aren't shrinking too rapidly, and that we are allowing enough time
        /// for the pool to actually get used.
        const MIN_TIME_TO_SHRINK: Duration = Duration::from_secs(600);

        let last_changed = self.last_changed_target.get_or_insert(now);
        let time_since_last_change = now.saturating_duration_since(*last_changed);

        // TODO: we may want to have separate have_been_exhausted/have_been_under_highwater
        // flags for NAIVE and GUARDED circuits.
        //
        // TODO: stem_target and guarded_stem_target currently grow/shrink at the same rate,
        // which is not ideal.
        //
        // Instead, we should switch to an adaptive strategy, where the two targets are updated
        // based on how many NAIVE/GUARDED circuit requests we got.
        if self.have_been_exhausted {
            if time_since_last_change < MIN_TIME_TO_GROW {
                return;
            }
            self.stem_target *= 2;
            self.guarded_stem_target *= 2;
        } else if !self.have_been_under_highwater {
            if time_since_last_change < MIN_TIME_TO_SHRINK {
                return;
            }

            self.stem_target /= 2;
            self.guarded_stem_target /= 2;
        }
        self.last_changed_target = Some(now);
        self.stem_target = self
            .stem_target
            .clamp(DEFAULT_NAIVE_STEM_TARGET, MAX_NAIVE_STEM_TARGET);
        self.guarded_stem_target = self
            .guarded_stem_target
            .clamp(DEFAULT_GUARDED_STEM_TARGET, MAX_GUARDED_STEM_TARGET);
        self.have_been_exhausted = false;
        self.have_been_under_highwater = false;
    }

    /// Purge all the circuits from the pool.
    #[allow(clippy::unnecessary_wraps)] // for consistency and future-proofing
    pub(super) fn retire_all_circuits(&mut self) -> Result<(), tor_config::ReconfigureError> {
        self.have_been_exhausted = true;

        // Purge all circuits from this pool
        self.circuits.clear();

        Ok(())
    }
}

/// Preferences for what kind of circuit to select from the pool.
#[derive(Default, Debug, Clone)]
pub(super) struct HsCircPrefs {
    /// If `Some`, specifies the [`HsCircStemKind`] we would like.
    pub(super) kind_prefs: Option<HsCircStemKind>,
}

impl HsCircPrefs {
    /// Set the preferred [`HsCircStemKind`].
    pub(super) fn preferred_stem_kind(&mut self, kind: HsCircStemKind) -> &mut Self {
        self.kind_prefs = Some(kind);
        self
    }
}

/// Helper: find a random item `elt` in `slice` such that `predicate(elt)` is
/// true. Return the index of that item.
///
/// Can arbitrarily reorder `slice`. This allows us to visit the indices in uniform-at-random
/// order, without having to do any O(N) operations or allocations.
fn random_idx_where<R, T, P>(rng: &mut R, mut slice: &mut [T], predicate: P) -> Option<usize>
where
    R: Rng,
    P: Fn(&T) -> bool,
{
    while !slice.is_empty() {
        let idx = rng
            .gen_range_checked(0..slice.len())
            .expect("slice was not empty but is now empty");
        if predicate(&slice[idx]) {
            return Some(idx);
        }
        let last_idx = slice.len() - 1;
        // Move the one we just tried to the end,
        // and eliminate it from consideration.
        slice.swap(idx, last_idx);
        slice = &mut slice[..last_idx];
    }
    // We didn't find any.
    None
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn selection_requires_exact_length() {
        let mut pool = Pool::<crate::mocks::FakeCirc>::default();
        pool.set_policy(3, true);
        pool.take_policy_changed();
        pool.insert(HsCircStem {
            circ: crate::mocks::FakeCirc {
                id: crate::mocks::FakeId::next(),
            },
            kind: HsCircStemKind::Naive,
            n_hops: 2,
        });
        let mut rng = testing_rng();
        assert!(
            pool.take_one_where(&mut rng, |_| true, &HsCircPrefs::default(), 3)
                .is_none()
        );
        pool.insert(HsCircStem {
            circ: crate::mocks::FakeCirc {
                id: crate::mocks::FakeId::next(),
            },
            kind: HsCircStemKind::Naive,
            n_hops: 3,
        });
        assert!(
            pool.take_one_where(&mut rng, |_| true, &HsCircPrefs::default(), 2)
                .is_some()
        );
    }

    #[test]
    fn preemptive_targets_keep_lengths_separate() {
        let circ = HsCircStem {
            circ: crate::mocks::FakeCirc {
                id: crate::mocks::FakeId::next(),
            },
            kind: HsCircStemKind::Naive,
            n_hops: 2,
        };
        let mut pool = Pool::<crate::mocks::FakeCirc>::default();
        pool.insert(circ);
        // 1 short NAIVE present: short NAIVE needs 3-1=2 more, short GUARDED needs 1.
        let ctl = pool.circuits_to_launch(true);
        assert_eq!(ctl.short_stems(), 2 + 1);
        // + 3 standard NAIVE still missing (the short one does not count) + 1 standard GUARDED.
        assert_eq!(ctl.n_to_launch(), 2 + 1 + 3 + 1);
        pool.insert(HsCircStem {
            circ: crate::mocks::FakeCirc {
                id: crate::mocks::FakeId::next(),
            },
            kind: HsCircStemKind::Guarded,
            n_hops: 2,
        });
        // GUARDED short target now satisfied: 2 short NAIVE still missing.
        assert_eq!(pool.circuits_to_launch(true).short_stems(), 2);
        // Insert the remaining short NAIVE stems: short targets fully satisfied.
        for _ in 0..2 {
            pool.insert(HsCircStem {
                circ: crate::mocks::FakeCirc {
                    id: crate::mocks::FakeId::next(),
                },
                kind: HsCircStemKind::Naive,
                n_hops: 2,
            });
        }
        assert_eq!(pool.circuits_to_launch(true).short_stems(), 0);
    }

    #[test]
    fn random_idx() {
        let mut rng = testing_rng();
        let mut orig_numbers: Vec<i32> = vec![1, 3, 4, 8, 11, 19, 12, 6, 27];
        let mut numbers = orig_numbers.clone();

        let mut found: std::collections::HashMap<i32, bool> =
            numbers.iter().map(|n| (*n, false)).collect();

        for _ in 0..1000 {
            let idx = random_idx_where(&mut rng, &mut numbers[..], |n| n & 1 == 1).unwrap();
            assert!(numbers[idx] & 1 == 1);
            found.insert(numbers[idx], true);
        }

        for num in numbers.iter() {
            assert!(found[num] == (num & 1 == 1));
        }

        // Number may be reordered, but should still have the same elements.
        numbers.sort();
        orig_numbers.sort();
        assert_eq!(numbers, orig_numbers);
    }

    #[test]
    fn random_idx_empty() {
        let mut rng = testing_rng();
        let idx = random_idx_where(&mut rng, &mut [], |_: &i32| panic!());
        assert_eq!(idx, None);
    }

    #[test]
    fn random_idx_none() {
        let mut rng = testing_rng();
        let mut numbers: Vec<i32> = vec![1, 3, 4, 8, 11, 19, 12, 6, 27];
        assert_eq!(
            random_idx_where(&mut rng, &mut numbers[..], |_: &i32| false),
            None
        );
    }
}
