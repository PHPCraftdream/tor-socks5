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
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
use super::*;

#[test]
fn updated_minimum_invalidates_a_cached_fast_estimate() {
    use crate::timeouts::TimeoutEstimator;
    let mut estimator = ParetoTimeoutEstimator::default();
    for n in 0..200 {
        estimator.note_hop_completed(2, Duration::from_millis(100 + n % 100), true);
    }
    let action = Action::BuildCircuit { length: 3 };
    assert!(estimator.timeouts(&action).0 < Duration::from_secs(1));
    let params = NetParameters::from_map(&"cbtmintimeout=10000".parse().unwrap());
    estimator.update_params(&params);
    let (timeout, abandon) = estimator.timeouts(&action);
    assert!(
        timeout >= Duration::from_secs(10),
        "stale estimate: {timeout:?}"
    );
    assert!(abandon >= timeout);
}
use crate::timeouts::TimeoutEstimator;
use tor_basic_utils::RngExt as _;
use tor_basic_utils::test_rng::testing_rng;

/// Return an action to build a 3-hop circuit.
fn b3() -> Action {
    Action::BuildCircuit { length: 3 }
}

impl From<u32> for MsecDuration {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

#[test]
fn ms_partial_cmp() {
    #![allow(clippy::eq_op)]
    let myriad: MsecDuration = 10_000.into();
    let lakh: MsecDuration = 100_000.into();
    let crore: MsecDuration = 10_000_000.into();

    assert!(myriad < lakh);
    assert!(myriad == myriad);
    assert!(crore > lakh);
    assert!(crore >= crore);
    assert!(crore <= crore);
}

#[test]
fn history_lowlev() {
    assert_eq!(History::bucket_center(1.into()), 5.into());
    assert_eq!(History::bucket_center(903.into()), 905.into());
    assert_eq!(History::bucket_center(0.into()), 5.into());
    assert_eq!(History::bucket_center(u32::MAX.into()), 4294967295.into());

    let mut h = History::new_empty();
    h.inc_bucket(7.into());
    h.inc_bucket(8.into());
    h.inc_bucket(9.into());
    h.inc_bucket(10.into());
    h.inc_bucket(11.into());
    h.inc_bucket(12.into());
    h.inc_bucket(13.into());
    h.inc_bucket(299.into());
    assert_eq!(h.time_histogram.get(&5.into()), Some(&3));
    assert_eq!(h.time_histogram.get(&15.into()), Some(&4));
    assert_eq!(h.time_histogram.get(&25.into()), None);
    assert_eq!(h.time_histogram.get(&295.into()), Some(&1));

    h.dec_bucket(299.into());
    h.dec_bucket(24.into());
    h.dec_bucket(12.into());

    assert_eq!(h.time_histogram.get(&15.into()), Some(&3));
    assert_eq!(h.time_histogram.get(&25.into()), None);
    assert_eq!(h.time_histogram.get(&295.into()), None);

    h.add_success(true);
    h.add_success(false);
    assert_eq!(h.success_history.len(), 2);

    h.clear();
    assert_eq!(h.time_histogram.len(), 0);
    assert_eq!(h.time_history.len(), 0);
    assert_eq!(h.success_history.len(), 0);
}

#[test]
fn time_observation_management() {
    let mut h = History::new_empty();
    h.set_time_history_len(8); // to make it easier to overflow.

    h.add_time(300.into());
    h.add_time(500.into());
    h.add_time(542.into());
    h.add_time(305.into());
    h.add_time(543.into());
    h.add_time(307.into());

    assert_eq!(h.n_times(), 6);
    let v = h.n_most_frequent_bins(10);
    assert_eq!(&v[..], [(305.into(), 3), (545.into(), 2), (505.into(), 1)]);
    let v = h.n_most_frequent_bins(2);
    assert_eq!(&v[..], [(305.into(), 3), (545.into(), 2)]);

    let v: Vec<_> = h.sparse_histogram().collect();
    assert_eq!(&v[..], [(305.into(), 3), (505.into(), 1), (545.into(), 2)]);

    h.add_time(212.into());
    h.add_time(203.into());
    // now we replace the first couple of older elements.
    h.add_time(617.into());
    h.add_time(413.into());

    assert_eq!(h.n_times(), 8);

    let v: Vec<_> = h.sparse_histogram().collect();
    assert_eq!(
        &v[..],
        [
            (205.into(), 1),
            (215.into(), 1),
            (305.into(), 2),
            (415.into(), 1),
            (545.into(), 2),
            (615.into(), 1)
        ]
    );

    let h2 = History::from_sparse_histogram(v.clone().into_iter());
    let v2: Vec<_> = h2.sparse_histogram().collect();
    assert_eq!(v, v2);
}

#[test]
fn success_observation_mechanism() {
    let mut h = History::new_empty();
    h.set_success_history_len(20);

    assert_eq!(h.n_recent_timeouts(), 0);
    h.add_success(true);
    assert_eq!(h.n_recent_timeouts(), 0);
    h.add_success(false);
    assert_eq!(h.n_recent_timeouts(), 1);
    for _ in 0..200 {
        h.add_success(false);
    }
    assert_eq!(h.n_recent_timeouts(), 20);
    h.add_success(true);
    h.add_success(true);
    h.add_success(true);
    assert_eq!(h.n_recent_timeouts(), 20 - 3);

    h.set_success_history_len(10);
    assert_eq!(h.n_recent_timeouts(), 10 - 3);
}

#[test]
fn xm_calculation() {
    let mut h = History::new_empty();
    assert_eq!(h.estimate_xm(2), None);

    for n in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
        h.add_time(MsecDuration(*n));
    }

    let v = h.n_most_frequent_bins(2);
    assert_eq!(&v[..], [(305.into(), 3), (545.into(), 2)]);
    let est = (305 * 3 + 545 * 2) / 5;
    assert_eq!(h.estimate_xm(2), Some(est));
    assert_eq!(est, 401);
}

#[test]
fn pareto_estimate() {
    let mut h = History::new_empty();
    assert!(h.pareto_estimate(2).is_none());

    for n in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
        h.add_time(MsecDuration(*n));
    }
    let expected_log_sum: f64 = [401, 500, 542, 401, 543, 401, 401, 401, 617, 413]
        .iter()
        .map(|x| f64::from(*x).ln())
        .sum();
    let expected_log_xm: f64 = (401_f64).ln() * 10.0;
    let expected_alpha = 10.0 / (expected_log_sum - expected_log_xm);
    let expected_inv_alpha = 1.0 / expected_alpha;

    let p = h.pareto_estimate(2).unwrap();

    // We can't do "eq" with floats, so we'll do "very close".
    assert!((401.0 - p.x_m).abs() < 1.0e-9);
    assert!((expected_inv_alpha - p.inv_alpha).abs() < 1.0e-9);

    let q60 = p.quantile(0.60);
    let q99 = p.quantile(0.99);

    assert!((q60 - 451.127) < 0.001);
    assert!((q99 - 724.841) < 0.001);
}

#[test]
fn pareto_estimate_timeout() {
    let mut est = ParetoTimeoutEstimator::default();

    assert_eq!(
        est.timeouts(&b3()),
        (Duration::from_secs(60), Duration::from_secs(60))
    );
    // Set the parameters up to mimic the situation in
    // `pareto_estimate` above.
    est.p.min_observations = 0;
    est.p.n_modes_for_xm = 2;
    assert_eq!(
        est.timeouts(&b3()),
        (Duration::from_secs(60), Duration::from_secs(60))
    );

    for msec in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
        let d = Duration::from_millis(*msec);
        est.note_hop_completed(2, d, true);
    }

    let t = est.timeouts(&b3());
    assert_eq!(t.0.as_micros(), 493_169);
    assert_eq!(t.1.as_micros(), 724_841);

    let t2 = est.timeouts(&b3());
    assert_eq!(t2, t);

    let t2 = est.timeouts(&Action::BuildCircuit { length: 4 });
    assert_eq!(t2.0, t.0.mul_f64(10.0 / 6.0));
    assert_eq!(t2.1, t.1.mul_f64(10.0 / 6.0));
}

#[test]
fn pareto_estimate_clear() {
    let mut est = ParetoTimeoutEstimator::default();

    // Set the parameters up to mimic the situation in
    // `pareto_estimate` above.
    let params = NetParameters::from_map(&"cbtmincircs=1 cbtnummodes=2".parse().unwrap());
    est.update_params(&params);

    assert_eq!(est.timeouts(&b3()).0.as_micros(), 60_000_000);
    assert!(est.learning_timeouts());

    for msec in &[300, 500, 542, 305, 543, 307, 212, 203, 617, 413] {
        let d = Duration::from_millis(*msec);
        est.note_hop_completed(2, d, true);
    }
    assert_ne!(est.timeouts(&b3()).0.as_micros(), 60_000_000);
    assert!(!est.learning_timeouts());
    assert_eq!(est.history.n_recent_timeouts(), 0);

    // 17 timeouts happen and we're still getting real numbers...
    for _ in 0..18 {
        est.note_circ_timeout(2, Duration::from_secs(2000));
    }
    assert_ne!(est.timeouts(&b3()).0.as_micros(), 60_000_000);

    // ... but 18 means "reset".
    est.note_circ_timeout(2, Duration::from_secs(2000));
    assert_eq!(est.timeouts(&b3()).0.as_micros(), 60_000_000);

    // And if we fail 18 bunch more times, it doubles.
    for _ in 0..20 {
        est.note_circ_timeout(2, Duration::from_secs(2000));
    }
    assert_eq!(est.timeouts(&b3()).0.as_micros(), 120_000_000);
}

#[test]
fn default_params() {
    let p1 = Params::default();
    let p2 = Params::from(&tor_netdir::params::NetParameters::default());
    // discount version of derive(eq)
    assert_eq!(format!("{:?}", p1), format!("{:?}", p2));
}

#[test]
fn state_conversion() {
    // We have tests elsewhere for converting to and from
    // histograms, so all we really need to ddo here is make sure
    // that the histogram conversion happens.

    let mut est = ParetoTimeoutEstimator::default();
    let mut rng = testing_rng();
    for _ in 0..1000 {
        let d = Duration::from_millis(rng.gen_range_checked(10..3_000).unwrap());
        est.note_hop_completed(2, d, true);
    }

    let state = est.build_state().unwrap();
    assert_eq!(state.version, 1);
    assert!(state.current_timeout.is_some());

    let mut est2 = ParetoTimeoutEstimator::from_state(state);
    let act = Action::BuildCircuit { length: 3 };
    // This isn't going to be exact, since we're recording histogram bins
    // instead of exact timeouts.
    let ms1 = est.timeouts(&act).0.as_millis() as i32;
    let ms2 = est2.timeouts(&act).0.as_millis() as i32;
    assert!((ms1 - ms2).abs() < 50);
}

#[test]
fn validate_iterator_sample() {
    // The documentation for IteratorRandom::sample says that it
    // returns fewer than N elements if the iterators has fewer than N elements.
    // But rand has changed behavior in the past, so let's make sure this doesn't
    // change in the future.
    use rand::seq::IteratorRandom as _;
    let mut rng = testing_rng();
    let mut ten_elements = (1..=10).sample(&mut rng, 100);
    ten_elements.sort();
    assert_eq!(ten_elements.len(), 10);
    assert_eq!(ten_elements, (1..=10).collect::<Vec<_>>());
}

// TODO: add tests from Tor.
