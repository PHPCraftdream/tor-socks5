#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::time::{Duration, Instant, SystemTime};

mod internal;

/// The core trait of this crait, [`SaturatingTime`].
///
/// This trait provides methods for performing saturating arithmetic on those
/// types in [`std::time`] that not already come with such a functionality,
/// such as [`SystemTime`] or [`Instant`].
///
/// The trait itself is not implementable from the outside, because it is sealed
/// by an internal trait.
///
/// See the methods or the top-level documentation for concrete code examples.
pub trait SaturatingTime: internal::SaturatingTime {
    /// Returns the maximum value for this type on the current platform.
    ///
    /// This limit is highly platform specific.  It differs heavily between
    /// Unix, Windows, and other operating systems.
    ///
    /// The limit itself is calculated dynamically during runtime with a correct
    /// algorithm.  Afterwards, it gets stored in a lazy static value, meaning
    /// that only the first call to it will be slightly more expensive, whereas
    /// all latter calls will result in an immediate return of the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let max = SystemTime::max_value();
    ///
    /// // Adding zero to the maximum value will change nothing.
    /// assert!(max.checked_add(Duration::ZERO).is_some());
    ///
    /// // Adding 1ns to the maximum value will fail.
    /// assert!(max.checked_add(Duration::new(0, 1)).is_none());
    ///
    /// // Subtracting 1ns from the maximum value will work of course.
    /// assert!(max.checked_sub(Duration::new(0, 1)).is_some());
    /// ```
    fn max_value() -> Self {
        internal::SaturatingTime::max_value()
    }

    /// Returns the minimum value for this type on the current platform.
    ///
    /// This limit is highly platform specific.  It differs heavily between
    /// Unix, Windows, and other operating systems.
    ///
    /// The limit itself is calculated dynamically during runtime with a correct
    /// algorithm.  Afterwards, it gets stored in a lazy static value, meaning
    /// that only the first call to it will be slightly more expensive, whereas
    /// all latter calls will result in an immediate return of the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let min = SystemTime::min_value();
    ///
    /// // Subtracting a zero from the minimum value will change nothing.
    /// assert!(min.checked_sub(Duration::ZERO).is_some());
    ///
    /// // Subtracting 1ns from the minimum value will fail.
    /// assert!(min.checked_sub(Duration::new(0, 1)).is_none());
    ///
    /// // Adding 1ns to the minimum value will work of course.
    /// assert!(min.checked_add(Duration::new(0, 1)).is_some());
    /// ```
    fn min_value() -> Self {
        internal::SaturatingTime::min_value()
    }

    /// Performs a saturating addition of a [`Duration`].
    ///
    /// The resulting value will saturate to [`SaturatingTime::max_value()`] in
    /// the case the addition would have caused an overflow of value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let max = SystemTime::max_value();
    ///
    /// // Adding zero will change nothing.
    /// assert_eq!(max.saturating_add(Duration::ZERO), max);
    ///
    /// // Adding 1ns would overflow so we saturate to the maximum.
    /// assert_eq!(max.saturating_add(Duration::new(0, 1)), max);
    /// ```
    fn saturating_add(self, duration: Duration) -> Self {
        // tor-socks5 local patch: `unwrap_or(max_value())` EAGERLY evaluates
        // `max_value()` on every call, even when `checked_add` succeeds.
        // `max_value()` forces the `MAX_SYSTEM_TIME`/`MAX_INSTANT` `LazyLock`,
        // whose `find_max` binary-search (internal.rs) does not terminate on
        // some platforms (observed: Windows `SystemTime`), spinning at 100%
        // CPU forever. That hung `RouterDesc::parse` (the only consumer that
        // adds a duration to a parsed time), so embedded arti could never use
        // a bridge. Use `unwrap_or_else` so the limit is only computed on a
        // genuine overflow.
        self.checked_add(duration)
            .unwrap_or_else(SaturatingTime::max_value)
    }

    /// Performs a saturating subtraction of a [`Duration`].
    ///
    /// The resulting value will saturate to [`SaturatingTime::min_value()`] in
    /// the case the subtraction would have caused an overflow of value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let min = SystemTime::min_value();
    ///
    /// // Subtracting zero will change nothing.
    /// assert_eq!(min.saturating_sub(Duration::ZERO), min);
    ///
    /// // Subtracting 1ns would overflow so we saturate to the minimum.
    /// assert_eq!(min.saturating_sub(Duration::new(0, 1)), min);
    /// ```
    fn saturating_sub(self, duration: Duration) -> Self {
        // See `saturating_add`: avoid eagerly forcing the (possibly
        // non-terminating) min/max limit search on every call.
        self.checked_sub(duration)
            .unwrap_or_else(SaturatingTime::min_value)
    }

    /// Performs a saturating time difference calculation between two points.
    ///
    /// The resulting value will saturate to [`Duration::ZERO`] in the case that
    /// the `earlier` point in time is actually not earlier, thereby resulting
    /// in a negative difference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let epoch = SystemTime::UNIX_EPOCH;
    /// let now = SystemTime::now();
    /// let min = SystemTime::min_value();
    ///
    /// assert!(now.saturating_duration_since(epoch).as_secs() > 0);
    /// assert!(epoch.saturating_duration_since(epoch) == Duration::ZERO);
    /// assert!(min.saturating_duration_since(epoch) == Duration::ZERO);
    /// ```
    fn saturating_duration_since(&self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }
}

impl SaturatingTime for SystemTime {}

impl SaturatingTime for Instant {
    // Override to use the provided implementation from the standard library.
    fn saturating_duration_since(&self, earlier: Self) -> Duration {
        Self::saturating_duration_since(self, earlier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal;
    use std::{
        fmt::Debug,
        ops::{Add, Sub},
        time::{Instant, SystemTime},
    };

    /// Verifies the maximum and minimum values of [`SaturatingTime`] equal
    /// their pedant in [`internal::SaturatingTime`].
    fn min_max<T: SaturatingTime + PartialEq + Debug>() {
        assert_eq!(
            <T as SaturatingTime>::max_value(),
            <T as internal::SaturatingTime>::max_value()
        );
        assert_eq!(
            <T as SaturatingTime>::min_value(),
            <T as internal::SaturatingTime>::min_value()
        );
    }

    /// Verifies the saturating arithmetic for [`SaturatingTime`].
    fn saturating_add_sub<
        T: SaturatingTime + PartialEq + Debug + Add<Duration, Output = T> + Sub<Duration, Output = T>,
    >() {
        let max = <T as SaturatingTime>::max_value();
        assert_eq!(max.saturating_add(Duration::ZERO), max);
        assert_eq!(max.saturating_add(Duration::new(0, 1)), max);
        assert_eq!(max.saturating_sub(Duration::ZERO), max);
        assert_eq!(
            max.saturating_sub(Duration::new(0, 1)),
            max - Duration::new(0, 1)
        );

        let min = <T as SaturatingTime>::min_value();
        assert_eq!(min.saturating_sub(Duration::ZERO), min);
        assert_eq!(min.saturating_sub(Duration::new(0, 1)), min);
        assert_eq!(min.saturating_add(Duration::ZERO), min);
        assert_eq!(
            min.saturating_add(Duration::new(0, 1)),
            min + Duration::new(0, 1)
        );
    }

    /// Verifies whether the saturating logic behind [`Duration`] types work.
    fn saturating_duration<T: SaturatingTime + PartialEq + Debug>() {
        // The duration from the same anchor should always be zero.
        let anchor = T::anchor();
        assert_eq!(anchor.saturating_duration_since(anchor), Duration::ZERO);

        // Try with a later anchor.
        let later_anchor = anchor.checked_add(Duration::from_secs(1)).unwrap();
        assert!(later_anchor.saturating_duration_since(anchor) == Duration::from_secs(1));
        assert_eq!(
            anchor.saturating_duration_since(later_anchor),
            Duration::ZERO
        );

        // Try with min and max.
        let max = <T as SaturatingTime>::max_value();
        let min = <T as SaturatingTime>::min_value();

        // This first assertion might not be so portable, maybe remove it if
        // this becomes a problem.
        assert_eq!(max.saturating_duration_since(min), Duration::MAX);
        assert_eq!(min.saturating_duration_since(max), Duration::ZERO);
    }

    /// Calls [`min_max()`] using [`SystemTime`].
    // tor-socks5: forces the SystemTime limit search, non-terminating on
    // Windows (see internal::find_limit); ignored so it doesn't hang the suite.
    #[test]
    #[ignore = "forces non-terminating SystemTime limit search on Windows (see find_limit)"]
    fn system_time_min_max() {
        min_max::<SystemTime>();
    }

    /// Calls [`min_max()`] using [`Instant`].
    #[test]
    fn instant_min_max() {
        min_max::<Instant>();
    }

    /// Calls [`saturating_add_sub()`] and [`saturating_duration()`] using [`SystemTime`].
    // tor-socks5: forces `SystemTime::max_value()`/`min_value()`, whose limit
    // search does not terminate on Windows (see internal::find_limit). Our fix
    // makes production code never reach that path; this upstream test exercises
    // it directly, so it is ignored rather than left to hang `cargo test`.
    #[test]
    #[ignore = "forces non-terminating SystemTime limit search on Windows (see find_limit)"]
    fn system_time_saturating() {
        saturating_add_sub::<SystemTime>();
        saturating_duration::<SystemTime>();
    }

    /// Calls [`saturating_add_sub()`] and [`saturating_duration()`] using [`Instant`].
    #[test]
    fn instant_saturating() {
        saturating_add_sub::<Instant>();
        saturating_duration::<Instant>();
    }

    /// Regression (tor-socks5): a plain, non-overflowing `saturating_add` /
    /// `saturating_sub` must return promptly and must NOT spin forever forcing
    /// the platform min/max search. On Windows the original eager
    /// `unwrap_or(max_value())` made every call drive a non-terminating
    /// `find_max`, hanging `RouterDesc::parse` (and thus arti's use of bridges)
    /// at 100% CPU. A watchdog thread turns any such hang into a failure.
    #[test]
    fn saturating_add_sub_does_not_hang() {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000); // ~2026
            // Neither of these overflows, so with the lazy `unwrap_or_else` fix
            // the (possibly non-terminating) limit search is never reached.
            let later = base.saturating_add(Duration::from_secs(5 * 86400));
            let earlier = base.saturating_sub(Duration::from_secs(86400));
            let _ = tx.send(later > earlier);
        });

        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(ok) => assert!(ok, "saturating_add should be after saturating_sub"),
            Err(_) => panic!("saturating arithmetic hung (>10s) — eager limit search regression"),
        }
    }
}
