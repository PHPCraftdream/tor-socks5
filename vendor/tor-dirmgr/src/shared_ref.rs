//! Utility module to safely refer to a mutable Arc.

use std::sync::{Arc, RwLock};

use educe::Educe;

use crate::{Error, Result};

/// A shareable mutable-ish optional reference to a an [`Arc`].
///
/// Because you can't actually change a shared [`Arc`], this type implements
/// mutability by replacing the Arc itself with a new value.  It tries
/// to avoid needless clones by taking advantage of [`Arc::make_mut`].
///
// We give this construction its own type to simplify its users, and make
// sure we don't hold the lock against any async suspend points.
#[derive(Debug, Educe)]
#[educe(Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental-api")))]
#[cfg_attr(not(feature = "experimental-api"), allow(unreachable_pub))]
pub struct SharedMutArc<T> {
    /// Locked reference to the current value.
    ///
    /// (It's okay to use RwLock here, because we never suspend
    /// while holding the lock.)
    dir: RwLock<Option<Arc<T>>>,
}

#[cfg_attr(not(feature = "experimental-api"), allow(unreachable_pub))]
impl<T> SharedMutArc<T> {
    /// Construct a new empty SharedMutArc.
    pub fn new() -> Self {
        SharedMutArc::default()
    }

    /// Replace the current value with `new_val`.
    pub fn replace(&self, new_val: T) {
        let mut w = self
            .dir
            .write()
            // tor-socks5 local patch: recover from a poisoned lock instead of
            // re-panicking on every future access (see `mutate()` below for the
            // full rationale).
            .unwrap_or_else(|e| e.into_inner());
        *w = Some(Arc::new(new_val));
    }

    /// Remove the current value of this SharedMutArc.
    #[allow(unused)]
    pub(crate) fn clear(&self) {
        let mut w = self
            .dir
            .write()
            // tor-socks5 local patch: recover from a poisoned lock instead of
            // re-panicking on every future access (see `mutate()` below).
            .unwrap_or_else(|e| e.into_inner());
        *w = None;
    }

    /// Return a new reference to the current value, if there is one.
    pub fn get(&self) -> Option<Arc<T>> {
        let r = self
            .dir
            .read()
            // tor-socks5 local patch: recover from a poisoned lock instead of
            // re-panicking on every future access (see `mutate()` below).
            .unwrap_or_else(|e| e.into_inner());
        r.as_ref().map(Arc::clone)
    }

    /// Replace the contents of this SharedMutArc with the results of applying
    /// `func` to the inner value.
    ///
    /// Gives an error if there is no inner value.
    ///
    /// Other threads will not abe able to access the inner value
    /// while the function is running.
    ///
    /// # Panic-safety
    ///
    /// If `func` panics, the panic propagates out of this call as usual and the
    /// underlying lock is poisoned (standard `std::sync::RwLock` semantics).
    /// However, a subsequent `get()`/`replace()`/`mutate()` no longer re-panics
    /// on the poisoned lock: it recovers the guard via `PoisonError::into_inner()`
    /// and observes whatever value was present at the moment of the panic.
    ///
    /// A partial mutation performed by `func` before the panic is therefore NOT
    /// rolled back — recovering with possibly-stale data is the deliberate
    /// trade-off here, because the alternative (the upstream `.expect()`) is to
    /// re-panic on every single future access, permanently bricking this
    /// reference for a long-lived process that has no supervisor to restart it.
    // Note: If we decide to make this type public, we'll probably
    // want to fiddle with how we handle the return type.
    pub fn mutate<F, U>(&self, func: F) -> Result<U>
    where
        F: FnOnce(&mut T) -> Result<U>,
        T: Clone,
    {
        let mut writeable = self
            .dir
            .write()
            // tor-socks5 local patch: recover from a poisoned lock instead of
            // re-panicking forever. A panic inside the closure below poisons
            // this RwLock (standard std::sync::RwLock semantics); the upstream
            // .expect() would then re-panic on every subsequent
            // get()/replace()/mutate(), permanently bricking the shared netdir
            // for a long-lived headless process with no supervisor to restart
            // it — a single non-fatal panic in a spawned tokio task (e.g. an
            // edge-case microdescriptor parse inside DirMgr) would otherwise
            // turn every later directory read into a panic. into_inner() yields
            // the guard over whatever data survived the panic (it does NOT roll
            // back a partial mutation made before the panic). Mirrors the
            // unwrap_or_else(|e| e.into_inner()) pattern already used in this
            // repo's apps/socks5-proxy/src/tor_watchdog.rs.
            .unwrap_or_else(|e| e.into_inner());
        let dir = writeable.as_mut();
        match dir {
            None => Err(Error::DirectoryNotPresent), // Kinda bogus.
            Some(arc) => func(Arc::make_mut(arc)),
        }
    }
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    #[test]
    fn shared_mut_arc() {
        let val: SharedMutArc<Vec<u32>> = SharedMutArc::new();
        assert_eq!(val.get(), None);

        val.replace(Vec::new());
        assert_eq!(val.get().unwrap().as_ref()[..], Vec::<u32>::new());

        val.mutate(|v| {
            v.push(99);
            Ok(())
        })
        .unwrap();
        assert_eq!(val.get().unwrap().as_ref()[..], [99]);

        val.clear();
        assert_eq!(val.get(), None);

        assert!(
            val.mutate(|v| {
                v.push(99);
                Ok(())
            })
            .is_err()
        );
    }

    // tor-socks5 local patch: regression test for the panic-recovery behaviour
    // documented above. Without the unwrap_or_else fix, the second get()/mutate()
    // below would re-panic on the poisoned lock — the test would fail by
    // aborting instead of returning.
    #[test]
    fn mutate_panic_does_not_poison_forever() {
        let val: SharedMutArc<Vec<u32>> = SharedMutArc::new();
        val.replace(vec![1, 2, 3]);

        // A panic inside the mutate closure propagates out of mutate() and
        // poisons the underlying RwLock. Catch it so the test itself doesn't
        // abort on the expected panic.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            val.mutate(|v| -> Result<()> {
                v.push(99);
                panic!("intentional panic inside mutate closure");
            })
        }));
        assert!(result.is_err(), "expected the mutate closure to panic");

        // Without the fix, both of the following would panic AGAIN on the
        // poisoned lock. With the fix, they recover the lock via into_inner()
        // and observe the value as it stood at the moment of the panic: the
        // `push(99)` above is NOT rolled back (into_inner hands back the
        // partially-mutated data), which is the documented trade-off —
        // recover-with-possible-staleness beats permanent panic-on-every-access.
        assert_eq!(val.get().unwrap().as_ref()[..], [1, 2, 3, 99]);

        let mutate_ok = val.mutate(|v| {
            v.push(100);
            Ok(())
        });
        assert!(mutate_ok.is_ok(), "recovered mutate should succeed");
        assert_eq!(val.get().unwrap().as_ref()[..], [1, 2, 3, 99, 100]);
    }
}
