//! TS9-01: the pre-publish pause seam, parked INSIDE
//! `dns::store_cached_if_generation` around its `doh_cache()` mutex
//! acquisition. The old seam (`probe::dns_resolution::pre_publish_pause`)
//! sat in the *callers*, BEFORE the gated write was entered at all -- so the
//! `flush_landing_*` tests never actually stopped execution after the
//! generation check, and a reorder of check-vs-lock inside the function went
//! unobserved. Parking inside guarantees the flush window straddles exactly
//! the lock acquisition the TS8-01 fix relies on. Test-only module: never
//! compiled into non-test builds.

/// The gate a parked publisher waits on. Synchronous (`Condvar`, not
/// `tokio::sync::Notify`) because `store_cached_if_generation` is a sync fn
/// and the publisher runs on its own OS thread in the tests.
pub(crate) struct PublishParkGate {
    released: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
}

impl PublishParkGate {
    /// Let the parked publisher resume its write attempt.
    pub(crate) fn release(&self) {
        let mut released = self.released.lock().unwrap_or_else(|p| p.into_inner());
        *released = true;
        self.cv.notify_all();
    }
}

static PRE_PUBLISH_PAUSE: std::sync::Mutex<Option<std::sync::Arc<PublishParkGate>>> =
    std::sync::Mutex::new(None);

// The parked bit lives outside `PRE_PUBLISH_PAUSE` on purpose: the hook
// `take()`s the gate out before parking (so a second publisher sails
// through), which would make a flag stored inside that same Option
// unobservable to the test the instant it is set.
static PRE_PUBLISH_PAUSE_PARKED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) fn arm_pre_publish_pause() -> std::sync::Arc<PublishParkGate> {
    let gate = std::sync::Arc::new(PublishParkGate {
        released: std::sync::Mutex::new(false),
        cv: std::sync::Condvar::new(),
    });
    PRE_PUBLISH_PAUSE_PARKED.store(false, std::sync::atomic::Ordering::SeqCst);
    *PRE_PUBLISH_PAUSE.lock().unwrap_or_else(|p| p.into_inner()) =
        Some(std::sync::Arc::clone(&gate));
    gate
}

pub(crate) fn disarm_pre_publish_pause() {
    *PRE_PUBLISH_PAUSE.lock().unwrap_or_else(|p| p.into_inner()) = None;
    PRE_PUBLISH_PAUSE_PARKED.store(false, std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn pre_publish_pause_parked() -> bool {
    PRE_PUBLISH_PAUSE_PARKED.load(std::sync::atomic::Ordering::SeqCst)
}

/// One-shot: the first publisher to reach the hook consumes the gate and
/// parks; later ones sail through, so a post-flush lookup never stops here.
pub(crate) fn pre_publish_pause() {
    let gate = PRE_PUBLISH_PAUSE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take();
    if let Some(gate) = gate {
        // Flag BEFORE parking: the test polls this to know the publisher is
        // holding the window open. `released` starts false, so a release
        // racing the wait registration cannot be lost (re-checked in the
        // loop under the same mutex).
        PRE_PUBLISH_PAUSE_PARKED.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut released = gate.released.lock().unwrap_or_else(|p| p.into_inner());
        while !*released {
            released = gate.cv.wait(released).unwrap_or_else(|p| p.into_inner());
        }
    }
}
