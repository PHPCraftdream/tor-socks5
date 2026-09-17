//! Test-only synchronization seams for the cross-process race tests.
//! Gates are path- and site-scoped, RAII-armed (release + deregister on
//! drop, so a panicking test cannot leave one armed). Compiles away outside
//! `cfg(test)`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Where a gate parks a transaction: before its lock acquisition or after
/// its load (snapshot pinned, mutation/save not yet run).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Site {
    PreAcquire,
    PostLoad,
    /// Inside the admission verifier's blocking worker, right after it
    /// acquired VERIFY_LOCK (see `bridge_verifier::verify_bridges_sequential`).
    /// Lets a test pin the worker while it owns the verifier lock.
    AdmissionVerifyPostLock,
    /// In `drain_pool_with`, right before the confirm transaction that sheds
    /// the drained candidates whose outcome is durable. The drain holds NO
    /// pool lock here; a test parks the drain to run a concurrent pool
    /// writer between the take and the confirm.
    PreRestore,
    /// At the top of `promote_bridges_in_config` in `fetch_merge.rs`, before
    /// it touches the config. Used with the failure-injection registry, not
    /// the park gates.
    ConfigPromotion,
}

/// Guard for waits that must succeed (a transaction reaching its gated
/// site); firing means a broken seam, never a slow machine under test.
pub(crate) const HANG_GUARD: Duration = Duration::from_secs(10);

/// Fixed wait for a completion that must NOT happen while the first writer
/// owns the lock. Firing is the correct-protocol case (the test then
/// releases the pinned writer); an early completion proves the lock was
/// bypassed and the final data assertions fail. Ordering never depends on
/// the timeout — only on the lock and the gate releases.
pub(crate) const UNBLOCK_GUARD: Duration = Duration::from_secs(2);

struct GateInner {
    state: Mutex<(bool, bool)>, // (parked, released)
    cv: Condvar,
}

type GateKey = (Site, PathBuf);

static PARK_GATES: OnceLock<Mutex<HashMap<GateKey, Arc<GateInner>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<GateKey, Arc<GateInner>>> {
    PARK_GATES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A gate a test arms to park the first transaction matching its site and
/// path. Only the controller releases it on drop; wait clones do not.
pub(crate) struct ParkedGate {
    key: GateKey,
    inner: Arc<GateInner>,
    controller: bool,
}

impl Clone for ParkedGate {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            inner: Arc::clone(&self.inner),
            controller: false,
        }
    }
}

impl ParkedGate {
    pub(crate) fn arm(site: Site, path: &Path) -> Self {
        let inner = Arc::new(GateInner {
            state: Mutex::new((false, false)),
            cv: Condvar::new(),
        });
        registry()
            .lock()
            .expect("park gate registry")
            .insert((site, path.to_path_buf()), Arc::clone(&inner));
        Self {
            key: (site, path.to_path_buf()),
            inner,
            controller: true,
        }
    }

    /// Block until a transaction reached the gated site (hang guard only).
    /// Panics without holding the lock, so `Drop`'s release stays safe.
    pub(crate) fn wait_parked(&self, guard: Duration) {
        let deadline = Instant::now() + guard;
        let mut state = self.inner.state.lock().unwrap_or_else(|p| p.into_inner());
        while !state.0 {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next, _timeout) = self
                .inner
                .cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner());
            state = next;
        }
        let parked = state.0;
        drop(state);
        assert!(parked, "transaction never reached {:?}", self.key.0);
    }

    pub(crate) fn release(&self) {
        let mut state = self.inner.state.lock().unwrap_or_else(|p| p.into_inner());
        state.1 = true;
        self.inner.cv.notify_all();
    }
}

impl Drop for ParkedGate {
    fn drop(&mut self) {
        if !self.controller {
            return;
        }
        self.release();
        let mut gates = registry().lock().expect("park gate registry");
        if gates
            .get(&self.key)
            .is_some_and(|g| Arc::ptr_eq(g, &self.inner))
        {
            gates.remove(&self.key);
        }
    }
}

/// Transaction-site hook: if a gate is armed for this site and path, the
/// arriving transaction consumes it and parks until release; later arrivals
/// at the same site sail through.
pub(crate) fn park_if_armed(site: Site, path: &Path) {
    let Some(gate) = registry()
        .lock()
        .expect("park gate registry")
        .remove(&(site, path.to_path_buf()))
    else {
        return;
    };
    let mut state = gate.state.lock().unwrap_or_else(|p| p.into_inner());
    state.0 = true;
    gate.cv.notify_all();
    while !state.1 {
        state = gate.cv.wait(state).unwrap_or_else(|p| p.into_inner());
    }
}

/// Completion counters, keyed like the gates. A worker records itself here
/// AFTER the gated section finished (its lock guard already dropped), so a
/// test can prove that the worker itself — not the caller — reached
/// completion (the TS17-02 "worker finished" event).
static WORKER_DONE: OnceLock<Mutex<HashMap<GateKey, usize>>> = OnceLock::new();

fn done_registry() -> &'static Mutex<HashMap<GateKey, usize>> {
    WORKER_DONE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Called by the worker itself, after the gated section completed.
pub(crate) fn mark_worker_done(site: Site, path: &Path) {
    let mut done = done_registry().lock().unwrap_or_else(|p| p.into_inner());
    *done.entry((site, path.to_path_buf())).or_insert(0) += 1;
}

/// How many times a worker marked itself done at this site and path.
// Consumer arrives with the TS17-02 regression test (next chunk).
#[allow(dead_code)]
pub(crate) fn worker_done_count(site: Site, path: &Path) -> usize {
    done_registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&(site, path.to_path_buf()))
        .copied()
        .unwrap_or(0)
}

/// One-shot failure injections, keyed like the gates. Arming is not RAII:
/// a leaked arm is keyed by a per-test temp path and harmless. `take_failure`
/// consumes the arm, so the first arrival at the site fails and later ones
/// proceed — the "first drain loses, the retry succeeds" shape the TS17-08
/// regression needs, with no sleeps and no clocks.
static FAILURES: OnceLock<Mutex<HashSet<GateKey>>> = OnceLock::new();

fn failure_registry() -> &'static Mutex<HashSet<GateKey>> {
    FAILURES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Arm a one-shot failure for `site` at `path`: the next
/// [take_failure] there returns true.
pub(crate) fn arm_failure(site: Site, path: &Path) {
    failure_registry()
        .lock()
        .expect("failure registry")
        .insert((site, path.to_path_buf()));
}

/// Consume the armed failure for `site` at `path`, if any.
pub(crate) fn take_failure(site: Site, path: &Path) -> bool {
    failure_registry()
        .lock()
        .expect("failure registry")
        .remove(&(site, path.to_path_buf()))
}
