//! Counterfactual regressions use production schedule/cycle composition with
//! adversarial, gated IO. Clock is paused; scheduler is polled explicitly, so
//! no runtime auto-advance, sockets, task timing or yield-count handshake races.

use super::*;
use hickory_proto::rr::{Name, RecordType};
use std::cell::Cell;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Maintenance(usize),
    Page(usize, usize),
    Lookup(String),
}

#[derive(Default)]
struct State {
    events: VecDeque<Event>,
    live: BTreeSet<usize>,
    dropped_io: usize,
    active_io: usize,
    maximum_io: usize,
}

type Shared = Arc<Mutex<State>>;

struct IoGuard(Shared);
impl IoGuard {
    fn new(state: &Shared) -> Self {
        let mut s = state.lock().unwrap();
        s.active_io += 1;
        s.maximum_io = s.maximum_io.max(s.active_io);
        Self(state.clone())
    }
}
impl Drop for IoGuard {
    fn drop(&mut self) {
        let mut s = self.0.lock().unwrap();
        s.active_io -= 1;
        s.dropped_io += 1;
    }
}

struct FakeSnapshot {
    generation: usize,
    questions: Vec<Query>,
    state: Shared,
    page_gate: Option<CancellationToken>,
    page_error: bool,
}
impl Drop for FakeSnapshot {
    fn drop(&mut self) {
        assert!(self.state.lock().unwrap().live.remove(&self.generation));
    }
}
impl Snapshot for FakeSnapshot {
    type Cursor = usize;
    type Target = (usize, Query);
    async fn page(&self, after: Option<usize>) -> Result<Vec<Self::Target>> {
        let start = after.map_or(0, |n| n + 1);
        self.state
            .lock()
            .unwrap()
            .events
            .push_back(Event::Page(self.generation, start));
        if let Some(gate) = &self.page_gate {
            let _guard = IoGuard::new(&self.state);
            gate.cancelled().await;
        }
        if self.page_error {
            anyhow::bail!("injected page failure");
        }
        Ok(self
            .questions
            .iter()
            .enumerate()
            .skip(start)
            .take(128)
            .map(|(n, q)| (n, q.clone()))
            .collect())
    }
    fn cursor(target: &Self::Target) -> usize {
        target.0
    }
    fn question(target: Self::Target) -> Query {
        target.1
    }
}

struct FakeMaintenance {
    state: Shared,
    generation: usize,
    questions: Vec<Query>,
    fail_refresh: BTreeSet<usize>,
    fail_page: BTreeSet<usize>,
    page_gate: Option<CancellationToken>,
    refresh_gate: Option<CancellationToken>,
}
impl Maintenance for FakeMaintenance {
    type Snapshot = FakeSnapshot;
    async fn refresh(&mut self) -> Result<FakeSnapshot> {
        self.generation += 1;
        let generation = self.generation;
        self.state
            .lock()
            .unwrap()
            .events
            .push_back(Event::Maintenance(generation));
        if let Some(gate) = &self.refresh_gate {
            gate.cancelled().await;
        }
        if self.fail_refresh.contains(&generation) {
            anyhow::bail!("injected store failure");
        }
        let mut state = self.state.lock().unwrap();
        assert!(
            state.live.len() < 2,
            "third leased generation blocks real maintenance"
        );
        assert!(state.live.insert(generation));
        drop(state);
        Ok(FakeSnapshot {
            generation,
            questions: self.questions.clone(),
            state: self.state.clone(),
            page_gate: self.page_gate.clone(),
            page_error: self.fail_page.contains(&generation),
        })
    }
}

fn questions(n: usize) -> Vec<Query> {
    (0..n)
        .map(|i| {
            Query::query(
                Name::from_ascii(format!("target-{i:04}.example.")).unwrap(),
                RecordType::A,
            )
        })
        .collect()
}
fn maintenance(state: &Shared, n: usize) -> FakeMaintenance {
    FakeMaintenance {
        state: state.clone(),
        generation: 0,
        questions: questions(n),
        fail_refresh: BTreeSet::new(),
        fail_page: BTreeSet::new(),
        page_gate: None,
        refresh_gate: None,
    }
}

fn exchange(
    state: Shared,
    gate: CancellationToken,
) -> impl FnMut(Query) -> Pending<'static, Option<ResolvedAnswer>> + Send {
    // Cell is Send but NOT Sync: this is also a compilation witness that the
    // production composition never accidentally requires a Sync closure.
    let sequence = Cell::new(0usize);
    move |query| {
        sequence.set(sequence.get() + 1);
        let state = state.clone();
        let gate = gate.clone();
        Box::pin(async move {
            let _guard = IoGuard::new(&state);
            state
                .lock()
                .unwrap()
                .events
                .push_back(Event::Lookup(query.name().to_ascii()));
            gate.cancelled().await;
            None // failed lookup must not strand this cycle or future cycles
        })
    }
}

fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    future.as_mut().poll(&mut cx)
}

// Event is the handshake, not a sleep/yield. Explicit polling also prevents
// the paused Tokio runtime advancing to the next tick while awaiting an event.
fn event<F: Future>(mut future: Pin<&mut F>, state: &Shared) -> Event {
    for _ in 0..10_000 {
        if let Some(event) = state.lock().unwrap().events.pop_front() {
            return event;
        }
        assert!(
            poll_once(future.as_mut()).is_pending(),
            "scheduler ended unexpectedly"
        );
    }
    panic!("scheduler failed to produce expected IO handshake");
}
fn settle<F: Future>(mut future: Pin<&mut F>, state: &Shared) {
    // A bounded IO script has no unobserved acknowledgements: poll past its
    // explicit last Page(empty), allowing cycle completion to reach idle.
    for _ in 0..4 {
        assert!(poll_once(future.as_mut()).is_pending());
    }
    assert!(
        state.lock().unwrap().events.is_empty(),
        "unexpected extra IO"
    );
}
fn stop<F: Future<Output = Result<()>>>(mut future: Pin<&mut F>, token: &CancellationToken) {
    token.cancel();
    match poll_once(future.as_mut()) {
        Poll::Ready(result) => result.unwrap(),
        Poll::Pending => panic!("shutdown did not cancel pending work"),
    }
}
fn ready_gate() -> CancellationToken {
    let gate = CancellationToken::new();
    gate.cancel();
    gate
}

// Catches immediate prefetch from stale disk state, wrong cadence, and global
// scheduler state surviving restart. Oracle: startup evaluation + 7200 seconds.
#[tokio::test(start_paused = true)]
async fn startup_evaluation_precedes_prefetch_and_restart_resets_cadence() {
    let state = Shared::default();
    for _ in 0..2 {
        let mut store = maintenance(&state, 1);
        let token = CancellationToken::new();
        let mut run = Box::pin(schedule(
            &mut store,
            exchange(state.clone(), ready_gate()),
            token.clone(),
        ));
        assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
        assert_eq!(event(run.as_mut(), &state), Event::Page(1, 0));
        assert_eq!(
            event(run.as_mut(), &state),
            Event::Lookup("target-0000.example.".into())
        );
        assert_eq!(event(run.as_mut(), &state), Event::Page(1, 1));
        settle(run.as_mut(), &state);
        tokio::time::advance(Duration::from_secs(7199)).await;
        settle(run.as_mut(), &state);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(event(run.as_mut(), &state), Event::Maintenance(2));
        // One scheduler poll can record maintenance AND page/lookup work.
        // Consume the complete tick's IO before reusing this oracle on restart;
        // shutdown does not erase observations recorded before cancellation.
        assert_eq!(event(run.as_mut(), &state), Event::Page(2, 0));
        assert_eq!(
            event(run.as_mut(), &state),
            Event::Lookup("target-0000.example.".into())
        );
        assert_eq!(event(run.as_mut(), &state), Event::Page(2, 1));
        settle(run.as_mut(), &state);
        stop(run.as_mut(), &token);
        drop(run);
        assert!(state.lock().unwrap().live.is_empty());
        assert!(state.lock().unwrap().events.is_empty());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            state.lock().unwrap().events.is_empty(),
            "late IO after stop"
        );
    }
}

// Catches maintenance serialized behind network IO, queued cycles on completion,
// overlap, and retaining current snapshots until a third lease fails refresh.
#[tokio::test(start_paused = true)]
async fn gated_cycle_does_not_block_maintenance_or_accumulate_generations_or_backlog() {
    let state = Shared::default();
    let mut store = maintenance(&state, 1);
    let gate = CancellationToken::new();
    let token = CancellationToken::new();
    let mut run = Box::pin(schedule(
        &mut store,
        exchange(state.clone(), gate.clone()),
        token.clone(),
    ));
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
    assert_eq!(event(run.as_mut(), &state), Event::Page(1, 0));
    assert_eq!(
        event(run.as_mut(), &state),
        Event::Lookup("target-0000.example.".into())
    );
    for generation in 2..=5 {
        tokio::time::advance(Duration::from_secs(7200)).await;
        assert_eq!(event(run.as_mut(), &state), Event::Maintenance(generation));
        settle(run.as_mut(), &state);
        assert_eq!(state.lock().unwrap().live, BTreeSet::from([1]));
    }
    gate.cancel();
    assert_eq!(event(run.as_mut(), &state), Event::Page(1, 1));
    settle(run.as_mut(), &state);
    assert!(state.lock().unwrap().live.is_empty());
    tokio::time::advance(Duration::from_secs(7199)).await;
    settle(run.as_mut(), &state);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(6));
    assert_eq!(event(run.as_mut(), &state), Event::Page(6, 0));
    assert_eq!(
        event(run.as_mut(), &state),
        Event::Lookup("target-0000.example.".into())
    );
    assert_eq!(state.lock().unwrap().maximum_io, 1);
    stop(run.as_mut(), &token);
}

// Catches Burst missed-tick replay. A stalled scheduler gets one fresh refresh,
// not one refresh for every missed two-hour boundary.
#[tokio::test(start_paused = true)]
async fn missed_deadlines_are_skipped_not_replayed() {
    let state = Shared::default();
    let mut store = maintenance(&state, 0);
    let token = CancellationToken::new();
    let mut run = Box::pin(schedule(
        &mut store,
        exchange(state.clone(), ready_gate()),
        token.clone(),
    ));
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
    assert_eq!(event(run.as_mut(), &state), Event::Page(1, 0));
    settle(run.as_mut(), &state);
    tokio::time::advance(Duration::from_secs(7200 * 4 + 1)).await;
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(2));
    assert_eq!(event(run.as_mut(), &state), Event::Page(2, 0));
    settle(run.as_mut(), &state);
    stop(run.as_mut(), &token);
}

// Catches top-N truncation, stopping at a short/nonempty page, cursor replay,
// parallel exchanges, or a failed lookup aborting the remaining page.
#[tokio::test(start_paused = true)]
async fn all_targets_across_multiple_keyset_pages_are_sequential() {
    let state = Shared::default();
    let mut store = maintenance(&state, 301);
    let token = CancellationToken::new();
    let mut run = Box::pin(schedule(
        &mut store,
        exchange(state.clone(), ready_gate()),
        token.clone(),
    ));
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
    for i in 0..301 {
        if i % 128 == 0 {
            assert_eq!(event(run.as_mut(), &state), Event::Page(1, i));
        }
        assert_eq!(
            event(run.as_mut(), &state),
            Event::Lookup(format!("target-{i:04}.example."))
        );
    }
    assert_eq!(event(run.as_mut(), &state), Event::Page(1, 301));
    settle(run.as_mut(), &state);
    assert_eq!(state.lock().unwrap().maximum_io, 1);
    stop(run.as_mut(), &token);
}

// Catches terminating on store/page errors, retry spins, and stranded closure
// ownership after an early page error. Each failure retries only on next tick.
#[tokio::test(start_paused = true)]
async fn store_and_page_errors_recover_on_next_cycle() {
    let state = Shared::default();
    let mut store = maintenance(&state, 1);
    store.fail_refresh.insert(1);
    store.fail_page.insert(2);
    let token = CancellationToken::new();
    let mut run = Box::pin(schedule(
        &mut store,
        exchange(state.clone(), ready_gate()),
        token.clone(),
    ));
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
    settle(run.as_mut(), &state);
    tokio::time::advance(Duration::from_secs(7200)).await;
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(2));
    assert_eq!(event(run.as_mut(), &state), Event::Page(2, 0));
    settle(run.as_mut(), &state);
    tokio::time::advance(Duration::from_secs(7200)).await;
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(3));
    assert_eq!(event(run.as_mut(), &state), Event::Page(3, 0));
    assert_eq!(
        event(run.as_mut(), &state),
        Event::Lookup("target-0000.example.".into())
    );
    assert_eq!(event(run.as_mut(), &state), Event::Page(3, 1));
    settle(run.as_mut(), &state);
    stop(run.as_mut(), &token);
}

// Catches detached network/page futures, shutdown losing to ready tick/work,
// retained snapshots, and late work after releasing a cancelled IO gate.
#[tokio::test(start_paused = true)]
async fn shutdown_drops_page_or_network_wait_and_prevents_late_work() {
    for page_wait in [true, false] {
        let state = Shared::default();
        let mut store = maintenance(&state, 2);
        let gate = CancellationToken::new();
        if page_wait {
            store.page_gate = Some(gate.clone());
        }
        let token = CancellationToken::new();
        let network = if page_wait {
            ready_gate()
        } else {
            gate.clone()
        };
        let mut run = Box::pin(schedule(
            &mut store,
            exchange(state.clone(), network),
            token.clone(),
        ));
        assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
        assert_eq!(event(run.as_mut(), &state), Event::Page(1, 0));
        if !page_wait {
            assert_eq!(
                event(run.as_mut(), &state),
                Event::Lookup("target-0000.example.".into())
            );
        }
        tokio::time::advance(Duration::from_secs(7200)).await;
        stop(run.as_mut(), &token); // shutdown and tick ready simultaneously
        gate.cancel();
        drop(run);
        let s = state.lock().unwrap();
        assert_eq!(s.active_io, 0);
        assert_eq!(s.dropped_io, 1);
        assert!(s.live.is_empty());
        assert!(s.events.is_empty());
    }
}

// Catches waiting for a stalled publication reply before honoring shutdown,
// or retrying maintenance after terminal cancellation.
#[tokio::test(start_paused = true)]
async fn pending_startup_maintenance_is_cancelled_on_shutdown() {
    let state = Shared::default();
    let mut store = maintenance(&state, 1);
    let publication_gate = CancellationToken::new();
    store.refresh_gate = Some(publication_gate.clone());
    let token = CancellationToken::new();
    let mut run = Box::pin(schedule(
        &mut store,
        exchange(state.clone(), ready_gate()),
        token.clone(),
    ));
    assert_eq!(event(run.as_mut(), &state), Event::Maintenance(1));
    settle(run.as_mut(), &state);
    stop(run.as_mut(), &token);
    publication_gate.cancel();
    drop(run);
    assert!(state.lock().unwrap().events.is_empty());
    assert!(state.lock().unwrap().live.is_empty());
}

// Catches constructing/polling startup maintenance after already-cancelled
// shutdown, including synchronous closure invocation before a select guard.
#[tokio::test(start_paused = true)]
async fn already_cancelled_shutdown_performs_no_startup_io() {
    let state = Shared::default();
    let mut store = maintenance(&state, 1);
    let token = CancellationToken::new();
    token.cancel();
    let result = schedule(&mut store, exchange(state.clone(), ready_gate()), token).await;
    result.unwrap();
    assert!(state.lock().unwrap().events.is_empty());
}
