use super::AbortOnDrop;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

#[derive(Default)]
pub(crate) struct RecorderCounters {
    pub(crate) accept_overrun: Arc<AtomicUsize>,
    pub(crate) events_overrun: Arc<AtomicUsize>,
    pub(crate) panic_count: Arc<AtomicUsize>,
    pub(crate) panic_messages: Arc<Mutex<Vec<String>>>,
    pub(crate) worker_timeouts: Arc<AtomicUsize>,
    pub(crate) worker_errors: Arc<AtomicUsize>,
    pub(crate) aborted_workers: Arc<AtomicUsize>,
}

pub(crate) struct ScenarioCleanup<'a> {
    pub(crate) shutdown_tx: Option<oneshot::Sender<()>>,
    pub(crate) stop1_tx: watch::Sender<()>,
    pub(crate) stop2_tx: watch::Sender<()>,
    pub(crate) server: &'a mut AbortOnDrop<anyhow::Result<()>>,
    pub(crate) recorder1: &'a mut AbortOnDrop<()>,
    pub(crate) recorder2: &'a mut AbortOnDrop<()>,
    pub(crate) trap: &'a mut AbortOnDrop<()>,
    pub(crate) trap_listener: Arc<TcpListener>,
    pub(crate) trap_accepts: &'a AtomicUsize,
    pub(crate) trap_overrun: &'a AtomicUsize,
    pub(crate) events1_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) events2_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) traps_rx: mpsc::Receiver<TcpStream>,
    pub(crate) graceful_deadline: Instant,
    pub(crate) terminal_deadline: Instant,
}

/// Records lifecycle claims, not kernel ownership or process liveness.
/// Integration must validate live evidence; retained receipts describe past observations.
pub(crate) mod session_ledger {
    use std::sync::{Arc, Mutex};

    type Result<T> = std::result::Result<T, &'static str>;
    const CAPACITY: usize = 8;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Phase {
        Accepted,
        Greeting,
        Auth,
        Connect,
        Http,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Stage {
        Auth,
        Connect,
        Raw,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Credential {
        Global,
        Account,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Owner {
        Global {
            pid: u32,
        },
        Alternate {
            reserve: usize,
            construction: usize,
            entry: usize,
            slot: usize,
            pid: u32,
        },
    }

    impl Owner {
        fn valid(self) -> bool {
            match self {
                Self::Global { pid } => pid != 0,
                Self::Alternate {
                    entry, slot, pid, ..
                } => entry != 0 && (1..=15).contains(&slot) && pid != 0,
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Receipt {
        pub(crate) session: usize,
        pub(crate) stage: Stage,
        pub(crate) credential: Credential,
        pub(crate) owner: Owner,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum End {
        Closed,
        Rejected,
        PartialShutdown,
    }

    #[derive(Clone, Copy)]
    pub(crate) enum Event {
        Progress(Phase),
        Bind(Receipt),
        Critical(Stage, Credential),
        Delivered,
        Consumed,
        Correlated(Receipt),
        Terminal(End),
    }

    #[derive(Clone, Copy)]
    struct Entry {
        id: usize,
        phase: Phase,
        critical: Option<(Stage, Credential)>,
        expected: Option<Receipt>,
        observed: Option<Receipt>,
        delivered: bool,
        consumed: bool,
        terminal: Option<End>,
        released: bool,
    }

    impl Entry {
        fn new(id: usize) -> Self {
            Self {
                id,
                phase: Phase::Accepted,
                critical: None,
                expected: None,
                observed: None,
                delivered: false,
                consumed: false,
                terminal: None,
                released: false,
            }
        }

        fn apply(&mut self, event: Event, stopping: bool) -> bool {
            if self.released || self.terminal.is_some() {
                return false;
            }
            match event {
                Event::Progress(next) if self.critical.is_none() => {
                    let expected = match self.phase {
                        Phase::Accepted => Some(Phase::Greeting),
                        Phase::Greeting => Some(Phase::Auth),
                        Phase::Auth => Some(Phase::Connect),
                        Phase::Connect => Some(Phase::Http),
                        Phase::Http => None,
                    };
                    if expected != Some(next) {
                        return false;
                    }
                    self.phase = next;
                    true
                }
                Event::Bind(receipt) => {
                    if self.expected.is_some()
                        || receipt.session != self.id
                        || !receipt.owner.valid()
                    {
                        return false;
                    }
                    if self
                        .critical
                        .is_some_and(|value| value != (receipt.stage, receipt.credential))
                    {
                        return false;
                    }
                    self.expected = Some(receipt);
                    true
                }
                Event::Critical(stage, credential) => {
                    let expected_phase = match stage {
                        Stage::Auth => Phase::Auth,
                        Stage::Connect => Phase::Connect,
                        Stage::Raw => Phase::Http,
                    };
                    if self.critical.is_some() || self.phase != expected_phase {
                        return false;
                    }
                    if self
                        .expected
                        .is_some_and(|r| (r.stage, r.credential) != (stage, credential))
                    {
                        return false;
                    }
                    self.critical = Some((stage, credential));
                    true
                }
                Event::Delivered if self.critical.is_some() && !self.delivered => {
                    self.delivered = true;
                    true
                }
                Event::Consumed if self.delivered && !self.consumed => {
                    self.consumed = true;
                    true
                }
                Event::Correlated(receipt) => {
                    if self.expected != Some(receipt) || self.observed.is_some() {
                        return false;
                    }
                    self.observed = Some(receipt);
                    true
                }
                Event::Terminal(end) => {
                    let permitted = match end {
                        End::PartialShutdown => stopping && self.critical.is_none(),
                        End::Closed => matches!(self.critical, Some((Stage::Raw, _))),
                        End::Rejected => {
                            matches!(self.critical, Some((Stage::Auth | Stage::Connect, _)))
                        }
                    };
                    let handoff = self.delivered
                        && self.consumed
                        && self.observed.is_some()
                        && self.observed == self.expected;
                    if !permitted || (end != End::PartialShutdown && !handoff) {
                        return false;
                    }
                    self.terminal = Some(end);
                    true
                }
                _ => false,
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(crate) struct Observation {
        pub(crate) phase: Phase,
        pub(crate) critical: Option<(Stage, Credential)>,
        pub(crate) delivered: bool,
        pub(crate) consumed: bool,
        pub(crate) terminal: Option<End>,
        pub(crate) released: bool,
    }

    struct State {
        entries: [Option<Entry>; CAPACITY],
        stopping: bool,
        invalid: bool,
        sealed: bool,
    }

    #[derive(Clone)]
    pub(crate) struct Ledger(Arc<Mutex<State>>);

    pub(crate) struct Lease {
        ledger: Ledger,
        id: usize,
    }

    impl Ledger {
        pub(crate) fn new() -> Self {
            Self(Arc::new(Mutex::new(State {
                entries: [None; CAPACITY],
                stopping: false,
                invalid: false,
                sealed: false,
            })))
        }

        pub(crate) fn accepted(&self, id: usize) -> Result<Lease> {
            let mut state = self.0.lock().map_err(|_| "session ledger poisoned")?;
            if state.invalid
                || state.stopping
                || state.sealed
                || state.entries.iter().flatten().any(|e| e.id == id)
            {
                state.invalid = true;
                return Err("session admission invalid");
            }
            let Some(slot) = state.entries.iter_mut().find(|e| e.is_none()) else {
                state.invalid = true;
                return Err("session capacity exceeded");
            };
            *slot = Some(Entry::new(id));
            Ok(Lease {
                ledger: self.clone(),
                id,
            })
        }

        pub(crate) fn observe(&self, id: usize, event: Event) -> Result<()> {
            let mut state = self.0.lock().map_err(|_| "session ledger poisoned")?;
            if state.invalid || state.sealed {
                state.invalid = true;
                return Err("session ledger invalid");
            }
            let stopping = state.stopping;
            let valid = state
                .entries
                .iter_mut()
                .flatten()
                .find(|e| e.id == id)
                .is_some_and(|e| e.apply(event, stopping));
            if !valid {
                state.invalid = true;
                return Err("session event invalid");
            }
            Ok(())
        }

        pub(crate) fn stopping(&self) -> Result<()> {
            let mut state = self.0.lock().map_err(|_| "session ledger poisoned")?;
            if state.invalid || state.sealed {
                state.invalid = true;
                return Err("session ledger invalid");
            }
            state.stopping = true;
            Ok(())
        }

        pub(crate) fn lost(&self) {
            if let Ok(mut state) = self.0.lock() {
                state.invalid = true;
            }
        }

        pub(crate) fn inspect(&self, id: usize) -> Result<Observation> {
            let state = self.0.lock().map_err(|_| "session ledger poisoned")?;
            let entry = state
                .entries
                .iter()
                .flatten()
                .find(|entry| entry.id == id)
                .ok_or("session observation missing")?;
            Ok(Observation {
                phase: entry.phase,
                critical: entry.critical,
                delivered: entry.delivered,
                consumed: entry.consumed,
                terminal: entry.terminal,
                released: entry.released,
            })
        }

        pub(crate) fn is_sealed(&self) -> bool {
            self.0
                .lock()
                .is_ok_and(|state| state.sealed && !state.invalid)
        }

        pub(crate) fn finish(&self) -> Result<()> {
            let mut state = self.0.lock().map_err(|_| "session ledger poisoned")?;
            if state.invalid
                || state
                    .entries
                    .iter()
                    .flatten()
                    .any(|e| e.terminal.is_none() || !e.released)
            {
                state.invalid = true;
                return Err("session reconciliation failed");
            }
            state.sealed = true;
            Ok(())
        }
    }

    impl Lease {
        pub(crate) fn apply(&self, event: Event) -> Result<()> {
            self.ledger.observe(self.id, event)
        }
    }

    impl Drop for Lease {
        fn drop(&mut self) {
            let Ok(mut state) = self.ledger.0.lock() else {
                return;
            };
            let stopping = state.stopping;
            let Some(entry) = state.entries.iter_mut().flatten().find(|e| e.id == self.id) else {
                state.invalid = true;
                return;
            };
            if entry.released {
                state.invalid = true;
                return;
            }
            entry.released = true;
            if entry.terminal.is_none() {
                if stopping && entry.critical.is_none() {
                    entry.terminal = Some(End::PartialShutdown);
                } else {
                    state.invalid = true;
                }
            }
        }
    }

    fn exercise(
        stage: Stage,
        credential: Credential,
        owner: Owner,
        omit: Option<usize>,
        duplicate: Option<usize>,
        replacement: Option<(usize, Event)>,
    ) -> bool {
        let ledger = Ledger::new();
        let lease = ledger.accepted(0).expect("synthetic admission failed");
        let receipt = Receipt {
            session: 0,
            stage,
            credential,
            owner,
        };
        let phases = [Phase::Greeting, Phase::Auth, Phase::Connect, Phase::Http];
        let count = match stage {
            Stage::Auth => 2,
            Stage::Connect => 3,
            Stage::Raw => 4,
        };
        for phase in &phases[..count] {
            assert!(lease.apply(Event::Progress(*phase)).is_ok());
        }
        let end = if stage == Stage::Raw {
            End::Closed
        } else {
            End::Rejected
        };
        let events = [
            Event::Bind(receipt),
            Event::Correlated(receipt),
            Event::Critical(stage, credential),
            Event::Delivered,
            Event::Consumed,
            Event::Terminal(end),
        ];
        for (index, event) in events.into_iter().enumerate() {
            if omit == Some(index) {
                continue;
            }
            let event = match replacement {
                Some((at, value)) if at == index => value,
                _ => event,
            };
            let _ = lease.apply(event);
            if duplicate == Some(index) {
                let _ = lease.apply(event);
            }
        }
        drop(lease);
        ledger.finish().is_ok()
    }

    /// Synthetic receipts and PIDs exercise bookkeeping only, not live ownership.
    pub(crate) fn run_controls() {
        let global = Owner::Global { pid: 123 };
        let alternate = Owner::Alternate {
            reserve: 9,
            construction: 0,
            entry: 11,
            slot: 2,
            pid: 124,
        };
        for stage in [Stage::Auth, Stage::Connect, Stage::Raw] {
            for credential in [Credential::Global, Credential::Account] {
                for owner in [global, alternate] {
                    assert!(exercise(stage, credential, owner, None, None, None));
                }
            }
            for index in 0..6 {
                assert!(!exercise(
                    stage,
                    Credential::Global,
                    global,
                    Some(index),
                    None,
                    None
                ));
                assert!(!exercise(
                    stage,
                    Credential::Global,
                    global,
                    None,
                    Some(index),
                    None
                ));
            }
            let wrong_stage = if stage == Stage::Auth {
                Stage::Connect
            } else {
                Stage::Auth
            };
            let receipt = Receipt {
                session: 0,
                stage,
                credential: Credential::Global,
                owner: global,
            };
            for wrong in [
                Receipt {
                    session: 1,
                    ..receipt
                },
                Receipt {
                    stage: wrong_stage,
                    ..receipt
                },
                Receipt {
                    credential: Credential::Account,
                    ..receipt
                },
                Receipt {
                    owner: Owner::Global { pid: 125 },
                    ..receipt
                },
            ] {
                assert!(!exercise(
                    stage,
                    Credential::Global,
                    global,
                    None,
                    None,
                    Some((1, Event::Correlated(wrong)))
                ));
            }
            assert!(!exercise(
                stage,
                Credential::Global,
                global,
                None,
                None,
                Some((2, Event::Critical(wrong_stage, Credential::Global)))
            ));
            assert!(!exercise(
                stage,
                Credential::Global,
                global,
                None,
                None,
                Some((2, Event::Critical(stage, Credential::Account)))
            ));
            assert!(!exercise(
                stage,
                Credential::Global,
                global,
                None,
                None,
                Some((3, Event::Consumed))
            ));
            assert!(!exercise(
                stage,
                Credential::Global,
                global,
                None,
                None,
                Some((5, Event::Terminal(End::PartialShutdown)))
            ));
        }

        let ledger = Ledger::new();
        let leases: [Option<Lease>; CAPACITY] = std::array::from_fn(|id| {
            Some(
                ledger
                    .accepted(id)
                    .expect("synthetic capacity admission failed"),
            )
        });
        assert!(ledger.stopping().is_ok());
        drop(leases);
        assert!(ledger.finish().is_ok());
        let ledger = Ledger::new();
        let leases: [Option<Lease>; CAPACITY] = std::array::from_fn(|id| {
            Some(
                ledger
                    .accepted(id)
                    .expect("synthetic capacity admission failed"),
            )
        });
        assert!(ledger.accepted(CAPACITY).is_err());
        drop(leases);
        assert!(ledger.finish().is_err());

        let ledger = Ledger::new();
        let lease = ledger.accepted(0).expect("synthetic admission failed");
        assert!(ledger.accepted(0).is_err());
        drop(lease);
        assert!(ledger.finish().is_err());
        let ledger = Ledger::new();
        assert!(ledger.observe(99, Event::Delivered).is_err());
        assert!(ledger.finish().is_err());
        for lost in [false, true] {
            let ledger = Ledger::new();
            let lease = ledger.accepted(0).expect("synthetic admission failed");
            assert!(ledger.stopping().is_ok());
            if lost {
                ledger.lost();
            }
            drop(lease);
            assert_eq!(ledger.finish().is_err(), lost);
        }

        for count in 0..=4 {
            let ledger = Ledger::new();
            let lease = ledger.accepted(0).expect("synthetic admission failed");
            for phase in &[Phase::Greeting, Phase::Auth, Phase::Connect, Phase::Http][..count] {
                assert!(lease.apply(Event::Progress(*phase)).is_ok());
            }
            assert!(ledger.stopping().is_ok());
            if count % 2 == 0 {
                assert!(lease.apply(Event::Terminal(End::PartialShutdown)).is_ok());
            }
            drop(lease);
            assert!(ledger.finish().is_ok());
        }

        let ledger = Ledger::new();
        let lease = ledger.accepted(0).expect("synthetic admission failed");
        drop(lease);
        assert!(ledger.finish().is_err());
        let ledger = Ledger::new();
        let lease = ledger.accepted(0).expect("synthetic admission failed");
        assert!(ledger.finish().is_err());
        assert!(ledger.stopping().is_err());
        drop(lease);
        assert!(ledger.finish().is_err());

        for stage in [Stage::Auth, Stage::Connect, Stage::Raw] {
            let ledger = Ledger::new();
            let lease = ledger.accepted(0).expect("synthetic admission failed");
            let phases = [Phase::Greeting, Phase::Auth, Phase::Connect, Phase::Http];
            let count = match stage {
                Stage::Auth => 2,
                Stage::Connect => 3,
                Stage::Raw => 4,
            };
            for phase in &phases[..count] {
                assert!(lease.apply(Event::Progress(*phase)).is_ok());
            }
            assert!(lease
                .apply(Event::Critical(stage, Credential::Global))
                .is_ok());
            assert!(ledger.stopping().is_ok());
            assert!(lease.apply(Event::Terminal(End::PartialShutdown)).is_err());
            drop(lease);
            assert!(ledger.finish().is_err());
        }

        assert!(!exercise(
            Stage::Raw,
            Credential::Global,
            global,
            None,
            None,
            Some((5, Event::Terminal(End::Rejected)))
        ));
        assert!(!exercise(
            Stage::Auth,
            Credential::Global,
            global,
            None,
            None,
            Some((5, Event::Terminal(End::Closed)))
        ));
        for owner in [
            Owner::Global { pid: 0 },
            Owner::Alternate {
                reserve: 0,
                construction: 0,
                entry: 0,
                slot: 1,
                pid: 1,
            },
            Owner::Alternate {
                reserve: 0,
                construction: 0,
                entry: 1,
                slot: 16,
                pid: 1,
            },
        ] {
            assert!(!exercise(
                Stage::Auth,
                Credential::Global,
                owner,
                None,
                None,
                None
            ));
        }
    }
}
