use std::future::{poll_fn, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Result};
use futures::FutureExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

use super::construction_consumer::{finish_stream, Consumer};
use super::construction_wire::{Client, State as WireState};
use super::{Entry, OwnerRegistry, SelectionProbe};
use crate::tor_watchdog::TorHandle;

const REGISTRY_CAP: usize = 16;
tokio::task_local! {
    static ACTIVE: Arc<Scope>;
}

/// Capture before spawning: Tokio task-local values are not inherited automatically.
pub(crate) fn inherit_scope<F: Future>(work: F) -> impl Future<Output = F::Output> {
    let scope = ACTIVE.try_with(Arc::clone).ok();
    async move {
        match scope {
            Some(scope) => ACTIVE.scope(scope, work).await,
            None => work.await,
        }
    }
}

pub(super) struct RetainedRegistry {
    probe: Arc<SelectionProbe>,
    global: TorHandle,
    cancel: CancellationToken,
    entries: Mutex<Vec<Arc<Entry>>>,
    close_failed: std::sync::atomic::AtomicBool,
    _quarantine: Arc<Mutex<Vec<std::fs::File>>>,
}

impl RetainedRegistry {
    fn cancel(&self) {
        self.cancel.cancel();
    }

    /// cancel-safe: NO — retain this registry and resume its owned cleanup.
    async fn close(&self) -> Result<()> {
        self.cancel();
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("construction registry retention poisoned"))?
            .clone();
        OwnerRegistry::close_entries(&self.global, &self.close_failed, entries).await
    }
}

struct Registration {
    consumer: Consumer,
    retained: Arc<RetainedRegistry>,
}

struct ScopeState {
    sender: Option<mpsc::Sender<Registration>>,
    next: u64,
    remaining: usize,
    closed: bool,
    failure: Option<&'static str>,
}

struct Scope {
    deadline: Instant,
    phase: u8,
    state: Mutex<ScopeState>,
}

struct HookGuard(Arc<Scope>);

impl HookGuard {
    fn stop(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        state.sender.take();
    }

    fn failure(&self) -> Option<&'static str> {
        self.0
            .state
            .lock()
            .map_or(Some("construction hook poisoned"), |state| state.failure)
    }

    fn next(&self) -> u64 {
        self.0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .next
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Called synchronously before the actual registry's probe is published.
pub(super) fn attach(registry: &OwnerRegistry) -> Result<()> {
    let scope = ACTIVE.try_with(Arc::clone).ok();
    let Some(scope) = scope else {
        return Ok(());
    };
    let mut state = scope
        .state
        .lock()
        .map_err(|_| anyhow!("construction hook poisoned"))?;
    if state.closed
        || state.failure.is_some()
        || state.remaining == 0
        || Instant::now() >= scope.deadline
    {
        state
            .failure
            .get_or_insert("construction attachment unavailable");
        bail!("construction attachment unavailable");
    }
    let retained = Arc::new(RetainedRegistry {
        probe: Arc::clone(&registry.selection_probe),
        global: registry.global.clone(),
        cancel: registry.cancel.clone(),
        entries: Mutex::new(Vec::new()),
        close_failed: std::sync::atomic::AtomicBool::new(false),
        _quarantine: Arc::clone(&registry.storage_quarantine),
    });
    let consumer = Consumer::install(
        Arc::clone(&retained.probe),
        state.next,
        scope.phase,
        scope.deadline,
    )?;
    let next = state
        .next
        .checked_add(1)
        .ok_or_else(|| anyhow!("construction registry overflow"))?;
    *retained
        .probe
        .registry_retention
        .lock()
        .map_err(|_| anyhow!("construction registry retention poisoned"))? =
        Some(Arc::downgrade(&retained));
    let registration = Registration { consumer, retained };
    if state
        .sender
        .as_ref()
        .is_none_or(|sender| sender.try_send(registration).is_err())
    {
        state
            .failure
            .get_or_insert("construction registration delivery failed");
        bail!("construction registration delivery failed");
    }
    state.next = next;
    state.remaining -= 1;
    Ok(())
}

/// Reserve has completed; retain its actual entry before construction can start.
pub(super) fn retain_entry(probe: &SelectionProbe, entry: &Arc<Entry>) -> Result<()> {
    let retained = probe
        .registry_retention
        .lock()
        .map_err(|_| anyhow!("construction registry retention poisoned"))?
        .clone();
    let Some(retained) = retained else {
        return Ok(());
    };
    let retained = retained
        .upgrade()
        .ok_or_else(|| anyhow!("construction registry driver lost"))?;
    let mut entries = retained
        .entries
        .lock()
        .map_err(|_| anyhow!("construction registry retention poisoned"))?;
    if !entries.iter().any(|old| Arc::ptr_eq(old, entry)) {
        if entries.len() >= super::CAPACITY - 1 {
            bail!("construction retained entry capacity");
        }
        entries.push(Arc::clone(entry));
    }
    Ok(())
}

struct Record {
    registration: Registration,
    enabled: bool,
    closed: bool,
    finished: bool,
}

type Scenario = Pin<Box<dyn Future<Output = std::thread::Result<()>>>>;

pub(crate) struct Session {
    client: Client,
    work: Option<Scenario>,
    deadline: Instant,
    next_registry: u64,
    records: Vec<Record>,
    hook: Option<HookGuard>,
    registrations: Option<mpsc::Receiver<Registration>>,
    failure: Option<&'static str>,
    coordinator: Option<super::owner_intent::Coordinator>,
}

impl Session {
    pub(crate) fn new(stream: TcpStream, deadline: Instant) -> Self {
        Self {
            client: Client::new(stream, deadline),
            work: None,
            deadline,
            next_registry: 1,
            records: Vec::new(),
            hook: None,
            registrations: None,
            failure: None,
            coordinator: None,
        }
    }

    /// Private CI metadata projects the supervisor's remaining existing four-minute budget.
    /// It is not product configuration and never raises the external timeout.
    /// cancel-safe: YES — cancellation drops only the not-yet-registered socket.
    #[allow(
        dead_code,
        reason = "Called by the pt_owner_contract main, not binary unit tests."
    )]
    pub(crate) async fn from_environment() -> Result<Option<Self>> {
        let Some(deadline) = super::owner_budget::from_environment()? else {
            return Ok(None);
        };
        let address = SocketAddr::from(([127, 0, 0, 1], 19053));
        let stream = timeout_at(deadline, TcpStream::connect(address))
            .await
            .map_err(|_| anyhow!("construction evidence connection deadline"))??;
        let mut session = Self::new(stream, deadline);
        session.coordinator = Some(super::owner_intent::Coordinator::bind(deadline).await?);
        Ok(Some(session))
    }

    pub(crate) fn registries_closed(&self) -> bool {
        self.work.is_none()
            && self.hook.is_none()
            && self.registrations.is_none()
            && self.records.iter().all(|record| record.closed)
            && self
                .coordinator
                .as_ref()
                .is_none_or(|owner| !owner.has_active())
    }

    fn fail(&mut self, reason: &'static str) {
        self.failure.get_or_insert(reason);
        if let Some(owner) = &mut self.coordinator {
            owner.stop();
        }
        if let Some(hook) = &self.hook {
            hook.stop();
        }
        for record in &mut self.records {
            record.enabled = false;
            record.registration.retained.cancel();
            if !record.finished {
                record.registration.consumer.reject_buffered();
            }
        }
    }

    fn start(&mut self, phase: u8, deadline: Instant) -> Result<()> {
        if self.failure.is_some()
            || self.work.is_some()
            || self.hook.is_some()
            || self.registrations.is_some()
            || phase > 1
            || deadline > self.deadline
            || Instant::now() >= deadline
        {
            bail!("construction driver phase lifecycle");
        }
        let (sender, receiver) = mpsc::channel(REGISTRY_CAP);
        let scope = Arc::new(Scope {
            deadline,
            phase,
            state: Mutex::new(ScopeState {
                sender: Some(sender),
                next: self.next_registry,
                remaining: REGISTRY_CAP.saturating_sub(self.records.len()),
                closed: false,
                failure: None,
            }),
        });
        if ACTIVE.try_with(|_| ()).is_ok() {
            bail!("construction hook already installed");
        }
        self.hook = Some(HookGuard(scope));
        self.registrations = Some(receiver);
        Ok(())
    }

    fn insert(&mut self, registration: Registration) -> usize {
        // Scope reserves one of the remaining sixteen slots before enqueue.
        let index = self.records.len();
        self.records.push(Record {
            registration,
            enabled: false,
            closed: false,
            finished: false,
        });
        index
    }

    async fn register(&mut self, registration: Registration) {
        let index = self.insert(registration);
        let record = &mut self.records[index];
        if self.failure.is_none()
            && record
                .registration
                .consumer
                .open(&mut self.client)
                .await
                .is_ok()
        {
            record.enabled = true;
            return;
        }
        self.fail("construction context open failed");
    }

    fn end_scope(&mut self) {
        if let Some(hook) = self.hook.take() {
            self.next_registry = hook.next();
            drop(hook);
        }
    }

    async fn collect_registrations(&mut self) {
        loop {
            let next = self
                .registrations
                .as_mut()
                .and_then(|receiver| receiver.try_recv().ok());
            let Some(registration) = next else {
                break;
            };
            self.register(registration).await;
        }
        self.registrations.take();
    }

    /// cancel-safe: NO — retain this Session and call finish() after interruption.
    /// A phase deadline hands ownership back here without dropping scenario cleanup.
    pub(crate) async fn run_phase<F: Future<Output = ()> + 'static>(
        &mut self,
        phase: u8,
        deadline: Instant,
        work: F,
    ) -> Result<()> {
        let deadline = deadline.min(self.deadline);
        self.start(phase, deadline)?;
        let scope = Arc::clone(&self.hook.as_ref().expect("phase hook exists").0);
        self.work = Some(Box::pin(
            ACTIVE.scope(scope, std::panic::AssertUnwindSafe(work).catch_unwind()),
        ));
        let timer = tokio::time::sleep_until(deadline);
        tokio::pin!(timer);
        let mut accepting = true;
        let outcome = loop {
            if let Some(reason) = self.hook.as_ref().and_then(HookGuard::failure) {
                self.fail(reason);
            }
            if self
                .coordinator
                .as_ref()
                .is_some_and(|owner| owner.has_active())
            {
                let owner = self.coordinator.as_mut().expect("active owner intent");
                let result = tokio::select! {
                    biased;
                    outcome = self.work.as_mut().expect("scenario retained").as_mut() => Err(Some(outcome)),
                    result = poll_fn(|cx| owner.poll_active(cx)) => Ok(result),
                    _ = &mut timer => Err(None),
                };
                match result {
                    Ok(Ok(())) => continue,
                    Ok(Err(_)) => {
                        self.fail("owner intent failed");
                        continue;
                    }
                    Err(outcome) => {
                        self.fail("owner intent interrupted");
                        break outcome;
                    }
                }
            }
            enum Event<T> {
                Work(T),
                Child(Result<super::owner_intent::Request>),
                Registration(Option<Box<Registration>>),
                Ready(usize, Result<(), super::construction_consumer::Error>),
                Deadline,
            }
            let event = {
                let receiver = self.registrations.as_mut().expect("phase receiver exists");
                let records = &mut self.records;
                let coordinator = &mut self.coordinator;
                let work = self.work.as_mut().expect("scenario is retained");
                tokio::select! {
                    biased;
                    result = work.as_mut() => Event::Work(result),
                    registration = receiver.recv(), if accepting => {
                        Event::Registration(registration.map(Box::new))
                    }
                    ready = poll_fn(|cx| poll_ready(records, cx)), if self.failure.is_none() => {
                        Event::Ready(ready.0, ready.1)
                    }
                    child = poll_fn(|cx| match coordinator {
                        Some(owner) => owner.poll_request(cx, deadline),
                        None => Poll::Pending,
                    }), if self.failure.is_none() => Event::Child(child),
                    _ = &mut timer => Event::Deadline,
                }
            };
            match event {
                Event::Work(outcome) => break Some(outcome),
                Event::Child(Ok(request)) => {
                    if self
                        .coordinator
                        .as_mut()
                        .expect("owner coordinator exists")
                        .start(request, phase, deadline)
                        .is_err()
                    {
                        self.fail("owner readiness rejected");
                    }
                }
                Event::Child(Err(_)) => self.fail("owner readiness request failed"),
                Event::Registration(Some(registration)) => {
                    let index = self.insert(*registration);
                    if self.failure.is_some() {
                        self.fail("construction registration after failure");
                        continue;
                    }
                    let result = {
                        let mut opening = Box::pin(
                            self.records[index]
                                .registration
                                .consumer
                                .open(&mut self.client),
                        );
                        tokio::select! {
                            biased;
                            outcome = self.work.as_mut().expect("scenario is retained").as_mut() => Err(outcome),
                            result = &mut opening => Ok(result),
                        }
                    };
                    match result {
                        Ok(Ok(())) => self.records[index].enabled = true,
                        Ok(Err(_)) => self.fail("construction context open failed"),
                        Err(outcome) => {
                            self.fail("scenario ended during construction open");
                            break Some(outcome);
                        }
                    }
                }
                Event::Registration(None) => accepting = false,
                Event::Deadline => {
                    self.fail("construction phase deadline");
                    break None;
                }
                Event::Ready(index, Err(_)) => {
                    self.records[index].enabled = false;
                    self.fail("construction receiver failed");
                }
                Event::Ready(index, Ok(())) => {
                    let result = {
                        let mut delivery = Box::pin(
                            self.records[index]
                                .registration
                                .consumer
                                .deliver(&mut self.client),
                        );
                        tokio::select! {
                            biased;
                            outcome = self.work.as_mut().expect("scenario is retained").as_mut() => Err(outcome),
                            result = &mut delivery => Ok(result),
                        }
                    };
                    match result {
                        Ok(Ok(_)) => {
                            if let Some(owner) = &mut self.coordinator {
                                let delivery = self.records[index]
                                    .registration
                                    .consumer
                                    .deliveries()
                                    .last()
                                    .expect("delivered evidence retained");
                                if owner.observe(delivery, phase).is_err() {
                                    self.fail("owner assignment registration failed");
                                }
                            }
                        }
                        Ok(Err(_)) => self.fail("construction delivery failed"),
                        Err(outcome) => {
                            self.fail("scenario ended during construction delivery");
                            break Some(outcome);
                        }
                    }
                }
            }
        };
        if let Some(outcome) = outcome {
            self.work.take();
            if outcome.is_err() {
                self.fail("owner scenario panicked");
            }
        }
        self.end_scope();
        self.collect_registrations().await;
        if let Some(owner) = &mut self.coordinator {
            owner.pause_requests();
            if !owner.phase_complete(phase) {
                self.fail("owner intent phase incomplete");
            }
        }
        if self.work.is_none()
            && self
                .coordinator
                .as_ref()
                .is_none_or(|owner| !owner.has_active())
        {
            self.close_records(deadline).await;
        }
        if self.failure.is_some() {
            bail!("construction evidence phase failed");
        }
        Ok(())
    }

    async fn close_records(&mut self, deadline: Instant) {
        for index in 0..self.records.len() {
            if !self.records[index].closed {
                self.records[index].registration.retained.cancel();
                let result =
                    timeout_at(deadline, self.records[index].registration.retained.close()).await;
                if !matches!(result, Ok(Ok(()))) {
                    self.fail("construction registry cleanup failed");
                    continue;
                }
                self.records[index].closed = true;
            }
            if !self.records[index].finished {
                let result = self.records[index]
                    .registration
                    .consumer
                    .finish(&mut self.client)
                    .await;
                self.records[index].enabled = false;
                self.records[index].finished = true;
                if result.is_err() {
                    self.fail("construction terminal evidence failed");
                }
            }
        }
    }

    /// cancel-safe: NO — retain this Session until actual terminal waits complete.
    /// This may exceed detection deadlines; the isolated supervisor remains the hard bound.
    pub(crate) async fn settle(&mut self) -> Result<()> {
        self.fail("construction evidence terminal recovery");
        self.end_scope();
        self.collect_registrations().await;
        if let Some(owner) = &mut self.coordinator {
            if owner.settle().await.is_err() {
                self.fail("owner intent terminal failure");
            }
        }
        if let Some(work) = self.work.as_mut() {
            let outcome = work.as_mut().await;
            self.work.take();
            if outcome.is_err() {
                self.fail("owner scenario panicked");
            }
        }
        for index in 0..self.records.len() {
            if !self.records[index].closed {
                if self.records[index]
                    .registration
                    .retained
                    .close()
                    .await
                    .is_err()
                {
                    self.fail("construction registry remains retained");
                    continue;
                }
                self.records[index].closed = true;
            }
            if !self.records[index].finished {
                let result = self.records[index]
                    .registration
                    .consumer
                    .finish(&mut self.client)
                    .await;
                self.records[index].finished = true;
                if result.is_err() {
                    self.fail("construction terminal evidence failed");
                }
            }
        }
        if !self.registries_closed() {
            bail!("construction registries remain retained");
        }
        Ok(())
    }

    /// A terminal cleanup failure must not unwind the last owners of running work.
    /// The existing isolated supervisor timeout terminates this failed harness.
    #[allow(
        dead_code,
        reason = "Called by pt_owner_contract cleanup, not binary unit tests."
    )]
    pub(crate) async fn hold_for_supervisor(&mut self) {
        poll_fn(|_| {
            let _retained = &self.records;
            Poll::<()>::Pending
        })
        .await;
    }

    /// cancel-safe: NO — retain and resume the Session until cleanup is observed.
    pub(crate) async fn finish(&mut self) -> Result<()> {
        if self.hook.is_some() || self.work.is_some() {
            self.fail("unfinished construction phase");
        }
        self.end_scope();
        self.collect_registrations().await;
        if let Some(owner) = &mut self.coordinator {
            match timeout_at(self.deadline, owner.settle()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => self.fail("owner intent terminal failure"),
                Err(_) => {
                    self.fail("owner intent cleanup deadline");
                    bail!("owner intent transaction remains retained");
                }
            }
        }
        if let Some(work) = self.work.as_mut() {
            match timeout_at(self.deadline, work.as_mut()).await {
                Ok(outcome) => {
                    self.work.take();
                    if outcome.is_err() {
                        self.fail("owner scenario panicked");
                    }
                }
                Err(_) => {
                    self.fail("construction scenario cleanup deadline");
                    bail!("construction scenario remains retained");
                }
            }
        }
        self.close_records(self.deadline).await;
        let terminals = !self.records.is_empty()
            && self.records.iter().all(|record| {
                record.closed
                    && record.finished
                    && record
                        .registration
                        .consumer
                        .terminal()
                        .is_some_and(|terminal| terminal.wire_receipt.is_some())
            });
        if terminals
            && self.client.state() == WireState::Ready
            && finish_stream(&mut self.client, self.deadline)
                .await
                .is_err()
        {
            self.fail("construction stream finish failed");
        }
        if self.failure.is_some() || !terminals || self.client.state() != WireState::Finished {
            bail!("construction evidence session incomplete");
        }
        Ok(())
    }
}

fn poll_ready(
    records: &mut [Record],
    cx: &mut Context<'_>,
) -> Poll<(usize, Result<(), super::construction_consumer::Error>)> {
    for (index, record) in records.iter_mut().enumerate() {
        if record.enabled {
            if record.registration.consumer.has_pending() {
                return Poll::Ready((index, Ok(())));
            }
            if let Poll::Ready(result) = record.registration.consumer.poll_receive(cx) {
                return Poll::Ready((index, result));
            }
        }
    }
    // The registration receiver, scenario, and timer share this driver's waker.
    Poll::Pending
}

#[cfg(test)]
mod tests {
    include!("tests/construction_driver_tests.rs");
}
