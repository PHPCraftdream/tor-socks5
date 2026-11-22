//! Bridge groups: the services that name a `bridge_group` are hosted by a Tor
//! client of their own, limited to the group's bridges, instead of the
//! process-wide client that carries every bridge.
//!
//! A group's client keeps its guard state and its onion keystore under
//! `<arti base>/group-<name>/` and reads the process client's directory cache,
//! so it starts without downloading the consensus again. Its bridges are
//! claimed from the process client's working list, under one lock hold so two
//! groups never take the same free bridge: a bridge the process drops is
//! replaced before the next bootstrap attempt and on every maintenance tick,
//! and a client that stops hosting the group's services is re-created. Both
//! repairs stay inside the group: nothing here writes the process client's
//! bridge file, bridge store or slots.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use arti_wrapper::{Settings, TorTunnel};
use bridge_line::BridgeLine;
use proxy_config::{OnionServiceEntry, WatchdogConfig};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tor_socks5_onion::host::{
    OnionHost, OnionHostConfig, OnionHostStatus, ServiceFailure, ServiceStatus,
};
use tor_socks5_runtime::tor_watchdog::TorHandle;
use tracing::{error, info, warn, Instrument};

#[path = "groups_claim.rs"]
mod claim;

use claim::Claim;
pub(crate) use claim::{log_claimed, log_replaced, warn_shortage, GroupBridges};

/// Most bridges a group puts circuits on at once; the rest stand by.
const MAX_PRIMARY_GUARDS: u8 = 3;

/// One group: its bridge count and the services it hosts.
#[derive(Debug)]
pub(crate) struct GroupPlan {
    pub(crate) bridges: u8,
    pub(crate) entries: Vec<OnionServiceEntry>,
}

/// The enabled services split by the client that hosts them.
#[derive(Debug, Default)]
pub(crate) struct Split {
    /// Services of the process-wide client.
    pub(crate) shared: Vec<OnionServiceEntry>,
    /// Services of each group, by group name.
    pub(crate) groups: BTreeMap<String, GroupPlan>,
}

/// Split the entries by `bridge_group`. The services file already guarantees
/// that the enabled services of a group agree on `bridges`.
pub(crate) fn split_entries(entries: Vec<OnionServiceEntry>) -> Split {
    let mut split = Split::default();
    for entry in entries {
        let Some((name, bridges)) = entry
            .bridge_group_spec()
            .map(|(name, bridges)| (name.to_owned(), bridges))
        else {
            split.shared.push(entry);
            continue;
        };
        split
            .groups
            .entry(name)
            .or_insert_with(|| GroupPlan {
                bridges,
                entries: Vec::new(),
            })
            .entries
            .push(entry);
    }
    split
}

/// The bridges of one group.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Assigned {
    pub(crate) bridges: Vec<BridgeLine>,
    /// Some of them also serve another group: the pool ran out.
    pub(crate) overlaps: bool,
    /// Fewer bridges than the group asked for: the pool is smaller.
    pub(crate) short: bool,
}

/// Give every group its own slice of the pool, in group-name order over the
/// pool sorted by bridge line, so the same pool gives the same groups the
/// same bridges at every start. When the pool is used up the slices wrap
/// around and overlap; `Assigned::overlaps` says so.
pub(crate) fn assign_bridges(
    pool: &[BridgeLine],
    groups: &BTreeMap<String, GroupPlan>,
) -> BTreeMap<String, Assigned> {
    let mut sorted: Vec<(String, &BridgeLine)> =
        pool.iter().map(|line| (line.to_string(), line)).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted.dedup_by(|a, b| a.0 == b.0);
    let len = sorted.len();
    let mut cursor = 0usize;
    let mut assigned = BTreeMap::new();
    for (name, plan) in groups {
        let wanted = usize::from(plan.bridges);
        let take = wanted.min(len);
        let bridges = (cursor..cursor + take)
            .map(|position| sorted[position % len].1.clone())
            .collect();
        assigned.insert(
            name.clone(),
            Assigned {
                bridges,
                overlaps: cursor + take > len,
                short: wanted > len,
            },
        );
        cursor += take;
    }
    assigned
}

/// The directory of a group under the arti base directory. The `group-`
/// prefix keeps a group name from ever being a reserved file name.
fn group_dir(base: &Path, group: &str) -> PathBuf {
    base.join(format!("group-{group}"))
}

/// The onion keystore of a group's client: arti pins it under its state dir,
/// the way the host expects it for the client's base directory.
fn group_keystore_dir(group_base: &Path) -> PathBuf {
    group_base.join("state").join("keystore")
}

/// Circuits spread over up to [`MAX_PRIMARY_GUARDS`] bridges, so one failing
/// bridge takes only part of the group's circuits with it.
fn guard_spread(count: usize) -> u8 {
    u8::try_from(count)
        .unwrap_or(u8::MAX)
        .clamp(1, MAX_PRIMARY_GUARDS)
}

/// The settings of a group's client: the process client's, with the group's
/// bridges and its own state. The directory cache stays the process client's.
fn group_settings(
    main: &Settings,
    group: &str,
    bridges: Vec<BridgeLine>,
) -> anyhow::Result<(Settings, PathBuf)> {
    if bridges.is_empty() {
        // A client without bridges would reach Tor directly.
        bail!("the group has no bridges");
    }
    if main.pre_endpoint.is_some() {
        bail!("bridge groups need bridges, but the process reaches Tor through a pre-proxy");
    }
    let base = main
        .state_dir
        .as_deref()
        .context("bridge groups need the arti state directory")?;
    let mut settings = main.clone();
    settings.cache_dir = Some(main.cache_dir.clone().unwrap_or_else(|| base.join("cache")));
    let group_base = group_dir(base, group);
    let keystore_dir = group_keystore_dir(&group_base);
    settings.state_dir = Some(group_base);
    settings.guard_spread = guard_spread(bridges.len());
    settings.bridges = bridges;
    Ok((settings, keystore_dir))
}

/// Deadline of one bootstrap attempt. A dead bridge can leave the group's
/// client making no progress at all, so a stuck attempt is cut and retried
/// instead of waited on until the process ends.
const BOOTSTRAP_ATTEMPT_LIMIT: Duration = Duration::from_secs(120);

/// Pause after the first failed attempt; it doubles for every next failure.
const BOOTSTRAP_FIRST_DELAY: Duration = Duration::from_secs(5);

/// Ceiling of that pause: a group whose bridges stay dead keeps retrying at
/// this cadence instead of growing the gap further.
const BOOTSTRAP_MAX_DELAY: Duration = Duration::from_secs(300);

/// Pause after the `failures`-th failed attempt: [`BOOTSTRAP_FIRST_DELAY`]
/// doubled once per failure, never above [`BOOTSTRAP_MAX_DELAY`].
fn retry_delay(failures: u32) -> Duration {
    // The shift is capped, so the doubling cannot overflow.
    let factor = 1u32 << failures.saturating_sub(1).min(16);
    BOOTSTRAP_FIRST_DELAY
        .saturating_mul(factor)
        .min(BOOTSTRAP_MAX_DELAY)
}

/// Run `attempt` until it succeeds or `token` is cancelled, and return what it
/// produced (`None` on cancellation). A failed attempt, and one that misses
/// [`BOOTSTRAP_ATTEMPT_LIMIT`], is logged and followed by a [`retry_delay`]
/// pause, so the services of a group wait for a working client instead of
/// staying unhosted until a restart. Both the attempt and the pause are cut by
/// `token`. The attempt is injected, so the loop is testable without Tor.
async fn bootstrap_until_ready<F, Fut, T, E>(mut attempt: F, token: &CancellationToken) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Into<anyhow::Error>,
{
    let mut failures = 0u32;
    loop {
        let outcome = tokio::select! {
            biased;
            () = token.cancelled() => return None,
            result = tokio::time::timeout(BOOTSTRAP_ATTEMPT_LIMIT, attempt()) => result,
        };
        let error = match outcome {
            Ok(Ok(value)) => return Some(value),
            Ok(Err(error)) => error.into(),
            Err(_elapsed) => anyhow!(
                "the attempt did not finish in {}s",
                BOOTSTRAP_ATTEMPT_LIMIT.as_secs()
            ),
        };
        failures += 1;
        let delay = retry_delay(failures);
        // `{error:#}` keeps the whole chain: the outer error says little.
        warn!(
            attempt = failures,
            retry_in = ?delay,
            error = %format!("{error:#}"),
            "bridge group did not bootstrap; its services stay unhosted until a retry works"
        );
        tokio::select! {
            biased;
            () = token.cancelled() => return None,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// How long a group whose client never got a service reachable may run before
/// that client counts as stuck: publishing descriptors normally takes well
/// under this.
const GROUP_START_WINDOW: Duration = Duration::from_secs(600);

/// Ceiling of that window for a group that keeps failing to get reachable: a
/// hopeless group is cycled at this cadence instead of faster.
const GROUP_START_WINDOW_MAX: Duration = Duration::from_secs(1800);

/// How many further clients a group whose host failed every service is given
/// before it is left stopped: an all-`Failed` host is usually a spent
/// address-wait budget, which a new client can still fix, but it can also be a
/// keystore or identity problem no new client can.
const MAX_FAILED_RESTARTS: u32 = 2;

/// How long the host of a finished generation gets to release the keystore
/// lock before it is aborted.
const HOST_STOP_LIMIT: Duration = Duration::from_secs(30);

/// How long the bridge watcher of a finished generation gets to notice the
/// cancelled token before it is aborted.
const WATCH_STOP_LIMIT: Duration = Duration::from_secs(5);

/// The window a client that has never been reachable may run before it is
/// re-created: it doubles per restart up to [`GROUP_START_WINDOW_MAX`].
pub(crate) fn start_window(restarts: u32) -> Duration {
    let factor = 1u32 << restarts.min(16);
    GROUP_START_WINDOW
        .saturating_mul(factor)
        .min(GROUP_START_WINDOW_MAX)
}

/// What the host's services say about one group client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupHealth {
    /// At least one service reports itself reachable: the client works.
    Reachable,
    /// Services are still starting or failing to recover: no verdict yet.
    Starting,
    /// Every service failed for a reason a new client could fix, such as a
    /// spent address-wait budget (see [`MAX_FAILED_RESTARTS`]).
    Retryable,
    /// Every service failed for a reason no new client can fix (keys,
    /// configuration, keystore) or simply stopped.
    Fatal,
}

impl GroupHealth {
    /// Whether this client hosts nothing at all any more.
    fn is_down(self) -> bool {
        matches!(self, GroupHealth::Retryable | GroupHealth::Fatal)
    }
}

/// Judge a host status snapshot over all of its services at once, so the
/// verdict cannot depend on the order of the names: one reachable service keeps
/// the group up whatever its neighbours do, a service that is neither reachable
/// nor done keeps the group starting, and only a group where every service is
/// done can be retryable or fatal.
pub(crate) fn group_health(status: &OnionHostStatus) -> GroupHealth {
    if status.services.is_empty() {
        return GroupHealth::Starting;
    }
    let mut every_failure_retryable = true;
    let mut pending = false;
    for state in status.services.values() {
        match state.status {
            ServiceStatus::Running | ServiceStatus::DegradedReachable => {
                return GroupHealth::Reachable
            }
            ServiceStatus::Failed => {
                if !matches!(
                    state.failure,
                    Some(ServiceFailure::AddressUnavailable { .. })
                ) {
                    every_failure_retryable = false;
                }
            }
            ServiceStatus::Stopped => every_failure_retryable = false,
            // Not done and not reachable yet: keep reading, a later service
            // may be reachable and then decides.
            _ => pending = true,
        }
    }
    if pending {
        GroupHealth::Starting
    } else if every_failure_retryable {
        GroupHealth::Retryable
    } else {
        GroupHealth::Fatal
    }
}

/// What to do with one group client, given its health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationVerdict {
    /// Keep hosting.
    Running,
    /// The client no longer hosts the group's services: re-create it.
    Restart,
    /// Nothing can be hosted and no further client is worth trying.
    Stop,
}

/// Judge one group client: `unhealthy_for` is how long it has been without a
/// reachable service, `window` the budget for that, and `retries_left` whether
/// the budget of clients for a retryable failure is not spent yet. A reachable
/// service resets the clock; a fatal failure stops at once, whatever the budget.
pub(crate) fn verdict(
    health: GroupHealth,
    unhealthy_for: Duration,
    window: Duration,
    retries_left: bool,
) -> GenerationVerdict {
    match health {
        GroupHealth::Fatal => GenerationVerdict::Stop,
        GroupHealth::Retryable if retries_left => GenerationVerdict::Restart,
        GroupHealth::Retryable => GenerationVerdict::Stop,
        GroupHealth::Reachable => GenerationVerdict::Running,
        GroupHealth::Starting if unhealthy_for >= window => GenerationVerdict::Restart,
        GroupHealth::Starting => GenerationVerdict::Running,
    }
}

/// The process client's `[watchdog]` section decides whether a group is
/// maintained at all: off for the process means off for groups too.
fn maintained(cfg: WatchdogConfig) -> bool {
    cfg.enabled && cfg.check_interval_secs > 0
}

/// One bootstrap attempt of a group: the settings the client was built with.
struct Prepared {
    settings: Settings,
    keystore_dir: PathBuf,
}

/// Prepare one attempt: claim the group's bridges from the process's `working`
/// list first, so an attempt is never retried on a bridge the process has
/// already dropped, then build the settings of a client for the claimed set.
/// `None` is maintenance off: the attempt runs on the bridges the group was
/// given at start.
fn prepare(
    main: &Settings,
    group: &str,
    bridges: &mut Vec<BridgeLine>,
    working: Option<&[BridgeLine]>,
    groups: &GroupBridges,
) -> anyhow::Result<Prepared> {
    if let Some(working) = working {
        let claim = groups.claim(group, bridges, working);
        warn_shortage(&claim);
        // No client exists yet, so this is a claim, not a replacement.
        log_claimed(&claim);
        *bridges = claim.bridges;
    }
    let (settings, keystore_dir) = group_settings(main, group, bridges.clone())?;
    Ok(Prepared {
        settings,
        keystore_dir,
    })
}

/// Bootstrap a group's client, claiming its bridges from `working` before every
/// attempt: a group that has not bootstrapped yet therefore still picks up a
/// bridge the process offers in the meantime instead of retrying a dead one.
/// `working` returning `None` is maintenance off: nothing is claimed. The
/// attempt is injected, so the loop is testable without Tor. A configuration
/// error is returned instead of retried: no number of attempts can fix it.
async fn bootstrap_group<T, W, B, Fut, E>(
    groups: &GroupBridges,
    name: &str,
    main: &Settings,
    bridges: &mut Vec<BridgeLine>,
    mut working: W,
    mut boot: B,
    token: &CancellationToken,
) -> anyhow::Result<Option<(T, Prepared)>>
where
    W: FnMut() -> Option<Vec<BridgeLine>>,
    B: FnMut(Settings) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Into<anyhow::Error>,
{
    // Validated once, with the settings the attempts will build: a group that
    // can never have a client fails here instead of retrying forever.
    group_settings(main, name, bridges.clone())?;
    let bootstrapped = bootstrap_until_ready(
        || {
            let attempt = match prepare(main, name, bridges, working().as_deref(), groups) {
                Ok(prepared) => Ok((boot(prepared.settings.clone()), prepared)),
                Err(error) => {
                    error!(
                        %error,
                        "bridge group cannot configure its client for the claimed bridges"
                    );
                    Err(error)
                }
            };
            async move {
                let (client, prepared) = attempt?;
                let client = client.await.map_err(Into::into)?;
                Ok::<(T, Prepared), anyhow::Error>((client, prepared))
            }
        },
        token,
    )
    .await;
    Ok(bootstrapped)
}

/// The bridges a bootstrap attempt may claim: the process client's working list
/// while the group is maintained, and nothing when it is not — a group with
/// maintenance off keeps the bridges it was assigned at start.
fn offered_bridges(
    maintenance: bool,
    mut working: impl FnMut() -> Vec<BridgeLine>,
) -> Option<Vec<BridgeLine>> {
    if maintenance {
        Some(working())
    } else {
        None
    }
}

/// One maintenance tick: reserve free bridges for the group and ask its client
/// to switch; `switch` is the client's reconfigure and says whether it took the
/// new set. The replacement is reported only after the client took it, and a
/// refused switch puts the reserved bridges back in the pool while the old ones
/// stay with the group.
fn apply_claim(
    name: &str,
    groups: &GroupBridges,
    current: &[BridgeLine],
    working: &[BridgeLine],
    switch: impl FnOnce(&[BridgeLine]) -> bool,
) -> Option<Claim> {
    let claim = groups.reserve_for(name, current, working);
    warn_shortage(&claim);
    if claim.taken.is_empty() {
        return None;
    }
    if switch(&claim.bridges) {
        groups.commit(name, &claim);
        log_replaced(&claim);
        Some(claim)
    } else {
        groups.rollback(name, current);
        None
    }
}

/// Keep the group on the bridges the process client still works with, for as
/// long as `token` runs. The swap reconfigures the group's own client only.
async fn watch_bridges(
    name: String,
    handle: TorHandle,
    pool: TorHandle,
    mut settings: Settings,
    groups: Arc<GroupBridges>,
    cfg: WatchdogConfig,
    token: CancellationToken,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.check_interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let Some(tor) = (tokio::select! {
            biased;
            () = token.cancelled() => return,
            tor = handle.tunnel() => tor,
        }) else {
            // The client of this generation is being drained.
            return;
        };
        let current = handle.active_bridges();
        // Selection and reservation under one lock, then the switch: the new
        // bridges are claimed before the client is asked to move, the old ones
        // stay claimed until it has actually moved.
        let applied = apply_claim(
            &name,
            &groups,
            &current,
            &pool.active_bridges(),
            |bridges| {
                let mut candidate = settings.clone();
                candidate.bridges = bridges.to_vec();
                candidate.guard_spread = guard_spread(bridges.len());
                match tor.reconfigure_bridges(&candidate) {
                    Ok(()) => {
                        settings = candidate;
                        true
                    }
                    Err(error) => {
                        warn!(
                            %error,
                            "bridge group could not apply its replacement bridges; the reserved \
                             ones go back to the pool"
                        );
                        false
                    }
                }
            },
        );
        if let Some(claim) = applied {
            handle.set_active_bridges(claim.bridges);
        }
    }
}

/// How one group client's run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerationEnd {
    /// The server's token was cancelled.
    Cancelled,
    /// The client stopped hosting the group's services: re-create it.
    Restart,
    /// Every service failed and the budget of clients for that is spent.
    Stop,
    /// Every service failed: one more client may still help.
    AllFailed,
}

/// Watch one group client until its run ends. A client with a reachable
/// service is left alone; one without any for `reachable` (it had one) or
/// `start` (it never did) is re-created, which is the repair a group has in
/// place of the process client's stale-channel watchdog. `retries_left` says
/// whether a host that failed every service for a retryable reason may still be
/// tried with a new client. `token` belongs to the client of this run.
async fn supervise(
    status: &mut watch::Receiver<OnionHostStatus>,
    token: &CancellationToken,
    start: Duration,
    reachable: Duration,
    retries_left: bool,
) -> GenerationEnd {
    let mut since = tokio::time::Instant::now();
    let mut was_reachable = false;
    let mut previous = GroupHealth::Starting;
    loop {
        let health = group_health(&status.borrow_and_update());
        let now = tokio::time::Instant::now();
        if health == GroupHealth::Reachable {
            was_reachable = true;
        }
        // A group that has just stopped being reachable starts its clock
        // here; while its health keeps one class the clock keeps running.
        if health != previous {
            since = now;
        }
        previous = health;
        let window = if was_reachable { reachable } else { start };
        match verdict(health, now.duration_since(since), window, retries_left) {
            GenerationVerdict::Running => {}
            GenerationVerdict::Restart if health == GroupHealth::Retryable => {
                return GenerationEnd::AllFailed
            }
            GenerationVerdict::Restart => return GenerationEnd::Restart,
            GenerationVerdict::Stop => return GenerationEnd::Stop,
        }
        if health == GroupHealth::Reachable {
            // Nothing to time out while the group is reachable.
            tokio::select! {
                biased;
                () = token.cancelled() => return GenerationEnd::Cancelled,
                changed = status.changed() => {
                    if changed.is_err() {
                        return GenerationEnd::Stop;
                    }
                }
            }
            continue;
        }
        tokio::select! {
            biased;
            () = token.cancelled() => return GenerationEnd::Cancelled,
            changed = status.changed() => {
                if changed.is_err() {
                    return GenerationEnd::Stop;
                }
            }
            () = tokio::time::sleep_until(since + window) => {}
        }
    }
}

/// Wait until the host stops hosting while the watchdog is off. `true` when
/// the token cancelled the wait instead.
async fn wait_for_stop(
    status: &mut watch::Receiver<OnionHostStatus>,
    token: &CancellationToken,
) -> bool {
    loop {
        if group_health(&status.borrow_and_update()).is_down() {
            return false;
        }
        tokio::select! {
            biased;
            () = token.cancelled() => return true,
            changed = status.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
        }
    }
}

/// A maintenance task of one generation. Dropping it aborts the task, so
/// nothing of a finished generation outlives the group task that owns it.
struct GroupTask(JoinHandle<()>);

impl GroupTask {
    fn new(task: JoinHandle<()>) -> Self {
        Self(task)
    }

    /// Wait for the task to finish, abort it if it will not, and then keep
    /// waiting: an abort does not land while the task sits in a blocking call,
    /// and the next generation must not start while a task of this one can still
    /// change the registry.
    async fn stop(mut self, limit: Duration, what: &str) {
        if tokio::time::timeout(limit, &mut self.0).await.is_ok() {
            return;
        }
        warn!(
            limit_s = limit.as_secs(),
            "bridge group {what} did not stop in time; aborting it"
        );
        self.0.abort();
        while tokio::time::timeout(limit, &mut self.0).await.is_err() {
            warn!(
                "bridge group {what} is still running after an abort; waiting for it to \
                 finish before the client is released"
            );
        }
    }
}

impl Drop for GroupTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Stop every task of one generation and only then run `release`. The order is
/// the point: a task of the finished generation must not change the registry
/// after the bridges of the next one have been read. Split so that order is
/// testable without Tor.
async fn stop_before_release(
    generation: &CancellationToken,
    watcher: Option<GroupTask>,
    producer: GroupTask,
    release: impl Future<Output = ()>,
) {
    generation.cancel();
    if let Some(watcher) = watcher {
        watcher.stop(WATCH_STOP_LIMIT, "bridge watcher").await;
    }
    producer.stop(HOST_STOP_LIMIT, "host").await;
    release.await;
}

/// End one client's run and return the bridges the group holds afterwards: the
/// tasks of the generation are done first, the client is released second, and
/// the registry is read last, so a finished task cannot change it behind the
/// next generation's back. Split so that order is testable without Tor.
async fn close_generation(
    generation: &CancellationToken,
    watcher: Option<GroupTask>,
    producer: GroupTask,
    release: impl Future<Output = ()>,
    groups: &GroupBridges,
    name: &str,
) -> Option<Vec<BridgeLine>> {
    stop_before_release(generation, watcher, producer, release).await;
    groups.bridges_of(name)
}

/// Everything one group needs to run until the server's token is cancelled.
pub(crate) struct GroupRun {
    pub(crate) name: String,
    pub(crate) plan: GroupPlan,
    pub(crate) assigned: Assigned,
    /// The process client's settings: a group starts from them.
    pub(crate) main: Settings,
    /// The process client, whose working bridge list seeds the claims.
    pub(crate) pool: TorHandle,
    /// The bridges of every group, so a replacement never takes another
    /// group's.
    pub(crate) groups: Arc<GroupBridges>,
    /// The process client's `[watchdog]` section: a group follows it.
    pub(crate) watchdog: WatchdogConfig,
    pub(crate) config_path: PathBuf,
    pub(crate) token: CancellationToken,
}

/// Host the services of one group on a Tor client of its own, until the
/// server's token is cancelled. Failures are logged and end only this group.
/// Every bootstrap attempt claims the group's bridges from the process client's
/// working list, and a client that stops hosting the group's services is
/// re-created on the bridges the group holds at that moment.
pub(crate) async fn run_group(run: GroupRun) {
    let GroupRun {
        name,
        plan,
        assigned,
        main,
        pool,
        groups,
        watchdog,
        config_path,
        token,
    } = run;
    let span = tracing::info_span!("bridge_group", group = %name);
    let task_span = span.clone();
    async move {
        if assigned.short {
            warn!(
                wanted = plan.bridges,
                got = assigned.bridges.len(),
                "the bridge pool is smaller than the group asks for"
            );
        }
        if assigned.overlaps {
            warn!(
                "the bridge pool is used up: some bridges of this group also serve another \
                 group, so one failing bridge can take down both"
            );
        }
        let maintenance = maintained(watchdog);
        if !maintenance {
            info!("bridge group maintenance is off: the process client's watchdog is disabled");
        }
        let mut bridges = assigned.bridges;
        let mut restarts = 0u32;
        let mut failed_restarts = 0u32;
        loop {
            info!(
                bridges = bridges.len(),
                services = plan.entries.len(),
                restart = restarts,
                failed_restart = failed_restarts,
                "starting a bridge group: bootstrapping its own Tor client"
            );
            let offered = {
                let pool = pool.clone();
                move || offered_bridges(maintenance, || pool.active_bridges())
            };
            let bootstrapped = match bootstrap_group(
                &groups,
                &name,
                &main,
                &mut bridges,
                offered,
                TorTunnel::bootstrap_with,
                &token,
            )
            .await
            {
                Ok(bootstrapped) => bootstrapped,
                Err(error) => {
                    error!(%error, "bridge group not started: its services are not hosted");
                    groups.release(&name);
                    return;
                }
            };
            let Some((tunnel, prepared)) = bootstrapped else {
                info!("bridge group stopped before its Tor client bootstrapped");
                groups.release(&name);
                return;
            };
            let handle = TorHandle::new_with_settings(tunnel, &prepared.settings);
            // The host of this run stops with the server's token as well.
            let generation = token.child_token();
            let host_config =
                OnionHostConfig::new(handle.clone(), prepared.keystore_dir, generation.clone())
                    .with_entries(plan.entries.clone())
                    .with_config_path(Some(config_path.clone()));
            let host = OnionHost::new(host_config).start();
            let mut status = host.subscribe();
            let producer = GroupTask::new(host.detach());
            let watcher = if maintenance {
                Some(GroupTask::new(tokio::spawn(
                    watch_bridges(
                        name.clone(),
                        handle.clone(),
                        pool.clone(),
                        prepared.settings.clone(),
                        Arc::clone(&groups),
                        watchdog,
                        generation.clone(),
                    )
                    .instrument(span.clone()),
                )))
            } else {
                None
            };
            let end = if maintenance {
                supervise(
                    &mut status,
                    &generation,
                    start_window(restarts),
                    Duration::from_secs(watchdog.stale_after_secs),
                    failed_restarts < MAX_FAILED_RESTARTS,
                )
                .await
            } else if wait_for_stop(&mut status, &generation).await {
                GenerationEnd::Cancelled
            } else {
                GenerationEnd::Stop
            };
            // Every task of this generation stops before the client is released,
            // and the bridges of the next generation are read after both.
            let next = close_generation(
                &generation,
                watcher,
                producer,
                async move {
                    // Release the client so its pluggable-transport children close.
                    drop(handle.drain().await);
                },
                &groups,
                &name,
            )
            .await;
            if let Some(next) = next.filter(|next| !next.is_empty()) {
                bridges = next;
            }
            match end {
                GenerationEnd::Cancelled => {
                    info!("bridge group stopped");
                    groups.release(&name);
                    return;
                }
                GenerationEnd::Stop => {
                    warn!(
                        "bridge group can host no service and no further client is worth \
                         trying; stopping the group"
                    );
                    groups.release(&name);
                    return;
                }
                GenerationEnd::Restart => {
                    restarts = restarts.saturating_add(1);
                    warn!(
                        restart = restarts,
                        next_start_window = ?start_window(restarts),
                        "bridge group lost every reachable service; re-creating its Tor client"
                    );
                }
                GenerationEnd::AllFailed => {
                    failed_restarts = failed_restarts.saturating_add(1);
                    warn!(
                        failed_restart = failed_restarts,
                        limit = MAX_FAILED_RESTARTS,
                        "every service of the bridge group failed; trying a new client \
                         before giving up"
                    );
                }
            }
        }
    }
    .instrument(task_span)
    .await;
}

#[cfg(test)]
#[path = "groups_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "groups_watchdog_tests.rs"]
mod watchdog_tests;
