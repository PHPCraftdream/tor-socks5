//! `BridgeDescMgr` - downloads and caches bridges' router descriptors

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt::{self, Debug, Display};
use std::num::NonZeroU8;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use async_trait::async_trait;
use derive_more::{Deref, DerefMut};
use educe::Educe;
use futures::FutureExt;
use futures::future;
use futures::select;
use futures::stream::{BoxStream, StreamExt};
use futures::task::SpawnError;
use tracing::{debug, info, trace};

use safelog::sensitive;
use tor_basic_utils::retry::RetryDelay;
use tor_checkable::{SelfSigned, Timebound};
use tor_circmgr::CircMgr;
use tor_error::{AbsRetryTime, HasRetryTime, RetryTime};
use tor_error::{ErrorKind, HasKind, error_report, internal};
use tor_guardmgr::bridge::{BridgeConfig, BridgeDesc};
use tor_guardmgr::bridge::{BridgeDescError, BridgeDescEvent, BridgeDescList, BridgeDescProvider};
use tor_netdoc::doc::routerdesc::RouterDesc;
use tor_rtcompat::{Runtime, SpawnExt as _};
use web_time_compat::{Duration, Instant, SystemTime};

use crate::event::FlagPublisher;
use crate::storage::CachedBridgeDescriptor;
use crate::{DirMgrStore, DynStore};

#[cfg(test)]
mod bdtest;

/// The key we use in all our data structures
///
/// This type saves typing and would make it easier to change the bridge descriptor manager
/// to take and handle another way of identifying the bridges it is working with.
type BridgeKey = BridgeConfig;

/// Active vs dormant state, as far as the bridge descriptor manager is concerned
///
/// This is usually derived in higher layers from `arti_client::DormantMode`,
/// whether `TorClient::bootstrap()` has been called, etc.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
// TODO: These proliferating `Dormancy` enums should be centralized and unified with `TaskHandle`
//     https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/845#note_2853190
pub enum Dormancy {
    /// Dormant (inactive)
    ///
    /// Bridge descriptor downloads, or refreshes, will not be started.
    ///
    /// In-progress downloads will be stopped if possible,
    /// but they may continue until they complete (or fail).
    // TODO async task cancellation: actually cancel these in this case
    ///
    /// So a dormant BridgeDescMgr may still continue to
    /// change the return value from [`bridges()`](BridgeDescProvider::bridges)
    /// and continue to report [`BridgeDescEvent`]s.
    ///
    /// When the BridgeDescMgr is dormant,
    /// `bridges()` may return stale descriptors
    /// (that is, descriptors which ought to have been refetched and may no longer be valid),
    /// or stale errors
    /// (that is, errors which occurred some time ago,
    /// and which would normally have been retried by now).
    Dormant,

    /// Active
    ///
    /// Bridge descriptors will be downloaded as requested.
    ///
    /// When a bridge descriptor manager has been `Dormant`,
    /// it may continue to provide stale data (as described)
    /// for a while after it is made `Active`,
    /// until the required refreshes and retries have taken place (or failed).
    Active,
}

/// **Downloader and cache for bridges' router descriptors**
///
/// This is a handle which is cheap to clone and has internal mutability.
#[derive(Clone)]
pub struct BridgeDescMgr<R: Runtime, M = ()>
where
    M: Mockable<R>,
{
    /// The actual manager
    ///
    /// We have the `Arc` in here, rather than in our callers, because this
    /// makes the API nicer for them, and also because some of our tasks
    /// want a handle they can use to relock and modify the state.
    mgr: Arc<Manager<R, M>>,
}

/// Configuration for the `BridgeDescMgr`
///
/// Currently, the only way to make this is via its `Default` impl.
// TODO: there should be some way to override the defaults.  See #629 for considerations.
#[derive(Debug, Clone)]
pub struct BridgeDescDownloadConfig {
    /// How many bridge descriptor downloads to attempt in parallel?
    parallelism: NonZeroU8,

    /// Default/initial time to retry a failure to download a descriptor
    ///
    /// (This has the semantics of an initial delay for [`RetryDelay`],
    /// and is used unless there is more specific retry information for the particular failure.)
    retry: Duration,

    /// When a downloaded descriptor is going to expire, how soon in advance to refetch it?
    prefetch: Duration,

    /// Minimum interval between successive refetches of the descriptor for the same bridge
    ///
    /// This limits the download activity which can be caused by an errant bridge.
    ///
    /// If the descriptor's validity information is shorter than this, we will use
    /// it after it has expired (rather than treating the bridge as broken).
    min_refetch: Duration,

    /// Maximum interval between successive refetches of the descriptor for the same bridge
    ///
    /// This sets an upper bound on how old a descriptor we are willing to use.
    /// When this time expires, a refetch attempt will be started even if the
    /// descriptor is not going to expire soon.
    //
    // TODO: When this is configurable, we need to make sure we reject
    // configurations with max_refresh < min_refresh, or we may panic.
    max_refetch: Duration,
}

impl Default for BridgeDescDownloadConfig {
    fn default() -> Self {
        let secs = Duration::from_secs;
        BridgeDescDownloadConfig {
            // tor-socks5 local patch: fetch all configured bridges' descriptors
            // concurrently. These are cheap one-hop fetches; letting them race
            // means a reachable bridge gets its descriptor (→ becomes a usable
            // Data guard) without waiting behind dead/slow bridges in the pool.
            // (Bulk consensus/microdesc downloads are kept gentle separately,
            // via the client's download_schedule, to avoid flooding bridges.)
            parallelism: 12.try_into().expect("parallelism is zero"),
            // The upstream 30s initial retry is too slow to recover a one-hop
            // fetch that failed on a transient reset, leaving a bridge
            // "unsuitable to purpose" (dir_info_missing) for a long time; a 5s
            // base retry is far more responsive.
            retry: secs(5),
            prefetch: secs(1000),
            min_refetch: secs(3600),
            max_refetch: secs(3600 * 3), // matches C Tor behaviour
        }
    }
}

/// Mockable internal methods for within the `BridgeDescMgr`
///
/// Implemented for `()`, meaning "do not use mocks: use the real versions of everything".
///
/// This (`()`) is the default for the type parameter in
/// [`BridgeDescMgr`],
/// and it is the only publicly available implementation,
/// since this trait is sealed.
pub trait Mockable<R>: mockable::MockableAPI<R> {}
impl<R: Runtime> Mockable<R> for () {}

/// Private module which seals [`Mockable`]
/// by containing [`MockableAPI`](mockable::MockableAPI)
mod mockable {
    use super::*;

    /// Defines the actual mockable APIs
    ///
    /// Not nameable (and therefore not implementable)
    /// outside the `bridgedesc` module,
    #[async_trait]
    pub trait MockableAPI<R>: Clone + Send + Sync + 'static {
        /// Circuit manager
        type CircMgr: Send + Sync + 'static;

        /// Download this bridge's descriptor, and return it as a string
        ///
        /// Runs in a task.
        /// Called by `Manager::download_descriptor`, which handles parsing and validation.
        ///
        /// If `if_modified_since` is `Some`,
        /// should tolerate an HTTP 304 Not Modified and return `None` in that case.
        /// If `if_modified_since` is `None`, returning `Ok(None,)` is forbidden.
        async fn download(
            self,
            runtime: &R,
            circmgr: &Self::CircMgr,
            bridge: &BridgeConfig,
            if_modified_since: Option<SystemTime>,
        ) -> Result<Option<String>, Error>;
    }
}
#[async_trait]
impl<R: Runtime> mockable::MockableAPI<R> for () {
    type CircMgr = Arc<CircMgr<R>>;

    /// Actual code for downloading a descriptor document
    async fn download(
        self,
        runtime: &R,
        circmgr: &Self::CircMgr,
        bridge: &BridgeConfig,
        _if_modified_since: Option<SystemTime>,
    ) -> Result<Option<String>, Error> {
        use tor_rtcompat::SleepProviderExt as _;
        // tor-socks5 local patch: bound the whole bridge-descriptor fetch with
        // a hard timeout. Upstream wraps NO timeout around
        // get_or_launch_dir_specific + begin_dir_stream + send_request, so a
        // slow/unresponsive bridge makes this hang indefinitely (observed: a
        // queued fetch with neither success nor failure for minutes). While it
        // hangs the bridge never acquires its descriptor, stays
        // `dir_info_missing` → "unsuitable to purpose", and NO Data circuit can
        // be built — the proxy bootstraps the directory but can't carry
        // traffic. With a timeout the attempt fails cleanly, the guard is
        // marked down, and another bridge from the pool is promoted/retried.
        let fetch = async {
            // TODO actually support _if_modified_since
            let tunnel = circmgr.get_or_launch_dir_specific(bridge).await?;
            let mut stream = tunnel
                .begin_dir_stream()
                .await
                .map_err(Error::StreamFailed)?;
            let request = tor_dirclient::request::RoutersOwnDescRequest::new();
            let response = tor_dirclient::send_request(runtime, &request, &mut stream, None)
                .await
                .map_err(|dce| match dce {
                    tor_dirclient::Error::RequestFailed(re) => Error::RequestFailed(re),
                    _ => internal!(
                        "tor_dirclient::send_request gave non-RequestFailed {:?}",
                        dce
                    )
                    .into(),
                })?;
            let output = response.into_output_string()?;
            Ok::<Option<String>, Error>(Some(output))
        };
        // Bound each attempt: get_or_launch_dir_specific can hang while an
        // obfs4 channel keeps resetting (os 10054/10053).  The bound must still
        // cover a cold channel establishment; the previous 10s value expired
        // after SOCKS/TLS had succeeded but before the descriptor response.
        // Obfs4 channels commonly need more than ten seconds on a cold start
        // (the TCP/SOCKS/TLS sequence itself can consume that budget).  Ten
        // seconds made every otherwise-working bridge look broken immediately
        // after the binary update.  Keep a finite bound so a dead bridge cannot
        // block the descriptor queue forever, but give a real channel enough
        // time to return its descriptor.
        match runtime.timeout(Duration::from_secs(30), fetch).await {
            Ok(r) => r,
            Err(_) => Err(Error::RequestFailed(
                tor_dirclient::RequestFailedError {
                    source: None,
                    error: tor_dirclient::RequestError::DirTimeout,
                },
            )),
        }
    }
}

/// The actual manager.
struct Manager<R: Runtime, M: Mockable<R>> {
    /// The mutable state
    state: Mutex<State>,

    /// Runtime, used for tasks and sleeping
    runtime: R,

    /// Circuit manager, used for creating circuits
    circmgr: M::CircMgr,

    /// Persistent state store
    store: Arc<Mutex<DynStore>>,

    /// Mock for testing, usually `()`
    mockable: M,
}

/// State: our downloaded descriptors (cache), and records of what we're doing
///
/// Various functions (both tasks and public entrypoints),
/// which generally start with a `Manager`,
/// lock the mutex and modify this.
///
/// Generally, the flow is:
///
///  * A public entrypoint, or task, obtains a [`StateGuard`].
///    It modifies the state to represent the callers' new requirements,
///    or things it has done, by updating the state,
///    preserving the invariants but disturbing the "liveness" (see below).
///
///  * [`StateGuard::drop`] calls [`State::process`].
///    This restores the liveness properties.
///
/// ### Possible states of a bridge:
///
/// A bridge can be in one of the following states,
/// represented by its presence in these particular data structures inside `State`:
///
///  * `running`/`queued`: newly added, no outcome yet.
///  * `current` + `running`/`queued`: we are fetching (or going to)
///  * `current = OK` + `refetch_schedule`: fetched OK, will refetch before expiry
///  * `current = Err` + `retry_schedule`: failed, will retry at some point
///
/// ### Invariants:
///
/// Can be disrupted in the middle of a principal function,
/// but should be restored on return.
///
/// * **Tracked**:
///   Each bridge appears at most once in
///   `running`, `queued`, `refetch_schedule` and `retry_schedule`.
///   We call such a bridge Tracked.
///
/// * **Current**
///   Every bridge in `current` is Tracked.
///   (But not every Tracked bridge is necessarily in `current`, yet.)
///
/// * **Schedules**
///   Every bridge in `refetch_schedule` or `retry_schedule` is also in `current`.
///
/// * **Input**:
///   Exactly each bridge that was passed to
///   the last call to [`set_bridges()`](BridgeDescMgr::set_bridges) is Tracked.
///   (If we encountered spawn failures, we treat this as trying to shut down,
///   so we cease attempts to get bridges, and discard the relevant state, violating this.)
///
/// * **Limit**:
///   `running` is capped at the effective parallelism: zero if we are dormant,
///   the configured parallelism otherwise.
///
/// ### Liveness properties:
///
/// These can be disrupted by any function which holds a [`StateGuard`].
/// Will be restored by [`process()`](State::process),
/// which is called when `StateGuard` is dropped.
///
/// Functions that take a `StateGuard` may disturb these invariants
/// and rely on someone else to restore them.
///
/// * **Running**:
///   If `queued` is nonempty, `running` is full.
///
/// * **Timeout**:
///   `earliest_timeout` is the earliest timeout in
///   either `retry_schedule` or `refetch_schedule`.
///   (Disturbances of this property which occur due to system time warps
///   are not necessarily detected and remedied in a timely way,
///   but will be remedied no later than after `max_refetch`.)
struct State {
    /// Our configuration
    config: Arc<BridgeDescDownloadConfig>,

    /// People who will be told when `current` changes.
    subscribers: FlagPublisher<BridgeDescEvent>,

    /// Our current idea of our output, which we give out handles onto.
    current: Arc<BridgeDescList>,

    /// Bridges whose descriptors we are currently downloading.
    running: HashMap<BridgeKey, RunningInfo>,

    /// Bridges which we want to download,
    /// but we're waiting for `running` to be less than `effective_parallelism()`.
    queued: VecDeque<QueuedEntry>,

    /// Are we dormant?
    dormancy: Dormancy,

    /// Bridges that we have a descriptor for,
    /// and when they should be refetched due to validity expiry.
    ///
    /// This is indexed by `SystemTime` because that helps avoids undesirable behaviors
    /// when the system clock changes.
    refetch_schedule: BinaryHeap<RefetchEntry<SystemTime, ()>>,

    /// Bridges that failed earlier, and when they should be retried.
    retry_schedule: BinaryHeap<RefetchEntry<Instant, RetryDelay>>,

    /// Earliest time from either `retry_schedule` or `refetch_schedule`
    ///
    /// `None` means "wait indefinitely".
    earliest_timeout: postage::watch::Sender<Option<Instant>>,
}

impl Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /// Helper to format one bridge entry somewhere
        fn fmt_bridge(
            f: &mut fmt::Formatter,
            b: &BridgeConfig,
            info: &(dyn Display + '_),
        ) -> fmt::Result {
            let info = info.to_string(); // fmt::Formatter doesn't enforce precision, so do this
            writeln!(f, "    {:80.80} | {}", info, b)
        }

        /// Helper to format one of the schedules
        fn fmt_schedule<TT: Ord + Copy + Debug, RD>(
            f: &mut fmt::Formatter,
            summary: &str,
            name: &str,
            schedule: &BinaryHeap<RefetchEntry<TT, RD>>,
        ) -> fmt::Result {
            writeln!(f, "  {}:", name)?;
            for b in schedule {
                fmt_bridge(f, &b.bridge, &format_args!("{} {:?}", summary, &b.when))?;
            }
            Ok(())
        }

        // We are going to have to go multi-line because of the bridge lines,
        // so do completely bespoke formatting rather than `std::fmt::DebugStruct`
        // or a derive.
        writeln!(f, "State {{")?;
        // We'd like to print earliest_timeout but watch::Sender::borrow takes &mut
        writeln!(f, "  earliest_timeout: ???, ..,")?;
        writeln!(f, "  current:")?;
        for (b, v) in &*self.current {
            fmt_bridge(
                f,
                b,
                &match v {
                    Err(e) => Cow::from(format!("C Err {}", e)),
                    Ok(_) => "C Ok".into(),
                },
            )?;
        }
        writeln!(f, "  running:")?;
        for b in self.running.keys() {
            fmt_bridge(f, b, &"R")?;
        }
        writeln!(f, "  queued:")?;
        for qe in &self.queued {
            fmt_bridge(f, &qe.bridge, &"Q")?;
        }
        fmt_schedule(f, "FS", "refetch_schedule", &self.refetch_schedule)?;
        fmt_schedule(f, "TS", "retry_schedule", &self.retry_schedule)?;
        write!(f, "}}")?;

        Ok(())
    }
}

/// Value of the entry in `running`
#[derive(Debug)]
struct RunningInfo {
    /// For cancelling downloads no longer wanted
    join: JoinHandle,

    /// If this previously failed, the persistent retry delay.
    retry_delay: Option<RetryDelay>,
}

/// Entry in `queued`
#[derive(Debug)]
struct QueuedEntry {
    /// The bridge to fetch
    bridge: BridgeKey,

    /// If this previously failed, the persistent retry delay.
    retry_delay: Option<RetryDelay>,
}

/// Entry in one of the `*_schedule`s
///
/// Implements `Ord` and `Eq` but *only looking at the refetch time*.
/// So don't deduplicate by `[Partial]Eq`, or use as a key in a map.
#[derive(Debug)]
struct RefetchEntry<TT, RD> {
    /// When should we requeued this bridge for fetching
    ///
    /// Either [`Instant`] (in `retry_schedule`) or [`SystemTime`] (in `refetch_schedule`).
    when: TT,

    /// The bridge to refetch
    bridge: BridgeKey,

    /// Retry delay
    ///
    /// `RetryDelay` if we previously failed (ie, if this is a retry entry);
    /// otherwise `()`.
    retry_delay: RD,
}

impl<TT: Ord, RD> Ord for RefetchEntry<TT, RD> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.when.cmp(&other.when).reverse()
        // We don't care about the ordering of BridgeConfig or retry_delay.
        // Different BridgeConfig with the same fetch time will be fetched in "some order".
    }
}

impl<TT: Ord, RD> PartialOrd for RefetchEntry<TT, RD> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<TT: Ord, RD> PartialEq for RefetchEntry<TT, RD> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<TT: Ord, RD> Eq for RefetchEntry<TT, RD> {}

/// Dummy task join handle
///
/// We would like to be able to cancel now-redundant downloads
/// using something like `tokio::task::JoinHandle::abort()`.
/// tor-rtcompat doesn't support that so we stub it for now.
///
/// Providing this stub means the place where the cancellation needs to take place
/// already has the appropriate call to our [`JoinHandle::abort`].
#[derive(Debug)]
struct JoinHandle;

impl JoinHandle {
    /// Would abort this async task, if we could do that.
    fn abort(&self) {}
}

impl<R: Runtime> BridgeDescMgr<R> {
    /// Create a new `BridgeDescMgr`
    ///
    /// This is the public constructor.
    //
    // TODO: That this constructor requires a DirMgr is rather odd.
    // In principle there is little reason why you need a DirMgr to make a BridgeDescMgr.
    // However, BridgeDescMgr needs a Store, and currently that is a private trait, and the
    // implementation is constructible only from the dirmgr's config.  This should probably be
    // tidied up somehow, at some point, perhaps by exposing `Store` and its configuration.
    pub fn new(
        config: &BridgeDescDownloadConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<tor_circmgr::CircMgr<R>>,
        dormancy: Dormancy,
    ) -> Result<Self, StartupError> {
        Self::new_internal(runtime, circmgr, store.store, config, dormancy, ())
    }
}

/// If download was successful, what we obtained
///
/// Generated by `process_document`, from a downloaded (or cached) textual descriptor.
#[derive(Debug)]
struct Downloaded {
    /// The bridge descriptor, fully parsed and verified
    desc: BridgeDesc,

    /// When we should start a refresh for this descriptor
    ///
    /// This is derived from the expiry time,
    /// and clamped according to limits in the configuration).
    refetch: SystemTime,
}

/// Bridge descriptor retrieval and scheduling.
mod manager;
/// Error which occurs during bridge descriptor manager startup
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartupError {
    /// No circuit manager in the directory manager
    #[error(
        "tried to create bridge descriptor manager from directory manager with no circuit manager"
    )]
    MissingCircMgr,

    /// Unable to spawn task
    //
    // TODO lots of our Errors have a variant exactly like this.
    // Maybe we should make a struct tor_error::SpawnError.
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use StartupError as SE;
        match self {
            SE::MissingCircMgr => EK::Internal,
            SE::Spawn { cause, .. } => cause.kind(),
        }
    }
}

/// An error which occurred trying to obtain the descriptor for a particular bridge
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Couldn't establish a circuit to the bridge
    #[error("Failed to establish circuit")]
    CircuitFailed(#[from] tor_circmgr::Error),

    /// Couldn't establish a directory stream to the bridge
    #[error("Failed to establish directory stream")]
    StreamFailed(#[source] tor_circmgr::Error),

    /// Directory request failed
    #[error("Directory request failed")]
    RequestFailed(#[from] tor_dirclient::RequestFailedError),

    /// Failed to parse descriptor in response
    #[error("Failed to parse descriptor in response")]
    ParseFailed(#[from] tor_netdoc::Error),

    /// Signature check failed
    #[error("Signature check failed")]
    SignatureCheckFailed(#[from] Arc<signature::Error>),

    /// Obtained descriptor but it is outside its validity time
    #[error("Descriptor is outside its validity time, as supplied")]
    BadValidityTime(#[from] tor_checkable::TimeValidityError),

    /// A bridge descriptor has very extreme validity times
    /// such that our refetch time calculations overflow.
    #[error("Descriptor validity time range is too extreme for us to cope with")]
    ExtremeValidityTime,

    /// There was a programming error somewhere in our code, or the calling code.
    #[error("Programming error")]
    Bug(#[from] tor_error::Bug),

    /// Error used for testing
    #[cfg(test)]
    #[error("Error for testing, {0:?}, retry at {1:?}")]
    TestError(&'static str, RetryTime),
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        let bridge_protocol_violation = EK::TorAccessFailed;
        match self {
            // We trust that tor_circmgr returns TorAccessFailed when it ought to.
            E::CircuitFailed(e) => e.kind(),
            E::StreamFailed(e) => e.kind(),
            E::RequestFailed(e) => e.kind(),
            E::ParseFailed(..) => bridge_protocol_violation,
            E::SignatureCheckFailed(..) => bridge_protocol_violation,
            E::ExtremeValidityTime => bridge_protocol_violation,
            E::BadValidityTime(..) => EK::ClockSkew,
            E::Bug(e) => e.kind(),
            #[cfg(test)]
            E::TestError(..) => EK::Internal,
        }
    }
}

impl HasRetryTime for Error {
    fn retry_time(&self) -> RetryTime {
        use Error as E;
        use RetryTime as R;
        match self {
            // Errors with their own retry times
            E::CircuitFailed(e) => e.retry_time(),

            // Remote misbehavior, maybe the network is being strange?
            E::StreamFailed(..) => R::AfterWaiting,
            E::RequestFailed(..) => R::AfterWaiting,

            // Remote misconfiguration, detected *after* we successfully made the channel
            // (so not a network problem).  We'll say "never" for RetryTime,
            // even though actually we will in fact retry in at most `max_refetch`.
            E::ParseFailed(..) => R::Never,
            E::SignatureCheckFailed(..) => R::Never,
            E::BadValidityTime(..) => R::Never,
            E::ExtremeValidityTime => R::Never,

            // Probably, things are broken here, rather than remotely.
            E::Bug(..) => R::Never,

            #[cfg(test)]
            E::TestError(_, retry) => *retry,
        }
    }
}

impl BridgeDescError for Error {}

impl State {
    /// Consistency check (for testing)
    ///
    /// `input` should be what was passed to `set_bridges` (or `None` if not known).
    ///
    /// Does not make any changes.
    /// Only takes `&mut` because postage::watch::Sender::borrow` wants it.
    #[cfg(test)]
    fn check_consistency<'i, R, I>(&mut self, runtime: &R, input: Option<I>)
    where
        R: Runtime,
        I: IntoIterator<Item = &'i BridgeKey>,
    {
        /// Where we found a thing was Tracked
        #[derive(Debug, Clone, Copy, Eq, PartialEq)]
        enum Where {
            /// Found in `running`
            Running,
            /// Found in `queued`
            Queued,
            /// Found in the schedule `sch`
            Schedule {
                sch_name: &'static str,
                /// Starts out as `false`, set to `true` when we find this in `current`
                found_in_current: bool,
            },
        }

        /// Records the expected input from `input`, and what we have found so far
        struct Tracked {
            /// Were we told what the last `set_bridges` call got as input?
            known_input: bool,
            /// `Some` means we have seen this bridge in one our records (other than `current`)
            tracked: HashMap<BridgeKey, Option<Where>>,
            /// Earliest instant found in any schedule
            earliest: Option<Instant>,
        }

        let mut tracked = if let Some(input) = input {
            let tracked = input.into_iter().map(|b| (b.clone(), None)).collect();
            Tracked {
                tracked,
                known_input: true,
                earliest: None,
            }
        } else {
            Tracked {
                tracked: HashMap::new(),
                known_input: false,
                earliest: None,
            }
        };

        impl Tracked {
            /// Note that `bridge` is Tracked
            fn note(&mut self, where_: Where, b: &BridgeKey) {
                match self.tracked.get(b) {
                    // Invariant *Tracked* - ie appears at most once
                    Some(Some(prev_where)) => {
                        panic!("duplicate {:?} {:?} {:?}", prev_where, where_, b);
                    }
                    // Invariant *Input (every tracked bridge is was in input)*
                    None if self.known_input => {
                        panic!("unexpected {:?} {:?}", where_, b);
                    }
                    // OK, we've not seen it before, note it as being here
                    _ => {
                        self.tracked.insert(b.clone(), Some(where_));
                    }
                }
            }
        }

        /// Walk `schedule` and update `tracked` (including `tracked.earliest`)
        ///
        /// Check invariant *Tracked* and *Schedule* wrt this schedule.
        #[cfg(test)]
        fn walk_sch<TT: Ord + Copy + Debug, RD, CT: Fn(TT) -> Instant>(
            tracked: &mut Tracked,
            sch_name: &'static str,
            schedule: &BinaryHeap<RefetchEntry<TT, RD>>,
            conv_time: CT,
        ) {
            let where_ = Where::Schedule {
                sch_name,
                found_in_current: false,
            };

            if let Some(first) = schedule.peek() {
                // Of course this is a heap, so this ought to be a wasteful scan,
                // but, indirectly,this tests our implementation of `Ord` for `RefetchEntry`.
                for re in schedule {
                    tracked.note(where_, &re.bridge);
                }

                let scanned = schedule
                    .iter()
                    .map(|re| re.when)
                    .min()
                    .expect("schedule empty!");
                assert_eq!(scanned, first.when);
                tracked.earliest = Some(
                    [tracked.earliest, Some(conv_time(scanned))]
                        .into_iter()
                        .flatten()
                        .min()
                        .expect("flatten of chain Some was empty"),
                );
            }
        }

        // *Timeout* (prep)
        //
        // This will fail if there is clock skew, but won't mind if
        // the earliest refetch time is in the past.
        let now_wall = runtime.wallclock();
        let now_mono = runtime.now();
        let adj_wall = |wallclock: SystemTime| {
            // Good grief what a palaver!
            if let Ok(ahead) = wallclock.duration_since(now_wall) {
                now_mono + ahead
            } else if let Ok(behind) = now_wall.duration_since(wallclock) {
                now_mono
                    .checked_sub(behind)
                    .expect("time subtraction underflow")
            } else {
                panic!("times should be totally ordered!")
            }
        };

        // *Tracked*
        //
        // We walk our data structures in turn

        for b in self.running.keys() {
            tracked.note(Where::Running, b);
        }
        for qe in &self.queued {
            tracked.note(Where::Queued, &qe.bridge);
        }

        walk_sch(&mut tracked, "refetch", &self.refetch_schedule, adj_wall);
        walk_sch(&mut tracked, "retry", &self.retry_schedule, |t| t);

        // *Current*
        for b in self.current.keys() {
            let found = tracked
                .tracked
                .get_mut(b)
                .and_then(Option::as_mut)
                .unwrap_or_else(|| panic!("current but untracked {:?}", b));
            if let Where::Schedule {
                found_in_current, ..
            } = found
            {
                *found_in_current = true;
            }
        }

        // *Input (sense: every input bridge is tracked)*
        //
        // (Will not cope if spawn ever failed, since that violates the invariant.)
        for (b, where_) in &tracked.tracked {
            match where_ {
                None => panic!("missing {}", &b),
                Some(Where::Schedule {
                    sch_name,
                    found_in_current,
                }) => {
                    assert!(found_in_current, "not-Schedule {} {}", &b, sch_name);
                }
                _ => {}
            }
        }

        // *Limit*
        let parallelism = self.effective_parallelism();
        assert!(self.running.len() <= parallelism);

        // *Running*
        assert!(self.running.len() == parallelism || self.queued.is_empty());

        // *Timeout* (final)
        assert_eq!(tracked.earliest, *self.earliest_timeout.borrow());
    }
}
