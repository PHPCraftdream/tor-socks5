//! Bridge groups: the services that name a `bridge_group` are hosted by a Tor
//! client of their own, limited to the group's bridges, instead of the
//! process-wide client that carries every bridge.
//!
//! A group's client keeps its guard state and its onion keystore under
//! `<arti base>/group-<name>/` and reads the process client's directory cache,
//! so it starts without downloading the consensus again. The group's bridges
//! are picked at start from the bridges the process client works with and are
//! not replaced while the process runs.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use arti_wrapper::{Settings, TorTunnel};
use bridge_line::BridgeLine;
use proxy_config::OnionServiceEntry;
use tokio_util::sync::CancellationToken;
use tor_socks5_onion::host::{OnionHost, OnionHostConfig};
use tor_socks5_runtime::tor_watchdog::TorHandle;
use tracing::{error, info, warn, Instrument};

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

/// The settings of a group's client: the process client's, with the group's
/// bridges and its own state. The directory cache stays the process client's.
/// Up to [`MAX_PRIMARY_GUARDS`] bridges carry circuits at once, so one failing
/// takes only part of the service's circuits with it.
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
    let spread = u8::try_from(bridges.len())
        .unwrap_or(u8::MAX)
        .clamp(1, MAX_PRIMARY_GUARDS);
    let mut settings = main.clone();
    settings.cache_dir = Some(main.cache_dir.clone().unwrap_or_else(|| base.join("cache")));
    let group_base = group_dir(base, group);
    let keystore_dir = group_keystore_dir(&group_base);
    settings.state_dir = Some(group_base);
    settings.guard_spread = spread;
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

/// Host the services of one group on a Tor client of its own, until `token`
/// is cancelled. Failures are logged and end only this group.
pub(crate) async fn run_group(
    name: String,
    plan: GroupPlan,
    assigned: Assigned,
    main: Settings,
    config_path: PathBuf,
    token: CancellationToken,
) {
    let span = tracing::info_span!("bridge_group", group = %name);
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
        let (settings, keystore_dir) = match group_settings(&main, &name, assigned.bridges) {
            Ok(group) => group,
            Err(error) => {
                error!(%error, "bridge group not started: its services are not hosted");
                return;
            }
        };
        info!(
            bridges = settings.bridges.len(),
            services = plan.entries.len(),
            "starting a bridge group: bootstrapping its own Tor client"
        );
        let tunnel =
            bootstrap_until_ready(|| TorTunnel::bootstrap_with(settings.clone()), &token).await;
        let Some(tunnel) = tunnel else {
            info!("bridge group cancelled before its Tor client bootstrapped");
            return;
        };
        let handle = TorHandle::new_with_settings(tunnel, &settings);
        let host_config = OnionHostConfig::new(handle.clone(), keystore_dir, token)
            .with_entries(plan.entries)
            .with_config_path(Some(config_path));
        let mut host =
            super::service::AbortOnDropHandle::new(OnionHost::new(host_config).start().detach());
        if let Err(error) = host.join().await {
            warn!(%error, "bridge group host task ended with a join error");
        }
        // Release the client so its pluggable-transport children close.
        drop(handle.drain().await);
    }
    .instrument(span)
    .await;
}

#[cfg(test)]
#[path = "groups_tests.rs"]
mod tests;
