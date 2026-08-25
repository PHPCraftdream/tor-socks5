//! Code to construct paths through the Tor network
//!
//! TODO: I'm not sure this belongs in circmgr, but this is the best place
//! I can think of for now.  I'm also not sure this should be public.

pub(crate) mod dirpath;
pub(crate) mod exitpath;

// Care must be taken if/when we decide to make this pub.
//
// The `HsPathBuilder` exposes two path building functions,
// one that uses vanguards, and one that doesn't.
// We want to strongly encourage the use of the vanguards-aware
// version of the function whenever the `vanguards` feature is enabled,
// without breaking any of its existing non-vanguard uses.
#[cfg(feature = "hs-common")]
pub(crate) mod hspath;

use std::result::Result as StdResult;
use std::time::SystemTime;

use itertools::Either;
use rand::Rng;

use tor_dircommon::fallback::FallbackDir;
use tor_error::{Bug, bad_api_usage, internal};
#[cfg(feature = "geoip")]
use tor_geoip::{CountryCode, HasCountryCode};
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_linkspec::{HasAddrs, HasRelayIds, OwnedChanTarget, OwnedCircTarget, RelayIdSet};
use tor_netdir::{FamilyRules, NetDir, Relay, RelayWeight, WeightRole};
use tor_relay_selection::{RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::Vanguard;
use tracing::instrument;

use crate::usage::ExitPolicy;
use crate::{DirInfo, Error, PathConfig, Result};

/// A list of Tor relays through the network.
pub struct TorPath<'a> {
    /// The inner TorPath state.
    inner: TorPathInner<'a>,
}

/// Non-public helper type to represent the different kinds of Tor path.
///
/// (This is a separate type to avoid exposing its details to the user.)
///
/// NOTE: This type should NEVER be visible outside of path.rs and its
/// sub-modules.
enum TorPathInner<'a> {
    /// A single-hop path for use with a directory cache, when a relay is
    /// known.
    OneHop(Relay<'a>), // This could just be a routerstatus.
    /// A single-hop path for use with a directory cache, when we don't have
    /// a consensus.
    FallbackOneHop(&'a FallbackDir),
    /// A single-hop path taken from an OwnedChanTarget.
    OwnedOneHop(OwnedChanTarget),
    /// A multi-hop path, containing one or more relays.
    Path(Vec<MaybeOwnedRelay<'a>>),
}

/// Identifier for a relay that could be either known from a NetDir, or
/// specified as an OwnedCircTarget.
///
/// NOTE: This type should NEVER be visible outside of path.rs and its
/// sub-modules.
#[derive(Clone)]
enum MaybeOwnedRelay<'a> {
    /// A relay from the netdir.
    Relay(Relay<'a>),
    /// An owned description of a relay.
    //
    // TODO: I don't love boxing this, but it fixes a warning about
    // variant sizes and is probably not the worst thing we could do.  OTOH, we
    // could probably afford to use an Arc here and in guardmgr? -nickm
    //
    // TODO: Try using an Arc. -nickm
    Owned(Box<OwnedCircTarget>),
}

impl<'a> MaybeOwnedRelay<'a> {
    /// Extract an OwnedCircTarget from this relay.
    fn to_owned(&self) -> OwnedCircTarget {
        match self {
            MaybeOwnedRelay::Relay(r) => OwnedCircTarget::from_circ_target(r),
            MaybeOwnedRelay::Owned(o) => o.as_ref().clone(),
        }
    }
}

impl<'a> From<OwnedCircTarget> for MaybeOwnedRelay<'a> {
    fn from(ct: OwnedCircTarget) -> Self {
        MaybeOwnedRelay::Owned(Box::new(ct))
    }
}
impl<'a> From<Relay<'a>> for MaybeOwnedRelay<'a> {
    fn from(r: Relay<'a>) -> Self {
        MaybeOwnedRelay::Relay(r)
    }
}
impl<'a> HasAddrs for MaybeOwnedRelay<'a> {
    fn addrs(&self) -> impl Iterator<Item = std::net::SocketAddr> {
        match self {
            MaybeOwnedRelay::Relay(r) => Either::Left(r.addrs()),
            MaybeOwnedRelay::Owned(r) => Either::Right(r.addrs()),
        }
    }
}
impl<'a> HasRelayIds for MaybeOwnedRelay<'a> {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        match self {
            MaybeOwnedRelay::Relay(r) => r.identity(key_type),
            MaybeOwnedRelay::Owned(r) => r.identity(key_type),
        }
    }
}

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
impl<'a> From<Vanguard<'a>> for MaybeOwnedRelay<'a> {
    fn from(r: Vanguard<'a>) -> Self {
        MaybeOwnedRelay::Relay(r.relay().clone())
    }
}

impl<'a> TorPath<'a> {
    /// Create a new one-hop path for use with a directory cache with a known
    /// relay.
    pub fn new_one_hop(relay: Relay<'a>) -> Self {
        Self {
            inner: TorPathInner::OneHop(relay),
        }
    }

    /// Create a new one-hop path for use with a directory cache when we don't
    /// have a consensus.
    pub fn new_fallback_one_hop(fallback_dir: &'a FallbackDir) -> Self {
        Self {
            inner: TorPathInner::FallbackOneHop(fallback_dir),
        }
    }

    /// Construct a new one-hop path for directory use from an arbitrarily
    /// chosen channel target.
    pub fn new_one_hop_owned<T: tor_linkspec::ChanTarget>(target: &T) -> Self {
        Self {
            inner: TorPathInner::OwnedOneHop(OwnedChanTarget::from_chan_target(target)),
        }
    }

    /// Create a new multi-hop path with a given number of ordered relays.
    pub fn new_multihop(relays: impl IntoIterator<Item = Relay<'a>>) -> Self {
        Self {
            inner: TorPathInner::Path(relays.into_iter().map(MaybeOwnedRelay::from).collect()),
        }
    }
    /// Construct a new multi-hop path from a vector of `MaybeOwned`.
    ///
    /// Internal only; do not expose without fixing up this API a bit.
    fn new_multihop_from_maybe_owned(relays: Vec<MaybeOwnedRelay<'a>>) -> Self {
        Self {
            inner: TorPathInner::Path(relays),
        }
    }

    /// Return the final relay in this path, if this is a path for use
    /// with exit circuits.
    fn exit_relay(&self) -> Option<&MaybeOwnedRelay<'a>> {
        match &self.inner {
            TorPathInner::Path(relays) if !relays.is_empty() => Some(&relays[relays.len() - 1]),
            _ => None,
        }
    }

    /// Return the exit policy of the final relay in this path, if this is a
    /// path for use with exit circuits with an exit taken from the network
    /// directory.
    pub(crate) fn exit_policy(&self) -> Option<ExitPolicy> {
        self.exit_relay().and_then(|r| match r {
            MaybeOwnedRelay::Relay(r) => Some(ExitPolicy::from_relay(r)),
            MaybeOwnedRelay::Owned(_) => None,
        })
    }

    /// Return the country code of the final relay in this path, if this is a
    /// path for use with exit circuits with an exit taken from the network
    /// directory.
    #[cfg(feature = "geoip")]
    pub(crate) fn country_code(&self) -> Option<CountryCode> {
        self.exit_relay().and_then(|r| match r {
            MaybeOwnedRelay::Relay(r) => r.country_code(),
            MaybeOwnedRelay::Owned(_) => None,
        })
    }

    /// Return the number of relays in this path.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        use TorPathInner::*;
        match &self.inner {
            OneHop(_) => 1,
            FallbackOneHop(_) => 1,
            OwnedOneHop(_) => 1,
            Path(p) => p.len(),
        }
    }

    /// Return true if every `Relay` in this path has the stable flag.
    ///
    /// Assumes that Owned elements of this path are stable.
    pub(crate) fn appears_stable(&self) -> bool {
        // TODO #504: this looks at low_level_details() in questionable way.
        match &self.inner {
            TorPathInner::OneHop(r) => r.low_level_details().is_flagged_stable(),
            TorPathInner::FallbackOneHop(_) => true,
            TorPathInner::OwnedOneHop(_) => true,
            TorPathInner::Path(relays) => relays.iter().all(|maybe_owned| match maybe_owned {
                MaybeOwnedRelay::Relay(r) => r.low_level_details().is_flagged_stable(),
                MaybeOwnedRelay::Owned(_) => true,
            }),
        }
    }
}

/// A path composed entirely of owned components.
#[derive(Clone, Debug)]
pub(crate) enum OwnedPath {
    /// A path where we only know how to make circuits via CREATE_FAST.
    ChannelOnly(OwnedChanTarget),
    /// A path of one or more hops created via normal Tor handshakes.
    Normal(Vec<OwnedCircTarget>),
}

impl<'a> TryFrom<&TorPath<'a>> for OwnedPath {
    type Error = crate::Error;
    fn try_from(p: &TorPath<'a>) -> Result<OwnedPath> {
        use TorPathInner::*;

        Ok(match &p.inner {
            FallbackOneHop(h) => OwnedPath::ChannelOnly(OwnedChanTarget::from_chan_target(*h)),
            OneHop(h) => OwnedPath::Normal(vec![OwnedCircTarget::from_circ_target(h)]),
            OwnedOneHop(owned) => OwnedPath::ChannelOnly(owned.clone()),
            Path(p) if !p.is_empty() => {
                OwnedPath::Normal(p.iter().map(MaybeOwnedRelay::to_owned).collect())
            }
            Path(_) => {
                return Err(bad_api_usage!("Path with no entries!").into());
            }
        })
    }
}

impl OwnedPath {
    /// Return the number of hops in this path.
    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> usize {
        match self {
            OwnedPath::ChannelOnly(_) => 1,
            OwnedPath::Normal(p) => p.len(),
        }
    }

    /// Return a reference to the first hop of this path, as an OwnedChanTarget.
    pub(crate) fn first_hop_as_chantarget(&self) -> &OwnedChanTarget {
        match self {
            OwnedPath::ChannelOnly(ct) => ct,
            // This access won't panic, since we enforce that path is nonempty.
            OwnedPath::Normal(path) => path[0].chan_target(),
        }
    }
}

/// A path builder that builds multi-hop, anonymous paths.
trait AnonymousPathBuilder {
    /// Return the "target" that every chosen relay must be able to share a circuit with with.
    fn compatible_with(&self) -> Option<&OwnedChanTarget>;

    /// Return a short description of the path we're trying to build,
    /// for error reporting purposes.
    fn path_kind(&self) -> &'static str;

    /// Find a suitable exit node from either the chosen exit or from the network directory.
    ///
    /// Return the exit, along with the usage for a middle node corresponding
    /// to this exit.
    /// tor-socks5 local patch: the `PathConfig`, so that the Tier 2
    /// bandwidth floor can reach exit selection in the implementors.
    fn pick_exit<'a, R: Rng>(
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        guard_exclusion: RelayExclusion<'a>,
        rs_cfg: &RelaySelectionConfig<'_>,
        config: &PathConfig,
    ) -> Result<(Relay<'a>, RelayUsage)>;
}

/// Try to create and return a path corresponding to the requirements of
/// this builder.
#[instrument(skip_all, level = "trace")]
fn pick_path<'a, B: AnonymousPathBuilder, R: Rng, RT: Runtime>(
    builder: &B,
    rng: &mut R,
    netdir: DirInfo<'a>,
    guards: &GuardMgr<RT>,
    config: &PathConfig,
    _now: SystemTime,
) -> Result<(TorPath<'a>, GuardMonitor, GuardUsable)> {
    let netdir = match netdir {
        DirInfo::Directory(d) => d,
        _ => {
            return Err(bad_api_usage!(
                "Tried to build a multihop path without a network directory"
            )
            .into());
        }
    };
    let rs_cfg = config.relay_selection_config();
    let family_rules = FamilyRules::from(netdir.params());

    let target_exclusion = match builder.compatible_with() {
        Some(ct) => {
            // Exclude the target from appearing in other positions in the path.
            let ids = RelayIdSet::from_iter(ct.identities().map(|id_ref| id_ref.to_owned()));
            // TODO torspec#265: we do not apply same-family restrictions
            // (a relay in the same family as the target can occur in the path).
            //
            // We need to decide if this is the correct behavior,
            // and if so, document it in torspec.
            RelayExclusion::exclude_identities(ids)
        }
        None => RelayExclusion::no_relays_excluded(),
    };

    // TODO-SPEC: Because of limitations in guard selection, we have to
    // pick the guard before the exit, which is not what our spec says.
    let (guard, mon, usable) = select_guard(netdir, guards, builder.compatible_with())?;

    let guard_exclusion = match &guard {
        MaybeOwnedRelay::Relay(r) => RelayExclusion::exclude_relays_in_same_family(
            &config.relay_selection_config(),
            vec![r.clone()],
            family_rules,
        ),
        MaybeOwnedRelay::Owned(ct) => RelayExclusion::exclude_channel_target_family(
            &config.relay_selection_config(),
            ct.as_ref(),
            netdir,
        ),
    };

    let mut exclusion = guard_exclusion.clone();
    exclusion.extend(&target_exclusion);
    let (exit, middle_usage) = builder.pick_exit(rng, netdir, exclusion, &rs_cfg, config)?;

    let mut family_exclusion =
        RelayExclusion::exclude_relays_in_same_family(&rs_cfg, vec![exit.clone()], family_rules);
    family_exclusion.extend(&guard_exclusion);
    let mut exclusion = family_exclusion;
    exclusion.extend(&target_exclusion);

    let selector = RelaySelector::new(middle_usage, exclusion);
    // Tier 2: the middle relay is optionally restricted to the upper
    // band of the consensus bandwidth distribution.
    let middle = select_relay_with_bandwidth_floor(
        &selector,
        rng,
        netdir,
        config.min_bandwidth_percentile,
        WeightRole::Middle,
        builder.path_kind(),
        "middle relay",
    )?;
    let hops = vec![
        guard,
        MaybeOwnedRelay::from(middle),
        MaybeOwnedRelay::from(exit),
    ];

    ensure_unique_hops(&hops)?;

    Ok((TorPath::new_multihop_from_maybe_owned(hops), mon, usable))
}

/// Returns an error if the specified hop list contains duplicates.
fn ensure_unique_hops<'a>(hops: &'a [MaybeOwnedRelay<'a>]) -> StdResult<(), Bug> {
    for (i, hop) in hops.iter().enumerate() {
        if let Some(hop2) = hops
            .iter()
            .skip(i + 1)
            .find(|hop2| hop.clone().has_any_relay_id_from(*hop2))
        {
            return Err(internal!(
                "invalid path: the IDs of hops {} and {} overlap?!",
                hop.display_relay_ids(),
                hop2.display_relay_ids()
            ));
        }
    }
    Ok(())
}

// tor-socks5 local patch (docs/circuit-speed-plan.md Tier 2): safety
// minimum for the bandwidth-floor candidate pool. If applying the floor
// would leave fewer than this many usable middle/exit candidates, we fall
// back to the stock unfiltered selection instead — an over-aggressive
// floor must degrade to "usually fast", never to "cannot build circuits".
const MIN_FILTERED_POOL: usize = 20;

/// tor-socks5 local patch (docs/circuit-speed-plan.md Tier 2): pick a
/// relay with `selector`, additionally excluding candidates below the
/// `floor_percentile`-th percentile of the consensus role-weight
/// distribution of the candidates that `selector` itself permits.
///
/// `floor_percentile == 0` (the default) makes this exactly the stock
/// `RelaySelector::select_relay` call — identical behaviour and RNG
/// consumption.
///
/// We use the role weights from `NetDir::relay_weight` (the same weights
/// `pick_relay` samples proportionally to) rather than the raw consensus
/// `w Bandwidth=` figure, because the latter is only exposed behind
/// tor-netdir's `experimental-api` feature. For a fixed role the weight is
/// monotone in the relay's measured bandwidth, so the percentile ordering
/// is preserved.
///
/// Never fails harder than the stock selection: if the floor would shrink
/// the candidate pool below [`MIN_FILTERED_POOL`], or the filtered pick
/// somehow finds nothing, we fall back to the unfiltered stock selection.
pub(crate) fn select_relay_with_bandwidth_floor<'d, R: Rng>(
    selector: &RelaySelector<'_>,
    rng: &mut R,
    netdir: &'d NetDir,
    floor_percentile: u8,
    role: WeightRole,
    path_kind: &'static str,
    role_name: &'static str,
) -> Result<Relay<'d>> {
    if floor_percentile == 0 {
        return select_relay_stock(selector, rng, netdir, path_kind, role_name);
    }

    let candidates: Vec<Relay<'d>> = netdir
        .relays()
        .filter(|r| selector.permits_relay(r))
        .collect();

    // The unfiltered pool is already tiny (test networks, badly desynced
    // directories): keep stock behaviour rather than filtering further.
    if candidates.len() < MIN_FILTERED_POOL {
        return select_relay_stock(selector, rng, netdir, path_kind, role_name);
    }

    let mut weights: Vec<_> = candidates
        .iter()
        .map(|r| netdir.relay_weight(r, role))
        .collect();
    weights.sort_unstable();
    let threshold = bandwidth_percentile_threshold(&weights, floor_percentile);

    let n_above = candidates
        .iter()
        .filter(|r| netdir.relay_weight(r, role) >= threshold)
        .count();
    if n_above < MIN_FILTERED_POOL {
        // The floor would leave too few candidates to build circuits
        // reliably: fall back to the unfiltered selection.
        return select_relay_stock(selector, rng, netdir, path_kind, role_name);
    }

    match netdir.pick_relay(rng, role, |r| {
        selector.permits_relay(r) && netdir.relay_weight(r, role) >= threshold
    }) {
        Some(relay) => Ok(relay),
        // Unreachable in practice (the same predicate admitted at least
        // MIN_FILTERED_POOL relays a moment ago), but a floor must never
        // turn a would-be-successful build into a failure.
        None => select_relay_stock(selector, rng, netdir, path_kind, role_name),
    }
}

/// tor-socks5 local patch: the stock `select_relay` call plus its error
/// mapping, factored out so that the default path of
/// [`select_relay_with_bandwidth_floor`] is textually identical to the
/// pre-patch code.
fn select_relay_stock<'d, R: Rng>(
    selector: &RelaySelector<'_>,
    rng: &mut R,
    netdir: &'d NetDir,
    path_kind: &'static str,
    role_name: &'static str,
) -> Result<Relay<'d>> {
    let (relay, info) = selector.select_relay(rng, netdir);
    relay.ok_or_else(|| Error::NoRelay {
        path_kind,
        role: role_name,
        problem: info.to_string(),
    })
}

/// tor-socks5 local patch: return the `percentile`-th percentile
/// (0 < percentile; values above 100 are treated as 100) of an
/// ascendingly sorted, non-empty slice of weights. Relays at or above
/// this value pass the floor.
fn bandwidth_percentile_threshold(sorted: &[RelayWeight], percentile: u8) -> RelayWeight {
    debug_assert!(!sorted.is_empty());
    debug_assert!(percentile > 0);
    // Nearest-lower-rank: the value at index floor(n * p / 100), clamped
    // into range (p >= 100 selects only relays carrying the maximum
    // weight). The product cannot overflow usize on any realistic
    // consensus (n <= ~10_000 relays, p <= 255 → n * p <= ~2.55M).
    let idx = (sorted
        .len()
        .saturating_mul(percentile as usize)
        / 100)
        .min(sorted.len() - 1);
    sorted[idx]
}

/// Try to select a guard corresponding to the requirements of
/// this builder.
#[instrument(skip_all, level = "trace")]
fn select_guard<'a, RT: Runtime>(
    netdir: &'a NetDir,
    guardmgr: &GuardMgr<RT>,
    compatible_with: Option<&OwnedChanTarget>,
) -> Result<(MaybeOwnedRelay<'a>, GuardMonitor, GuardUsable)> {
    // TODO: Extract this section into its own function, and see
    // what it can share with tor_relay_selection.
    let mut b = tor_guardmgr::GuardUsageBuilder::default();
    b.kind(tor_guardmgr::GuardUsageKind::Data);
    if let Some(avoid_target) = compatible_with {
        let mut family = RelayIdSet::new();
        family.extend(avoid_target.identities().map(|id| id.to_owned()));
        if let Some(avoid_relay) = netdir.by_ids(avoid_target) {
            family.extend(netdir.known_family_members(&avoid_relay).map(|r| *r.id()));
        }
        b.restrictions()
            .push(tor_guardmgr::GuardRestriction::AvoidAllIds(family));
    }
    let guard_usage = b.build().expect("Failed while building guard usage!");
    let (guard, mon, usable) = guardmgr.select_guard(guard_usage)?;
    let guard = if let Some(ct) = guard.as_circ_target() {
        // This is a bridge; we will not look for it in the network directory.
        MaybeOwnedRelay::from(ct.clone())
    } else {
        // Look this up in the network directory: we expect to find a relay.
        guard
            .get_relay(netdir)
            .ok_or_else(|| {
                internal!(
                    "Somehow the guardmgr gave us an unlisted guard {:?}!",
                    guard
                )
            })?
            .into()
    };
    Ok((guard, mon, usable))
}

/// For testing: make sure that `path` is the same when it is an owned
/// path.
#[cfg(test)]
fn assert_same_path_when_owned(path: &TorPath<'_>) {
    #![allow(clippy::unwrap_used)]
    let owned: OwnedPath = path.try_into().unwrap();

    match (&owned, &path.inner) {
        (OwnedPath::ChannelOnly(c), TorPathInner::FallbackOneHop(f)) => {
            assert!(c.same_relay_ids(*f));
        }
        (OwnedPath::Normal(p), TorPathInner::OneHop(h)) => {
            assert_eq!(p.len(), 1);
            assert!(p[0].same_relay_ids(h));
        }
        (OwnedPath::Normal(p1), TorPathInner::Path(p2)) => {
            assert_eq!(p1.len(), p2.len());
            for (n1, n2) in p1.iter().zip(p2.iter()) {
                assert!(n1.same_relay_ids(n2));
            }
        }
        (_, _) => {
            panic!("Mismatched path types.");
        }
    }
}

// tor-socks5 local patch (docs/circuit-speed-plan.md Tier 2): unit tests
// for the bandwidth-floor selection helper.
#[cfg(test)]
mod bandwidth_floor_tests {
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

    use tor_basic_utils::test_rng::{Config as TestRngConfig, testing_rng};
    use tor_linkspec::HasRelayIds as _;
    use tor_netdir::{RelayWeight, WeightRole, testnet};
    use tor_relay_selection::{RelayExclusion, RelaySelector, RelayUsage};

    use super::{
        MIN_FILTERED_POOL, bandwidth_percentile_threshold, select_relay_with_bandwidth_floor,
    };

    fn middle_selector() -> RelaySelector<'static> {
        RelaySelector::new(
            RelayUsage::middle_relay(None),
            RelayExclusion::no_relays_excluded(),
        )
    }

    #[test]
    fn percentile_threshold_indices() {
        let weights: Vec<RelayWeight> = (1..=100u64).map(RelayWeight::from).collect();
        // 50th percentile of 100 values: index 50 (value 51).
        assert_eq!(
            bandwidth_percentile_threshold(&weights, 50),
            RelayWeight::from(51)
        );
        // 1st percentile of 100 values: index 1 (value 2).
        assert_eq!(
            bandwidth_percentile_threshold(&weights, 1),
            RelayWeight::from(2)
        );
        // 100th percentile: the maximum.
        assert_eq!(
            bandwidth_percentile_threshold(&weights, 100),
            RelayWeight::from(100)
        );
        // Values above 100 clamp to the maximum.
        assert_eq!(
            bandwidth_percentile_threshold(&weights, 255),
            RelayWeight::from(100)
        );

        let small = vec![RelayWeight::from(10), RelayWeight::from(20)];
        // 50th percentile of 2 values: index 1.
        assert_eq!(
            bandwidth_percentile_threshold(&small, 50),
            RelayWeight::from(20)
        );
        // 49th percentile of 2 values: index 0.
        assert_eq!(
            bandwidth_percentile_threshold(&small, 49),
            RelayWeight::from(10)
        );
    }

    #[test]
    fn floor_excludes_low_bandwidth_candidates() {
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let selector = middle_selector();

        // The threshold the implementation should be enforcing: the 50th
        // percentile of the Middle-role weights of the permitted pool.
        let mut weights: Vec<_> = netdir
            .relays()
            .filter(|r| selector.permits_relay(r))
            .map(|r| netdir.relay_weight(&r, WeightRole::Middle))
            .collect();
        assert!(
            weights.len() >= MIN_FILTERED_POOL,
            "testnet pool must be large enough for the floor to engage"
        );
        weights.sort_unstable();
        let threshold = bandwidth_percentile_threshold(&weights, 50);
        // The floor must actually bite on this network: some permitted
        // relay must fall below it (otherwise this test would be vacuous).
        assert!(weights[0] < threshold);

        let mut rng = testing_rng();
        for _ in 0..200 {
            let relay = select_relay_with_bandwidth_floor(
                &selector,
                &mut rng,
                &netdir,
                50,
                WeightRole::Middle,
                "test circuit",
                "middle relay",
            )
            .unwrap();
            assert!(netdir.relay_weight(&relay, WeightRole::Middle) >= threshold);
        }
    }

    #[test]
    fn floor_falls_back_when_pool_is_tiny() {
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        // Shrink the permitted pool below MIN_FILTERED_POOL by excluding
        // most of the network outright: with only a handful of candidates,
        // even a 99th-percentile floor must behave like stock selection
        // and still succeed.
        let excluded: Vec<_> = netdir.relays().take(35).collect();
        assert_eq!(excluded.len(), 35);
        let selector = RelaySelector::new(
            RelayUsage::middle_relay(None),
            RelayExclusion::exclude_specific_relays(&excluded),
        );

        let mut rng = testing_rng();
        for _ in 0..50 {
            let relay = select_relay_with_bandwidth_floor(
                &selector,
                &mut rng,
                &netdir,
                99,
                WeightRole::Middle,
                "test circuit",
                "middle relay",
            )
            .unwrap();
            // Whatever was picked must still be one the selector permits.
            assert!(selector.permits_relay(&relay));
        }
    }

    #[test]
    fn floor_zero_matches_stock_selection_exactly() {
        // A zero floor must take the exact stock code path: with two
        // identically-seeded RNGs, the floored helper and a direct
        // `select_relay` call must pick the identical relay every time.
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let mut rng_floored = TestRngConfig::Deterministic.into_rng();
        let mut rng_stock = TestRngConfig::Deterministic.into_rng();

        for _ in 0..100 {
            let floored = select_relay_with_bandwidth_floor(
                &middle_selector(),
                &mut rng_floored,
                &netdir,
                0,
                WeightRole::Middle,
                "test circuit",
                "middle relay",
            )
            .unwrap();
            let (stock, _) = middle_selector().select_relay(&mut rng_stock, &netdir);
            let stock = stock.unwrap();
            assert!(floored.same_relay_ids(&stock));
        }
    }
}
