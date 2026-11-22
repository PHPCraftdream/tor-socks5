//! The bridge registry of the groups: which bridges every group works with, and
//! how a group gets free bridges from the process client's working list.
//!
//! Selection and recording happen under one lock hold, so two groups never get
//! the same free bridge. A bridge the client of a group still runs on stays
//! claimed until that client has actually switched: a reservation claims the
//! new bridges at once and keeps the old ones until the switch is known to have
//! worked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(test)]
use std::time::Duration;

use bridge_line::BridgeLine;
use tracing::{info, warn};

use super::Assigned;

/// What one claim of the process client's working list did for a group.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Claim {
    /// The group's bridges after the claim: the ones the process still works
    /// with in their order, then the replacements, then the dead ones no free
    /// bridge could replace.
    pub(crate) bridges: Vec<BridgeLine>,
    /// The group's bridges the process no longer works with.
    pub(crate) dead: Vec<BridgeLine>,
    /// Free working bridges taken in their place; fewer than `dead` when the
    /// working list has nothing more to give.
    pub(crate) taken: Vec<BridgeLine>,
}

impl Claim {
    /// Dead bridges left in the set for want of a free replacement.
    pub(crate) fn unreplaced(&self) -> usize {
        self.dead.len().saturating_sub(self.taken.len())
    }
}

/// Decide one claim without touching the registry: `current` is the group's
/// bridge set, `working` the process client's and `taken` the bridges other
/// groups hold. A bridge of `current` absent from `working` is dead; a free
/// bridge of `working` takes its place, in bridge-line order. Replacement is
/// partial: a dead bridge with no free bridge behind it stays in the set, so a
/// claim never changes the group's size.
pub(crate) fn plan_claim(
    current: &[BridgeLine],
    working: &[BridgeLine],
    taken: &BTreeSet<String>,
) -> Claim {
    let working_keys: BTreeSet<String> = working.iter().map(ToString::to_string).collect();
    let current_keys: BTreeSet<String> = current.iter().map(ToString::to_string).collect();
    let dead: Vec<BridgeLine> = current
        .iter()
        .filter(|bridge| !working_keys.contains(&bridge.to_string()))
        .cloned()
        .collect();
    let mut bridges: Vec<BridgeLine> = current
        .iter()
        .filter(|bridge| working_keys.contains(&bridge.to_string()))
        .cloned()
        .collect();
    if dead.is_empty() {
        return Claim {
            bridges,
            dead,
            taken: Vec::new(),
        };
    }
    let mut candidates: Vec<(String, BridgeLine)> = working
        .iter()
        .map(|bridge| (bridge.to_string(), bridge.clone()))
        .filter(|(key, _)| !current_keys.contains(key) && !taken.contains(key))
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates.dedup_by(|a, b| a.0 == b.0);
    let replacements: Vec<BridgeLine> = candidates
        .into_iter()
        .take(dead.len())
        .map(|(_, bridge)| bridge)
        .collect();
    bridges.extend(replacements.iter().cloned());
    bridges.extend(dead.iter().skip(replacements.len()).cloned());
    Claim {
        bridges,
        dead,
        taken: replacements,
    }
}

/// Test-only rendezvous between choosing free bridges and recording them. A
/// claim that reaches it waits briefly for a second claim to reach it too. Two
/// claims can meet here only if choosing and recording are not done under one
/// lock, so a test that expects exactly one winner fails when they are split.
#[cfg(test)]
#[derive(Debug, Default)]
struct Midpoint {
    armed: std::sync::atomic::AtomicBool,
    arrivals: Mutex<usize>,
    ready: std::sync::Condvar,
}

#[cfg(test)]
impl Midpoint {
    fn arm(&self) {
        *self.arrivals.lock().expect("arrivals") = 0;
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn meet(&self) {
        if !self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let mut arrivals = self.arrivals.lock().expect("arrivals");
        *arrivals += 1;
        if *arrivals >= 2 {
            self.ready.notify_all();
            return;
        }
        let _ = self
            .ready
            .wait_timeout(arrivals, Duration::from_millis(200))
            .expect("rendezvous");
    }
}

/// The bridges every group currently works with, shared by the group tasks so a
/// replacement never takes a bridge another group holds.
#[derive(Debug, Default)]
pub(crate) struct GroupBridges {
    groups: Mutex<BTreeMap<String, Vec<BridgeLine>>>,
    #[cfg(test)]
    midpoint: Midpoint,
}

impl GroupBridges {
    /// Seed the registry with the bridges assigned at start, before any group
    /// task runs: the first reservation of a group already sees the others.
    pub(crate) fn new(assigned: &BTreeMap<String, Assigned>) -> Arc<Self> {
        let groups = assigned
            .iter()
            .map(|(name, plan)| (name.clone(), plan.bridges.clone()))
            .collect();
        Arc::new(Self {
            groups: Mutex::new(groups),
            #[cfg(test)]
            midpoint: Midpoint::default(),
        })
    }

    /// Reserve free bridges for a group whose client is about to switch.
    pub(crate) fn reserve_for(
        &self,
        group: &str,
        current: &[BridgeLine],
        working: &[BridgeLine],
    ) -> Claim {
        self.reserve(group, current, working)
    }

    /// Choose free bridges for a group whose client is about to switch, and
    /// record it as holding the old and the new ones at once, both under one
    /// lock hold: the new bridges are claimed from the choice on, the old ones
    /// until [`Self::commit`] or [`Self::rollback`], and no other group can take
    /// either meanwhile.
    fn reserve(&self, group: &str, current: &[BridgeLine], working: &[BridgeLine]) -> Claim {
        let mut groups = self.lock();
        let taken: BTreeSet<String> = groups
            .iter()
            .filter(|(name, _)| name.as_str() != group)
            .flat_map(|(_, bridges)| bridges.iter().map(ToString::to_string))
            .collect();
        let claim = plan_claim(current, working, &taken);
        if claim.taken.is_empty() {
            return claim;
        }
        #[cfg(test)]
        self.midpoint.meet();
        let mut held = current.to_vec();
        held.extend(claim.taken.iter().cloned());
        groups.insert(group.to_owned(), held);
        claim
    }

    /// The client switched: the group holds only the reserved bridges now, so
    /// the old ones are free for the other groups.
    pub(crate) fn commit(&self, group: &str, claim: &Claim) {
        self.record(group, claim.bridges.clone());
    }

    /// The client kept its old set: the reserved bridges go back to the pool.
    pub(crate) fn rollback(&self, group: &str, current: &[BridgeLine]) {
        self.record(group, current.to_vec());
    }

    /// Take free bridges and record them at once: a group that has no client
    /// yet runs on the claimed set from the moment it is chosen.
    pub(crate) fn claim(
        &self,
        group: &str,
        current: &[BridgeLine],
        working: &[BridgeLine],
    ) -> Claim {
        let claim = self.reserve(group, current, working);
        if !claim.taken.is_empty() {
            self.commit(group, &claim);
        }
        claim
    }

    /// The group is gone: its bridges are free for the groups that remain.
    pub(crate) fn release(&self, group: &str) {
        self.lock().remove(group);
    }

    /// The bridges a group works with now.
    pub(crate) fn bridges_of(&self, group: &str) -> Option<Vec<BridgeLine>> {
        self.lock().get(group).cloned()
    }

    fn record(&self, group: &str, bridges: Vec<BridgeLine>) {
        self.lock().insert(group.to_owned(), bridges);
    }

    #[cfg(test)]
    pub(crate) fn arm_midpoint(&self) {
        self.midpoint.arm();
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Vec<BridgeLine>>> {
        self.groups
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

/// One line per bridge, for logs.
fn bridge_list(bridges: &[BridgeLine]) -> String {
    bridges
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Warn about dead bridges no free bridge could replace: the group keeps them.
pub(crate) fn warn_shortage(claim: &Claim) {
    if claim.unreplaced() > 0 {
        warn!(
            dead = claim.dead.len(),
            replaced = claim.taken.len(),
            bridges = %bridge_list(&claim.dead),
            "the process's working list has no free bridge for all of this group's dead \
             bridges: the group keeps the rest and tries again on the next check"
        );
    }
}

/// Log the bridges a claim replaced. Called only once the client really runs on
/// them, so a refused switch never reports a replacement.
pub(crate) fn log_replaced(claim: &Claim) {
    if !claim.taken.is_empty() {
        info!(
            dead = %bridge_list(&claim.dead),
            added = %bridge_list(&claim.taken),
            "bridge group replaced the bridges the process client no longer works with"
        );
    }
}

/// Log the bridges a group claimed before its client exists. No switch has
/// happened yet, so this reports a claim and never a replacement.
pub(crate) fn log_claimed(claim: &Claim) {
    if !claim.taken.is_empty() {
        info!(
            dead = %bridge_list(&claim.dead),
            added = %bridge_list(&claim.taken),
            "bridge group starts on the bridges it claimed from the process working list"
        );
    }
}

#[cfg(test)]
#[path = "groups_claim_tests.rs"]
mod tests;
