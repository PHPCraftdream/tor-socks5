//! Single-owner popular-question prefetch scheduler.
//!
//! Maintenance evaluates/persists the rolling window at startup and every two
//! hours. A busy cycle never queues another cycle: intervening publications are
//! dropped, and the next idle maintenance tick starts from its fresh snapshot.
//! Only the active generation is retained between ticks (store limit: two).
//! Routing, cache insertion/bypass, backend admission and the absolute 30-second
//! exchange budget belong to the caller. No names or error payloads are logged.
//! Inspected lockfile: Tokio 1.52.3, tokio-util 0.7.18, Hickory 0.26.1,
//! tracing 0.1.44, anyhow 1.0.102 (no downcast_mut use).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use hickory_proto::op::Query;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::query_statistics::{PopularCursor, PopularSnapshot, PopularTarget, StatisticsWorker};
use crate::ResolvedAnswer;

const PERIOD: Duration = Duration::from_secs(7200);
type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// Private RPITIT + Send interfaces: narrow IO seams, not public extension APIs.
// The production adapter and tests drive exactly the same scheduler/cycle.
trait Snapshot: Send + 'static {
    type Cursor: Send;
    type Target: Send;
    fn page(
        &self,
        after: Option<Self::Cursor>,
    ) -> impl Future<Output = Result<Vec<Self::Target>>> + Send;
    fn cursor(target: &Self::Target) -> Self::Cursor;
    fn question(target: Self::Target) -> Query;
}

impl Snapshot for PopularSnapshot {
    type Cursor = PopularCursor;
    type Target = PopularTarget;
    async fn page(&self, after: Option<PopularCursor>) -> Result<Vec<PopularTarget>> {
        let page = PopularSnapshot::page(self, after).await?;
        // Aggregate page workload only, never names. Saturation keeps
        // diagnostics safe even when multiple tuple counts sum past u64.
        let observed_queries = page
            .iter()
            .fold(0_u64, |total, target| total.saturating_add(target.count));
        tracing::debug!(
            generation = self.generation,
            targets = page.len(),
            observed_queries,
            "DNS popular prefetch page loaded"
        );
        Ok(page)
    }
    fn cursor(target: &PopularTarget) -> PopularCursor {
        target.cursor()
    }
    fn question(target: PopularTarget) -> Query {
        target.question
    }
}

trait Maintenance: Send {
    type Snapshot: Snapshot;
    fn refresh(&mut self) -> impl Future<Output = Result<Self::Snapshot>> + Send;
}

impl Maintenance for StatisticsWorker {
    type Snapshot = PopularSnapshot;
    fn refresh(&mut self) -> impl Future<Output = Result<PopularSnapshot>> + Send {
        StatisticsWorker::refresh(self)
    }
}

/// Run startup evaluation followed by independent two-hour maintenance.
///
/// `refresh` is uniquely owned, requires Send but not Sync, and is invoked once
/// per target sequentially. Shutdown drops pending network/page work and every
/// snapshot; the integration owner must subsequently drain statistics.
/// cancel-safe: NO — maintenance may already have published when cancelled.
/// Cancellation is terminal here, never drop-and-retry within the same tick;
/// the caller owns the worker and must await its explicit shutdown afterwards.
/// Page/exchange futures are disposable and must not detach network work.
pub(crate) async fn run<Refresh, Exchange>(
    statistics: &mut StatisticsWorker,
    refresh: Refresh,
    shutdown: CancellationToken,
) -> Result<()>
where
    Refresh: FnMut(Query) -> Exchange + Send,
    Exchange: Future<Output = Option<ResolvedAnswer>> + Send,
{
    schedule(statistics, refresh, shutdown).await
}

// A cycle returns ownership of FnMut so there is never a shared borrow (and
// therefore no accidental Sync bound), even across independent maintenance.
/// cancel-safe: yes for disposable prefetch — each page await is read-only;
/// each exchange await is caller-owned cancellable cache refresh. Dropping the
/// future drops its snapshot, cursor, bounded page and current exchange.
async fn cycle<S, Refresh, Exchange>(snapshot: S, mut refresh: Refresh) -> Refresh
where
    S: Snapshot,
    Refresh: FnMut(Query) -> Exchange + Send,
    Exchange: Future<Output = Option<ResolvedAnswer>> + Send,
{
    let mut after = None;
    loop {
        let page = match snapshot.page(after).await {
            Ok(page) => page,
            Err(_) => {
                tracing::warn!("DNS popular prefetch page failed; retry next maintenance tick");
                return refresh;
            }
        };
        if page.is_empty() {
            return refresh;
        }
        after = page.last().map(S::cursor);
        for target in page {
            if refresh(S::question(target)).await.is_none() {
                tracing::warn!("DNS popular prefetch lookup failed");
            }
            // Ready fake/cache futures must not monopolize the scheduler: the
            // bounded page is not an excuse to starve maintenance or shutdown.
            tokio::task::yield_now().await;
        }
    }
}

async fn active_result<Refresh>(active: &mut Option<Pending<'_, Refresh>>) -> Refresh {
    match active {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// cancel-safe: NO — same terminal maintenance cancellation contract as run.
async fn schedule<M, Refresh, Exchange>(
    maintenance: &mut M,
    refresh: Refresh,
    shutdown: CancellationToken,
) -> Result<()>
where
    M: Maintenance,
    Refresh: FnMut(Query) -> Exchange + Send,
    Exchange: Future<Output = Option<ResolvedAnswer>> + Send,
{
    // Immediate tick is intentional startup evaluation, not startup prefetch
    // against yesterday's persisted list. Skip, never replay missed deadlines.
    let mut ticks = tokio::time::interval_at(Instant::now(), PERIOD);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut idle = Some(refresh);
    let mut active: Option<Pending<'_, Refresh>> = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            _ = ticks.tick() => {},
            refresh = active_result(&mut active) => {
                active = None; // drop completed cycle AND its generation
                idle = Some(refresh);
                continue; // no replay/start on completion
            }
        }
        // Retain this operation across cycle completion; never recreate a
        // committed-but-unobserved refresh on a losing select arm.
        let publication = maintenance.refresh();
        tokio::pin!(publication);
        let snapshot = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                result = &mut publication => break result,
                refresh = active_result(&mut active) => {
                    active = None;
                    idle = Some(refresh);
                }
            }
        };
        match snapshot {
            Ok(snapshot) => {
                if let Some(refresh) = idle.take() {
                    active = Some(Box::pin(cycle(snapshot, refresh)));
                }
                // Otherwise publication drops here: active snapshot + this
                // temporary snapshot are at most two leases. No current-list
                // lease survives into the third refresh, no pending cycle.
            }
            Err(_) => {
                tracing::warn!("DNS popular list maintenance failed; retry next maintenance tick")
            }
        }
    }
}

#[cfg(test)]
#[path = "popular_prefetch_tests.rs"]
mod tests;
