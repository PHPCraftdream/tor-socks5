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
use super::*;
use crate::timeouts::TimeoutEstimator;
use futures::FutureExt;
use std::sync::Mutex;
use tor_chanmgr::ChannelUsage as CU;
use tor_linkspec::ChanTarget;
use tor_linkspec::{HasRelayIds, RelayIdType, RelayIds};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_memquota::ArcMemoryQuotaTrackerExt as _;
use tor_proto::memquota::ToplevelAccount;
use tor_rtcompat::SleepProvider;
use tracing::trace;

/// Make a new nonfunctional `Arc<GuardStatusHandle>`
fn gs() -> Arc<GuardStatusHandle> {
    Arc::new(None.into())
}

#[test]
// Re-enabled after work from eta, discussed in arti#149
fn test_double_timeout() {
    let t1 = Duration::from_secs(1);
    let t10 = Duration::from_secs(10);
    /// Return true if d1 is in range [d2...d2 + 0.5sec]
    fn duration_close_to(d1: Duration, d2: Duration) -> bool {
        d1 >= d2 && d1 <= d2 + Duration::from_millis(500)
    }

    tor_rtmock::MockRuntime::test_with_various(|rto| async move {
        // Try a future that's ready immediately.
        let x = double_timeout(&rto, async { Ok(3_u32) }, t1, t10).await;
        assert!(x.is_ok());
        assert_eq!(x.unwrap(), 3_u32);

        trace!("acquiesce after test1");
        #[allow(clippy::clone_on_copy)]
        #[allow(deprecated)] // TODO #1885
        let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

        // Try a future that's ready after a short delay.
        let rt_clone = rt.clone();
        // (We only want the short delay to fire, not any of the other timeouts.)
        rt_clone.block_advance("manually controlling advances");
        let x = rt
            .wait_for(double_timeout(
                &rt,
                async move {
                    let sl = rt_clone.sleep(Duration::from_millis(100));
                    rt_clone.allow_one_advance(Duration::from_millis(100));
                    sl.await;
                    Ok(4_u32)
                },
                t1,
                t10,
            ))
            .await;
        assert!(x.is_ok());
        assert_eq!(x.unwrap(), 4_u32);

        trace!("acquiesce after test2");
        #[allow(clippy::clone_on_copy)]
        #[allow(deprecated)] // TODO #1885
        let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

        // Try a future that passes the first timeout, and make sure that
        // it keeps running after it times out.
        let rt_clone = rt.clone();
        let (snd, rcv) = oneshot::channel();
        let start = rt.now();
        rt.block_advance("manually controlling advances");
        let x = rt
            .wait_for(double_timeout(
                &rt,
                async move {
                    let sl = rt_clone.sleep(Duration::from_secs(2));
                    rt_clone.allow_one_advance(Duration::from_secs(2));
                    sl.await;
                    snd.send(()).unwrap();
                    Ok(4_u32)
                },
                t1,
                t10,
            ))
            .await;
        assert!(matches!(x, Err(Error::CircTimeout(_))));
        let end = rt.now();
        assert!(duration_close_to(end - start, Duration::from_secs(1)));
        let waited = rt.wait_for(rcv).await;
        assert_eq!(waited, Ok(()));

        trace!("acquiesce after test3");
        #[allow(clippy::clone_on_copy)]
        #[allow(deprecated)] // TODO #1885
        let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

        // Try a future that times out and gets abandoned.
        let rt_clone = rt.clone();
        rt.block_advance("manually controlling advances");
        let (snd, rcv) = oneshot::channel();
        let start = rt.now();
        // Let it hit the first timeout...
        rt.allow_one_advance(Duration::from_secs(1));
        let x = rt
            .wait_for(double_timeout(
                &rt,
                async move {
                    rt_clone.sleep(Duration::from_secs(30)).await;
                    snd.send(()).unwrap();
                    Ok(4_u32)
                },
                t1,
                t10,
            ))
            .await;
        assert!(matches!(x, Err(Error::CircTimeout(_))));
        let end = rt.now();
        // ...and let it hit the second, too.
        rt.allow_one_advance(Duration::from_secs(9));
        let waited = rt.wait_for(rcv).await;
        assert!(waited.is_err());
        let end2 = rt.now();
        assert!(duration_close_to(end - start, Duration::from_secs(1)));
        assert!(duration_close_to(end2 - start, Duration::from_secs(10)));
    });
}

/// Get a pair of timeouts that we've encoded as an Ed25519 identity.
///
/// In our FakeCircuit code below, the first timeout is the amount of
/// time that we should sleep while building a hop to this key,
/// and the second timeout is the length of time-advance we should allow
/// after the hop is built.
///
/// (This is pretty silly, but it's good enough for testing.)
fn timeouts_from_key(id: &Ed25519Identity) -> (Duration, Duration) {
    let mut be = [0; 8];
    be[..].copy_from_slice(&id.as_bytes()[0..8]);
    let dur = u64::from_be_bytes(be);
    be[..].copy_from_slice(&id.as_bytes()[8..16]);
    let dur2 = u64::from_be_bytes(be);
    (Duration::from_millis(dur), Duration::from_millis(dur2))
}
/// Encode a pair of timeouts as an Ed25519 identity.
///
/// In our FakeCircuit code below, the first timeout is the amount of
/// time that we should sleep while building a hop to this key,
/// and the second timeout is the length of time-advance we should allow
/// after the hop is built.
///
/// (This is pretty silly but it's good enough for testing.)
fn key_from_timeouts(d1: Duration, d2: Duration) -> Ed25519Identity {
    let mut bytes = [0; 32];
    let dur = (d1.as_millis() as u64).to_be_bytes();
    bytes[0..8].copy_from_slice(&dur);
    let dur = (d2.as_millis() as u64).to_be_bytes();
    bytes[8..16].copy_from_slice(&dur);
    bytes.into()
}

/// As [`timeouts_from_key`], but first extract the relevant key from the
/// OwnedChanTarget.
fn timeouts_from_chantarget<CT: ChanTarget>(ct: &CT) -> (Duration, Duration) {
    // Extracting the Ed25519 identity should always succeed in this case:
    // we put it there ourselves!
    let ed_id = ct
        .identity(RelayIdType::Ed25519)
        .expect("No ed25519 key was present for fake ChanTarget‽")
        .try_into()
        .expect("ChanTarget provided wrong key type");
    timeouts_from_key(ed_id)
}

/// Replacement type for circuit, to implement buildable.
#[derive(Debug, Clone)]
struct FakeCirc {
    hops: Vec<RelayIds>,
    onehop: bool,
}
#[async_trait]
impl Buildable for Mutex<FakeCirc> {
    type Chan = ();

    async fn open_channel<RT: Runtime>(
        _chanmgr: &ChanMgr<RT>,
        _ct: &OwnedChanTarget,
        _guard_status: &GuardStatusHandle,
        _usage: ChannelUsage,
    ) -> Result<Arc<Self::Chan>> {
        Ok(Arc::new(()))
    }

    async fn create_chantarget<RT: Runtime>(
        _: Arc<Self::Chan>,
        rt: &RT,
        ct: &OwnedChanTarget,
        _: CircParameters,
        _timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    ) -> Result<Self> {
        let (d1, d2) = timeouts_from_chantarget(ct);
        rt.sleep(d1).await;
        if !d2.is_zero() {
            rt.allow_one_advance(d2);
        }

        let c = FakeCirc {
            hops: vec![RelayIds::from_relay_ids(ct)],
            onehop: true,
        };
        Ok(Mutex::new(c))
    }
    async fn create<RT: Runtime>(
        _: Arc<Self::Chan>,
        rt: &RT,
        ct: &OwnedCircTarget,
        _: CircParameters,
        _timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    ) -> Result<Self> {
        let (d1, d2) = timeouts_from_chantarget(ct);
        rt.sleep(d1).await;
        if !d2.is_zero() {
            rt.allow_one_advance(d2);
        }

        let c = FakeCirc {
            hops: vec![RelayIds::from_relay_ids(ct)],
            onehop: false,
        };
        Ok(Mutex::new(c))
    }
    async fn extend<RT: Runtime>(
        &self,
        rt: &RT,
        ct: &OwnedCircTarget,
        _: CircParameters,
    ) -> Result<()> {
        let (d1, d2) = timeouts_from_chantarget(ct);
        rt.sleep(d1).await;
        if !d2.is_zero() {
            rt.allow_one_advance(d2);
        }

        {
            let mut c = self.lock().unwrap();
            c.hops.push(RelayIds::from_relay_ids(ct));
        }
        Ok(())
    }
}

/// Fake implementation of TimeoutEstimator that just records its inputs.
struct TimeoutRecorder<R> {
    runtime: R,
    hist: Vec<(bool, u8, Duration)>,
    // How much advance to permit after being told of a timeout?
    on_timeout: Duration,
    // How much advance to permit after being told of a success?
    on_success: Duration,

    snd_success: Option<oneshot::Sender<()>>,
    rcv_success: Option<oneshot::Receiver<()>>,
}

impl<R> TimeoutRecorder<R> {
    fn new(runtime: R) -> Self {
        Self::with_delays(runtime, Duration::from_secs(0), Duration::from_secs(0))
    }

    fn with_delays(runtime: R, on_timeout: Duration, on_success: Duration) -> Self {
        let (snd_success, rcv_success) = oneshot::channel();
        Self {
            runtime,
            hist: Vec::new(),
            on_timeout,
            on_success,
            rcv_success: Some(rcv_success),
            snd_success: Some(snd_success),
        }
    }
}
impl<R: Runtime> TimeoutEstimator for Arc<Mutex<TimeoutRecorder<R>>> {
    fn note_hop_completed(&mut self, hop: u8, delay: Duration, is_last: bool) {
        if !is_last {
            return;
        }
        let (rt, advance) = {
            let mut this = self.lock().unwrap();
            this.hist.push((true, hop, delay));
            let _ = this.snd_success.take().unwrap().send(());
            (this.runtime.clone(), this.on_success)
        };
        if !advance.is_zero() {
            rt.allow_one_advance(advance);
        }
    }
    fn note_circ_timeout(&mut self, hop: u8, delay: Duration) {
        let (rt, advance) = {
            let mut this = self.lock().unwrap();
            this.hist.push((false, hop, delay));
            (this.runtime.clone(), this.on_timeout)
        };
        if !advance.is_zero() {
            rt.allow_one_advance(advance);
        }
    }
    fn timeouts(&mut self, _action: &Action) -> (Duration, Duration) {
        (Duration::from_secs(3), Duration::from_secs(100))
    }
    fn learning_timeouts(&self) -> bool {
        false
    }
    fn update_params(&mut self, _params: &tor_netdir::params::NetParameters) {}

    fn build_state(&mut self) -> Option<crate::timeouts::pareto::ParetoTimeoutState> {
        None
    }
}

/// Testing only: create a bogus circuit target
fn circ_t(id: Ed25519Identity) -> OwnedCircTarget {
    let mut builder = OwnedCircTarget::builder();
    builder
        .chan_target()
        .ed_identity(id)
        .rsa_identity([0x20; 20].into());
    builder
        .ntor_onion_key([0x33; 32].into())
        .protocols("".parse().unwrap())
        .build()
        .unwrap()
}
/// Testing only: create a bogus channel target
fn chan_t(id: Ed25519Identity) -> OwnedChanTarget {
    OwnedChanTarget::builder()
        .ed_identity(id)
        .rsa_identity([0x20; 20].into())
        .build()
        .unwrap()
}

async fn run_builder_test(
    rt: tor_rtmock::MockRuntime,
    advance_initial: Duration,
    path: OwnedPath,
    advance_on_timeout: Option<(Duration, Duration)>,
    usage: ChannelUsage,
) -> (Result<FakeCirc>, Vec<(bool, u8, Duration)>) {
    let chanmgr = Arc::new(
        ChanMgr::new(
            rt.clone(),
            Default::default(),
            Default::default(),
            &Default::default(),
            ToplevelAccount::new_noop(),
        )
        .unwrap(),
    );
    // always has 3 second timeout, 100 second abandon.
    let timeouts = match advance_on_timeout {
        Some((d1, d2)) => TimeoutRecorder::with_delays(rt.clone(), d1, d2),
        None => TimeoutRecorder::new(rt.clone()),
    };
    let timeouts = Arc::new(Mutex::new(timeouts));
    let builder: Builder<_, Mutex<FakeCirc>> = Builder::new(
        rt.clone(),
        chanmgr,
        timeouts::Estimator::new(Arc::clone(&timeouts)),
    );

    rt.block_advance("manually controlling advances");
    rt.allow_one_advance(advance_initial);
    let outcome = rt.spawn_join("build-owned", async move {
        let arcbuilder = Arc::new(builder);
        let params = exit_circparams_from_netparams(&NetParameters::default())?;
        arcbuilder.build_owned(path, &params, gs(), usage).await
    });

    // Now we wait for a success to finally, finally be reported.
    if advance_on_timeout.is_some() {
        let receiver = { timeouts.lock().unwrap().rcv_success.take().unwrap() };
        rt.spawn_identified("receiver", async move {
            receiver.await.unwrap();
        });
    }
    rt.advance_until_stalled().await;

    let circ = outcome.map(|m| Ok(m?.lock().unwrap().clone())).await;
    let timeouts = timeouts.lock().unwrap().hist.clone();

    (circ, timeouts)
}

#[test]
fn build_onehop() {
    tor_rtmock::MockRuntime::test_with_various(|rt| async move {
        let id_100ms = key_from_timeouts(Duration::from_millis(100), Duration::from_millis(0));
        let path = OwnedPath::ChannelOnly(chan_t(id_100ms));

        let (outcome, timeouts) =
            run_builder_test(rt, Duration::from_millis(100), path, None, CU::UserTraffic).await;
        let circ = outcome.unwrap();
        assert!(circ.onehop);
        assert_eq!(circ.hops.len(), 1);
        assert!(circ.hops[0].same_relay_ids(&chan_t(id_100ms)));

        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0].0); // success
        assert_eq!(timeouts[0].1, 0); // one-hop
        assert_eq!(timeouts[0].2, Duration::from_millis(100));
    });
}

#[test]
fn build_threehop() {
    tor_rtmock::MockRuntime::test_with_various(|rt| async move {
        let id_100ms = key_from_timeouts(Duration::from_millis(100), Duration::from_millis(200));
        let id_200ms = key_from_timeouts(Duration::from_millis(200), Duration::from_millis(300));
        let id_300ms = key_from_timeouts(Duration::from_millis(300), Duration::from_millis(0));
        let path = OwnedPath::Normal(vec![circ_t(id_100ms), circ_t(id_200ms), circ_t(id_300ms)]);

        let (outcome, timeouts) =
            run_builder_test(rt, Duration::from_millis(100), path, None, CU::UserTraffic).await;
        let circ = outcome.unwrap();
        assert!(!circ.onehop);
        assert_eq!(circ.hops.len(), 3);
        assert!(circ.hops[0].same_relay_ids(&chan_t(id_100ms)));
        assert!(circ.hops[1].same_relay_ids(&chan_t(id_200ms)));
        assert!(circ.hops[2].same_relay_ids(&chan_t(id_300ms)));

        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0].0); // success
        assert_eq!(timeouts[0].1, 2); // three-hop
        assert_eq!(timeouts[0].2, Duration::from_millis(600));
    });
}

#[test]
fn build_huge_timeout() {
    tor_rtmock::MockRuntime::test_with_various(|rt| async move {
        let id_100ms = key_from_timeouts(Duration::from_millis(100), Duration::from_millis(200));
        let id_200ms = key_from_timeouts(Duration::from_millis(200), Duration::from_millis(2700));
        let id_hour = key_from_timeouts(Duration::from_secs(3600), Duration::from_secs(0));

        let path = OwnedPath::Normal(vec![circ_t(id_100ms), circ_t(id_200ms), circ_t(id_hour)]);

        let (outcome, timeouts) =
            run_builder_test(rt, Duration::from_millis(100), path, None, CU::UserTraffic).await;
        assert!(matches!(outcome, Err(Error::CircTimeout(_))));

        assert_eq!(timeouts.len(), 1);
        assert!(!timeouts[0].0); // timeout

        // BUG: Sometimes this is 1 and sometimes this is 2.
        // assert_eq!(timeouts[0].1, 2); // at third hop.
        assert_eq!(timeouts[0].2, Duration::from_millis(3000));
    });
}

#[test]
fn build_modest_timeout() {
    tor_rtmock::MockRuntime::test_with_various(|rt| async move {
        let id_100ms = key_from_timeouts(Duration::from_millis(100), Duration::from_millis(200));
        let id_200ms = key_from_timeouts(Duration::from_millis(200), Duration::from_millis(2700));
        let id_3sec = key_from_timeouts(Duration::from_millis(3000), Duration::from_millis(0));

        let timeout_advance = (Duration::from_millis(4000), Duration::from_secs(0));

        let path = OwnedPath::Normal(vec![circ_t(id_100ms), circ_t(id_200ms), circ_t(id_3sec)]);

        let (outcome, timeouts) = run_builder_test(
            rt.clone(),
            Duration::from_millis(100),
            path,
            Some(timeout_advance),
            CU::UserTraffic,
        )
        .await;
        assert!(matches!(outcome, Err(Error::CircTimeout(_))));

        assert_eq!(timeouts.len(), 2);
        assert!(!timeouts[0].0); // timeout

        // BUG: Sometimes this is 1 and sometimes this is 2.
        //assert_eq!(timeouts[0].1, 2); // at third hop.
        assert_eq!(timeouts[0].2, Duration::from_millis(3000));

        assert!(timeouts[1].0); // success
        assert_eq!(timeouts[1].1, 2); // three-hop
        // BUG: This timer is not always reliable, due to races.
        //assert_eq!(timeouts[1].2, Duration::from_millis(3300));
    });
}
