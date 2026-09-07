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
use mocks::FakeBuilder;
use tor_guardmgr::GuardMgr;
use tor_linkspec::OwnedChanTarget;
use tor_netdir::testprovider::TestNetDirProvider;
use tor_persist::TestingStateMgr;

use super::*;

#[test]
fn get_params() {
    use tor_netdir::{MdReceiver, PartialNetDir};
    use tor_netdoc::doc::netstatus::NetParams;
    // If it's just fallbackdir, we get the default parameters.
    let fb = FallbackList::from([]);
    let di: DirInfo<'_> = (&fb).into();

    let p1 = di.circ_params(&TargetTunnelUsage::Dir).unwrap();
    assert!(!p1.extend_by_ed25519_id);

    // Now try with a directory and configured parameters.
    let (consensus, microdescs) = tor_netdir::testnet::construct_network().unwrap();
    let mut params = NetParams::default();
    params.set("circwindow".into(), 100);
    params.set("ExtendByEd25519ID".into(), 1);
    let mut dir = PartialNetDir::new(consensus, Some(&params));
    for m in microdescs {
        dir.add_microdesc(m);
    }
    let netdir = dir.unwrap_if_sufficient().unwrap();
    let di: DirInfo<'_> = (&netdir).into();
    let p2 = di.circ_params(&TargetTunnelUsage::Dir).unwrap();
    assert!(p2.extend_by_ed25519_id);

    // Now try with a bogus circwindow value.
    let (consensus, microdescs) = tor_netdir::testnet::construct_network().unwrap();
    let mut params = NetParams::default();
    params.set("circwindow".into(), 100_000);
    params.set("ExtendByEd25519ID".into(), 1);
    let mut dir = PartialNetDir::new(consensus, Some(&params));
    for m in microdescs {
        dir.add_microdesc(m);
    }
    let netdir = dir.unwrap_if_sufficient().unwrap();
    let di: DirInfo<'_> = (&netdir).into();
    let p2 = di.circ_params(&TargetTunnelUsage::Dir).unwrap();
    assert!(p2.extend_by_ed25519_id);
}

fn make_circmgr<R: Runtime>(runtime: R) -> Arc<CircMgrInner<FakeBuilder<R>, R>> {
    let config = crate::config::test_config::TestConfig::default();
    let statemgr = TestingStateMgr::new();
    let guardmgr =
        GuardMgr::new(runtime.clone(), statemgr.clone(), &config).expect("Create GuardMgr");
    let builder = FakeBuilder::new(
        &runtime,
        statemgr.clone(),
        &tor_guardmgr::TestConfig::default(),
    );
    let circmgr = Arc::new(CircMgrInner::new_generic(
        &config, &runtime, &guardmgr, builder,
    ));
    let netdir = Arc::new(TestNetDirProvider::new());
    CircMgrInner::launch_background_tasks(&circmgr, &runtime, &netdir, statemgr)
        .expect("launch CircMgrInner background tasks");
    circmgr
}

#[test]
#[cfg(feature = "hs-common")]
fn test_launch_hs_unmanaged() {
    tor_rtmock::MockRuntime::test_with_various(|runtime| async move {
        let circmgr = make_circmgr(runtime.clone());
        let netdir = tor_netdir::testnet::construct_netdir()
            .unwrap_if_sufficient()
            .unwrap();

        let (ret_tx, ret_rx) = tor_async_utils::oneshot::channel();
        runtime.spawn_identified("launch_hs_unamanged", async move {
            ret_tx
                .send(
                    circmgr
                        .launch_hs_unmanaged::<OwnedChanTarget>(
                            None,
                            &netdir,
                            HsCircStemKind::Naive,
                            None,
                        )
                        .await,
                )
                .unwrap();
        });
        runtime.advance_by(Duration::from_millis(60)).await;
        ret_rx.await.unwrap().unwrap();
    });
}
