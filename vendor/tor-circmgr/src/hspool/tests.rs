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
#![allow(clippy::cognitive_complexity)]

use tor_config::ExplicitOrAuto;
#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::VanguardConfigBuilder;
use tor_guardmgr::VanguardMode;
use tor_memquota::ArcMemoryQuotaTrackerExt as _;
use tor_proto::memquota::ToplevelAccount;
use tor_rtmock::MockRuntime;

use super::*;
use crate::{CircMgrInner, TestConfig};

/// Create a `CircMgr` with an underlying `VanguardMgr` that runs in the specified `mode`.
fn circmgr_with_vanguards<R: Runtime>(
    runtime: R,
    mode: VanguardMode,
) -> Arc<CircMgrInner<crate::build::TunnelBuilder<R>, R>> {
    let chanmgr = tor_chanmgr::ChanMgr::new(
        runtime.clone(),
        Default::default(),
        tor_chanmgr::Dormancy::Dormant,
        &Default::default(),
        ToplevelAccount::new_noop(),
    )
    .unwrap();
    let guardmgr = tor_guardmgr::GuardMgr::new(
        runtime.clone(),
        tor_persist::TestingStateMgr::new(),
        &tor_guardmgr::TestConfig::default(),
    )
    .unwrap();

    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    let vanguard_config = VanguardConfigBuilder::default()
        .mode(ExplicitOrAuto::Explicit(mode))
        .build()
        .unwrap();

    let config = TestConfig {
        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        vanguard_config,
        ..Default::default()
    };

    CircMgrInner::new(
        &config,
        tor_persist::TestingStateMgr::new(),
        &runtime,
        Arc::new(chanmgr),
        &guardmgr,
    )
    .unwrap()
    .into()
}

// Prevents TROVE-2024-005 (arti#1424)
#[test]
fn pool_with_vanguards_disabled() {
    MockRuntime::test_with_various(|runtime| async move {
        let circmgr = circmgr_with_vanguards(runtime, VanguardMode::Disabled);
        let circpool = HsCircPoolInner::new_internal(&circmgr);
        assert!(circpool.vanguard_mode() == VanguardMode::Disabled);
    });
}

#[test]
#[cfg(all(feature = "vanguards", feature = "hs-common"))]
fn pool_with_vanguards_enabled() {
    MockRuntime::test_with_various(|runtime| async move {
        for mode in [VanguardMode::Lite, VanguardMode::Full] {
            let circmgr = circmgr_with_vanguards(runtime.clone(), mode);
            let circpool = HsCircPoolInner::new_internal(&circmgr);
            assert!(circpool.vanguard_mode() == mode);
        }
    });
}
