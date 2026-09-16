//! A general interface for Tor client usage.
//!
//! To construct a client, run the [`TorClient::create_bootstrapped`] method.
//! Once the client is bootstrapped, you can make anonymous
//! connections ("streams") over the Tor network using
//! [`TorClient::connect`].

#[cfg(feature = "rpc")]
use {derive_deftly::Deftly, tor_rpcbase::templates::*};

use crate::address::{IntoTorAddr, ResolveInstructions, StreamInstructions};

use crate::config::{ClientAddrConfig, StreamTimeoutConfig, TorClientConfig};
use crate::status::BootstrapStatus;
use safelog::{Sensitive, sensitive};
use tor_async_utils::{DropNotifyWatchSender, PostageWatchSenderExt};
use tor_chanmgr::ChanMgrConfig;
use tor_circmgr::ClientDataTunnel;
use tor_circmgr::isolation::{Isolation, StreamIsolation};
use tor_circmgr::{IsolationToken, TargetPort, isolation::StreamIsolationBuilder};
use tor_config::MutCfg;
#[cfg(feature = "bridge-client")]
use tor_dirmgr::bridgedesc::BridgeDescMgr;
use tor_dirmgr::{DirMgrStore, Timeliness};
use tor_error::{Bug, error_report, internal};
use tor_guardmgr::{GuardMgr, RetireCircuits};
use tor_keymgr::Keystore;
use tor_memquota::MemoryQuotaTracker;
use tor_netdir::{NetDirProvider, params::NetParameters};
use tor_persist::StateMgr;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tor_persist::TestingStateMgr;
#[cfg(feature = "onion-service-service")]
use tor_persist::state_dir::StateDirectory;
use tor_proto::client::stream::{DataStream, IpVersionPreference, StreamParameters};
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio"),
))]
use tor_rtcompat::PreferredRuntime;
use tor_rtcompat::{Runtime, SleepProviderExt};
#[cfg(feature = "onion-service-client")]
use {
    tor_config::BoolOrAuto,
    tor_hsclient::{HsClientConnector, HsClientDescEncKeypairSpecifier, HsClientSecretKeysBuilder},
    tor_hscrypto::pk::{HsClientDescEncKey, HsClientDescEncKeypair, HsClientDescEncSecretKey},
    tor_netdir::DirEvent,
};

#[cfg(all(feature = "onion-service-service", feature = "experimental-api"))]
use tor_hsservice::HsIdKeypairSpecifier;
#[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
use {tor_hscrypto::pk::HsId, tor_hscrypto::pk::HsIdKeypair, tor_keymgr::KeystoreSelector};

use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, config::ArtiKeystoreKind};

#[cfg(feature = "ephemeral-keystore")]
use tor_keymgr::ArtiEphemeralKeystore;

#[cfg(feature = "ctor-keystore")]
use tor_keymgr::{CTorClientKeystore, CTorServiceKeystore};

use futures::StreamExt as _;
use futures::lock::Mutex as AsyncMutex;
use std::net::IpAddr;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use tor_rtcompat::SpawnExt;

use crate::err::ErrorDetail;
use crate::{TorClientBuilder, status, util};
#[cfg(feature = "geoip")]
use tor_geoip::CountryCode;
use tor_rtcompat::scheduler::TaskHandle;
use tracing::{debug, info, instrument};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tor_persist::FsStateMgr as UsingStateMgr;

// TODO wasm: This is not the right choice, but at least it compiles.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tor_persist::TestingStateMgr as UsingStateMgr;

/// An active client session on the Tor network.
///
/// While it's running, it will fetch directory information, build
/// circuits, and make connections for you.
///
/// # In the Arti RPC System
///
/// An open client on the Tor network.
///
/// A `TorClient` can be used to open anonymous connections,
/// and (eventually) perform other activities.
///
/// You can use an `RpcSession` as a `TorClient`, or use the `isolated_client` method
/// to create a new `TorClient` whose stream will not share circuits with any other Tor client.
///
/// This ObjectID for this object can be used as the target of a SOCKS stream.
#[cfg_attr(
    feature = "rpc",
    derive(Deftly),
    derive_deftly(Object),
    deftly(rpc(expose_outside_of_session))
)]
pub struct TorClient<R: Runtime> {
    /// Default isolation token for streams through this client.
    ///
    /// This is eventually used for `owner_token` in `tor-circmgr/src/usage.rs`, and is orthogonal
    /// to the `stream_isolation` which comes from `connect_prefs` (or a passed-in `StreamPrefs`).
    /// (ie, both must be the same to share a circuit).
    client_isolation: IsolationToken,
    /// Connection preferences.  Starts out as `Default`,  Inherited by our clones.
    connect_prefs: StreamPrefs,

    /// Inner structure respresenting all components shared across different
    /// TorClients.
    client: Arc<ClientShared<R>>,
}

/// Shared pieces of a `TorClient`, used to implement client functionality.
///
/// In the future, we might choose to expose this along with APIs.
struct ClientShared<R: Runtime> {
    /// Asynchronous runtime object.
    runtime: R,

    /// Inner typestate object to represent the parts of the ClientShared that may be absent
    /// depending on whether we are running.
    inner: Mutex<Inner<R>>,

    /// Memory quota tracker
    memquota: Arc<MemoryQuotaTracker>,

    /// A handle to this client's [`InertTorClient`].
    ///
    /// Used for accessing the key manager and other persistent state.
    inert_client: InertTorClient,

    /// Location on disk where we store persistent data containing both location and Mistrust information.
    ///
    ///
    /// This path is configured via `[storage]` in the config but is not used directly as a
    /// StateDirectory in most places. Instead, its path and Mistrust information are copied
    /// to subsystems like `dirmgr`, `keymgr`, and `statemgr` during `TorClient` creation.
    #[cfg(feature = "onion-service-service")]
    state_directory: StateDirectory,
    /// Location on disk where we store persistent data (cooked state manager).
    statemgr: UsingStateMgr,

    /// Directory manager persistent storage.
    dirmgr_store: DirMgrStore<R>,

    /// Client address configuration
    addrcfg: MutCfg<ClientAddrConfig>,
    /// Client DNS configuration
    timeoutcfg: MutCfg<StreamTimeoutConfig>,
    /// Mutex used to serialize concurrent attempts to reconfigure a TorClient.
    ///
    /// See [`TorClient::reconfigure`] for more information on its use.
    reconfigure_lock: Arc<Mutex<()>>,

    /// A stream of bootstrap messages that we can clone when a client asks for
    /// it.
    ///
    /// (We don't need to observe this stream ourselves, since it drops each
    /// unobserved status change when the next status change occurs.)
    status_receiver: status::BootstrapEvents,

    /// mutex used to prevent two tasks from trying to bootstrap at once.
    bootstrap_in_progress: AsyncMutex<()>,

    /// Whether or not we should call `bootstrap` before doing things that require
    /// bootstrapping. If this is `false`, we will just call `wait_for_bootstrap`
    /// instead.
    should_bootstrap: BootstrapBehavior,

    /// Shared boolean for whether we're currently in "dormant mode" or not.
    //
    // The sent value is `Option`, so that `None` is sent when the sender, here,
    // is dropped,.  That shuts down the monitoring task.
    dormant: Mutex<DropNotifyWatchSender<Option<DormantMode>>>,

    /// The path resolver given to us by a [`TorClientConfig`].
    ///
    /// We must not add our own variables to it since `TorClientConfig` uses it to perform its own
    /// path expansions. If we added our own variables, it would introduce an inconsistency where
    /// paths expanded by the `TorClientConfig` would expand differently than when expanded by us.
    path_resolver: Arc<tor_config_path::CfgPathResolver>,
}

/// A typestate object holding the parts of the client state that we may or may not have
/// depending on whether we are running.
enum Inner<R: Runtime> {
    /// The client is not constructed.
    ///
    /// In this state, the client won't try to connect to the network.
    NotConstructed(Box<NotConstructedInner<R>>),

    /// The client is either bootstrapped or trying to bootstrap.
    Running(Arc<RunningInner<R>>),

    /// The client has failed in a non-recoverable way.
    Poisoned(Box<ErrorDetail>),
}

/// Information stored by a never-bootstrapped [`TorClient`],
/// used to eventually construct a [`RunningInner`] and bootstrap.
struct NotConstructedInner<R: Runtime> {
    /// The client's configuration.
    config: TorClientConfig,

    /// A receiver to give to various tasks that want to monitor our dormant status.
    dormant_recv: postage::watch::Receiver<Option<DormantMode>>,

    /// A sender used to produce updates about our bootstrapping status.
    ///
    /// NOTE: The fact that this type is not Clone is the only reason
    /// that [`RunningInner::new`] needs to take NotConstructedInner by value.
    /// With some redesign we could simplify this, and do away with [`Inner::Poisoned`].
    status_sender: postage::watch::Sender<BootstrapStatus>,

    /// A (possibly user-provided) builder used to construct our NetDirProvider.
    dirmgr_builder: Arc<dyn crate::builder::DirProviderBuilder<R>>,

    /// A (possibly user-provided) set of in-process extensions for our NetDirProvider.
    dirmgr_extensions: tor_dirmgr::config::DirMgrExtensions,

    /// tor-socks5 local patch: optional observability hook invoked
    /// immediately before Arti's intentional protocol-mismatch shutdown.
    fatal_protocol_error_handler: Option<Arc<dyn crate::builder::FatalProtocolErrorHandler>>,
}

/// Data structures for a "running" client.
///
/// A running client is one that is either bootstrapped, or potentially trying to bootstrap.
///
/// All structures that potentially interact with the network belong here.
///
/// We defer the creation of this structure and its members until bootstrap time,
/// to make sure that before we are bootstrapping, nothing will try to connect to the network
/// or launch expensive background tasks.
struct RunningInner<R: Runtime> {
    /// Channel manager, used by circuits etc.,
    ///
    /// Used directly by client only for reconfiguration.
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<tor_circmgr::CircMgr<R>>,
    /// Directory manager for keeping our directory material up to date.
    dirmgr: Arc<dyn tor_dirmgr::DirProvider>,
    /// Bridge descriptor manager
    ///
    /// None until we have bootstrapped.
    ///
    /// Lock hierarchy: don't acquire this before dormant
    //
    // TODO: after or as part of https://gitlab.torproject.org/tpo/core/arti/-/issues/634
    // this can be   bridge_desc_mgr: BridgeDescMgr<R>>
    // since BridgeDescMgr is Clone and all its methods take `&self` (it has a lock inside)
    // Or maybe BridgeDescMgr should not be Clone, since we want to make Weaks of it,
    // which we can't do when the Arc is inside.
    #[cfg(feature = "bridge-client")]
    bridge_desc_mgr: Arc<Mutex<Option<Arc<BridgeDescMgr<R>>>>>,
    /// Pluggable transport manager.
    #[cfg(feature = "pt-client")]
    pt_mgr: Arc<tor_ptmgr::PtMgr<R>>,
    /// HS client connector
    #[cfg(feature = "onion-service-client")]
    hsclient: HsClientConnector<R>,
    /// Circuit pool for providing onion services with circuits.
    #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
    hs_circ_pool: Arc<tor_circmgr::hspool::HsCircPool<R>>,
    /// Guard manager
    #[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
    guardmgr: GuardMgr<R>,
}

/// A Tor client that is not runnable.
///
/// Can be used to access the state that would be used by a running [`TorClient`].
///
/// An `InertTorClient` never connects to the network.
#[derive(Clone)]
pub struct InertTorClient {
    /// The key manager.
    ///
    /// This is used for retrieving private keys, certificates, and other sensitive data (for
    /// example, for retrieving the keys necessary for connecting to hidden services that are
    /// running in restricted discovery mode).
    ///
    /// If this crate is compiled _with_ the `keymgr` feature, [`TorClient`] will use a functional
    /// key manager implementation.
    ///
    /// If this crate is compiled _without_ the `keymgr` feature, then [`TorClient`] will use a
    /// no-op key manager implementation instead.
    ///
    /// See the [`KeyMgr`] documentation for more details.
    keymgr: Option<Arc<KeyMgr>>,
}

impl InertTorClient {
    /// Create an `InertTorClient` from a `TorClientConfig`.
    pub(crate) fn new(config: &TorClientConfig) -> StdResult<Self, ErrorDetail> {
        let keymgr = Self::create_keymgr(config)?;

        Ok(Self { keymgr })
    }

    /// Create a [`KeyMgr`] using the specified configuration.
    ///
    /// Returns `Ok(None)` if keystore use is disabled.
    fn create_keymgr(config: &TorClientConfig) -> StdResult<Option<Arc<KeyMgr>>, ErrorDetail> {
        let keystore = config.storage.keystore();
        let permissions = config.storage.permissions();
        let primary_store: Box<dyn Keystore> = match keystore.primary_kind() {
            Some(ArtiKeystoreKind::Native) => {
                let (state_dir, _mistrust) = config.state_dir()?;
                let key_store_dir = state_dir.join("keystore");

                let native_store =
                    ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, permissions)?;
                // Should only log fs paths at debug level or lower,
                // unless they're part of a diagnostic message.
                debug!("Using keystore from {key_store_dir:?}");

                Box::new(native_store)
            }
            #[cfg(feature = "ephemeral-keystore")]
            Some(ArtiKeystoreKind::Ephemeral) => {
                // TODO: make the keystore ID somehow configurable
                let ephemeral_store: ArtiEphemeralKeystore =
                    ArtiEphemeralKeystore::new("ephemeral".to_string());
                Box::new(ephemeral_store)
            }
            None => {
                info!("Running without a keystore");
                return Ok(None);
            }
            ty => return Err(internal!("unrecognized keystore type {ty:?}").into()),
        };

        let mut builder = KeyMgrBuilder::default().primary_store(primary_store);

        #[cfg(feature = "ctor-keystore")]
        for config in config.storage.keystore().ctor_svc_stores() {
            let store: Box<dyn Keystore> = Box::new(CTorServiceKeystore::from_path_and_mistrust(
                config.path(),
                permissions,
                config.id().clone(),
                // TODO: these nicknames should be cross-checked with configured
                // svc nicknames as part of config validation!!!
                config.nickname().clone(),
            )?);

            builder.secondary_stores().push(store);
        }

        #[cfg(feature = "ctor-keystore")]
        for config in config.storage.keystore().ctor_client_stores() {
            let store: Box<dyn Keystore> = Box::new(CTorClientKeystore::from_path_and_mistrust(
                config.path(),
                permissions,
                config.id().clone(),
            )?);

            builder.secondary_stores().push(store);
        }

        let keymgr = builder
            .build()
            .map_err(|_| internal!("failed to build keymgr"))?;
        Ok(Some(Arc::new(keymgr)))
    }

    /// Generate a service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// See [`TorClient::generate_service_discovery_key`].
    //
    // TODO: decide whether this should use get_or_generate before making it
    // non-experimental
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn generate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        let mut rng = tor_llcrypto::rng::CautiousRng;
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "generate client service discovery key",
            })?
            .generate::<HsClientDescEncKeypair>(
                &spec, selector, &mut rng, false, /* overwrite */
            )?;

        Ok(key.public().clone())
    }

    /// Rotate the service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// See [`TorClient::rotate_service_discovery_key`].
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    pub fn rotate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        let mut rng = tor_llcrypto::rng::CautiousRng;
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "rotate client service discovery key",
            })?
            .generate::<HsClientDescEncKeypair>(
                &spec, selector, &mut rng, true, /* overwrite */
            )?;

        Ok(key.public().clone())
    }

    /// Insert a service discovery secret key for connecting to a hidden service running in
    /// "restricted discovery" mode
    ///
    /// See [`TorClient::insert_service_discovery_key`].
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn insert_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
        hs_client_desc_enc_secret_key: HsClientDescEncSecretKey,
    ) -> crate::Result<HsClientDescEncKey> {
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let client_desc_enc_key = HsClientDescEncKey::from(&hs_client_desc_enc_secret_key);
        let client_desc_enc_keypair =
            HsClientDescEncKeypair::new(client_desc_enc_key.clone(), hs_client_desc_enc_secret_key);
        let _key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "insert client service discovery key",
            })?
            .insert::<HsClientDescEncKeypair>(client_desc_enc_keypair, &spec, selector, false)?;
        Ok(client_desc_enc_key)
    }

    /// Return the service discovery public key for the service with the specified `hsid`.
    ///
    /// See [`TorClient::get_service_discovery_key`].
    #[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "onion-service-client", feature = "experimental-api")))
    )]
    pub fn get_service_discovery_key(
        &self,
        hsid: HsId,
    ) -> crate::Result<Option<HsClientDescEncKey>> {
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "get client service discovery key",
            })?
            .get::<HsClientDescEncKeypair>(&spec)?
            .map(|key| key.public().clone());

        Ok(key)
    }

    /// Removes the service discovery keypair for the service with the specified `hsid`.
    ///
    /// See [`TorClient::remove_service_discovery_key`].
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn remove_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<Option<()>> {
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let result = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "remove client service discovery key",
            })?
            .remove::<HsClientDescEncKeypair>(&spec, selector)?;
        match result {
            Some(_) => Ok(Some(())),
            None => Ok(None),
        }
    }

    /// Getter for keymgr.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn keymgr(&self) -> crate::Result<&KeyMgr> {
        Ok(self.keymgr.as_ref().ok_or(ErrorDetail::KeystoreRequired {
            action: "get key manager handle",
        })?)
    }

    /// Create (but do not launch) a new
    /// [`OnionService`](tor_hsservice::OnionService)
    /// using the given configuration.
    ///
    /// See [`TorClient::create_onion_service`].
    #[cfg(feature = "onion-service-service")]
    #[instrument(skip_all, level = "trace")]
    pub fn create_onion_service(
        &self,
        config: &TorClientConfig,
        svc_config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<tor_hsservice::OnionService> {
        let keymgr = self.keymgr.as_ref().ok_or(ErrorDetail::KeystoreRequired {
            action: "create onion service",
        })?;

        let (state_dir, mistrust) = config.state_dir()?;
        let state_dir =
            self::StateDirectory::new(state_dir, mistrust).map_err(ErrorDetail::StateAccess)?;

        Ok(tor_hsservice::OnionService::builder()
            .config(svc_config)
            .keymgr(keymgr.clone())
            .state_dir(state_dir)
            .build()
            .map_err(ErrorDetail::OnionServiceSetup)?)
    }
}

/// Preferences for whether a [`TorClient`] should bootstrap on its own or not.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootstrapBehavior {
    /// Bootstrap the client automatically when requests are made that require the client to be
    /// bootstrapped.
    #[default]
    OnDemand,
    /// Make no attempts to automatically bootstrap. [`TorClient::bootstrap`] must be manually
    /// invoked in order for the [`TorClient`] to become useful.
    ///
    /// Attempts to use the client (e.g. by creating connections or resolving hosts over the Tor
    /// network) before calling [`bootstrap`](TorClient::bootstrap) will fail, and
    /// return an error that has kind [`ErrorKind::BootstrapRequired`](crate::ErrorKind::BootstrapRequired).
    Manual,
}

/// What level of sleep to put a Tor client into.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DormantMode {
    /// The client functions as normal, and background tasks run periodically.
    #[default]
    Normal,
    /// Background tasks are suspended, conserving CPU usage. Attempts to use the client will
    /// wake it back up again.
    Soft,
}

/// Preferences for how to route a stream over the Tor network.
#[derive(Debug, Default, Clone)]
pub struct StreamPrefs {
    /// What kind of IPv6/IPv4 we'd prefer, and how strongly.
    ip_ver_pref: IpVersionPreference,
    /// How should we isolate connection(s)?
    isolation: StreamIsolationPreference,
    /// Whether to return the stream optimistically.
    optimistic_stream: bool,
    // TODO GEOIP Ideally this would be unconditional, with CountryCode maybe being Void
    // This probably applies in many other places, so probably:   git grep 'cfg.*geoip'
    // and consider each one with a view to making it unconditional.  Background:
    //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1537#note_2935256
    //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1537#note_2942214
    #[cfg(feature = "geoip")]
    /// A country to restrict the exit relay's location to.
    country_code: Option<CountryCode>,
    /// Whether to try to make connections to onion services.
    ///
    /// `Auto` means to use the client configuration.
    #[cfg(feature = "onion-service-client")]
    pub(crate) connect_to_onion_services: BoolOrAuto,
}

/// Record of how we are isolating connections
#[derive(Debug, Default, Clone)]
enum StreamIsolationPreference {
    /// No additional isolation
    #[default]
    None,
    /// Isolation parameter to use for connections
    Explicit(Box<dyn Isolation>),
    /// Isolate every connection!
    EveryStream,
}

impl From<DormantMode> for tor_chanmgr::Dormancy {
    fn from(dormant: DormantMode) -> tor_chanmgr::Dormancy {
        match dormant {
            DormantMode::Normal => tor_chanmgr::Dormancy::Active,
            DormantMode::Soft => tor_chanmgr::Dormancy::Dormant,
        }
    }
}
#[cfg(feature = "bridge-client")]
impl From<DormantMode> for tor_dirmgr::bridgedesc::Dormancy {
    fn from(dormant: DormantMode) -> tor_dirmgr::bridgedesc::Dormancy {
        match dormant {
            DormantMode::Normal => tor_dirmgr::bridgedesc::Dormancy::Active,
            DormantMode::Soft => tor_dirmgr::bridgedesc::Dormancy::Dormant,
        }
    }
}

/// Client construction and stream preferences.
mod bootstrap;
pub(crate) use bootstrap::notify_fatal_protocol_error;
/// Client reconfiguration and stream operations.
mod operations;
/// Exit stream-open timeout selection and bounded retry policy.
mod stream_retry;
use stream_retry::{retry_exit_stream, retryable_stream_error, snapshot_exit_stream_timeouts};
impl<R: Runtime> ClientShared<R> {
    /// Used by `bootstrap_inner`: Return a `RunningInner`, constructing it if necessary.
    fn instantiate_running_inner(
        &self,
        mut inner_guard: std::sync::MutexGuard<'_, Inner<R>>,
    ) -> Result<Arc<RunningInner<R>>, ErrorDetail> {
        match &*inner_guard {
            Inner::Running(running_inner) => Ok(Arc::clone(running_inner)),
            Inner::Poisoned(e) => Err(e.as_ref().clone()),
            Inner::NotConstructed(_) => {
                let error = ErrorDetail::from(internal!("Client under construction"));
                let mut pending = Inner::Poisoned(Box::new(error));
                std::mem::swap(&mut pending, &mut *inner_guard);
                let Inner::NotConstructed(pending) = pending else {
                    panic!("Surprising type change");
                };
                match RunningInner::new(*pending, self) {
                    Ok(running_inner) => {
                        *inner_guard = Inner::Running(Arc::clone(&running_inner));
                        Ok(running_inner)
                    }
                    Err(e) => {
                        *inner_guard = Inner::Poisoned(Box::new(e.clone()));
                        Err(e)
                    }
                }
            }
        }
    }

    /// Implementation of `bootstrap`, split out in order to avoid manually specifying
    /// double error conversions.
    async fn bootstrap_inner(&self) -> StdResult<(), ErrorDetail> {
        // Wait for an existing bootstrap attempt to finish first.
        //
        // This is a futures::lock::Mutex, so it's okay to await while we hold it.
        let _bootstrap_lock = self.bootstrap_in_progress.lock().await;

        let running = self.instantiate_running_inner(self.inner.lock().expect("lock poisoned"))?;

        // Make sure we have a bridge descriptor manager, which is active iff required
        #[cfg(feature = "bridge-client")]
        {
            let mut dormant = self.dormant.lock().expect("dormant lock poisoned");
            let dormant = dormant.borrow();
            let dormant = dormant.ok_or_else(|| internal!("dormant dropped"))?.into();

            let mut bdm = running.bridge_desc_mgr.lock().expect("bdm lock poisoned");
            if bdm.is_none() {
                let new_bdm = Arc::new(BridgeDescMgr::new(
                    &Default::default(),
                    self.runtime.clone(),
                    self.dirmgr_store.clone(),
                    running.circmgr.clone(),
                    dormant,
                )?);
                running
                    .guardmgr
                    .install_bridge_desc_provider(&(new_bdm.clone() as _))
                    .map_err(ErrorDetail::GuardMgrSetup)?;
                // If ^ that fails, we drop the BridgeDescMgr again.  It may do some
                // work but will hopefully eventually quit.
                *bdm = Some(new_bdm);
            }
        }

        if self
            .statemgr
            .try_lock()
            .map_err(ErrorDetail::StateAccess)?
            .held()
        {
            debug!("It appears we have the lock on our state files.");
        } else {
            info!(
                "Another process has the lock on our state files. We'll proceed in read-only mode."
            );
        }

        // If we fail to bootstrap (i.e. we return before the disarm() point below), attempt to
        // unlock the state files.
        let unlock_guard = util::StateMgrUnlockGuard::new(&self.statemgr);

        running
            .dirmgr
            .bootstrap()
            .await
            .map_err(ErrorDetail::DirMgrBootstrap)?;

        // Since we succeeded, disarm the unlock guard.
        unlock_guard.disarm();

        Ok(())
    }

    /// Ensure that this client is running and bootstrapped, and return a [`RunningInner`] if it is.
    ///
    /// If we're not bootstrapped,
    /// we either try to bootstrap or return an error,
    /// depending on `self.should_bootstrap`:
    ///
    /// ## For `BootstrapBehavior::OnDemand` clients
    ///
    /// Initiate a bootstrap by calling `bootstrap_inner`
    /// (which is idempotent, so attempts to bootstrap twice will just do nothing).
    ///
    /// ## For `BootstrapBehavior::Manual` clients
    ///
    /// Check whether a bootstrap is in progress; if one is, wait until it finishes.
    /// Then see whether we're bootstrapped, and return either a success or a failure.
    #[instrument(skip_all, level = "trace")]
    async fn wait_for_bootstrap_running(
        &self,
        action: &'static str,
    ) -> StdResult<Arc<RunningInner<R>>, ErrorDetail> {
        match self.should_bootstrap {
            BootstrapBehavior::OnDemand => {
                self.bootstrap_inner().await?;
            }
            BootstrapBehavior::Manual => {
                // Grab the lock, and immediately release it.  That will ensure that nobody else is trying to bootstrap.
                self.bootstrap_in_progress.lock().await;
            }
        }
        self.dormant
            .lock()
            .map_err(|_| internal!("dormant poisoned"))?
            .try_maybe_send(|dormant| {
                Ok::<_, Bug>(Some({
                    match dormant.ok_or_else(|| internal!("dormant dropped"))? {
                        DormantMode::Soft => DormantMode::Normal,
                        other @ DormantMode::Normal => other,
                    }
                }))
            })?;
        self.running_inner(action)
    }

    /// If we are currently bootstrapping or running, return a [`RunningInner`].
    fn running_inner(&self, action: &'static str) -> StdResult<Arc<RunningInner<R>>, ErrorDetail> {
        let guard = self.inner.lock().expect("Lock poisoned");
        match &*guard {
            Inner::NotConstructed(_) => Err(ErrorDetail::BootstrapRequired { action }),
            Inner::Running(running_inner) => Ok(Arc::clone(running_inner)),
            Inner::Poisoned(e) => Err(e.as_ref().clone()),
        }
    }

    /// Ensure that our bootstrap state is [`RunningInner`], if possible.
    ///
    /// Return an error if our [`BootstrapBehavior`] is `Manual` and have not created a
    /// [`RunningInner`].
    fn initiate_bootstrap_if_needed(
        &self,
        action: &'static str,
    ) -> StdResult<Arc<RunningInner<R>>, ErrorDetail> {
        let guard = self.inner.lock().expect("Lock poisoned");
        match &*guard {
            Inner::Running(running_inner) => Ok(Arc::clone(running_inner)),
            Inner::Poisoned(e) => Err(e.as_ref().clone()),
            Inner::NotConstructed(_) => match self.should_bootstrap {
                BootstrapBehavior::Manual => Err(ErrorDetail::BootstrapRequired { action }),
                BootstrapBehavior::OnDemand => self.instantiate_running_inner(guard),
            },
        }
    }

    /// This is split out from `reconfigure` so we can do the all-or-nothing
    /// check without recursion. the caller to this method must hold the
    /// `reconfigure_lock`.
    #[instrument(level = "trace", skip_all)]
    fn reconfigure_inner(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
        _reconfigure_lock_guard: &std::sync::MutexGuard<'_, ()>,
    ) -> crate::Result<()> {
        // We ignore 'new_config.path_resolver' here since CfgPathResolver does not impl PartialEq
        // and we have no way to compare them, but this field is explicitly documented as being
        // non-reconfigurable anyways.
        let addr_cfg = &new_config.address_filter;
        let timeout_cfg = &new_config.stream_timeouts;
        let state_cfg = new_config
            .storage
            .expand_state_dir(&self.path_resolver)
            .map_err(wrap_err)?;

        // TODO wasm: This ins't really how things should be long term,
        // but once we have a more generic notion of configuring storage
        // we can change this to comply with it.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            if state_cfg != self.statemgr.path() {
                how.cannot_change("storage.state_dir").map_err(wrap_err)?;
            }
        }

        self.memquota
            .reconfigure(new_config.system.memory.clone(), how)
            .map_err(wrap_err)?;

        let mut inner_lock = self.inner.lock().expect("Lock poisoned");
        match &mut *inner_lock {
            Inner::Poisoned(e) => return Err(e.as_ref().clone().into()),
            Inner::NotConstructed(nc) => nc.reconfigure(new_config, how)?,
            Inner::Running(r) => {
                let running = Arc::clone(r);
                drop(inner_lock);
                running.reconfigure(new_config, how)?;
            }
        }
        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        self.addrcfg.replace(addr_cfg.clone());
        self.timeoutcfg.replace(timeout_cfg.clone());

        Ok(())
    }
}

/// Monitor `dormant_mode` and enable/disable periodic tasks as applicable
///
/// This function is spawned as a task during client construction.
// TODO should this perhaps be done by each TaskHandle?
async fn tasks_monitor_dormant<R: Runtime>(
    mut dormant_rx: postage::watch::Receiver<Option<DormantMode>>,
    netdir: Arc<dyn NetDirProvider>,
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    #[cfg(feature = "bridge-client")] bridge_desc_mgr: Arc<Mutex<Option<Arc<BridgeDescMgr<R>>>>>,
    periodic_task_handles: Vec<TaskHandle>,
) {
    while let Some(Some(mode)) = dormant_rx.next().await {
        let netparams = netdir.params();

        chanmgr
            .set_dormancy(mode.into(), netparams)
            .unwrap_or_else(|e| error_report!(e, "couldn't set dormancy"));

        // IEFI simplifies handling of exceptional cases, as "never mind, then".
        #[cfg(feature = "bridge-client")]
        (|| {
            let mut bdm = bridge_desc_mgr.lock().ok()?;
            let bdm = bdm.as_mut()?;
            bdm.set_dormancy(mode.into());
            Some(())
        })();

        let is_dormant = matches!(mode, DormantMode::Soft);

        for task in periodic_task_handles.iter() {
            if is_dormant {
                task.cancel();
            } else {
                task.fire();
            }
        }
    }
}

/// Alias for TorError::from(Error)
pub(crate) fn wrap_err<T>(err: T) -> crate::Error
where
    ErrorDetail: From<T>,
{
    ErrorDetail::from(err).into()
}

#[cfg(test)]
#[path = "client/tests.rs"]
mod test;
