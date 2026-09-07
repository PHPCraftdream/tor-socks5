//! Implementation for the primary directory state machine.
//!
//! There are three (active) states that a download can be in: looking
//! for a consensus ([`GetConsensusState`]), looking for certificates
//! to validate that consensus ([`GetCertsState`]), and looking for
//! microdescriptors ([`GetMicrodescsState`]).
//!
//! These states have no contact with the network, and are purely
//! reactive to other code that drives them.  See the
//! [`bootstrap`](crate::bootstrap) module for functions that actually
//! load or download directory information.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::mem;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tor_basic_utils::RngExt as _;
use tor_dircommon::retry::DownloadSchedule;
use tor_error::{internal, warn_report};
use tor_netdir::{MdReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::UncheckedAuthCert;
use tor_netdoc::doc::netstatus::{Lifetime, ProtoStatuses};
use tracing::{debug, warn};

use crate::event::DirProgress;

use crate::storage::DynStore;
use crate::{
    CacheUsage, ClientRequest, DirMgrConfig, DocId, DocumentText, Error, Readiness, Result,
    docmeta::{AuthCertMeta, ConsensusMeta},
    event,
};
use crate::{DocSource, SharedMutArc};
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
#[cfg(feature = "geoip")]
use tor_geoip::GeoipDb;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::{
    microdesc::{MdDigest, Microdesc},
    netstatus::MdConsensus,
};
use tor_netdoc::{
    AllowAnnotations,
    doc::{
        authcert::{AuthCert, AuthCertKeyIds},
        microdesc::MicrodescReader,
        netstatus::{ConsensusFlavor, UnvalidatedMdConsensus},
    },
};
use tor_rtcompat::Runtime;

/// A change to the currently running `NetDir`, returned by the state machines in this module.
#[derive(Debug)]
pub(crate) enum NetDirChange<'a> {
    /// If the provided `NetDir` is suitable for use (i.e. the caller determines it can build
    /// circuits with it), replace the current `NetDir` with it.
    ///
    /// The caller must call `DirState::on_netdir_replaced` if the replace was successful.
    AttemptReplace {
        /// The netdir to replace the current one with, if it's usable.
        ///
        /// The `Option` is always `Some` when returned from the state machine; it's there
        /// so that the caller can call `.take()` to avoid cloning the netdir.
        netdir: &'a mut Option<NetDir>,
        /// The consensus metadata for this netdir.
        consensus_meta: &'a ConsensusMeta,
    },
    /// Add the provided microdescriptors to the current `NetDir`.
    AddMicrodescs(&'a mut Vec<Microdesc>),
    /// Replace the recommended set of subprotocols.
    SetRequiredProtocol {
        /// The time at which the protocol statuses were recommended
        timestamp: SystemTime,
        /// The recommended set of protocols.
        protos: Arc<ProtoStatuses>,
    },
}

/// A "state" object used to represent our progress in downloading a
/// directory.
///
/// These state objects are not meant to know about the network, or
/// how to fetch documents at all.  Instead, they keep track of what
/// information they are missing, and what to do when they get that
/// information.
///
/// Every state object has two possible transitions: "resetting", and
/// "advancing".  Advancing happens when a state has no more work to
/// do, and needs to transform into a different kind of object.
/// Resetting happens when this state needs to go back to an initial
/// state in order to start over -- either because of an error or
/// because the information it has downloaded is no longer timely.
pub(crate) trait DirState: Send {
    /// Return a human-readable description of this state.
    fn describe(&self) -> String;
    /// Return a list of the documents we're missing.
    ///
    /// If every document on this list were to be loaded or downloaded, then
    /// the state should either become "ready to advance", or "complete."
    ///
    /// This list should never _grow_ on a given state; only advancing
    /// or resetting the state should add new DocIds that weren't
    /// there before.
    fn missing_docs(&self) -> Vec<DocId>;
    /// Describe whether this state has reached `ready` status.
    fn is_ready(&self, ready: Readiness) -> bool;
    /// If the state object wants to make changes to the currently running `NetDir`,
    /// return the proposed changes.
    fn get_netdir_change(&mut self) -> Option<NetDirChange<'_>> {
        None
    }
    /// Return true if this state can advance to another state via its
    /// `advance` method.
    fn can_advance(&self) -> bool;
    /// Add one or more documents from our cache; returns 'true' if there
    /// was any change in this state.
    ///
    /// Set `changed` to true if any semantic changes in this state were made.
    ///
    /// An error return does not necessarily mean that no data was added;
    /// partial successes are possible.
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()>;

    /// Add information that we have just downloaded to this state.
    ///
    /// This method receives a copy of the original request, and should reject
    /// any documents that do not pertain to it.
    ///
    /// If `storage` is provided, then we should write any accepted documents
    /// into `storage` so they can be saved in a cache.
    ///
    /// Set `changed` to true if any semantic changes in this state were made.
    ///
    /// An error return does not necessarily mean that no data was added;
    /// partial successes are possible.
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()>;
    /// Return a summary of this state as a [`DirProgress`].
    fn bootstrap_progress(&self) -> event::DirProgress;
    /// Return a configuration for attempting downloads.
    fn dl_config(&self) -> DownloadSchedule;
    /// If possible, advance to the next state.
    fn advance(self: Box<Self>) -> Box<dyn DirState>;
    /// Return a time (if any) when downloaders should stop attempting to
    /// advance this state, and should instead reset it and start over.
    fn reset_time(&self) -> Option<SystemTime>;
    /// Reset this state and start over.
    fn reset(self: Box<Self>) -> Box<dyn DirState>;
}

/// An object that can provide a previous netdir for the bootstrapping state machines to use.
pub(crate) trait PreviousNetDir: Send + Sync + 'static + Debug {
    /// Get the previous netdir, if there still is one.
    fn get_netdir(&self) -> Option<Arc<NetDir>>;
}

impl PreviousNetDir for SharedMutArc<NetDir> {
    fn get_netdir(&self) -> Option<Arc<NetDir>> {
        self.get()
    }
}

/// Initial state: fetching or loading a consensus directory.
#[derive(Clone, Debug)]
pub(crate) struct GetConsensusState<R: Runtime> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,

    /// If present, a time after which we want our consensus to have
    /// been published.
    //
    // TODO: This is not yet used everywhere it could be.  In the future maybe
    // it should be inserted into the DocId::LatestConsensus  alternative rather
    // than being recalculated in make_consensus_request,
    after: Option<SystemTime>,

    /// If present, our next state.
    ///
    /// (This is present once we have a consensus.)
    next: Option<GetCertsState<R>>,

    /// A list of RsaIdentity for the authorities that we believe in.
    ///
    /// No consensus can be valid unless it purports to be signed by
    /// more than half of these authorities.
    authority_ids: Vec<RsaIdentity>,

    /// A `Runtime` implementation.
    rt: R,
    /// The configuration of the directory manager. Used for download configuration
    /// purposes.
    config: Arc<DirMgrConfig>,
    /// If one exists, the netdir we're trying to update.
    prev_netdir: Option<Arc<dyn PreviousNetDir>>,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: Arc<dyn crate::filter::DirFilter>,
}

impl<R: Runtime> GetConsensusState<R> {
    /// Create a new `GetConsensusState`, using the cache as per `cache_usage` and downloading as
    /// per the relevant sections of `config`. If `prev_netdir` is supplied, information from that
    /// directory may be used to complete the next one.
    pub(crate) fn new(
        rt: R,
        config: Arc<DirMgrConfig>,
        cache_usage: CacheUsage,
        prev_netdir: Option<Arc<dyn PreviousNetDir>>,
        #[cfg(feature = "dirfilter")] filter: Arc<dyn crate::filter::DirFilter>,
    ) -> Self {
        let authority_ids = config.authorities().v3idents().clone();
        let after = prev_netdir
            .as_ref()
            .and_then(|x| x.get_netdir())
            .map(|nd| nd.lifetime().valid_after());

        GetConsensusState {
            cache_usage,
            after,
            next: None,
            authority_ids,
            rt,
            config,
            prev_netdir,
            #[cfg(feature = "dirfilter")]
            filter,
        }
    }
}

impl<R: Runtime> DirState for GetConsensusState<R> {
    fn describe(&self) -> String {
        if self.next.is_some() {
            "About to fetch certificates."
        } else {
            match self.cache_usage {
                CacheUsage::CacheOnly => "Looking for a cached consensus.",
                CacheUsage::CacheOkay => "Looking for a consensus.",
                CacheUsage::MustDownload => "Downloading a consensus.",
            }
        }
        .to_string()
    }
    fn missing_docs(&self) -> Vec<DocId> {
        if self.can_advance() {
            return Vec::new();
        }
        let flavor = ConsensusFlavor::Microdesc;
        vec![DocId::LatestConsensus {
            flavor,
            cache_usage: self.cache_usage,
        }]
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        false
    }
    fn can_advance(&self) -> bool {
        self.next.is_some()
    }
    fn bootstrap_progress(&self) -> DirProgress {
        if let Some(next) = &self.next {
            next.bootstrap_progress()
        } else {
            DirProgress::NoConsensus { after: self.after }
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        self.config.schedule.retry_consensus()
    }
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()> {
        let text = match docs.into_iter().next() {
            None => return Ok(()),
            Some((
                DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    ..
                },
                text,
            )) => text,
            _ => return Err(Error::CacheCorruption("Not an md consensus")),
        };

        let source = DocSource::LocalCache;

        self.add_consensus_text(
            source,
            text.as_str().map_err(Error::BadUtf8InCache)?,
            None,
            changed,
        )?;
        Ok(())
    }
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()> {
        let requested_newer_than = match request {
            ClientRequest::Consensus(r) => r.last_consensus_date(),
            _ => None,
        };
        let meta = self.add_consensus_text(source, text, requested_newer_than, changed)?;

        if let Some(store) = storage {
            let mut w = store.lock().expect("Directory storage lock poisoned");
            w.store_consensus(meta, ConsensusFlavor::Microdesc, true, text)?;
        }
        Ok(())
    }
    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        match self.next {
            Some(next) => Box::new(next),
            None => self,
        }
    }
    fn reset_time(&self) -> Option<SystemTime> {
        None
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        self
    }
}

impl<R: Runtime> GetConsensusState<R> {
    /// Helper: try to set the current consensus text from an input string
    /// `text`.  Refuse it if the authorities could never be correct, or if it
    /// is ill-formed.
    ///
    /// If `cutoff` is provided, treat any consensus older than `cutoff` as
    /// older-than-requested.
    ///
    /// Errors from this method are not fatal to the download process.
    fn add_consensus_text(
        &mut self,
        source: DocSource,
        text: &str,
        cutoff: Option<SystemTime>,
        changed: &mut bool,
    ) -> Result<&ConsensusMeta> {
        // Try to parse it and get its metadata.
        let (consensus_meta, unvalidated) = {
            let (signedval, remainder, parsed) =
                MdConsensus::parse(text).map_err(|e| Error::from_netdoc(source.clone(), e))?;
            #[cfg(feature = "dirfilter")]
            let parsed = self.filter.filter_consensus(parsed)?;
            let parsed = self.config.tolerance.extend_tolerance(parsed);
            let now = self.rt.wallclock();
            let timely = parsed.check_valid_at(&now)?;
            if let Some(cutoff) = cutoff {
                if timely.peek_lifetime().valid_after() < cutoff {
                    return Err(Error::Unwanted("consensus was older than requested"));
                }
            }
            let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &timely);
            (meta, timely)
        };

        // Check out what authorities we believe in, and see if enough
        // of them are purported to have signed this consensus.
        let unvalidated = unvalidated.set_n_authorities(self.authority_ids.len());

        let id_refs: Vec<_> = self.authority_ids.iter().collect();
        if !unvalidated.authorities_are_correct(&id_refs[..]) {
            return Err(Error::UnrecognizedAuthorities);
        }
        // Yes, we've added the consensus.  That's a change.
        *changed = true;

        // Make a set of all the certificates we want -- the subset of
        // those listed on the consensus that we would indeed accept as
        // authoritative.
        let desired_certs = unvalidated
            .signing_cert_ids()
            .filter(|m| self.recognizes_authority(&m.id_fingerprint))
            .collect();

        self.next = Some(GetCertsState {
            cache_usage: self.cache_usage,
            consensus_source: source,
            consensus: GetCertsConsensus::Unvalidated(unvalidated),
            consensus_meta,
            missing_certs: desired_certs,
            certs: Vec::new(),
            rt: self.rt.clone(),
            config: self.config.clone(),
            prev_netdir: self.prev_netdir.take(),
            protocol_statuses: None,
            #[cfg(feature = "dirfilter")]
            filter: self.filter.clone(),
        });

        // Unwrap should be safe because `next` was just assigned
        #[allow(clippy::unwrap_used)]
        Ok(&self.next.as_ref().unwrap().consensus_meta)
    }

    /// Return true if `id` is an authority identity we recognize
    fn recognizes_authority(&self, id: &RsaIdentity) -> bool {
        self.authority_ids.iter().any(|auth| auth == id)
    }
}

/// One of two possible internal states for the consensus in a GetCertsState.
///
/// This inner object is advanced by `try_checking_sigs`.
#[derive(Clone, Debug)]
enum GetCertsConsensus {
    /// We have an unvalidated consensus; we haven't checked its signatures.
    Unvalidated(UnvalidatedMdConsensus),
    /// A validated consensus: the signatures are fine and we can advance.
    Validated(MdConsensus),
    /// We failed to validate the consensus, even after getting enough certificates.
    Failed,
}

/// Second state: fetching or loading authority certificates.
///
/// TODO: we should probably do what C tor does, and try to use the
/// same directory that gave us the consensus.
///
/// TODO SECURITY: This needs better handling for the DOS attack where
/// we are given a bad consensus signed with fictional certificates
/// that we can never find.
#[derive(Clone, Debug)]
struct GetCertsState<R: Runtime> {
    /// The cache usage we had in mind when we began.  Used to reset.
    cache_usage: CacheUsage,
    /// Where did we get our consensus?
    consensus_source: DocSource,
    /// The consensus that we are trying to validate, or an error if we've given
    /// up on validating it.
    consensus: GetCertsConsensus,
    /// Metadata for the consensus.
    consensus_meta: ConsensusMeta,
    /// A set of the certificate keypairs for the certificates we don't
    /// have yet.
    missing_certs: HashSet<AuthCertKeyIds>,
    /// A list of the certificates we've been able to load or download.
    certs: Vec<AuthCert>,

    /// A `Runtime` implementation.
    rt: R,
    /// The configuration of the directory manager. Used for download configuration
    /// purposes.
    config: Arc<DirMgrConfig>,
    /// If one exists, the netdir we're trying to update.
    prev_netdir: Option<Arc<dyn PreviousNetDir>>,

    /// If present a set of protocols to install as our latest recommended set.
    protocol_statuses: Option<(SystemTime, Arc<ProtoStatuses>)>,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: Arc<dyn crate::filter::DirFilter>,
}

impl<R: Runtime> GetCertsState<R> {
    /// Handle a certificate result returned by `tor_netdoc`: checking it for timeliness
    /// and well-signedness.
    ///
    /// On success return the `AuthCert` and the string that represents it within the string `within`.
    /// On failure, return an error.
    fn check_parsed_certificate<'s>(
        &self,
        parsed: tor_netdoc::Result<UncheckedAuthCert>,
        source: &DocSource,
        within: &'s str,
    ) -> Result<(AuthCert, &'s str)> {
        let parsed = parsed.map_err(|e| Error::from_netdoc(source.clone(), e))?;
        let cert_text = parsed
            .within(within)
            .expect("Certificate was not in input as expected");
        let wellsigned = parsed.check_signature()?;
        let now = self.rt.wallclock();
        let timely_cert = self
            .config
            .tolerance
            .extend_tolerance(wellsigned)
            .check_valid_at(&now)?;
        Ok((timely_cert, cert_text))
    }

    /// If we have enough certificates, and we have not yet checked the
    /// signatures on the consensus, try checking them.
    ///
    /// If the consensus is valid, remove the unvalidated consensus from `self`
    /// and put the validated consensus there instead.
    ///
    /// If the consensus is invalid, throw it out set a blocking error.
    fn try_checking_sigs(&mut self) -> Result<()> {
        use GetCertsConsensus as C;
        // Temporary value; we'll replace the consensus field with something
        // better before the method returns.
        let mut consensus = C::Failed;
        std::mem::swap(&mut consensus, &mut self.consensus);

        let unvalidated = match consensus {
            C::Unvalidated(uv) if uv.key_is_correct(&self.certs[..]).is_ok() => uv,
            _ => {
                // nothing to check at this point.  Either we already checked the consensus, or we don't yet have enough certificates.
                self.consensus = consensus;
                return Ok(());
            }
        };

        let (new_consensus, outcome) = match unvalidated.check_signature(&self.certs[..]) {
            Ok(validated) => (C::Validated(validated), Ok(())),
            Err(cause) => (
                C::Failed,
                Err(Error::ConsensusInvalid {
                    source: self.consensus_source.clone(),
                    cause,
                }),
            ),
        };
        self.consensus = new_consensus;

        // Update our protocol recommendations if we have a validated consensus,
        // and if we haven't already updated our recommendations.
        if let GetCertsConsensus::Validated(v) = &self.consensus {
            if self.protocol_statuses.is_none() {
                let protoset: &Arc<ProtoStatuses> = v.protocol_statuses();
                self.protocol_statuses = Some((
                    self.consensus_meta.lifetime().valid_after(),
                    Arc::clone(protoset),
                ));
            }
        }

        outcome
    }
}

/// Directory bootstrap state transitions.
mod transitions;
#[derive(Debug, Clone)]
struct GetMicrodescsState<R: Runtime> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,
    /// Total number of microdescriptors listed in the consensus.
    n_microdescs: usize,
    /// The current status of our netdir.
    partial: PendingNetDir,
    /// Metadata for the current consensus.
    meta: ConsensusMeta,
    /// A pending list of microdescriptor digests whose
    /// "last-listed-at" times we should update.
    newly_listed: Vec<MdDigest>,
    /// A time after which we should try to replace this directory and
    /// find a new one.  Since this is randomized, we only compute it
    /// once.
    reset_time: SystemTime,

    /// A `Runtime` implementation.
    rt: R,
    /// The configuration of the directory manager. Used for download configuration
    /// purposes.
    config: Arc<DirMgrConfig>,
    /// If one exists, the netdir we're trying to update.
    prev_netdir: Option<Arc<dyn PreviousNetDir>>,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: Arc<dyn crate::filter::DirFilter>,
}

/// Information about a network directory that might not be ready to become _the_ current network
/// directory.
#[derive(Debug, Clone)]
enum PendingNetDir {
    /// A NetDir for which we have a consensus, but not enough microdescriptors.
    Partial(PartialNetDir),
    /// A NetDir we're either trying to get our caller to replace, or that the caller
    /// has already taken from us.
    ///
    /// After the netdir gets taken, the `collected_microdescs` and `missing_microdescs`
    /// fields get used. Before then, we just do operations on the netdir.
    Yielding {
        /// The actual netdir. This starts out as `Some`, but our caller can `take()` it
        /// from us.
        netdir: Option<NetDir>,
        /// Microdescs we have collected in order to yield to our caller.
        collected_microdescs: Vec<Microdesc>,
        /// Which microdescs we need for the netdir that either is or used to be in `netdir`.
        ///
        /// NOTE(eta): This MUST always match the netdir's own idea of which microdescs we need.
        ///            We do this by copying the netdir's missing microdescs into here when we
        ///            instantiate it.
        ///            (This code assumes that it doesn't add more needed microdescriptors later!)
        missing_microdescs: HashSet<MdDigest>,
        /// The time at which we should renew this netdir, assuming we have
        /// driven it to a "usable" state.
        replace_dir_time: SystemTime,
    },
    /// A dummy value, so we can use `mem::replace`.
    Dummy,
}

/// Choose a random download time to replace a consensus whose lifetime
/// is `lifetime`.
fn pick_download_time(lifetime: &Lifetime) -> SystemTime {
    let (lowbound, uncertainty) = client_download_range(lifetime);
    lowbound + rand::rng().gen_range_infallible(..=uncertainty)
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let valid_until = lt.valid_until();
    let voting_interval = lt.voting_period();
    let whole_lifetime = valid_until
        .duration_since(valid_after)
        .expect("valid-after must precede valid-until");

    // From dir-spec:
    // "This time is chosen uniformly at random from the interval
    // between the time 3/4 into the first interval after the
    // consensus is no longer fresh, and 7/8 of the time remaining
    // after that before the consensus is invalid."
    let lowbound = voting_interval + (voting_interval * 3) / 4;
    let remainder = whole_lifetime
        .checked_sub(lowbound)
        .expect("Arithmetic did not work as expected");
    let uncertainty = (remainder * 7) / 8;

    (valid_after + lowbound, uncertainty)
}

/// If `err` is some, return `Err(err)`.  Otherwise return Ok(()).
fn opt_err_to_result(e: Option<Error>) -> Result<()> {
    match e {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// A dummy state implementation, used when we need to temporarily write a
/// placeholder into a box.
///
/// Calling any method on this state will panic.
#[derive(Clone, Debug)]
pub(crate) struct PoisonedState;

impl DirState for PoisonedState {
    fn describe(&self) -> String {
        unimplemented!()
    }
    fn missing_docs(&self) -> Vec<DocId> {
        unimplemented!()
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        unimplemented!()
    }
    fn can_advance(&self) -> bool {
        unimplemented!()
    }
    fn add_from_cache(
        &mut self,
        _docs: HashMap<DocId, DocumentText>,
        _changed: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn add_from_download(
        &mut self,
        _text: &str,
        _request: &ClientRequest,
        _source: DocSource,
        _storage: Option<&Mutex<DynStore>>,
        _changed: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn bootstrap_progress(&self) -> event::DirProgress {
        unimplemented!()
    }
    fn dl_config(&self) -> DownloadSchedule {
        unimplemented!()
    }
    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        unimplemented!()
    }
    fn reset_time(&self) -> Option<SystemTime> {
        unimplemented!()
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        unimplemented!()
    }
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod test;
