//! Declare an error type for the tor-dirmgr crate.

use std::error::Error as StdError;
use std::sync::Arc;

use crate::DocSource;
use fs_mistrust::anon_home::PathExt as _;
use futures::task::SpawnError;
use thiserror::Error;
use tor_error::{ErrorKind, HasKind};
use tor_persist::FsMistrustErrorExt as _;

/// An error originated by the directory manager code
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// We received a document we didn't want at all.
    #[error("Received an object we didn't ask for: {0}")]
    Unwanted(&'static str),
    /// The NetDir we downloaded is older than the one we already have.
    #[error("Downloaded netdir is older than the one we have")]
    NetDirOlder,
    /// This DirMgr doesn't support downloads.
    #[error("Tried to download information on a DirMgr with no download support")]
    NoDownloadSupport,
    /// We couldn't read something from disk that we should have been
    /// able to read.
    #[error("Corrupt cache: {0}")]
    CacheCorruption(&'static str),
    /// rusqlite gave us an error.
    #[error("Error from sqlite database")]
    SqliteError(#[source] Arc<rusqlite::Error>),
    /// Error while creating a read-only store.
    #[error("Failed to create read-only store")]
    ReadOnlyStorage(#[from] ReadOnlyStorageError),
    /// A schema version that says we can't read it.
    #[error("Unrecognized data storage schema v{schema}. (We support v{supported})")]
    UnrecognizedSchema {
        /// The schema version in the database
        schema: u32,
        /// The schema that we actually support.
        supported: u32,
    },
    /// User requested an operation that required a usable
    /// bootstrapped directory, but we didn't have one.
    #[error("Directory not present or not up-to-date")]
    DirectoryNotPresent,
    /// A consensus document is signed by an unrecognized authority set.
    #[error("Authorities on consensus are not the ones we expect")]
    UnrecognizedAuthorities,
    /// A directory manager has been dropped; background tasks can exit too.
    #[error("Dirmgr has been dropped; background tasks exiting")]
    ManagerDropped,
    /// We made a bunch of attempts, but weren't unable to advance the
    /// state of a download.
    #[error("Unable to finish bootstrapping a directory")]
    CantAdvanceState,
    /// Error while accessing a lockfile.
    #[error("Unable to access lock file")]
    LockFile(Arc<std::io::Error>),
    /// Error while accessing a file in the store.
    #[error("Error while {action} cache file {}", fname.anonymize_home())]
    CacheFile {
        /// What we were doing when we encountered the error.
        action: &'static str,
        /// The file that we were trying to access.
        fname: std::path::PathBuf,
        /// The underlying IO error.
        #[source]
        error: Arc<std::io::Error>,
    },
    /// An error given by the consensus diff crate.
    #[error("Problem applying consensus diff")]
    ConsensusDiffError(#[from] tor_consdiff::Error),
    /// Invalid UTF8 in directory response.
    #[error("Invalid utf-8 from directory server")]
    BadUtf8FromDirectory(#[source] std::string::FromUtf8Error),
    /// Invalid UTF8 from our cache.
    #[error("Invalid utf-8 in directory cache")]
    BadUtf8InCache(#[source] std::str::Utf8Error),
    /// Invalid hexadecimal value in the cache.
    #[error("Invalid hexadecimal id in directory cache")]
    BadHexInCache(#[source] hex::FromHexError),
    /// Invalid json value in the cache
    #[error("Invalid JSON in directory cache")]
    BadJsonInCache(#[source] Arc<serde_json::Error>),
    /// An error given by the network document crate.
    #[error("Invalid document from {source}")]
    NetDocError {
        /// Where the document came from.
        source: DocSource,
        /// What error we got.
        #[source]
        cause: tor_netdoc::Error,
    },
    /// An error indicating that the consensus could not be validated.
    ///
    /// This kind of error is only returned during the certificate fetching
    /// state; it indicates that a consensus which previously seemed to be
    /// plausible has turned out to be wrong after we got the certificates.
    #[error("Could not validate consensus from {source}")]
    ConsensusInvalid {
        /// Where the document came from.
        source: DocSource,
        /// What error we got.
        #[source]
        cause: tor_netdoc::Error,
    },
    /// An error caused by an expired or not-yet-valid object.
    #[error("Directory object expired or not yet valid")]
    UntimelyObject(#[from] tor_checkable::TimeValidityError),
    /// An error given by dirclient
    #[error("Problem downloading directory object")]
    DirClientError(#[from] tor_dirclient::Error),
    /// An error given by the checkable crate.
    #[error("Invalid signatures")]
    SignatureError(#[source] Arc<signature::Error>),
    /// An attempt was made to bootstrap a `DirMgr` created in offline mode.
    #[error("Tried to bootstrap a DirMgr that was configured as offline-only")]
    OfflineMode,
    /// A problem accessing our cache directory (for example, no such directory)
    #[error("Problem accessing cache directory")]
    CacheAccess(#[from] fs_mistrust::Error),
    /// A problem accessing our cache directory (for example, no such directory)
    ///
    /// This variant name is misleading - see the docs for [`fs_mistrust::Error`].
    /// Please use [`Error::CacheAccess`] instead.
    #[error("Problem accessing cache directory")]
    #[deprecated = "use Error::CacheAccess instead"]
    CachePermissions(#[source] fs_mistrust::Error),
    /// Unable to spawn task
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Other error from an external directory provider
    #[error("Error from external directory provider")]
    ExternalDirProvider {
        /// What happened
        #[source]
        cause: Arc<dyn std::error::Error + Send + Sync + 'static>,

        /// The kind
        kind: ErrorKind,
    },

    /// A programming problem, either in our code or the code calling it.
    #[error("Internal programming issue")]
    Bug(#[from] tor_error::Bug),
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Self {
        Self::SignatureError(Arc::new(err))
    }
}

impl From<tor_rtcompat::scheduler::SleepError> for Error {
    fn from(err: tor_rtcompat::scheduler::SleepError) -> Self {
        use tor_rtcompat::scheduler::SleepError::*;
        match err {
            ScheduleDropped => Error::ManagerDropped,
            e => tor_error::into_internal!("Unexpected sleep error")(e).into(),
        }
    }
}

impl AsRef<dyn StdError + 'static> for Error {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        self
    }
}

/// The effect that a given error has on our bootstrapping process
#[derive(Copy, Clone, Debug)]
pub(crate) enum BootstrapAction {
    /// The error isn't fatal.  We should blame it on its source (if any), and
    /// continue bootstrapping.
    Nonfatal,
    /// The error requires that we restart bootstrapping from scratch.  
    ///
    /// This kind of error typically means that we've downloaded a consensus
    /// that turned out to be useless at a later stage, and so we need to
    /// restart the downloading process from the beginning, by downloading a
    /// fresh one.
    Reset,
    /// The error indicates that we cannot bootstrap, and should stop trying.
    ///
    /// These are typically internal programming errors, filesystem access
    /// problems, directory manager shutdown, and the like.
    Fatal,
}

impl Error {
    /// Construct a new `Error` from a `SpawnError`.
    pub(crate) fn from_spawn(spawning: &'static str, err: SpawnError) -> Error {
        Error::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }

    /// Construct a new `Error` from `tor_netdoc::Error`.
    ///
    /// Also takes a source so that we can keep track of where the document came from.
    pub(crate) fn from_netdoc(source: DocSource, cause: tor_netdoc::Error) -> Error {
        Error::NetDocError { source, cause }
    }

    /// Construct a new `Error` from `std::io::Error` for an error that occurred
    /// while locking a file.
    pub(crate) fn from_lockfile(err: std::io::Error) -> Error {
        Error::LockFile(Arc::new(err))
    }

    /// Return true if this error is serious enough that we should mark this
    /// cache as having failed.
    pub(crate) fn indicates_cache_failure(&self) -> bool {
        #[allow(deprecated)]
        match self {
            // These indicate a problem from the cache.
            Error::Unwanted(_)
            | Error::UnrecognizedAuthorities
            | Error::BadUtf8FromDirectory(_)
            | Error::ConsensusDiffError(_)
            | Error::SignatureError(_)
            | Error::ConsensusInvalid { .. }
            | Error::UntimelyObject(_) => true,

            // These errors cannot come from a directory cache.
            Error::NoDownloadSupport
            | Error::CacheCorruption(_)
            | Error::CachePermissions(_)
            | Error::CacheAccess(_)
            | Error::SqliteError(_)
            | Error::ReadOnlyStorage(_)
            | Error::UnrecognizedSchema { .. }
            | Error::DirectoryNotPresent
            | Error::ManagerDropped
            | Error::CantAdvanceState
            | Error::LockFile { .. }
            | Error::CacheFile { .. }
            | Error::BadUtf8InCache(_)
            | Error::BadHexInCache(_)
            | Error::OfflineMode
            | Error::Spawn { .. }
            | Error::NetDirOlder
            | Error::BadJsonInCache(_)
            | Error::Bug(_) => false,

            // For this one, we delegate.
            Error::DirClientError(e) => e.should_retire_circ(),

            // TODO: This one is special.  It could mean that the directory
            // cache is serving us bad unparsable stuff, or it could mean that
            // for some reason we're unable to parse a real legit document.
            //
            // If the cache is serving us something unparsable, it might be
            // because the cache doesn't know all the same parsing rules for the
            // object that we know.  That case might need special handling to
            // avoid erroneously avoiding a good cache... especially if the document
            // is one that the cache could be tricked into serving us.
            Error::NetDocError { .. } => true,

            // We can never see this kind of error from within the crate.
            Error::ExternalDirProvider { .. } => false,
        }
    }

    /// Return information about which directory cache caused this error, if
    /// this error contains one.
    pub(crate) fn responsible_cache(&self) -> Option<&tor_dirclient::SourceInfo> {
        match self {
            Error::NetDocError {
                source: DocSource::DirServer { source },
                ..
            } => source.as_ref(),
            Error::ConsensusInvalid {
                source: DocSource::DirServer { source },
                ..
            } => source.as_ref(),
            _ => None,
        }
    }

    /// Return information about what to do if this error occurs during the
    /// bootstrapping process.
    #[allow(dead_code)]
    pub(crate) fn bootstrap_action(&self) -> BootstrapAction {
        #[allow(deprecated)]
        match self {
            Error::Unwanted(_)
            | Error::NetDirOlder
            | Error::UnrecognizedAuthorities
            | Error::ConsensusDiffError(_)
            | Error::BadUtf8FromDirectory(_)
            | Error::UntimelyObject(_)
            | Error::DirClientError(_)
            | Error::SignatureError(_)
            | Error::NetDocError { .. } => BootstrapAction::Nonfatal,

            Error::ConsensusInvalid { .. } | Error::CantAdvanceState => BootstrapAction::Reset,

            Error::NoDownloadSupport
            | Error::OfflineMode
            | Error::CacheCorruption(_)
            | Error::SqliteError(_)
            | Error::ReadOnlyStorage(_)
            | Error::UnrecognizedSchema { .. }
            | Error::ManagerDropped
            | Error::LockFile { .. }
            | Error::CacheFile { .. }
            | Error::BadUtf8InCache(_)
            | Error::BadHexInCache(_)
            | Error::CachePermissions(_)
            | Error::CacheAccess(_)
            | Error::Spawn { .. }
            | Error::BadJsonInCache(_)
            | Error::ExternalDirProvider { .. } => BootstrapAction::Fatal,

            // These should actually be impossible during the bootstrap process.
            Error::DirectoryNotPresent | Error::Bug(_) => BootstrapAction::Fatal,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        use ErrorKind as EK;
        let kind = sqlite_error_kind(&err);
        match kind {
            EK::Internal | EK::BadApiUsage => {
                // TODO: should this be a .is_bug() on EK ?
                tor_error::Bug::from_error(kind, err, "sqlite detected bug").into()
            }
            _ => Self::SqliteError(Arc::new(err)),
        }
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        #[allow(deprecated)]
        match self {
            E::Unwanted(_) => EK::TorProtocolViolation,
            E::NoDownloadSupport => EK::NotImplemented,
            E::CacheCorruption(_) => EK::CacheCorrupted,
            E::CachePermissions(e) => e.cache_error_kind(),
            E::CacheAccess(e) => e.cache_error_kind(),
            E::SqliteError(e) => sqlite_error_kind(e),
            E::ReadOnlyStorage(_) => EK::LocalResourceAlreadyInUse,
            E::UnrecognizedSchema { .. } => EK::CacheCorrupted,
            E::BadJsonInCache(_) => EK::CacheCorrupted,
            E::DirectoryNotPresent => EK::DirectoryExpired,
            E::NetDirOlder => EK::TorDirectoryError,
            E::BadUtf8FromDirectory(_) => EK::TorProtocolViolation,
            E::BadUtf8InCache(_) => EK::CacheCorrupted,
            E::BadHexInCache(_) => EK::CacheCorrupted,
            E::UnrecognizedAuthorities => EK::TorProtocolViolation,
            E::ManagerDropped => EK::ArtiShuttingDown,
            E::CantAdvanceState => EK::TorAccessFailed,
            E::LockFile { .. } => EK::CacheAccessFailed,
            E::CacheFile { .. } => EK::CacheAccessFailed,
            E::ConsensusDiffError(_) => EK::TorProtocolViolation,
            E::NetDocError { source, .. } => match source {
                DocSource::LocalCache => EK::CacheCorrupted,
                DocSource::DirServer { .. } => EK::TorProtocolViolation,
            },
            E::ConsensusInvalid { source, .. } => match source {
                DocSource::LocalCache => EK::CacheCorrupted,
                DocSource::DirServer { .. } => EK::TorProtocolViolation,
            },
            E::UntimelyObject(_) => EK::TorProtocolViolation,
            E::DirClientError(e) => e.kind(),
            E::SignatureError(_) => EK::TorProtocolViolation,
            E::OfflineMode => EK::BadApiUsage,
            E::Spawn { cause, .. } => cause.kind(),
            E::ExternalDirProvider { kind, .. } => *kind,
            E::Bug(e) => e.kind(),
        }
    }
}

/// Convert a sqlite error code into a real ErrorKind.
fn sqlite_error_kind(e: &rusqlite::Error) -> ErrorKind {
    use ErrorKind as EK;
    use rusqlite::ErrorCode as RE;

    match e {
        rusqlite::Error::SqliteFailure(code, _) => match code.code {
            RE::DatabaseCorrupt => EK::CacheCorrupted,
            RE::SchemaChanged
            | RE::TooBig
            | RE::ConstraintViolation
            | RE::TypeMismatch
            | RE::ApiMisuse
            | RE::NoLargeFileSupport
            | RE::ParameterOutOfRange
            | RE::OperationInterrupted
            | RE::ReadOnly
            | RE::OperationAborted
            | RE::OutOfMemory
            | RE::InternalMalfunction => EK::Internal,

            // tor-socks5 local patch: SQLITE_BUSY / SQLITE_LOCKED are transient
            // file-lock contention on the cache database, not a programming
            // bug. On a long-lived Windows desktop process the cache db is
            // routinely locked for a few ms by antivirus real-time scanning,
            // Windows Search indexing, or OneDrive/backup sync over the cache
            // directory; SQLITE_BUSY/LOCKED literally mean "try again later".
            // Move them out of the EK::Internal arm so From<rusqlite::Error>
            // below no longer wraps them as tor_error::Bug("sqlite detected
            // bug") and instead classifies them as CacheAccessFailed, alongside
            // the other environmental cache-access IO failures
            // (FileLockingProtocolFailed, SystemIoFailure, CannotOpen, ...).
            // OperationInterrupted/OperationAborted are deliberately left in
            // EK::Internal: they are explicit cancel/abort signals, not
            // transient file-lock contention, so reclassifying them would be
            // unjustified scope creep.
            RE::DatabaseBusy
            | RE::DatabaseLocked
            | RE::FileLockingProtocolFailed
            | RE::AuthorizationForStatementDenied
            | RE::NotFound
            | RE::DiskFull
            | RE::CannotOpen
            | RE::SystemIoFailure
            | RE::PermissionDenied => EK::CacheAccessFailed,
            RE::NotADatabase => EK::InvalidConfig,
            _ => EK::Internal,
        },

        // TODO: Some of the other sqlite error types can sometimes represent
        // possible database corruption (like UTF8Error.)  But I haven't
        // found a way to distinguish when.
        _ => EK::Internal,
    }
}

/// An error coming from a read-only store.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ReadOnlyStorageError {
    /// We couldn't find the database.
    #[error("The database could not be found.")]
    NoDatabase,

    /// A schema version that is not current.
    #[error("Incompatible data storage schema v{schema}. (We expected v{supported})")]
    IncompatibleSchema {
        /// The schema version in the database
        schema: u32,
        /// The schema that we actually support.
        supported: u32,
    },
}

// tor-socks5 local patch: regression tests for the SQLITE_BUSY/LOCKED
// reclassification above. Without the patch, DatabaseBusy/DatabaseLocked map
// to EK::Internal and From<rusqlite::Error> wraps them as Error::Bug; with the
// patch they map to EK::CacheAccessFailed and become a plain Error::SqliteError.
#[cfg(test)]
mod test {
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
    use tor_error::ErrorKind as EK;

    /// Build a `rusqlite::Error::SqliteFailure` carrying the given primary
    /// `ErrorCode`, with a neutral `extended_code` of 0.
    fn sqlite_failure(code: rusqlite::ErrorCode) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error { code, extended_code: 0 }, None)
    }

    #[test]
    fn sqlite_busy_locked_are_transient_cache_access() {
        // Direct classification: BUSY/LOCKED must map to CacheAccessFailed,
        // not Internal.
        assert_eq!(
            sqlite_error_kind(&sqlite_failure(rusqlite::ErrorCode::DatabaseBusy)),
            EK::CacheAccessFailed
        );
        assert_eq!(
            sqlite_error_kind(&sqlite_failure(rusqlite::ErrorCode::DatabaseLocked)),
            EK::CacheAccessFailed
        );

        // End-to-end through From<rusqlite::Error>: a transient file lock must
        // become a plain Error::SqliteError (retriable cache-access failure),
        // NOT an Error::Bug carrying "sqlite detected bug".
        let busy: Error = sqlite_failure(rusqlite::ErrorCode::DatabaseBusy).into();
        assert!(
            matches!(busy, Error::SqliteError(_)),
            "SQLITE_BUSY must not be wrapped as Error::Bug"
        );
        assert_eq!(busy.kind(), EK::CacheAccessFailed);
    }

    #[test]
    fn sqlite_classification_unchanged_around_the_patch() {
        // Environmental IO failures keep their existing CacheAccessFailed home.
        assert_eq!(
            sqlite_error_kind(&sqlite_failure(rusqlite::ErrorCode::SystemIoFailure)),
            EK::CacheAccessFailed
        );
        assert_eq!(
            sqlite_error_kind(&sqlite_failure(rusqlite::ErrorCode::FileLockingProtocolFailed)),
            EK::CacheAccessFailed
        );
        // Genuine "shouldn't happen" codes stay Internal — the patch does not
        // broaden the reclassification to explicit cancel/abort signals.
        assert_eq!(
            sqlite_error_kind(&sqlite_failure(rusqlite::ErrorCode::OperationInterrupted)),
            EK::Internal
        );
        assert_eq!(
            sqlite_error_kind(&sqlite_failure(rusqlite::ErrorCode::InternalMalfunction)),
            EK::Internal
        );
    }
}
