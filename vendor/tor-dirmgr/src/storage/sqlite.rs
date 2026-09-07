//! Net document storage backed by sqlite3.
//!
//! We store most objects in sqlite tables, except for very large ones,
//! which we store as "blob" files in a separate directory.

use super::ExpirationConfig;
use crate::docmeta::{AuthCertMeta, ConsensusMeta};
use crate::err::ReadOnlyStorageError;
use crate::storage::{InputString, Store};
use crate::{Error, Result};

use fs_mistrust::CheckedDir;
use tor_basic_utils::PathExt as _;
use tor_error::{internal, into_internal, warn_report};
use tor_netdoc::doc::authcert::AuthCertKeyIds;
use tor_netdoc::doc::microdesc::MdDigest;
use tor_netdoc::doc::netstatus::{ConsensusFlavor, Lifetime};
#[cfg(feature = "routerdesc")]
use tor_netdoc::doc::routerdesc::RdDigest;
use web_time_compat::SystemTimeExt;

#[cfg(feature = "bridge-client")]
pub(crate) use {crate::storage::CachedBridgeDescriptor, tor_guardmgr::bridge::BridgeConfig};

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::SystemTime;

use fslock_guard::LockFileGuard;
use rusqlite::{OpenFlags, OptionalExtension, Transaction, params};
use time::OffsetDateTime;
use tracing::{trace, warn};

/// Possible status of a lockfile.
///
/// (Sqlite does its own locking, but we would like to cover the blobs directory
/// as well)
enum LockFile {
    /// We are not even trying to lock, but permitting write operations
    /// regardless.
    ///
    /// This is the implementation we use for ephemeral testing databases.
    /// Don't use it in production!
    NotLocking,

    /// We aren't locked.
    ///
    /// The provided path is the path to the lockfile that we will try to open if
    /// we
    Unlocked(PathBuf),

    /// We have the lock.
    ///
    Locked(
        // We never need to read this field; we only need to hold it so that the
        // lock file isn't closed.
        #[allow(unused)] LockFileGuard,
    ),
}

/// Local directory cache using a Sqlite3 connection.
pub(crate) struct SqliteStore {
    /// Connection to the sqlite3 database.
    conn: rusqlite::Connection,
    /// Location for the sqlite3 database; used to reopen it.
    sql_path: Option<PathBuf>,
    /// Location to store blob files.
    blob_dir: CheckedDir,
    /// Lockfile to prevent concurrent write attempts from different
    /// processes.
    ///
    /// If this is LockFile::NotLocking we aren't using a lockfile.  Watch out!
    ///
    /// (sqlite supports that with connection locking, but we want to
    /// be a little more coarse-grained here)
    lockfile: LockFile,
}

/// # Some notes on blob consistency, and the lack thereof.
///
/// We store large documents (currently, consensuses) in separate files,
/// called "blobs",
/// outside of the sqlite database.
/// We do this for performance reasons: for large objects,
/// mmap is far more efficient than sqlite in RAM and CPU.
///
/// In the sqlite database, we keep track of our blobs
/// using the ExtDocs table.
/// This scheme makes it possible for the blobs and the table
/// get out of sync.
///
/// In summary:
///   - _Vanished_ blobs (ones present only in ExtDocs) are possible;
///     we try to tolerate them.
///   - _Orphaned_ blobs (ones present only on the disk) are possible;
///     we try to tolerate them.
///   - _Corrupted_ blobs (ones with the wrong contents) are possible
///     but (we hope) unlikely;
///     we do not currently try to tolerate them.
///
/// In more detail:
///
/// Here are the practices we use when _writing_ blobs:
///
/// - We always create a blob before updating the ExtDocs table,
///   and remove an entry from the ExtDocs before deleting the blob.
/// - If we decide to roll back the transaction that adds the row to ExtDocs,
///   we delete the blob after doing so.
/// - We use [`CheckedDir::write_and_replace`] to store blobs,
///   so a half-formed blob shouldn't be common.
///   (We assume that "close" and "rename" are serialized by the OS,
///   so that _if_ the rename happens, the file is completely written.)
/// - Blob filenames include a digest of the file contents,
///   so collisions are unlikely.
///
/// Here are the practices we use when _deleting_ blobs:
/// - First, we drop the row from the ExtDocs table.
///   Only then do we delete the file.
///
/// These practices can result in _orphaned_ blobs
/// (ones with no row in the ExtDoc table),
/// or in _half-written_ blobs files with tempfile names
/// (which also have no row in the ExtDoc table).
/// This happens if we crash at the wrong moment.
/// Such blobs can be safely removed;
/// we do so in [`SqliteStore::remove_unreferenced_blobs`].
///
/// Despite our efforts, _vanished_ blobs
/// (entries in the ExtDoc table with no corresponding file)
/// are also possible.  They could happen for these reasons:
/// - The filesystem might not serialize or sync things in a way that's
///   consistent with the DB.
/// - An automatic process might remove random cache files.
/// - The user might run around deleting things to free space.
///
/// We try to tolerate vanished blobs.
///
/// _Corrupted_ blobs are also possible.  They can happen on FS corruption,
/// or on somebody messing around with the cache directory manually.
/// We do not attempt to tolerate corrupted blobs.
///
/// ## On trade-offs
///
/// TODO: The practices described above are more likely
/// to create _orphaned_ blobs than _vanished_ blobs.
/// We initially made this trade-off decision on the mistaken theory
/// that we could avoid vanished blobs entirely.
/// We _may_ want to revisit this choice,
/// on the rationale that we can respond to vanished blobs as soon as we notice they're gone,
/// whereas we can only handle orphaned blobs with a periodic cleanup.
/// On the other hand, since we need to handle both cases,
/// it may not matter very much in practice.
#[allow(unused)]
mod blob_consistency {}

/// Specific error returned when a blob will not be read.
///
/// This error is an internal type: it's never returned to the user.
#[derive(Debug)]
enum AbsentBlob {
    /// We did not find a blob file on the disk.
    VanishedFile,
    /// We did not even find a blob to read in ExtDocs.
    NothingToRead,
}

impl SqliteStore {
    /// Construct or open a new SqliteStore at some location on disk.
    /// The provided location must be a directory, or a possible
    /// location for a directory: the directory will be created if
    /// necessary.
    ///
    /// If readonly is true, the result will be a read-only store.
    /// Otherwise, when readonly is false, the result may be
    /// read-only or read-write, depending on whether we can acquire
    /// the lock.
    ///
    /// # Limitations:
    ///
    /// The file locking that we use to ensure that only one dirmgr is
    /// writing to a given storage directory at a time is currently
    /// _per process_. Therefore, you might get unexpected results if
    /// two SqliteStores are created in the same process with the
    /// path.
    pub(crate) fn from_path_and_mistrust<P: AsRef<Path>>(
        path: P,
        mistrust: &fs_mistrust::Mistrust,
        mut readonly: bool,
    ) -> Result<Self> {
        let path = path.as_ref();
        let sqlpath = path.join("dir.sqlite3");
        let blobpath = path.join("dir_blobs/");
        let lockpath = path.join("dir.lock");

        let verifier = mistrust.verifier().permit_readable().check_content();

        let blob_dir = if readonly {
            verifier.secure_dir(blobpath)?
        } else {
            verifier.make_secure_dir(blobpath)?
        };

        // Check permissions on the sqlite and lock files; don't require them to
        // exist.
        for p in [&lockpath, &sqlpath] {
            match mistrust
                .verifier()
                .permit_readable()
                .require_file()
                .check(p)
            {
                Ok(()) | Err(fs_mistrust::Error::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        let lockfile = if !readonly {
            match LockFileGuard::try_lock(&lockpath).map_err(Error::from_lockfile)? {
                Some(guard) => LockFile::Locked(guard),
                None => {
                    // We couldn't get the lock.
                    readonly = true;
                    LockFile::Unlocked(lockpath)
                }
            }
        } else {
            LockFile::Unlocked(lockpath)
        };

        let flags = if readonly {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        };
        let conn = rusqlite::Connection::open_with_flags(&sqlpath, flags)?;
        let mut store = SqliteStore::from_conn_internal(conn, blob_dir, readonly)?;
        store.sql_path = Some(sqlpath);
        store.lockfile = lockfile;
        Ok(store)
    }

    /// Construct a new SqliteStore from a database connection and a location
    /// for blob files.
    ///
    /// Used for testing with a memory-backed database.
    ///
    /// Note: `blob_dir` must not be used for anything other than storing the blobs associated with
    /// this database, since we will freely remove unreferenced files from this directory.
    #[cfg(test)]
    fn from_conn(conn: rusqlite::Connection, blob_dir: CheckedDir) -> Result<Self> {
        Self::from_conn_internal(conn, blob_dir, false)
    }

    /// Construct a new SqliteStore from a database connection and a location
    /// for blob files.
    ///
    /// The `readonly` argument specifies whether the database connection should be read-only.
    fn from_conn_internal(
        conn: rusqlite::Connection,
        blob_dir: CheckedDir,
        readonly: bool,
    ) -> Result<Self> {
        // sqlite (as of Jun 2024) does not enforce foreign keys automatically unless you set this
        // pragma on the connection.
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let mut result = SqliteStore {
            conn,
            blob_dir,
            lockfile: LockFile::NotLocking,
            sql_path: None,
        };

        result.check_schema(readonly)?;

        Ok(result)
    }

    /// Check whether this database has a schema format we can read, and
    /// install or upgrade the schema if necessary.
    fn check_schema(&mut self, readonly: bool) -> Result<()> {
        let tx = self.conn.transaction()?;
        let db_n_tables: u32 = tx.query_row(
            "SELECT COUNT(name) FROM sqlite_master
             WHERE type='table'
             AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        let db_exists = db_n_tables > 0;

        // Update the schema from current_vsn to the latest (does not commit)
        let update_schema = |tx: &rusqlite::Transaction, current_vsn| {
            for (from_vsn, update) in UPDATE_SCHEMA.iter().enumerate() {
                let from_vsn = u32::try_from(from_vsn).expect("schema version >2^32");
                let new_vsn = from_vsn + 1;
                if current_vsn < new_vsn {
                    tx.execute_batch(update)?;
                    tx.execute(UPDATE_SCHEMA_VERSION, params![new_vsn, new_vsn])?;
                }
            }
            Ok::<_, Error>(())
        };

        if !db_exists {
            if !readonly {
                tx.execute_batch(INSTALL_V0_SCHEMA)?;
                update_schema(&tx, 0)?;
                tx.commit()?;
            } else {
                // The other process should have created the database!
                return Err(Error::ReadOnlyStorage(ReadOnlyStorageError::NoDatabase));
            }
            return Ok(());
        }

        let (version, readable_by): (u32, u32) = tx.query_row(
            "SELECT version, readable_by FROM TorSchemaMeta
             WHERE name = 'TorDirStorage'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        if version < SCHEMA_VERSION {
            if !readonly {
                update_schema(&tx, version)?;
                tx.commit()?;
            } else {
                return Err(Error::ReadOnlyStorage(
                    ReadOnlyStorageError::IncompatibleSchema {
                        schema: version,
                        supported: SCHEMA_VERSION,
                    },
                ));
            }

            return Ok(());
        } else if readable_by > SCHEMA_VERSION {
            return Err(Error::UnrecognizedSchema {
                schema: readable_by,
                supported: SCHEMA_VERSION,
            });
        }

        // rolls back the transaction, but nothing was done.
        Ok(())
    }

    /// Read a blob from disk, mapping it if possible.
    ///
    /// Return `Ok(Err(.))` if the file for the blob was not found on disk;
    /// returns an error in other cases.
    ///
    /// (See [`blob_consistency`] for information on why the blob might be absent.)
    fn read_blob(&self, path: &str) -> Result<StdResult<InputString, AbsentBlob>> {
        let file = match self.blob_dir.open(path, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(fs_mistrust::Error::NotFound(_)) => {
                warn!(
                    "{:?} was listed in the database, but its corresponding file had been deleted",
                    path
                );
                return Ok(Err(AbsentBlob::VanishedFile));
            }
            Err(e) => return Err(e.into()),
        };

        InputString::load(file)
            .map_err(|err| Error::CacheFile {
                action: "loading",
                fname: PathBuf::from(path),
                error: Arc::new(err),
            })
            .map(Ok)
    }

    /// Write a file to disk as a blob, and record it in the ExtDocs table.
    ///
    /// Return a SavedBlobHandle that describes where the blob is, and which
    /// can be used either to commit the blob or delete it.
    ///
    /// See [`blob_consistency`] for more information on guarantees.
    fn save_blob_internal(
        &mut self,
        contents: &[u8],
        doctype: &str,
        digest_type: &str,
        digest: &[u8],
        expires: OffsetDateTime,
    ) -> Result<blob_handle::SavedBlobHandle<'_>> {
        let digest = hex::encode(digest);
        let digeststr = format!("{}-{}", digest_type, digest);
        let fname = format!("{}_{}", doctype, digeststr);

        let full_path = self.blob_dir.join(&fname)?;
        let unlinker = blob_handle::Unlinker::new(&full_path);
        self.blob_dir
            .write_and_replace(&fname, contents)
            .map_err(|e| match e {
                fs_mistrust::Error::Io { err, .. } => Error::CacheFile {
                    action: "saving",
                    fname: full_path,
                    error: err,
                },
                err => err.into(),
            })?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(INSERT_EXTDOC, params![digeststr, expires, doctype, fname])?;

        Ok(blob_handle::SavedBlobHandle::new(
            tx, fname, digeststr, unlinker,
        ))
    }

    /// As `latest_consensus`, but do not retry.
    fn latest_consensus_internal(
        &self,
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    ) -> Result<StdResult<InputString, AbsentBlob>> {
        trace!(?flavor, ?pending, "Loading latest consensus from cache");
        let rv: Option<(OffsetDateTime, OffsetDateTime, String)> = match pending {
            None => self
                .conn
                .query_row(FIND_CONSENSUS, params![flavor.name()], |row| row.try_into())
                .optional()?,
            Some(pending_val) => self
                .conn
                .query_row(
                    FIND_CONSENSUS_P,
                    params![pending_val, flavor.name()],
                    |row| row.try_into(),
                )
                .optional()?,
        };

        if let Some((_va, _vu, filename)) = rv {
            // TODO blobs: If the cache is inconsistent (because this blob is _vanished_), and the cache has not yet
            // been cleaned, this may fail to find the latest consensus that we actually have.
            self.read_blob(&filename)
        } else {
            Ok(Err(AbsentBlob::NothingToRead))
        }
    }

    /// Save a blob to disk and commit it.
    #[cfg(test)]
    fn save_blob(
        &mut self,
        contents: &[u8],
        doctype: &str,
        digest_type: &str,
        digest: &[u8],
        expires: OffsetDateTime,
    ) -> Result<String> {
        let h = self.save_blob_internal(contents, doctype, digest_type, digest, expires)?;
        let fname = h.fname().to_string();
        h.commit()?;
        Ok(fname)
    }

    /// Return the valid-after time for the latest non non-pending consensus,
    #[cfg(test)]
    // We should revise the tests to use latest_consensus_meta instead.
    fn latest_consensus_time(&self, flavor: ConsensusFlavor) -> Result<Option<OffsetDateTime>> {
        Ok(self
            .latest_consensus_meta(flavor)?
            .map(|m| m.lifetime().valid_after().into()))
    }

    /// Remove the blob with name `fname`, but do not give an error on failure.
    ///
    /// See [`blob_consistency`]: we should call this only having first ensured
    /// that the blob is removed from the ExtDocs table.
    fn remove_blob_or_warn<P: AsRef<Path>>(&self, fname: P) {
        let fname = fname.as_ref();
        if let Err(e) = self.blob_dir.remove_file(fname) {
            warn_report!(e, "Unable to remove {}", fname.display_lossy());
        }
    }

    /// Delete any blob files that are old enough, and not mentioned in the ExtDocs table.
    ///
    /// There shouldn't typically be any, but we don't want to let our cache grow infinitely
    /// if we have a bug.
    fn remove_unreferenced_blobs(
        &self,
        now: OffsetDateTime,
        expiration: &ExpirationConfig,
    ) -> Result<()> {
        // Now, look for any unreferenced blobs that are a bit old.
        for ent in self.blob_dir.read_directory(".")?.flatten() {
            let md_error = |io_error| Error::CacheFile {
                action: "getting metadata",
                fname: ent.file_name().into(),
                error: Arc::new(io_error),
            };
            if ent
                .metadata()
                .map_err(md_error)?
                .modified()
                .map_err(md_error)?
                + expiration.consensuses
                >= now
            {
                // this file is sufficiently recent that we should not remove it, just to be cautious.
                continue;
            }
            let filename = match ent.file_name().into_string() {
                Ok(s) => s,
                Err(os_str) => {
                    // This filename wasn't utf-8.  We will never create one of these.
                    warn!(
                        "Removing bizarre file '{}' from blob store.",
                        os_str.to_string_lossy()
                    );
                    self.remove_blob_or_warn(ent.file_name());
                    continue;
                }
            };
            let found: (u32,) =
                self.conn
                    .query_row(COUNT_EXTDOC_BY_PATH, params![&filename], |row| {
                        row.try_into()
                    })?;
            if found == (0,) {
                warn!("Removing unreferenced file '{}' from blob store", &filename);
                self.remove_blob_or_warn(ent.file_name());
            }
        }

        Ok(())
    }

    /// Remove any entry in the ExtDocs table for which a blob file is vanished.
    ///
    /// This method is `O(n)` in the size of the ExtDocs table and the size of the directory.
    /// It doesn't take self, to avoid problems with the borrow checker.
    fn remove_entries_for_vanished_blobs<'a>(
        blob_dir: &CheckedDir,
        tx: &Transaction<'a>,
    ) -> Result<usize> {
        let in_directory: HashSet<PathBuf> = blob_dir
            .read_directory(".")?
            .flatten()
            .map(|dir_entry| PathBuf::from(dir_entry.file_name()))
            .collect();
        let in_db: Vec<String> = tx
            .prepare(FIND_ALL_EXTDOC_FILENAMES)?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<StdResult<Vec<String>, _>>()?;

        let mut n_removed = 0;
        for fname in in_db {
            if in_directory.contains(Path::new(&fname)) {
                // The blob is present; great!
                continue;
            }

            n_removed += tx.execute(DELETE_EXTDOC_BY_FILENAME, [fname])?;
        }

        Ok(n_removed)
    }
}

/// SQLite storage operations.
mod store;
/// Functionality related to uncommitted blobs.
mod blob_handle;
/// Convert a hexadecimal sha3-256 digest from the database into an array.
fn digest_from_hex(s: &str) -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(s, &mut bytes[..]).map_err(Error::BadHexInCache)?;
    Ok(bytes)
}

/// Convert a hexadecimal sha3-256 "digest string" as used in the
/// digest column from the database into an array.
fn digest_from_dstr(s: &str) -> Result<[u8; 32]> {
    if let Some(stripped) = s.strip_prefix("sha3-256-") {
        digest_from_hex(stripped)
    } else {
        Err(Error::CacheCorruption("Invalid digest in database"))
    }
}

/// Create a ConsensusMeta from a `Row` returned by one of
/// `FIND_LATEST_CONSENSUS_META` or `FIND_CONSENSUS_AND_META_BY_DIGEST`.
fn cmeta_from_row(row: &rusqlite::Row<'_>) -> Result<ConsensusMeta> {
    let va: OffsetDateTime = row.get(0)?;
    let fu: OffsetDateTime = row.get(1)?;
    let vu: OffsetDateTime = row.get(2)?;
    let d_signed: String = row.get(3)?;
    let d_all: String = row.get(4)?;
    let lifetime = Lifetime::new(va.into(), fu.into(), vu.into())
        .map_err(|_| Error::CacheCorruption("inconsistent lifetime in database"))?;
    Ok(ConsensusMeta::new(
        lifetime,
        digest_from_hex(&d_signed)?,
        digest_from_dstr(&d_all)?,
    ))
}

/// Return `SystemTime::get()` as an OffsetDateTime in UTC.
fn now_utc() -> OffsetDateTime {
    SystemTime::get().into()
}

/// Set up the tables for the arti cache schema in a sqlite database.
const INSTALL_V0_SCHEMA: &str = "
  -- Helps us version the schema.  The schema here corresponds to a
  -- version number called 'version', and it should be readable by
  -- anybody who is compliant with versions of at least 'readable_by'.
  CREATE TABLE TorSchemaMeta (
     name TEXT NOT NULL PRIMARY KEY,
     version INTEGER NOT NULL,
     readable_by INTEGER NOT NULL
  );

  INSERT INTO TorSchemaMeta (name, version, readable_by) VALUES ( 'TorDirStorage', 0, 0 );

  -- Keeps track of external blobs on disk.
  CREATE TABLE ExtDocs (
    -- Records a digest of the file contents, in the form '<digest_type>-hexstr'
    digest TEXT PRIMARY KEY NOT NULL,
    -- When was this file created?
    created DATE NOT NULL,
    -- After what time will this file definitely be useless?
    expires DATE NOT NULL,
    -- What is the type of this file? Currently supported are 'con_<flavor>'.
    --   (Before tor-dirmgr ~0.28.0, we would erroneously record 'con_flavor' as 'sha3-256';
    --   Nothing depended on this yet, but will be used in the future
    --   as we add more large-document types.)
    type TEXT NOT NULL,
    -- Filename for this file within our blob directory.
    filename TEXT NOT NULL
  );

  -- All the microdescriptors we know about.
  CREATE TABLE Microdescs (
    sha256_digest TEXT PRIMARY KEY NOT NULL,
    last_listed DATE NOT NULL,
    contents BLOB NOT NULL
  );

  -- All the authority certificates we know.
  CREATE TABLE Authcerts (
    id_digest TEXT NOT NULL,
    sk_digest TEXT NOT NULL,
    published DATE NOT NULL,
    expires DATE NOT NULL,
    contents BLOB NOT NULL,
    PRIMARY KEY (id_digest, sk_digest)
  );

  -- All the consensuses we're storing.
  CREATE TABLE Consensuses (
    valid_after DATE NOT NULL,
    fresh_until DATE NOT NULL,
    valid_until DATE NOT NULL,
    flavor TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    sha3_of_signed_part TEXT NOT NULL,
    digest TEXT NOT NULL,
    FOREIGN KEY (digest) REFERENCES ExtDocs (digest) ON DELETE CASCADE
  );
  CREATE INDEX Consensuses_vu on CONSENSUSES(valid_until);

";

/// Update the database schema, from each version to the next
const UPDATE_SCHEMA: &[&str] = &["
  -- Update the database schema from version 0 to version 1.
  CREATE TABLE RouterDescs (
    sha1_digest TEXT PRIMARY KEY NOT NULL,
    published DATE NOT NULL,
    contents BLOB NOT NULL
  );
","
  -- Update the database schema from version 1 to version 2.
  -- We create this table even if the bridge-client feature is disabled, but then don't touch it at all.
  CREATE TABLE BridgeDescs (
    bridge_line TEXT PRIMARY KEY NOT NULL,
    fetched DATE NOT NULL,
    until DATE NOT NULL,
    contents BLOB NOT NULL
  );
","
 -- Update the database schema from version 2 to version 3.

 -- Table to hold our latest ProtocolStatuses object, to tell us if we're obsolete.
 -- We hold this independently from our consensus,
 -- since we want to read it very early in our startup process,
 -- even if the consensus is expired.
 CREATE TABLE ProtocolStatus (
    -- Enforce that there is only one row in this table.
    -- (This is a bit kludgy, but I am assured that it is a common practice.)
    zero INTEGER PRIMARY KEY NOT NULL,
    -- valid-after date of the consensus from which we got this status
    date DATE NOT NULL,
    -- ProtoStatuses object, encoded as json
    statuses TEXT NOT NULL
 );
"];

/// Update the database schema version tracking, from each version to the next
const UPDATE_SCHEMA_VERSION: &str = "
  UPDATE TorSchemaMeta SET version=? WHERE version<?;
";

/// Version number used for this version of the arti cache schema.
const SCHEMA_VERSION: u32 = UPDATE_SCHEMA.len() as u32;

/// Query: find the latest-expiring microdesc consensus with a given
/// pending status.
const FIND_CONSENSUS_P: &str = "
  SELECT valid_after, valid_until, filename
  FROM Consensuses
  INNER JOIN ExtDocs ON ExtDocs.digest = Consensuses.digest
  WHERE pending = ? AND flavor = ?
  ORDER BY valid_until DESC
  LIMIT 1;
";

/// Query: find the latest-expiring microdesc consensus, regardless of
/// pending status.
const FIND_CONSENSUS: &str = "
  SELECT valid_after, valid_until, filename
  FROM Consensuses
  INNER JOIN ExtDocs ON ExtDocs.digest = Consensuses.digest
  WHERE flavor = ?
  ORDER BY valid_until DESC
  LIMIT 1;
";

/// Query: Find the valid-after time for the latest-expiring
/// non-pending consensus of a given flavor.
const FIND_LATEST_CONSENSUS_META: &str = "
  SELECT valid_after, fresh_until, valid_until, sha3_of_signed_part, digest
  FROM Consensuses
  WHERE pending = 0 AND flavor = ?
  ORDER BY valid_until DESC
  LIMIT 1;
";

/// Look up a consensus by its digest-of-signed-part string.
const FIND_CONSENSUS_AND_META_BY_DIGEST_OF_SIGNED: &str = "
  SELECT valid_after, fresh_until, valid_until, sha3_of_signed_part, Consensuses.digest, filename
  FROM Consensuses
  INNER JOIN ExtDocs on ExtDocs.digest = Consensuses.digest
  WHERE Consensuses.sha3_of_signed_part = ?
  LIMIT 1;
";

/// Query: Update the consensus whose digest field is 'digest' to call it
/// no longer pending.
const MARK_CONSENSUS_NON_PENDING: &str = "
  UPDATE Consensuses
  SET pending = 0
  WHERE digest = ?;
";

/// Query: Remove the consensus with a given digest field.
#[allow(dead_code)]
const REMOVE_CONSENSUS: &str = "
  DELETE FROM Consensuses
  WHERE digest = ?;
";

/// Query: Find the authority certificate with given key digests.
const FIND_AUTHCERT: &str = "
  SELECT contents FROM AuthCerts WHERE id_digest = ? AND sk_digest = ?;
";

/// Query: find the microdescriptor with a given hex-encoded sha256 digest
const FIND_MD: &str = "
  SELECT contents
  FROM Microdescs
  WHERE sha256_digest = ?
";

/// Query: find the router descriptors with a given hex-encoded sha1 digest
#[cfg(feature = "routerdesc")]
const FIND_RD: &str = "
  SELECT contents
  FROM RouterDescs
  WHERE sha1_digest = ?
";

/// Query: find every ExtDocs member that has expired.
const FIND_EXPIRED_EXTDOCS: &str = "
  SELECT filename FROM ExtDocs where expires < datetime('now');
";

/// Query: find whether an ExtDoc is listed.
const COUNT_EXTDOC_BY_PATH: &str = "
  SELECT COUNT(*) FROM ExtDocs WHERE filename = ?;
";

/// Query: Add a new entry to ExtDocs.
const INSERT_EXTDOC: &str = "
  INSERT OR REPLACE INTO ExtDocs ( digest, created, expires, type, filename )
  VALUES ( ?, datetime('now'), ?, ?, ? );
";

/// Query: Add a new consensus.
const INSERT_CONSENSUS: &str = "
  INSERT OR REPLACE INTO Consensuses
    ( valid_after, fresh_until, valid_until, flavor, pending, sha3_of_signed_part, digest )
  VALUES ( ?, ?, ?, ?, ?, ?, ? );
";

/// Query: Add a new AuthCert
const INSERT_AUTHCERT: &str = "
  INSERT OR REPLACE INTO Authcerts
    ( id_digest, sk_digest, published, expires, contents)
  VALUES ( ?, ?, ?, ?, ? );
";

/// Query: Add a new microdescriptor
const INSERT_MD: &str = "
  INSERT OR REPLACE INTO Microdescs ( sha256_digest, last_listed, contents )
  VALUES ( ?, ?, ? );
";

/// Query: Add a new router descriptor
#[allow(unused)]
#[cfg(feature = "routerdesc")]
const INSERT_RD: &str = "
  INSERT OR REPLACE INTO RouterDescs ( sha1_digest, published, contents )
  VALUES ( ?, ?, ? );
";

/// Query: Change the time when a given microdescriptor was last listed.
const UPDATE_MD_LISTED: &str = "
  UPDATE Microdescs
  SET last_listed = max(last_listed, ?)
  WHERE sha256_digest = ?;
";

/// Query: Find a cached bridge descriptor
#[cfg(feature = "bridge-client")]
const FIND_BRIDGEDESC: &str = "SELECT fetched, contents FROM BridgeDescs WHERE bridge_line = ?;";
/// Query: Record a cached bridge descriptor
#[cfg(feature = "bridge-client")]
const INSERT_BRIDGEDESC: &str = "
  INSERT OR REPLACE INTO BridgeDescs ( bridge_line, fetched, until, contents )
  VALUES ( ?, ?, ?, ? );
";
/// Query: Remove a cached bridge descriptor
#[cfg(feature = "bridge-client")]
#[allow(dead_code)]
const DELETE_BRIDGEDESC: &str = "DELETE FROM BridgeDescs WHERE bridge_line = ?;";

/// Query: Find all consensus extdocs that are not referenced in the consensus table.
///
/// Note: use of `sha3-256` is a synonym for `con_%` is a workaround.
const FIND_UNREFERENCED_CONSENSUS_EXTDOCS: &str = "
    SELECT filename FROM ExtDocs WHERE
         (type LIKE 'con_%' OR type = 'sha3-256')
    AND NOT EXISTS
         (SELECT digest FROM Consensuses WHERE Consensuses.digest = ExtDocs.digest);";

/// Query: Discard every expired extdoc.
///
/// External documents aren't exposed through [`Store`].
const DROP_OLD_EXTDOCS: &str = "DELETE FROM ExtDocs WHERE expires < datetime('now');";

/// Query: Discard an extdoc with a given path.
const DELETE_EXTDOC_BY_FILENAME: &str = "DELETE FROM ExtDocs WHERE filename = ?;";

/// Query: List all extdoc filenames.
const FIND_ALL_EXTDOC_FILENAMES: &str = "SELECT filename FROM ExtDocs;";

/// Query: Get the latest protocol status.
const FIND_LATEST_PROTOCOL_STATUS: &str = "SELECT date, statuses FROM ProtocolStatus WHERE zero=0;";
/// Query: Update the latest protocol status.
const UPDATE_PROTOCOL_STATUS: &str = "INSERT OR REPLACE INTO ProtocolStatus VALUES ( 0, ?, ? );";

/// Query: Discard every router descriptor that hasn't been listed for 3
/// months.
// TODO: Choose a more realistic time.
const DROP_OLD_ROUTERDESCS: &str = "DELETE FROM RouterDescs WHERE published < ?;";
/// Query: Discard every microdescriptor that hasn't been listed for 3 months.
// TODO: Choose a more realistic time.
const DROP_OLD_MICRODESCS: &str = "DELETE FROM Microdescs WHERE last_listed < ?;";
/// Query: Discard every expired authority certificate.
const DROP_OLD_AUTHCERTS: &str = "DELETE FROM Authcerts WHERE expires < ?;";
/// Query: Discard every consensus that's been expired for at least
/// two days.
const DROP_OLD_CONSENSUSES: &str = "DELETE FROM Consensuses WHERE valid_until < ?;";
/// Query: Discard every bridge descriptor that is too old, or from the future.  (Both ?=now.)
#[cfg(feature = "bridge-client")]
const DROP_OLD_BRIDGEDESCS: &str = "DELETE FROM BridgeDescs WHERE ? > until OR fetched > ?;";

#[cfg(test)]
#[path = "sqlite/tests.rs"]
pub(crate) mod test;
