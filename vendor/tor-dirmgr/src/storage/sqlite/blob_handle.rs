use std::path::{Path, PathBuf};

use crate::Result;
use rusqlite::Transaction;
use tor_basic_utils::PathExt as _;
use tor_error::warn_report;

/// Handle to a blob that we have saved to disk but
/// not yet committed to
/// the database, and the database transaction where we added a reference to it.
///
/// Used to either commit the blob (by calling [`SavedBlobHandle::commit`]),
/// or roll it back (by dropping the [`SavedBlobHandle`] without committing it.)
#[must_use]
pub(super) struct SavedBlobHandle<'a> {
    /// Transaction we're using to add the blob to the ExtDocs table.
    ///
    /// Note that struct fields are dropped in declaration order,
    /// so when we drop an uncommitted SavedBlobHandle,
    /// we roll back the transaction before we delete the file.
    /// (In practice, either order would be fine.)
    tx: Transaction<'a>,
    /// Filename for the file, with respect to the blob directory.
    fname: String,
    /// Declared digest string for this blob. Of the format
    /// "digesttype-hexstr".
    digeststr: String,
    /// An 'unlinker' for the blob file.
    unlinker: Unlinker,
}

impl<'a> SavedBlobHandle<'a> {
    /// Construct a SavedBlobHandle from its parts.
    pub(super) fn new(
        tx: Transaction<'a>,
        fname: String,
        digeststr: String,
        unlinker: Unlinker,
    ) -> Self {
        Self {
            tx,
            fname,
            digeststr,
            unlinker,
        }
    }

    /// Return a reference to the underlying database transaction.
    pub(super) fn tx(&self) -> &Transaction<'a> {
        &self.tx
    }
    /// Return the digest string of the saved blob.
    /// Other tables use this as a foreign key into ExtDocs.digest
    pub(super) fn digest_string(&self) -> &str {
        self.digeststr.as_ref()
    }
    /// Return the filename of this blob within the blob directory.
    #[allow(unused)] // used for testing.
    pub(super) fn fname(&self) -> &str {
        self.fname.as_ref()
    }
    /// Commit the relevant database transaction.
    pub(super) fn commit(self) -> Result<()> {
        // The blob has been written to disk, so it is safe to
        // commit the transaction.
        // If the commit returns an error, self.unlinker will remove the blob.
        // (This could result in a vanished blob if the commit reports an error,
        // but the transaction is still visible in the database.)
        self.tx.commit()?;
        // If we reach this point, we don't want to remove the file.
        self.unlinker.forget();
        Ok(())
    }
}

/// Handle to a file which we might have to delete.
///
/// When this handle is dropped, the file gets deleted, unless you have
/// first called [`Unlinker::forget`].
pub(super) struct Unlinker {
    /// The location of the file to remove, or None if we shouldn't
    /// remove it.
    p: Option<PathBuf>,
}
impl Unlinker {
    /// Make a new Unlinker for a given filename.
    pub(super) fn new<P: AsRef<Path>>(p: P) -> Self {
        Unlinker {
            p: Some(p.as_ref().to_path_buf()),
        }
    }
    /// Forget about this unlinker, so that the corresponding file won't
    /// get dropped.
    fn forget(mut self) {
        self.p = None;
    }
}
impl Drop for Unlinker {
    fn drop(&mut self) {
        if let Some(p) = self.p.take() {
            if let Err(e) = std::fs::remove_file(&p) {
                warn_report!(
                    e,
                    "Couldn't remove rolled-back blob file {}",
                    p.display_lossy()
                );
            }
        }
    }
}
