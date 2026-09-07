use super::*;

impl Store for SqliteStore {
    fn is_readonly(&self) -> bool {
        match &self.lockfile {
            LockFile::NotLocking => false, // no locks used; we can always write.
            LockFile::Unlocked(_) => true, // lock in use but we don't have it; can't write.
            LockFile::Locked(_) => false,  // we have the lock; we can write.
        }
    }

    fn upgrade_to_readwrite(&mut self) -> Result<bool> {
        let Some(sql_path) = self.sql_path.as_ref() else {
            // This is an ephemeral database with no disk representation.
            return Ok(true);
        };

        let lockpath = match &self.lockfile {
            LockFile::NotLocking => {
                // This should be unreachable.
                return Err(
                    internal!("No lockfile open; cannot upgrade to read-write storage").into(),
                );
            }
            LockFile::Locked(_) => return Ok(true),
            LockFile::Unlocked(path) => path,
        };
        // We aren't locked. Try to fix that.
        let Some(guard) = LockFileGuard::try_lock(lockpath).map_err(Error::from_lockfile)? else {
            // Somebody else has the lock.
            return Ok(false);
        };

        // Open a fresh RW sql connection. If it fails, we'll unlock the guard
        // and remain in our old state.
        let new_conn = rusqlite::Connection::open(sql_path)?;
        self.conn = new_conn;
        self.lockfile = LockFile::Locked(guard);
        Ok(true)
    }
    fn expire_all(&mut self, expiration: &ExpirationConfig) -> Result<()> {
        let tx = self.conn.transaction()?;
        // This works around a false positive; see
        //   https://github.com/rust-lang/rust-clippy/issues/8114
        #[allow(clippy::let_and_return)]
        let expired_blobs: Vec<String> = {
            let mut stmt = tx.prepare(FIND_EXPIRED_EXTDOCS)?;
            let names: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<StdResult<Vec<String>, _>>()?;
            names
        };

        let now = now_utc();
        tx.execute(DROP_OLD_EXTDOCS, [])?;

        // In theory bad system clocks might generate table rows with times far in the future.
        // However, for data which is cached here which comes from the network consensus,
        // we rely on the fact that no consensus from the future exists, so this can't happen.
        tx.execute(DROP_OLD_MICRODESCS, [now - expiration.microdescs])?;
        tx.execute(DROP_OLD_AUTHCERTS, [now - expiration.authcerts])?;
        tx.execute(DROP_OLD_CONSENSUSES, [now - expiration.consensuses])?;
        tx.execute(DROP_OLD_ROUTERDESCS, [now - expiration.router_descs])?;

        // Bridge descriptors come from bridges and bridges might send crazy times,
        // so we need to discard any that look like they are from the future,
        // since otherwise wrong far-future timestamps might live in our DB indefinitely.
        #[cfg(feature = "bridge-client")]
        tx.execute(DROP_OLD_BRIDGEDESCS, [now, now])?;

        // Find all consensus blobs that are no longer referenced,
        // and delete their entries from extdocs.
        let remove_consensus_blobs = {
            // TODO: This query can be O(n); but that won't matter for clients.
            // For relays, we may want to add an index to speed it up, if we use this code there too.
            let mut stmt = tx.prepare(FIND_UNREFERENCED_CONSENSUS_EXTDOCS)?;
            let filenames: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<StdResult<Vec<String>, _>>()?;
            drop(stmt);
            let mut stmt = tx.prepare(DELETE_EXTDOC_BY_FILENAME)?;
            for fname in filenames.iter() {
                stmt.execute([fname])?;
            }
            filenames
        };

        tx.commit()?;
        // Now that the transaction has been committed, these blobs are
        // unreferenced in the ExtDocs table, and we can remove them from disk.
        let mut remove_blob_files: HashSet<_> = expired_blobs.iter().collect();
        remove_blob_files.extend(remove_consensus_blobs.iter());

        for name in remove_blob_files {
            let fname = self.blob_dir.join(name);
            if let Ok(fname) = fname {
                if let Err(e) = std::fs::remove_file(&fname) {
                    warn_report!(
                        e,
                        "Couldn't remove orphaned blob file {}",
                        fname.display_lossy()
                    );
                }
            }
        }

        self.remove_unreferenced_blobs(now, expiration)?;

        Ok(())
    }

    // Note: We cannot, and do not, call this function when a transaction already exists.
    fn latest_consensus(
        &self,
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    ) -> Result<Option<InputString>> {
        match self.latest_consensus_internal(flavor, pending)? {
            Ok(s) => return Ok(Some(s)),
            Err(AbsentBlob::NothingToRead) => return Ok(None),
            Err(AbsentBlob::VanishedFile) => {
                // If we get here, the file was vanished.  Clean up the DB and try again.
            }
        }

        // We use unchecked_transaction() here because this API takes a non-mutable `SqliteStore`.
        // `unchecked_transaction()` will give an error if it is used
        // when a transaction already exists.
        // That's fine: We don't call this function from inside this module,
        // when a transaction might exist,
        // and we can't call multiple SqliteStore functions at once: it isn't sync.
        // Here we enforce that:
        static_assertions::assert_not_impl_any!(SqliteStore: Sync);

        // If we decide that this is unacceptable,
        // then since sqlite doesn't really support concurrent use of a connection,
        // we _could_ change the Store::latest_consensus API take &mut self,
        // or we could add a mutex,
        // or we could just not use a transaction object.
        let tx = self.conn.unchecked_transaction()?;
        Self::remove_entries_for_vanished_blobs(&self.blob_dir, &tx)?;
        tx.commit()?;

        match self.latest_consensus_internal(flavor, pending)? {
            Ok(s) => Ok(Some(s)),
            Err(AbsentBlob::NothingToRead) => Ok(None),
            Err(AbsentBlob::VanishedFile) => {
                warn!("Somehow remove_entries_for_vanished_blobs didn't resolve a VanishedFile");
                Ok(None)
            }
        }
    }

    fn latest_consensus_meta(&self, flavor: ConsensusFlavor) -> Result<Option<ConsensusMeta>> {
        let mut stmt = self.conn.prepare(FIND_LATEST_CONSENSUS_META)?;
        let mut rows = stmt.query(params![flavor.name()])?;
        if let Some(row) = rows.next()? {
            Ok(Some(cmeta_from_row(row)?))
        } else {
            Ok(None)
        }
    }
    #[cfg(test)]
    fn consensus_by_meta(&self, cmeta: &ConsensusMeta) -> Result<InputString> {
        if let Some((text, _)) =
            self.consensus_by_sha3_digest_of_signed_part(cmeta.sha3_256_of_signed())?
        {
            Ok(text)
        } else {
            Err(Error::CacheCorruption(
                "couldn't find a consensus we thought we had.",
            ))
        }
    }
    fn consensus_by_sha3_digest_of_signed_part(
        &self,
        d: &[u8; 32],
    ) -> Result<Option<(InputString, ConsensusMeta)>> {
        let digest = hex::encode(d);
        let mut stmt = self
            .conn
            .prepare(FIND_CONSENSUS_AND_META_BY_DIGEST_OF_SIGNED)?;
        let mut rows = stmt.query(params![digest])?;
        if let Some(row) = rows.next()? {
            let meta = cmeta_from_row(row)?;
            let fname: String = row.get(5)?;
            if let Ok(text) = self.read_blob(&fname)? {
                return Ok(Some((text, meta)));
            }
        }
        Ok(None)
    }
    fn store_consensus(
        &mut self,
        cmeta: &ConsensusMeta,
        flavor: ConsensusFlavor,
        pending: bool,
        contents: &str,
    ) -> Result<()> {
        let lifetime = cmeta.lifetime();
        let sha3_of_signed = cmeta.sha3_256_of_signed();
        let sha3_of_whole = cmeta.sha3_256_of_whole();
        let valid_after: OffsetDateTime = lifetime.valid_after().into();
        let fresh_until: OffsetDateTime = lifetime.fresh_until().into();
        let valid_until: OffsetDateTime = lifetime.valid_until().into();

        /// How long to keep a consensus around after it has expired
        const CONSENSUS_LIFETIME: time::Duration = time::Duration::days(4);

        // After a few days have passed, a consensus is no good for
        // anything at all, not even diffs.
        let expires = valid_until + CONSENSUS_LIFETIME;

        let doctype = format!("con_{}", flavor.name());

        let h = self.save_blob_internal(
            contents.as_bytes(),
            &doctype,
            "sha3-256",
            &sha3_of_whole[..],
            expires,
        )?;
        h.tx().execute(
            INSERT_CONSENSUS,
            params![
                valid_after,
                fresh_until,
                valid_until,
                flavor.name(),
                pending,
                hex::encode(sha3_of_signed),
                h.digest_string()
            ],
        )?;
        h.commit()?;
        Ok(())
    }
    fn mark_consensus_usable(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        let d = hex::encode(cmeta.sha3_256_of_whole());
        let digest = format!("sha3-256-{}", d);

        let tx = self.conn.transaction()?;
        let n = tx.execute(MARK_CONSENSUS_NON_PENDING, params![digest])?;
        trace!("Marked {} consensuses usable", n);
        tx.commit()?;

        Ok(())
    }
    fn delete_consensus(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        let d = hex::encode(cmeta.sha3_256_of_whole());
        let digest = format!("sha3-256-{}", d);

        // TODO: We should probably remove the blob as well, but for now
        // this is enough.
        let tx = self.conn.transaction()?;
        tx.execute(REMOVE_CONSENSUS, params![digest])?;
        tx.commit()?;

        Ok(())
    }

    fn authcerts(&self, certs: &[AuthCertKeyIds]) -> Result<HashMap<AuthCertKeyIds, String>> {
        let mut result = HashMap::new();
        // TODO(nickm): Do I need to get a transaction here for performance?
        let mut stmt = self.conn.prepare(FIND_AUTHCERT)?;

        for ids in certs {
            let id_digest = hex::encode(ids.id_fingerprint.as_bytes());
            let sk_digest = hex::encode(ids.sk_fingerprint.as_bytes());
            if let Some(contents) = stmt
                .query_row(params![id_digest, sk_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*ids, contents);
            }
        }

        Ok(result)
    }
    fn store_authcerts(&mut self, certs: &[(AuthCertMeta, &str)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_AUTHCERT)?;
        for (meta, content) in certs {
            let ids = meta.key_ids();
            let id_digest = hex::encode(ids.id_fingerprint.as_bytes());
            let sk_digest = hex::encode(ids.sk_fingerprint.as_bytes());
            let published: OffsetDateTime = meta.published().into();
            let expires: OffsetDateTime = meta.expires().into();
            stmt.execute(params![id_digest, sk_digest, published, expires, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    fn microdescs(&self, digests: &[MdDigest]) -> Result<HashMap<MdDigest, String>> {
        let mut result = HashMap::new();
        let mut stmt = self.conn.prepare(FIND_MD)?;

        // TODO(nickm): Should I speed this up with a transaction, or
        // does it not matter for queries?
        for md_digest in digests {
            let h_digest = hex::encode(md_digest);
            if let Some(contents) = stmt
                .query_row(params![h_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*md_digest, contents);
            }
        }

        Ok(result)
    }
    fn store_microdescs(&mut self, digests: &[(&str, &MdDigest)], when: SystemTime) -> Result<()> {
        let when: OffsetDateTime = when.into();

        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_MD)?;

        for (content, md_digest) in digests {
            let h_digest = hex::encode(md_digest);
            stmt.execute(params![h_digest, when, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }
    fn update_microdescs_listed(&mut self, digests: &[MdDigest], when: SystemTime) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(UPDATE_MD_LISTED)?;
        let when: OffsetDateTime = when.into();

        for md_digest in digests {
            let h_digest = hex::encode(md_digest);
            stmt.execute(params![when, h_digest])?;
        }

        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(feature = "routerdesc")]
    fn routerdescs(&self, digests: &[RdDigest]) -> Result<HashMap<RdDigest, String>> {
        let mut result = HashMap::new();
        let mut stmt = self.conn.prepare(FIND_RD)?;

        // TODO(nickm): Should I speed this up with a transaction, or
        // does it not matter for queries?
        for rd_digest in digests {
            let h_digest = hex::encode(rd_digest);
            if let Some(contents) = stmt
                .query_row(params![h_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*rd_digest, contents);
            }
        }

        Ok(result)
    }
    #[cfg(feature = "routerdesc")]
    fn store_routerdescs(&mut self, digests: &[(&str, SystemTime, &RdDigest)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_RD)?;

        for (content, when, rd_digest) in digests {
            let when: OffsetDateTime = (*when).into();
            let h_digest = hex::encode(rd_digest);
            stmt.execute(params![h_digest, when, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(feature = "bridge-client")]
    fn lookup_bridgedesc(&self, bridge: &BridgeConfig) -> Result<Option<CachedBridgeDescriptor>> {
        let bridge_line = bridge.to_string();
        Ok(self
            .conn
            .query_row(FIND_BRIDGEDESC, params![bridge_line], |row| {
                let (fetched, document): (OffsetDateTime, _) = row.try_into()?;
                let fetched = fetched.into();
                Ok(CachedBridgeDescriptor { fetched, document })
            })
            .optional()?)
    }

    #[cfg(feature = "bridge-client")]
    fn store_bridgedesc(
        &mut self,
        bridge: &BridgeConfig,
        entry: CachedBridgeDescriptor,
        until: SystemTime,
    ) -> Result<()> {
        if self.is_readonly() {
            // Hopefully whoever *does* have the lock will update the cache.
            // Otherwise it will contain a stale entry forever
            // (which we'll ignore, but waste effort on).
            return Ok(());
        }
        let bridge_line = bridge.to_string();
        let row = params![
            bridge_line,
            OffsetDateTime::from(entry.fetched),
            OffsetDateTime::from(until),
            entry.document,
        ];
        self.conn.execute(INSERT_BRIDGEDESC, row)?;
        Ok(())
    }

    #[cfg(feature = "bridge-client")]
    fn delete_bridgedesc(&mut self, bridge: &BridgeConfig) -> Result<()> {
        if self.is_readonly() {
            // This is called when we find corrupted or stale cache entries,
            // to stop us wasting time on them next time.
            // Hopefully whoever *does* have the lock will do this.
            return Ok(());
        }
        let bridge_line = bridge.to_string();
        self.conn.execute(DELETE_BRIDGEDESC, params![bridge_line])?;
        Ok(())
    }

    fn update_protocol_recommendations(
        &mut self,
        valid_after: SystemTime,
        protocols: &tor_netdoc::doc::netstatus::ProtoStatuses,
    ) -> Result<()> {
        let json =
            serde_json::to_string(&protocols).map_err(into_internal!("Cannot encode protocols"))?;
        let params = params![OffsetDateTime::from(valid_after), json];
        self.conn.execute(UPDATE_PROTOCOL_STATUS, params)?;
        Ok(())
    }

    fn cached_protocol_recommendations(
        &self,
    ) -> Result<Option<(SystemTime, tor_netdoc::doc::netstatus::ProtoStatuses)>> {
        let opt_row: Option<(OffsetDateTime, String)> = self
            .conn
            .query_row(FIND_LATEST_PROTOCOL_STATUS, [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;

        let (date, json) = match opt_row {
            Some(v) => v,
            None => return Ok(None),
        };

        let date = date.into();
        let statuses: tor_netdoc::doc::netstatus::ProtoStatuses =
            serde_json::from_str(json.as_str()).map_err(|e| Error::BadJsonInCache(Arc::new(e)))?;

        Ok(Some((date, statuses)))
    }
}
