    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::storage::EXPIRATION_DEFAULTS;
    use digest::Digest;
    use hex_literal::hex;
    use tempfile::{TempDir, tempdir};
    use time::ext::NumericalDuration;
    use tor_llcrypto::d::Sha3_256;

    pub(crate) fn new_empty() -> Result<(TempDir, SqliteStore)> {
        let tmp_dir = tempdir().unwrap();
        let sql_path = tmp_dir.path().join("db.sql");
        let conn = rusqlite::Connection::open(sql_path)?;
        let blob_path = tmp_dir.path().join("blobs");
        let blob_dir = fs_mistrust::Mistrust::builder()
            .dangerously_trust_everyone()
            .build()
            .unwrap()
            .verifier()
            .make_secure_dir(blob_path)
            .unwrap();
        let store = SqliteStore::from_conn(conn, blob_dir)?;

        Ok((tmp_dir, store))
    }

    #[test]
    fn init() -> Result<()> {
        let tmp_dir = tempdir().unwrap();
        let blob_dir = fs_mistrust::Mistrust::builder()
            .dangerously_trust_everyone()
            .build()
            .unwrap()
            .verifier()
            .secure_dir(&tmp_dir)
            .unwrap();
        let sql_path = tmp_dir.path().join("db.sql");
        // Initial setup: everything should work.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            let _store = SqliteStore::from_conn(conn, blob_dir.clone())?;
        }
        // Second setup: shouldn't need to upgrade.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            let _store = SqliteStore::from_conn(conn, blob_dir.clone())?;
        }
        // Third setup: shouldn't need to upgrade.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            conn.execute_batch("UPDATE TorSchemaMeta SET version = 9002;")?;
            let _store = SqliteStore::from_conn(conn, blob_dir.clone())?;
        }
        // Fourth: this says we can't read it, so we'll get an error.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            conn.execute_batch("UPDATE TorSchemaMeta SET readable_by = 9001;")?;
            let val = SqliteStore::from_conn(conn, blob_dir);
            assert!(val.is_err());
        }
        Ok(())
    }

    #[test]
    fn bad_blob_fname() -> Result<()> {
        let (_tmp_dir, store) = new_empty()?;

        assert!(store.blob_dir.join("abcd").is_ok());
        assert!(store.blob_dir.join("abcd..").is_ok());
        assert!(store.blob_dir.join("..abcd..").is_ok());
        assert!(store.blob_dir.join(".abcd").is_ok());

        assert!(store.blob_dir.join("..").is_err());
        assert!(store.blob_dir.join("../abcd").is_err());
        assert!(store.blob_dir.join("/abcd").is_err());

        Ok(())
    }

    #[test]
    fn blobs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = now_utc();
        let one_week = 1.weeks();

        let fname1 = store.save_blob(
            b"Hello world",
            "greeting",
            "sha1",
            &hex!("7b502c3a1f48c8609ae212cdfb639dee39673f5e"),
            now + one_week,
        )?;

        let fname2 = store.save_blob(
            b"Goodbye, dear friends",
            "greeting",
            "sha1",
            &hex!("2149c2a7dbf5be2bb36fb3c5080d0fb14cb3355c"),
            now - one_week,
        )?;

        assert_eq!(
            fname1,
            "greeting_sha1-7b502c3a1f48c8609ae212cdfb639dee39673f5e"
        );
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname1)?).unwrap()[..],
            b"Hello world"
        );
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname2)?).unwrap()[..],
            b"Goodbye, dear friends"
        );

        let n: u32 = store
            .conn
            .query_row("SELECT COUNT(filename) FROM ExtDocs", [], |row| row.get(0))?;
        assert_eq!(n, 2);

        let blob = store.read_blob(&fname2)?.unwrap();
        assert_eq!(blob.as_str().unwrap(), "Goodbye, dear friends");

        // Now expire: the second file should go away.
        store.expire_all(&EXPIRATION_DEFAULTS)?;
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname1)?).unwrap()[..],
            b"Hello world"
        );
        assert!(std::fs::read(store.blob_dir.join(&fname2)?).is_err());
        let n: u32 = store
            .conn
            .query_row("SELECT COUNT(filename) FROM ExtDocs", [], |row| row.get(0))?;
        assert_eq!(n, 1);

        Ok(())
    }

    #[test]
    fn consensus() -> Result<()> {
        use tor_netdoc::doc::netstatus;

        let (_tmp_dir, mut store) = new_empty()?;
        let now = now_utc();
        let one_hour = 1.hours();

        assert_eq!(
            store.latest_consensus_time(ConsensusFlavor::Microdesc)?,
            None
        );

        let cmeta = ConsensusMeta::new(
            netstatus::Lifetime::new(
                now.into(),
                (now + one_hour).into(),
                SystemTime::from(now + one_hour * 2),
            )
            .unwrap(),
            [0xAB; 32],
            [0xBC; 32],
        );

        store.store_consensus(
            &cmeta,
            ConsensusFlavor::Microdesc,
            true,
            "Pretend this is a consensus",
        )?;

        {
            assert_eq!(
                store.latest_consensus_time(ConsensusFlavor::Microdesc)?,
                None
            );
            let consensus = store
                .latest_consensus(ConsensusFlavor::Microdesc, None)?
                .unwrap();
            assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
            let consensus = store.latest_consensus(ConsensusFlavor::Microdesc, Some(false))?;
            assert!(consensus.is_none());
        }

        store.mark_consensus_usable(&cmeta)?;

        {
            assert_eq!(
                store.latest_consensus_time(ConsensusFlavor::Microdesc)?,
                now.into()
            );
            let consensus = store
                .latest_consensus(ConsensusFlavor::Microdesc, None)?
                .unwrap();
            assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
            let consensus = store
                .latest_consensus(ConsensusFlavor::Microdesc, Some(false))?
                .unwrap();
            assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
        }

        {
            let consensus_text = store.consensus_by_meta(&cmeta)?;
            assert_eq!(consensus_text.as_str()?, "Pretend this is a consensus");

            let (is, _cmeta2) = store
                .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                .unwrap();
            assert_eq!(is.as_str()?, "Pretend this is a consensus");

            let cmeta3 = ConsensusMeta::new(
                netstatus::Lifetime::new(
                    now.into(),
                    (now + one_hour).into(),
                    SystemTime::from(now + one_hour * 2),
                )
                .unwrap(),
                [0x99; 32],
                [0x99; 32],
            );
            assert!(store.consensus_by_meta(&cmeta3).is_err());

            assert!(
                store
                    .consensus_by_sha3_digest_of_signed_part(&[0x99; 32])?
                    .is_none()
            );
        }

        {
            assert!(
                store
                    .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                    .is_some()
            );
            store.delete_consensus(&cmeta)?;
            assert!(
                store
                    .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                    .is_none()
            );
        }

        Ok(())
    }

    #[test]
    fn authcerts() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;
        let now = now_utc();
        let one_hour = 1.hours();

        let keyids = AuthCertKeyIds {
            id_fingerprint: [3; 20].into(),
            sk_fingerprint: [4; 20].into(),
        };
        let keyids2 = AuthCertKeyIds {
            id_fingerprint: [4; 20].into(),
            sk_fingerprint: [3; 20].into(),
        };

        let m1 = AuthCertMeta::new(keyids, now.into(), SystemTime::from(now + one_hour * 24));

        store.store_authcerts(&[(m1, "Pretend this is a cert")])?;

        let certs = store.authcerts(&[keyids, keyids2])?;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs.get(&keyids).unwrap(), "Pretend this is a cert");

        Ok(())
    }

    #[test]
    fn microdescs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = now_utc();
        let one_day = 1.days();

        let d1 = [5_u8; 32];
        let d2 = [7; 32];
        let d3 = [42; 32];
        let d4 = [99; 32];

        let long_ago: OffsetDateTime = now - one_day * 100;
        store.store_microdescs(
            &[
                ("Fake micro 1", &d1),
                ("Fake micro 2", &d2),
                ("Fake micro 3", &d3),
            ],
            long_ago.into(),
        )?;

        store.update_microdescs_listed(&[d2], now.into())?;

        let mds = store.microdescs(&[d2, d3, d4])?;
        assert_eq!(mds.len(), 2);
        assert_eq!(mds.get(&d1), None);
        assert_eq!(mds.get(&d2).unwrap(), "Fake micro 2");
        assert_eq!(mds.get(&d3).unwrap(), "Fake micro 3");
        assert_eq!(mds.get(&d4), None);

        // Now we'll expire.  that should drop everything but d2.
        store.expire_all(&EXPIRATION_DEFAULTS)?;
        let mds = store.microdescs(&[d2, d3, d4])?;
        assert_eq!(mds.len(), 1);
        assert_eq!(mds.get(&d2).unwrap(), "Fake micro 2");

        Ok(())
    }

    #[test]
    #[cfg(feature = "routerdesc")]
    fn routerdescs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = now_utc();
        let one_day = 1.days();
        let long_ago: OffsetDateTime = now - one_day * 100;
        let recently = now - one_day;

        let d1 = [5_u8; 20];
        let d2 = [7; 20];
        let d3 = [42; 20];
        let d4 = [99; 20];

        store.store_routerdescs(&[
            ("Fake routerdesc 1", long_ago.into(), &d1),
            ("Fake routerdesc 2", recently.into(), &d2),
            ("Fake routerdesc 3", long_ago.into(), &d3),
        ])?;

        let rds = store.routerdescs(&[d2, d3, d4])?;
        assert_eq!(rds.len(), 2);
        assert_eq!(rds.get(&d1), None);
        assert_eq!(rds.get(&d2).unwrap(), "Fake routerdesc 2");
        assert_eq!(rds.get(&d3).unwrap(), "Fake routerdesc 3");
        assert_eq!(rds.get(&d4), None);

        // Now we'll expire.  that should drop everything but d2.
        store.expire_all(&EXPIRATION_DEFAULTS)?;
        let rds = store.routerdescs(&[d2, d3, d4])?;
        assert_eq!(rds.len(), 1);
        assert_eq!(rds.get(&d2).unwrap(), "Fake routerdesc 2");

        Ok(())
    }

    #[test]
    fn from_path_rw() -> Result<()> {
        let tmp = tempdir().unwrap();
        let mistrust = fs_mistrust::Mistrust::new_dangerously_trust_everyone();

        // Nothing there: can't open read-only
        let r = SqliteStore::from_path_and_mistrust(tmp.path(), &mistrust, true);
        assert!(r.is_err());
        assert!(!tmp.path().join("dir_blobs").try_exists().unwrap());

        // Opening it read-write will crate the files
        {
            let mut store = SqliteStore::from_path_and_mistrust(tmp.path(), &mistrust, false)?;
            assert!(tmp.path().join("dir_blobs").is_dir());
            assert!(matches!(&store.lockfile, LockFile::Locked(_)));
            assert!(!store.is_readonly());
            assert!(store.upgrade_to_readwrite()?); // no-op.
        }

        // At this point, we can successfully make a read-only connection.
        {
            let mut store2 = SqliteStore::from_path_and_mistrust(tmp.path(), &mistrust, true)?;
            assert!(store2.is_readonly());

            // Nobody else is locking this, so we can upgrade.
            assert!(store2.upgrade_to_readwrite()?); // no-op.
            assert!(!store2.is_readonly());
        }
        Ok(())
    }

    #[test]
    fn orphaned_blobs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;
        /*
        for ent in store.blob_dir.read_directory(".")?.flatten() {
            println!("{:?}", ent);
        }
        */
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 0);

        let now = now_utc();
        let one_week = 1.weeks();
        let _fname_good = store.save_blob(
            b"Goodbye, dear friends",
            "greeting",
            "sha1",
            &hex!("2149c2a7dbf5be2bb36fb3c5080d0fb14cb3355c"),
            now + one_week,
        )?;
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 1);

        // Now, create a two orphaned blobs: one with a recent timestamp, and one with an older
        // timestamp.
        store
            .blob_dir
            .write_and_replace("fairly_new", b"new contents will stay")?;
        store
            .blob_dir
            .write_and_replace("fairly_old", b"old contents will be removed")?;
        filetime::set_file_mtime(
            store.blob_dir.join("fairly_old")?,
            SystemTime::from(now - one_week).into(),
        )
        .expect("Can't adjust mtime");

        assert_eq!(store.blob_dir.read_directory(".")?.count(), 3);

        store.remove_unreferenced_blobs(now, &EXPIRATION_DEFAULTS)?;
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 2);

        Ok(())
    }

    #[test]
    fn unreferenced_consensus_blob() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = now_utc();
        let one_week = 1.weeks();

        // Make a blob that claims to be a consensus, and which has not yet expired, but which is
        // not listed in the consensus table.  It should get removed.
        let fname = store.save_blob(
            b"pretend this is a consensus",
            "con_fake",
            "sha1",
            &hex!("803e5a45eea7766a62a735e051a25a50ffb9b1cf"),
            now + one_week,
        )?;

        assert_eq!(store.blob_dir.read_directory(".")?.count(), 1);
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname)?).unwrap()[..],
            b"pretend this is a consensus"
        );
        let n: u32 = store
            .conn
            .query_row("SELECT COUNT(filename) FROM ExtDocs", [], |row| row.get(0))?;
        assert_eq!(n, 1);

        store.expire_all(&EXPIRATION_DEFAULTS)?;
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 0);

        let n: u32 = store
            .conn
            .query_row("SELECT COUNT(filename) FROM ExtDocs", [], |row| row.get(0))?;
        assert_eq!(n, 0);

        Ok(())
    }

    #[test]
    fn vanished_blob_cleanup() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = now_utc();
        let one_week = 1.weeks();

        // Make a few blobs.
        let mut fnames = vec![];
        for idx in 0..8 {
            let content = format!("Example {idx}");
            let digest = Sha3_256::digest(content.as_bytes());
            let fname = store.save_blob(
                content.as_bytes(),
                "blob",
                "sha3-256",
                digest.as_slice(),
                now + one_week,
            )?;
            fnames.push(fname);
        }

        // Delete the odd-numbered blobs.
        store.blob_dir.remove_file(&fnames[1])?;
        store.blob_dir.remove_file(&fnames[3])?;
        store.blob_dir.remove_file(&fnames[5])?;
        store.blob_dir.remove_file(&fnames[7])?;

        let n_removed = {
            let tx = store.conn.transaction()?;
            let n = SqliteStore::remove_entries_for_vanished_blobs(&store.blob_dir, &tx)?;
            tx.commit()?;
            n
        };
        assert_eq!(n_removed, 4);

        // Make sure that it was the _odd-numbered_ ones that got deleted from the DB.
        let (n_1,): (u32,) =
            store
                .conn
                .query_row(COUNT_EXTDOC_BY_PATH, params![&fnames[1]], |row| {
                    row.try_into()
                })?;
        let (n_2,): (u32,) =
            store
                .conn
                .query_row(COUNT_EXTDOC_BY_PATH, params![&fnames[2]], |row| {
                    row.try_into()
                })?;
        assert_eq!(n_1, 0);
        assert_eq!(n_2, 1);
        Ok(())
    }

    #[test]
    fn protocol_statuses() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = SystemTime::get();
        let hour = 1.hours();

        let valid_after = now;
        let protocols = serde_json::from_str(
            r#"{
            "client":{
                "required":"Link=5 LinkAuth=3",
                "recommended":"Link=1-5 LinkAuth=2-5"
            },
            "relay":{
                "required":"Wombat=20-22 Knish=25-27",
                "recommended":"Wombat=20-30 Knish=20-30"
            }
            }"#,
        )
        .unwrap();

        let v = store.cached_protocol_recommendations()?;
        assert!(v.is_none());

        store.update_protocol_recommendations(valid_after, &protocols)?;
        let v = store.cached_protocol_recommendations()?.unwrap();
        assert_eq!(v.0, now);
        assert_eq!(
            serde_json::to_string(&protocols).unwrap(),
            serde_json::to_string(&v.1).unwrap()
        );

        let protocols2 = serde_json::from_str(
            r#"{
            "client":{
                "required":"Link=5 ",
                "recommended":"Link=1-5"
            },
            "relay":{
                "required":"Wombat=20",
                "recommended":"Cons=6"
            }
            }"#,
        )
        .unwrap();

        let valid_after_2 = now + hour;
        store.update_protocol_recommendations(valid_after_2, &protocols2)?;

        let v = store.cached_protocol_recommendations()?.unwrap();
        assert_eq!(v.0, now + hour);
        assert_eq!(
            serde_json::to_string(&protocols2).unwrap(),
            serde_json::to_string(&v.1).unwrap()
        );

        Ok(())
    }
