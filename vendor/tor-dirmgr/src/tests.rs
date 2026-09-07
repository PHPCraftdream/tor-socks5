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
    use crate::docmeta::{AuthCertMeta, ConsensusMeta};
    use std::time::Duration;
    use tempfile::TempDir;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_netdoc::doc::netstatus::ConsensusFlavor;
    use tor_netdoc::doc::{authcert::AuthCertKeyIds, netstatus::Lifetime};
    use tor_rtcompat::SleepProvider;

    #[test]
    fn protocols() {
        let pr = supported_client_protocols();
        let expected = "DirCache=2".parse().unwrap();
        assert_eq!(pr, expected);
    }

    pub(crate) fn new_mgr<R: Runtime>(runtime: R) -> (TempDir, DirMgr<R>) {
        let dir = TempDir::new().unwrap();
        let config = DirMgrConfig {
            cache_dir: dir.path().into(),
            ..Default::default()
        };
        let store = DirMgrStore::new(&config, runtime.clone(), false).unwrap();
        let dirmgr = DirMgr::from_config(config, runtime, store, None, false).unwrap();

        (dir, dirmgr)
    }

    #[test]
    fn failing_accessors() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let (_tempdir, mgr) = new_mgr(rt);

            assert!(mgr.circmgr().is_err());
            assert!(mgr.netdir(Timeliness::Unchecked).is_err());
        });
    }

    #[test]
    fn load_and_store_internals() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let tomorrow = now + Duration::from_secs(86400);
            let later = tomorrow + Duration::from_secs(86400);

            let (_tempdir, mgr) = new_mgr(rt);

            // Seed the storage with a bunch of junk.
            let d1 = [5_u8; 32];
            let d2 = [7; 32];
            let d3 = [42; 32];
            let d4 = [99; 20];
            let d5 = [12; 20];
            let certid1 = AuthCertKeyIds {
                id_fingerprint: d4.into(),
                sk_fingerprint: d5.into(),
            };
            let certid2 = AuthCertKeyIds {
                id_fingerprint: d5.into(),
                sk_fingerprint: d4.into(),
            };

            {
                let mut store = mgr.store.lock().unwrap();

                store
                    .store_microdescs(
                        &[
                            ("Fake micro 1", &d1),
                            ("Fake micro 2", &d2),
                            ("Fake micro 3", &d3),
                        ],
                        now,
                    )
                    .unwrap();

                #[cfg(feature = "routerdesc")]
                store
                    .store_routerdescs(&[("Fake rd1", now, &d4), ("Fake rd2", now, &d5)])
                    .unwrap();

                store
                    .store_authcerts(&[
                        (
                            AuthCertMeta::new(certid1, now, tomorrow),
                            "Fake certificate one",
                        ),
                        (
                            AuthCertMeta::new(certid2, now, tomorrow),
                            "Fake certificate two",
                        ),
                    ])
                    .unwrap();

                let cmeta = ConsensusMeta::new(
                    Lifetime::new(now, tomorrow, later).unwrap(),
                    [102; 32],
                    [103; 32],
                );
                store
                    .store_consensus(&cmeta, ConsensusFlavor::Microdesc, false, "Fake consensus!")
                    .unwrap();
            }

            // Try to get it with text().
            let t1 = mgr.text(&DocId::Microdesc(d1)).unwrap().unwrap();
            assert_eq!(t1.as_str(), Ok("Fake micro 1"));

            let t2 = mgr
                .text(&DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    cache_usage: CacheUsage::CacheOkay,
                })
                .unwrap()
                .unwrap();
            assert_eq!(t2.as_str(), Ok("Fake consensus!"));

            let t3 = mgr.text(&DocId::Microdesc([255; 32])).unwrap();
            assert!(t3.is_none());

            // Now try texts()
            let d_bogus = DocId::Microdesc([255; 32]);
            let res = mgr
                .texts(vec![
                    DocId::Microdesc(d2),
                    DocId::Microdesc(d3),
                    d_bogus,
                    DocId::AuthCert(certid2),
                    #[cfg(feature = "routerdesc")]
                    DocId::RouterDesc(d5),
                ])
                .unwrap();
            assert_eq!(
                res.get(&DocId::Microdesc(d2)).unwrap().as_str(),
                Ok("Fake micro 2")
            );
            assert_eq!(
                res.get(&DocId::Microdesc(d3)).unwrap().as_str(),
                Ok("Fake micro 3")
            );
            assert!(!res.contains_key(&d_bogus));
            assert_eq!(
                res.get(&DocId::AuthCert(certid2)).unwrap().as_str(),
                Ok("Fake certificate two")
            );
            #[cfg(feature = "routerdesc")]
            assert_eq!(
                res.get(&DocId::RouterDesc(d5)).unwrap().as_str(),
                Ok("Fake rd2")
            );
        });
    }

    #[test]
    fn make_consensus_request() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let tomorrow = now + Duration::from_secs(86400);
            let later = tomorrow + Duration::from_secs(86400);

            let (_tempdir, mgr) = new_mgr(rt);
            let config = DirMgrConfig::default();

            // Try with an empty store.
            let req = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_consensus_request(
                    now,
                    ConsensusFlavor::Microdesc,
                    &**store,
                    &config,
                )
                .unwrap()
            };
            let tolerance = DirTolerance::default().post_valid_tolerance();
            match req {
                ClientRequest::Consensus(r) => {
                    assert_eq!(r.old_consensus_digests().count(), 0);
                    let date = r.last_consensus_date().unwrap();
                    assert!(date >= now - tolerance);
                    assert!(date <= now - tolerance + Duration::from_secs(3600));
                }
                _ => panic!("Wrong request type"),
            }

            // Add a fake consensus record.
            let d_prev = [42; 32];
            {
                let mut store = mgr.store.lock().unwrap();

                let cmeta = ConsensusMeta::new(
                    Lifetime::new(now, tomorrow, later).unwrap(),
                    d_prev,
                    [103; 32],
                );
                store
                    .store_consensus(&cmeta, ConsensusFlavor::Microdesc, false, "Fake consensus!")
                    .unwrap();
            }

            // Now try again.
            let req = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_consensus_request(
                    now,
                    ConsensusFlavor::Microdesc,
                    &**store,
                    &config,
                )
                .unwrap()
            };
            match req {
                ClientRequest::Consensus(r) => {
                    let ds: Vec<_> = r.old_consensus_digests().collect();
                    assert_eq!(ds.len(), 1);
                    assert_eq!(ds[0], &d_prev);
                    assert_eq!(r.last_consensus_date(), Some(now));
                }
                _ => panic!("Wrong request type"),
            }
        });
    }

    #[test]
    fn make_other_requests() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            use rand::RngExt;
            let (_tempdir, mgr) = new_mgr(rt);

            let certid1 = AuthCertKeyIds {
                id_fingerprint: [99; 20].into(),
                sk_fingerprint: [100; 20].into(),
            };
            let mut rng = testing_rng();
            #[cfg(feature = "routerdesc")]
            let rd_ids: Vec<DocId> = (0..1000).map(|_| DocId::RouterDesc(rng.random())).collect();
            let md_ids: Vec<DocId> = (0..1000).map(|_| DocId::Microdesc(rng.random())).collect();
            let config = DirMgrConfig::default();

            // Try an authcert.
            let query = DocId::AuthCert(certid1);
            let store = mgr.store.lock().unwrap();
            let reqs =
                bootstrap::make_requests_for_documents(&mgr.runtime, &[query], &**store, &config)
                    .unwrap();
            assert_eq!(reqs.len(), 1);
            let req = &reqs[0];
            if let ClientRequest::AuthCert(r) = req {
                assert_eq!(r.keys().next(), Some(&certid1));
            } else {
                panic!();
            }

            // Try a bunch of mds.
            let reqs =
                bootstrap::make_requests_for_documents(&mgr.runtime, &md_ids, &**store, &config)
                    .unwrap();
            assert_eq!(reqs.len(), 2);
            assert!(matches!(reqs[0], ClientRequest::Microdescs(_)));

            // Try a bunch of rds.
            #[cfg(feature = "routerdesc")]
            {
                let reqs = bootstrap::make_requests_for_documents(
                    &mgr.runtime,
                    &rd_ids,
                    &**store,
                    &config,
                )
                .unwrap();
                assert_eq!(reqs.len(), 2);
                assert!(matches!(reqs[0], ClientRequest::RouterDescs(_)));
            }
        });
    }

    #[test]
    fn expand_response() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let day = Duration::from_secs(86400);
            let config = DirMgrConfig::default();

            let (_tempdir, mgr) = new_mgr(rt);

            // Try a simple request: nothing should happen.
            let q = DocId::Microdesc([99; 32]);
            let r = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_requests_for_documents(&mgr.runtime, &[q], &**store, &config)
                    .unwrap()
            };
            let expanded = mgr.expand_response_text(&r[0], "ABC".to_string());
            assert_eq!(&expanded.unwrap(), "ABC");

            // Try a consensus response that doesn't look like a diff in
            // response to a query that doesn't ask for one.
            let latest_id = DocId::LatestConsensus {
                flavor: ConsensusFlavor::Microdesc,
                cache_usage: CacheUsage::CacheOkay,
            };
            let r = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_requests_for_documents(
                    &mgr.runtime,
                    &[latest_id],
                    &**store,
                    &config,
                )
                .unwrap()
            };
            let expanded = mgr.expand_response_text(&r[0], "DEF".to_string());
            assert_eq!(&expanded.unwrap(), "DEF");

            // Now stick some metadata and a string into the storage so that
            // we can ask for a diff.
            {
                let mut store = mgr.store.lock().unwrap();
                let d_in = [0x99; 32]; // This one, we can fake.
                let cmeta = ConsensusMeta::new(
                    Lifetime::new(now, now + day, now + 2 * day).unwrap(),
                    d_in,
                    d_in,
                );
                store
                    .store_consensus(
                        &cmeta,
                        ConsensusFlavor::Microdesc,
                        false,
                        "line 1\nline2\nline 3\n",
                    )
                    .unwrap();
            }

            // Try expanding something that isn't a consensus, even if we'd like
            // one.
            let r = {
                let store = mgr.store.lock().unwrap();
                bootstrap::make_requests_for_documents(
                    &mgr.runtime,
                    &[latest_id],
                    &**store,
                    &config,
                )
                .unwrap()
            };
            let expanded = mgr.expand_response_text(&r[0], "hello".to_string());
            assert_eq!(&expanded.unwrap(), "hello");

            // Finally, try "expanding" a diff (by applying it and checking the digest.
            let diff = "network-status-diff-version 1
hash 9999999999999999999999999999999999999999999999999999999999999999 8382374ca766873eb0d2530643191c6eaa2c5e04afa554cbac349b5d0592d300
2c
replacement line
.
".to_string();
            let expanded = mgr.expand_response_text(&r[0], diff);

            assert_eq!(expanded.unwrap(), "line 1\nreplacement line\nline 3\n");

            // If the digest is wrong, that should get rejected.
            let diff = "network-status-diff-version 1
hash 9999999999999999999999999999999999999999999999999999999999999999 9999999999999999999999999999999999999999999999999999999999999999
2c
replacement line
.
".to_string();
            let expanded = mgr.expand_response_text(&r[0], diff);
            assert!(expanded.is_err());
        });
    }
