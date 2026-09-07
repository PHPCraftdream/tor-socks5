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
    use super::*;
    use std::convert::TryInto;
    use std::sync::Arc;
    use tempfile::TempDir;
    use time::macros::datetime;
    use tor_dircommon::{
        authority::{AuthorityContacts, AuthorityContactsBuilder},
        config::{DownloadScheduleConfig, NetworkConfig},
    };
    use tor_netdoc::doc::authcert::AuthCertKeyIds;
    use tor_rtcompat::RuntimeSubstExt as _;
    use tor_rtmock::simple_time::SimpleMockTimeProvider;

    #[test]
    fn download_schedule() {
        let va = datetime!(2008-08-02 20:00 UTC).into();
        let fu = datetime!(2008-08-02 21:00 UTC).into();
        let vu = datetime!(2008-08-02 23:00 UTC).into();
        let lifetime = Lifetime::new(va, fu, vu).unwrap();

        let expected_start: SystemTime = datetime!(2008-08-02 21:45 UTC).into();
        let expected_range = Duration::from_millis((75 * 60 * 1000) * 7 / 8);

        let (start, range) = client_download_range(&lifetime);
        assert_eq!(start, expected_start);
        assert_eq!(range, expected_range);

        for _ in 0..100 {
            let when = pick_download_time(&lifetime);
            assert!(when > va);
            assert!(when >= expected_start);
            assert!(when < vu);
            assert!(when <= expected_start + range);
        }
    }

    /// Makes a memory-backed storage.
    fn temp_store() -> (TempDir, Mutex<DynStore>) {
        let tempdir = TempDir::new().unwrap();

        let store = crate::storage::SqliteStore::from_path_and_mistrust(
            tempdir.path(),
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
            false,
        )
        .unwrap();

        (tempdir, Mutex::new(Box::new(store)))
    }

    fn make_time_shifted_runtime(now: SystemTime, rt: impl Runtime) -> impl Runtime {
        let msp = SimpleMockTimeProvider::from_wallclock(now);
        rt.with_sleep_provider(msp.clone())
            .with_coarse_time_provider(msp)
    }

    fn make_dirmgr_config(authorities: Option<AuthorityContactsBuilder>) -> Arc<DirMgrConfig> {
        let mut netcfg = NetworkConfig::builder();
        netcfg.set_fallback_caches(vec![]);
        if let Some(a) = authorities {
            *netcfg.authorities() = a;
        }
        let cfg = DirMgrConfig {
            cache_dir: "/we_will_never_use_this/".into(),
            network: netcfg.build().unwrap(),
            ..Default::default()
        };
        Arc::new(cfg)
    }

    // Test data
    const CONSENSUS: &str = include_str!("../testdata/mdconsensus1.txt");
    const CONSENSUS2: &str = include_str!("../testdata/mdconsensus2.txt");
    const AUTHCERT_5696: &str = include_str!("../testdata/cert-5696.txt");
    const AUTHCERT_5A23: &str = include_str!("../testdata/cert-5A23.txt");
    #[allow(unused)]
    const AUTHCERT_7C47: &str = include_str!("../testdata/cert-7C47.txt");
    fn test_time() -> SystemTime {
        datetime!(2020-08-07 12:42:45 UTC).into()
    }
    fn rsa(s: &str) -> RsaIdentity {
        RsaIdentity::from_hex(s).unwrap()
    }
    fn test_authorities() -> AuthorityContactsBuilder {
        let mut builder = AuthorityContacts::builder();
        builder
            .v3idents()
            .push(rsa("5696AB38CB3852AFA476A5C07B2D4788963D5567"));
        builder
            .v3idents()
            .push(rsa("5A23BA701776C9C1AB1C06E734E92AB3D5350D64"));

        builder
    }
    fn authcert_id_5696() -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: rsa("5696ab38cb3852afa476a5c07b2d4788963d5567"),
            sk_fingerprint: rsa("f6ed4aa64d83caede34e19693a7fcf331aae8a6a"),
        }
    }
    fn authcert_id_5a23() -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: rsa("5a23ba701776c9c1ab1c06e734e92ab3d5350d64"),
            sk_fingerprint: rsa("d08e965cc6dcb6cb6ed776db43e616e93af61177"),
        }
    }
    // remember, we're saying that we don't recognize this one as an authority.
    fn authcert_id_7c47() -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: rsa("7C47DCB4A90E2C2B7C7AD27BD641D038CF5D7EBE"),
            sk_fingerprint: rsa("D3C013E0E6C82E246090D1C0798B75FCB7ACF120"),
        }
    }
    fn microdescs() -> HashMap<MdDigest, String> {
        const MICRODESCS: &str = include_str!("../testdata/microdescs.txt");
        let text = MICRODESCS;
        MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed)
            .unwrap()
            .map(|res| {
                let anno = res.unwrap();
                let text = anno.within(text).unwrap();
                let md = anno.into_microdesc();
                (*md.digest(), text.to_owned())
            })
            .collect()
    }

    #[test]
    fn get_consensus_state() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let rt = make_time_shifted_runtime(test_time(), rt);
            let cfg = make_dirmgr_config(None);

            let (_tempdir, store) = temp_store();

            let mut state = GetConsensusState::new(
                rt.clone(),
                cfg,
                CacheUsage::CacheOkay,
                None,
                #[cfg(feature = "dirfilter")]
                Arc::new(crate::filter::NilFilter),
            );

            // Is description okay?
            assert_eq!(&state.describe(), "Looking for a consensus.");

            // Basic properties: without a consensus it is not ready to advance.
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));

            // Basic properties: it doesn't want to reset.
            assert!(state.reset_time().is_none());

            // Its starting DirStatus is "fetching a consensus".
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching a consensus"
            );

            // Download configuration is simple: only 1 request can be done in
            // parallel.  It uses a consensus retry schedule.
            let retry = state.dl_config();
            assert_eq!(retry, DownloadScheduleConfig::default().retry_consensus());

            // Do we know what we want?
            let docs = state.missing_docs();
            assert_eq!(docs.len(), 1);
            let docid = docs[0];

            assert!(matches!(
                docid,
                DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    cache_usage: CacheUsage::CacheOkay,
                }
            ));
            let source = DocSource::DirServer { source: None };

            // Now suppose that we get some complete junk from a download.
            let req = tor_dirclient::request::ConsensusRequest::new(ConsensusFlavor::Microdesc);
            let req = crate::docid::ClientRequest::Consensus(req);
            let mut changed = false;
            let outcome = state.add_from_download(
                "this isn't a consensus",
                &req,
                source.clone(),
                Some(&store),
                &mut changed,
            );
            assert!(matches!(outcome, Err(Error::NetDocError { .. })));
            assert!(!changed);
            // make sure it wasn't stored...
            assert!(
                store
                    .lock()
                    .unwrap()
                    .latest_consensus(ConsensusFlavor::Microdesc, None)
                    .unwrap()
                    .is_none()
            );

            // Now try again, with a real consensus... but the wrong authorities.
            let mut changed = false;
            let outcome = state.add_from_download(
                CONSENSUS,
                &req,
                source.clone(),
                Some(&store),
                &mut changed,
            );
            assert!(matches!(outcome, Err(Error::UnrecognizedAuthorities)));
            assert!(!changed);
            assert!(
                store
                    .lock()
                    .unwrap()
                    .latest_consensus(ConsensusFlavor::Microdesc, None)
                    .unwrap()
                    .is_none()
            );

            // Great. Change the receiver to use a configuration where these test
            // authorities are recognized.
            let cfg = make_dirmgr_config(Some(test_authorities()));

            let mut state = GetConsensusState::new(
                rt.clone(),
                cfg,
                CacheUsage::CacheOkay,
                None,
                #[cfg(feature = "dirfilter")]
                Arc::new(crate::filter::NilFilter),
            );
            let mut changed = false;
            let outcome =
                state.add_from_download(CONSENSUS, &req, source, Some(&store), &mut changed);
            assert!(outcome.is_ok());
            assert!(changed);
            assert!(
                store
                    .lock()
                    .unwrap()
                    .latest_consensus(ConsensusFlavor::Microdesc, None)
                    .unwrap()
                    .is_some()
            );

            // And with that, we should be asking for certificates
            assert!(state.can_advance());
            assert_eq!(&state.describe(), "About to fetch certificates.");
            assert_eq!(state.missing_docs(), Vec::new());
            let next = Box::new(state).advance();
            assert_eq!(
                &next.describe(),
                "Downloading certificates for consensus (we are missing 2/2)."
            );

            // Try again, but this time get the state from the cache.
            let cfg = make_dirmgr_config(Some(test_authorities()));
            let mut state = GetConsensusState::new(
                rt,
                cfg,
                CacheUsage::CacheOkay,
                None,
                #[cfg(feature = "dirfilter")]
                Arc::new(crate::filter::NilFilter),
            );
            let text: crate::storage::InputString = CONSENSUS.to_owned().into();
            let map = vec![(docid, text.into())].into_iter().collect();
            let mut changed = false;
            let outcome = state.add_from_cache(map, &mut changed);
            assert!(outcome.is_ok());
            assert!(changed);
            assert!(state.can_advance());
        });
    }

    #[test]
    fn get_certs_state() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            /// Construct a GetCertsState with our test data
            fn new_getcerts_state(rt: impl Runtime) -> Box<dyn DirState> {
                let rt = make_time_shifted_runtime(test_time(), rt);
                let cfg = make_dirmgr_config(Some(test_authorities()));
                let mut state = GetConsensusState::new(
                    rt,
                    cfg,
                    CacheUsage::CacheOkay,
                    None,
                    #[cfg(feature = "dirfilter")]
                    Arc::new(crate::filter::NilFilter),
                );
                let source = DocSource::DirServer { source: None };
                let req = tor_dirclient::request::ConsensusRequest::new(ConsensusFlavor::Microdesc);
                let req = crate::docid::ClientRequest::Consensus(req);
                let mut changed = false;
                let outcome = state.add_from_download(CONSENSUS, &req, source, None, &mut changed);
                assert!(outcome.is_ok());
                Box::new(state).advance()
            }

            let (_tempdir, store) = temp_store();
            let mut state = new_getcerts_state(rt.clone());
            // Basic properties: description, status, reset time.
            assert_eq!(
                &state.describe(),
                "Downloading certificates for consensus (we are missing 2/2)."
            );
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));
            let consensus_expires: SystemTime = datetime!(2020-08-07 12:43:20 UTC).into();
            let post_valid_tolerance = crate::DirTolerance::default().post_valid_tolerance();
            assert_eq!(
                state.reset_time(),
                Some(consensus_expires + post_valid_tolerance)
            );
            let retry = state.dl_config();
            assert_eq!(retry, DownloadScheduleConfig::default().retry_certs());

            // Bootstrap status okay?
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching authority certificates (0/2)"
            );

            // Check that we get the right list of missing docs.
            let missing = state.missing_docs();
            assert_eq!(missing.len(), 2); // We are missing two certificates.
            assert!(missing.contains(&DocId::AuthCert(authcert_id_5696())));
            assert!(missing.contains(&DocId::AuthCert(authcert_id_5a23())));
            // we don't ask for this one because we don't recognize its authority
            assert!(!missing.contains(&DocId::AuthCert(authcert_id_7c47())));

            // Add one from the cache; make sure the list is still right
            let text1: crate::storage::InputString = AUTHCERT_5696.to_owned().into();
            // let text2: crate::storage::InputString = AUTHCERT_5A23.to_owned().into();
            let docs = vec![(DocId::AuthCert(authcert_id_5696()), text1.into())]
                .into_iter()
                .collect();
            let mut changed = false;
            let outcome = state.add_from_cache(docs, &mut changed);
            assert!(changed);
            assert!(outcome.is_ok()); // no error, and something changed.
            assert!(!state.can_advance()); // But we aren't done yet.
            let missing = state.missing_docs();
            assert_eq!(missing.len(), 1); // Now we're only missing one!
            assert!(missing.contains(&DocId::AuthCert(authcert_id_5a23())));
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching authority certificates (1/2)"
            );

            // Now try to add the other from a download ... but fail
            // because we didn't ask for it.
            let source = DocSource::DirServer { source: None };
            let mut req = tor_dirclient::request::AuthCertRequest::new();
            req.push(authcert_id_5696()); // it's the wrong id.
            let req = ClientRequest::AuthCert(req);
            let mut changed = false;
            let outcome = state.add_from_download(
                AUTHCERT_5A23,
                &req,
                source.clone(),
                Some(&store),
                &mut changed,
            );
            assert!(matches!(outcome, Err(Error::Unwanted(_))));
            assert!(!changed);
            let missing2 = state.missing_docs();
            assert_eq!(missing, missing2); // No change.
            assert!(
                store
                    .lock()
                    .unwrap()
                    .authcerts(&[authcert_id_5a23()])
                    .unwrap()
                    .is_empty()
            );

            // Now try to add the other from a download ... for real!
            let mut req = tor_dirclient::request::AuthCertRequest::new();
            req.push(authcert_id_5a23()); // Right idea this time!
            let req = ClientRequest::AuthCert(req);
            let mut changed = false;
            let outcome =
                state.add_from_download(AUTHCERT_5A23, &req, source, Some(&store), &mut changed);
            assert!(outcome.is_ok()); // No error, _and_ something changed!
            assert!(changed);
            let missing3 = state.missing_docs();
            assert!(missing3.is_empty());
            assert!(state.can_advance());
            assert!(
                !store
                    .lock()
                    .unwrap()
                    .authcerts(&[authcert_id_5a23()])
                    .unwrap()
                    .is_empty()
            );

            let next = state.advance();
            assert_eq!(
                &next.describe(),
                "Downloading microdescriptors (we are missing 6)."
            );

            // If we start from scratch and reset, we're back in GetConsensus.
            let state = new_getcerts_state(rt);
            let state = state.reset();
            assert_eq!(&state.describe(), "Downloading a consensus.");

            // TODO: I'd like even more tests to make sure that we never
            // accept a certificate for an authority we don't believe in.
        });
    }

    #[test]
    fn get_microdescs_state() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            /// Construct a GetCertsState with our test data
            fn new_getmicrodescs_state(rt: impl Runtime) -> GetMicrodescsState<impl Runtime> {
                let rt = make_time_shifted_runtime(test_time(), rt);
                let cfg = make_dirmgr_config(Some(test_authorities()));
                let (signed, rest, consensus) = MdConsensus::parse(CONSENSUS2).unwrap();
                let consensus = consensus
                    .dangerously_assume_timely()
                    .dangerously_assume_wellsigned();
                let meta = ConsensusMeta::from_consensus(signed, rest, &consensus);
                GetMicrodescsState::new(
                    CacheUsage::CacheOkay,
                    consensus,
                    meta,
                    rt,
                    cfg,
                    None,
                    #[cfg(feature = "dirfilter")]
                    Arc::new(crate::filter::NilFilter),
                )
            }
            fn d64(s: &str) -> MdDigest {
                use base64ct::{Base64Unpadded, Encoding as _};
                Base64Unpadded::decode_vec(s).unwrap().try_into().unwrap()
            }

            // If we start from scratch and reset, we're back in GetConsensus.
            let state = new_getmicrodescs_state(rt.clone());
            let state = Box::new(state).reset();
            assert_eq!(&state.describe(), "Looking for a consensus.");

            // Check the basics.
            let mut state = new_getmicrodescs_state(rt.clone());
            assert_eq!(
                &state.describe(),
                "Downloading microdescriptors (we are missing 4)."
            );
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));
            {
                let reset_time = state.reset_time().unwrap();
                let fresh_until: SystemTime = datetime!(2021-10-27 21:27:00 UTC).into();
                let valid_until: SystemTime = datetime!(2021-10-27 21:27:20 UTC).into();
                assert!(reset_time >= fresh_until);
                assert!(reset_time <= valid_until + state.config.tolerance.post_valid_tolerance());
            }
            let retry = state.dl_config();
            assert_eq!(retry, DownloadScheduleConfig::default().retry_microdescs());
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching microdescriptors (0/4)"
            );

            // Now check whether we're missing all the right microdescs.
            let missing = state.missing_docs();
            let md_text = microdescs();
            assert_eq!(missing.len(), 4);
            assert_eq!(md_text.len(), 4);
            let md1 = d64("LOXRj8YZP0kwpEAsYOvBZWZWGoWv5b/Bp2Mz2Us8d8g");
            let md2 = d64("iOhVp33NyZxMRDMHsVNq575rkpRViIJ9LN9yn++nPG0");
            let md3 = d64("/Cd07b3Bl0K0jX2/1cAvsYXJJMi5d8UBU+oWKaLxoGo");
            let md4 = d64("z+oOlR7Ga6cg9OoC/A3D3Ey9Rtc4OldhKlpQblMfQKo");
            for md_digest in [md1, md2, md3, md4] {
                assert!(missing.contains(&DocId::Microdesc(md_digest)));
                assert!(md_text.contains_key(&md_digest));
            }

            // Try adding a microdesc from the cache.
            let (_tempdir, store) = temp_store();
            let doc1: crate::storage::InputString = md_text.get(&md1).unwrap().clone().into();
            let docs = vec![(DocId::Microdesc(md1), doc1.into())]
                .into_iter()
                .collect();
            let mut changed = false;
            let outcome = state.add_from_cache(docs, &mut changed);
            assert!(outcome.is_ok()); // successfully loaded one MD.
            assert!(changed);
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));

            // Now we should be missing 3.
            let missing = state.missing_docs();
            assert_eq!(missing.len(), 3);
            assert!(!missing.contains(&DocId::Microdesc(md1)));
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching microdescriptors (1/4)"
            );

            // Try adding the rest as if from a download.
            let mut req = tor_dirclient::request::MicrodescRequest::new();
            let mut response = "".to_owned();
            for md_digest in [md2, md3, md4] {
                response.push_str(md_text.get(&md_digest).unwrap());
                req.push(md_digest);
            }
            let req = ClientRequest::Microdescs(req);
            let source = DocSource::DirServer { source: None };
            let mut changed = false;
            let outcome = state.add_from_download(
                response.as_str(),
                &req,
                source,
                Some(&store),
                &mut changed,
            );
            assert!(outcome.is_ok()); // successfully loaded MDs
            assert!(changed);
            match state.get_netdir_change().unwrap() {
                NetDirChange::AttemptReplace { netdir, .. } => {
                    assert!(netdir.take().is_some());
                }
                x => panic!("wrong netdir change: {:?}", x),
            }
            assert!(state.is_ready(Readiness::Complete));
            assert!(state.is_ready(Readiness::Usable));
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .microdescs(&[md2, md3, md4])
                    .unwrap()
                    .len(),
                3
            );

            let missing = state.missing_docs();
            assert!(missing.is_empty());
        });
    }
