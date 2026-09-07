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
    use super::sealed::RequestableInner;
    use super::*;
    use web_time_compat::SystemTimeExt;

    #[test]
    fn test_md_request() -> Result<()> {
        let d1 = b"This is a testing digest. it isn";
        let d2 = b"'t actually SHA-256.............";

        let mut req = MicrodescRequest::default();
        req.push(*d1);
        assert!(!req.partial_response_body_ok());
        req.push(*d2);
        assert!(req.partial_response_body_ok());
        assert_eq!(req.max_response_len(), 16 << 10);

        let req = crate::util::request_to_string(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/micro/d/J3QgYWN0dWFsbHkgU0hBLTI1Ni4uLi4uLi4uLi4uLi4-VGhpcyBpcyBhIHRlc3RpbmcgZGlnZXN0LiBpdCBpc24 HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                all_encodings()
            )
        );

        // Try it with FromIterator, and use some accessors.
        let req2: MicrodescRequest = vec![*d1, *d2].into_iter().collect();
        let ds: Vec<_> = req2.digests().collect();
        assert_eq!(ds, vec![d1, d2]);
        let req2 = crate::util::request_to_string(&req2.make_request()?);
        assert_eq!(req, req2);

        Ok(())
    }

    #[test]
    fn test_cert_request() -> Result<()> {
        let d1 = b"This is a testing dn";
        let d2 = b"'t actually SHA-256.";
        let key1 = AuthCertKeyIds {
            id_fingerprint: (*d1).into(),
            sk_fingerprint: (*d2).into(),
        };

        let d3 = b"blah blah blah 1 2 3";
        let d4 = b"I like pizza from Na";
        let key2 = AuthCertKeyIds {
            id_fingerprint: (*d3).into(),
            sk_fingerprint: (*d4).into(),
        };

        let mut req = AuthCertRequest::default();
        req.push(key1);
        assert!(!req.partial_response_body_ok());
        req.push(key2);
        assert!(req.partial_response_body_ok());
        assert_eq!(req.max_response_len(), 32 << 10);

        let keys: Vec<_> = req.keys().collect();
        assert_eq!(keys, vec![&key1, &key2]);

        let req = crate::util::request_to_string(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/keys/fp-sk/5468697320697320612074657374696e6720646e-27742061637475616c6c79205348412d3235362e+626c616820626c616820626c6168203120322033-49206c696b652070697a7a612066726f6d204e61 HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                all_encodings()
            )
        );

        let req2: AuthCertRequest = vec![key1, key2].into_iter().collect();
        let req2 = crate::util::request_to_string(&req2.make_request()?);
        assert_eq!(req, req2);

        Ok(())
    }

    #[test]
    fn test_consensus_request() -> Result<()> {
        let d1 = RsaIdentity::from_bytes(
            &hex::decode("03479E93EBF3FF2C58C1C9DBF2DE9DE9C2801B3E").unwrap(),
        )
        .unwrap();

        let d2 = b"blah blah blah 12 blah blah blah";
        let d3 = SystemTime::get();
        let mut req = ConsensusRequest::default();

        let when = httpdate::fmt_http_date(d3);

        req.push_authority_id(d1);
        req.push_old_consensus_digest(*d2);
        req.set_last_consensus_date(d3);
        assert!(!req.partial_response_body_ok());
        assert_eq!(req.max_response_len(), (16 << 20) - 1);
        assert_eq!(req.old_consensus_digests().next(), Some(d2));
        assert_eq!(req.authority_ids().next(), Some(&d1));
        assert_eq!(req.last_consensus_date(), Some(d3));

        let req = crate::util::request_to_string(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/status-vote/current/consensus-microdesc/03479e93ebf3ff2c58c1c9dbf2de9de9c2801b3e HTTP/1.0\r\naccept-encoding: {}\r\nif-modified-since: {}\r\nx-or-diff-from-consensus: 626c616820626c616820626c616820313220626c616820626c616820626c6168\r\n\r\n",
                all_encodings(),
                when
            )
        );

        // Request without authorities
        let req = ConsensusRequest::default();
        let req = crate::util::request_to_string(&req.make_request()?);
        assert_eq!(
            req,
            format!(
                "GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                all_encodings()
            )
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "routerdesc")]
    fn test_rd_request_all() -> Result<()> {
        let req = RouterDescRequest::all();
        assert!(req.partial_response_body_ok());
        assert_eq!(req.max_response_len(), 1 << 26);

        let req = crate::util::request_to_string(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/server/all HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                all_encodings()
            )
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "routerdesc")]
    fn test_rd_request() -> Result<()> {
        let d1 = b"at some point I got ";
        let d2 = b"of writing in hex...";

        let mut req = RouterDescRequest::default();

        if let RequestedDescs::Digests(ref mut digests) = req.requested_descriptors {
            digests.push(*d1);
        }
        assert!(!req.partial_response_body_ok());
        if let RequestedDescs::Digests(ref mut digests) = req.requested_descriptors {
            digests.push(*d2);
        }
        assert!(req.partial_response_body_ok());
        assert_eq!(req.max_response_len(), 16 << 10);

        let req = crate::util::request_to_string(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/server/d/617420736f6d6520706f696e74204920676f7420+6f662077726974696e6720696e206865782e2e2e HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                all_encodings()
            )
        );

        // Try it with FromIterator, and use some accessors.
        let req2: RouterDescRequest = vec![*d1, *d2].into_iter().collect();
        let ds: Vec<_> = match req2.requested_descriptors {
            RequestedDescs::Digests(ref digests) => digests.iter().collect(),
            RequestedDescs::AllDescriptors => Vec::new(),
        };
        assert_eq!(ds, vec![d1, d2]);
        let req2 = crate::util::request_to_string(&req2.make_request()?);
        assert_eq!(req, req2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "routerdesc")]
    fn test_extra_info_request() -> Result<()> {
        let req = ExtraInfoRequest::from_iter([[0; 20], [1; 20], [2; 20]]);
        assert_eq!(
            crate::util::request_to_string(&req.make_request()?),
            format!(
                "GET /tor/extra/d/{}+{}+{} HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                hex::encode_upper([0; 20]),
                hex::encode_upper([1; 20]),
                hex::encode_upper([2; 20]),
                all_encodings()
            )
        );

        let req = ExtraInfoRequest::all();
        assert_eq!(
            crate::util::request_to_string(&req.make_request()?),
            format!(
                "GET /tor/extra/all HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                all_encodings()
            )
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "hs-client")]
    fn test_hs_desc_download_request() -> Result<()> {
        use tor_llcrypto::pk::ed25519::Ed25519Identity;
        let hsid = [1, 2, 3, 4].iter().cycle().take(32).cloned().collect_vec();
        let hsid = Ed25519Identity::new(hsid[..].try_into().unwrap());
        let hsid = HsBlindId::from(hsid);
        let req = HsDescDownloadRequest::new(hsid);
        assert!(!req.partial_response_body_ok());
        assert_eq!(req.max_response_len(), 50 * 1000);

        let req = crate::util::request_to_string(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/hs/3/AQIDBAECAwQBAgMEAQIDBAECAwQBAgMEAQIDBAECAwQ HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                UNIVERSAL_ENCODINGS
            )
        );

        Ok(())
    }
