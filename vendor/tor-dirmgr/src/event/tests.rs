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
    use std::time::Duration;

    use super::*;
    use float_eq::assert_float_eq;
    use futures::stream::StreamExt;
    use tor_rtcompat::test_with_all_runtimes;
    use web_time_compat::SystemTimeExt;

    #[test]
    fn subscribe_and_publish() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();
            let mut sub1 = publish.subscribe();
            publish.publish(DirEvent::NewConsensus);
            let mut sub2 = publish.subscribe();
            let ev = event_listener::Event::new();
            let lis = ev.listen();

            futures::join!(
                async {
                    // sub1 was created in time to see this event...
                    let val1 = sub1.next().await;
                    assert_eq!(val1, Some(DirEvent::NewConsensus));
                    ev.notify(1); // Tell the third task below to drop the publisher.
                    let val2 = sub1.next().await;
                    assert_eq!(val2, None);
                },
                async {
                    let val = sub2.next().await;
                    assert_eq!(val, None);
                },
                async {
                    lis.await;
                    drop(publish);
                }
            );
        });
    }

    #[test]
    fn receive_two() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();

            let mut sub = publish.subscribe();
            let ev = event_listener::Event::new();
            let ev_lis = ev.listen();
            futures::join!(
                async {
                    let val1 = sub.next().await;
                    assert_eq!(val1, Some(DirEvent::NewDescriptors));
                    ev.notify(1);
                    let val2 = sub.next().await;
                    assert_eq!(val2, Some(DirEvent::NewConsensus));
                },
                async {
                    publish.publish(DirEvent::NewDescriptors);
                    ev_lis.await;
                    publish.publish(DirEvent::NewConsensus);
                }
            );
        });
    }

    #[test]
    fn two_publishers() {
        test_with_all_runtimes!(|_rt| async {
            let publish1: FlagPublisher<DirEvent> = FlagPublisher::new();
            let publish2 = publish1.clone();

            let mut sub = publish1.subscribe();
            let ev1 = event_listener::Event::new();
            let ev2 = event_listener::Event::new();
            let ev1_lis = ev1.listen();
            let ev2_lis = ev2.listen();
            futures::join!(
                async {
                    let mut count = [0_usize; 2];
                    // These awaits guarantee that we will see at least one event flag of each
                    // type, before the stream is dropped.
                    ev1_lis.await;
                    ev2_lis.await;
                    while let Some(e) = sub.next().await {
                        count[e.to_index() as usize] += 1;
                    }
                    assert!(count[0] > 0);
                    assert!(count[1] > 0);
                    assert!(count[0] <= 100);
                    assert!(count[1] <= 100);
                },
                async {
                    for _ in 0..100 {
                        publish1.publish(DirEvent::NewDescriptors);
                        ev1.notify(1);
                        tor_rtcompat::task::yield_now().await;
                    }
                    drop(publish1);
                },
                async {
                    for _ in 0..100 {
                        publish2.publish(DirEvent::NewConsensus);
                        ev2.notify(1);
                        tor_rtcompat::task::yield_now().await;
                    }
                    drop(publish2);
                }
            );
        });
    }

    #[test]
    fn receive_after_publishers_are_gone() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();

            let mut sub = publish.subscribe();

            publish.publish(DirEvent::NewConsensus);
            drop(publish);
            let v = sub.next().await;
            assert_eq!(v, Some(DirEvent::NewConsensus));
            let v = sub.next().await;
            assert!(v.is_none());
        });
    }

    #[test]
    fn failed_conversion() {
        assert_eq!(DirEvent::from_index(999), None);
    }

    #[test]
    fn dir_status_basics() {
        let now = SystemTime::get();
        let hour = Duration::new(3600, 0);

        let nothing = DirStatus {
            progress: DirProgress::NoConsensus { after: None },
            ..Default::default()
        };
        let lifetime = netstatus::Lifetime::new(now, now + hour, now + hour * 2).unwrap();
        let unval = DirStatus {
            progress: DirProgress::FetchingCerts {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime,
                n_certs: (3, 5),
            },
            ..Default::default()
        };
        let lifetime =
            netstatus::Lifetime::new(now + hour, now + hour * 2, now + hour * 3).unwrap();
        let with_c = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime,
                n_mds: (30, 40),
                usable: false,
            },
            ..Default::default()
        };

        // lifetime()
        assert!(nothing.usable_lifetime().is_none());
        assert_eq!(unval.usable_lifetime().unwrap().valid_after(), now);
        assert_eq!(
            with_c.usable_lifetime().unwrap().valid_until(),
            now + hour * 3
        );

        // frac() (It's okay if we change the actual numbers here later; the
        // current ones are more or less arbitrary.)
        const TOL: f32 = 0.00001;
        assert_float_eq!(nothing.frac(), 0.0, abs <= TOL);
        assert_float_eq!(unval.frac(), 0.25 + 0.06, abs <= TOL);
        assert_float_eq!(with_c.frac(), 0.35 + 0.65 * 0.75, abs <= TOL);

        // frac_at()
        let t1 = now + hour / 2;
        let t2 = t1 + hour * 2;
        assert!(nothing.frac_at(t1).is_none());
        assert_float_eq!(unval.frac_at(t1).unwrap(), 0.25 + 0.06, abs <= TOL);
        assert!(with_c.frac_at(t1).is_none());
        assert!(nothing.frac_at(t2).is_none());
        assert!(unval.frac_at(t2).is_none());
        assert_float_eq!(with_c.frac_at(t2).unwrap(), 0.35 + 0.65 * 0.75, abs <= TOL);
    }

    #[test]
    fn dir_status_display() {
        use time::macros::datetime;
        let t1: SystemTime = datetime!(2022-01-17 11:00:00 UTC).into();
        let hour = Duration::new(3600, 0);
        let lifetime = netstatus::Lifetime::new(t1, t1 + hour, t1 + hour * 3).unwrap();

        let ds = DirStatus {
            progress: DirProgress::NoConsensus { after: None },
            ..Default::default()
        };
        assert_eq!(ds.to_string(), "fetching a consensus");

        let ds = DirStatus {
            progress: DirProgress::FetchingCerts {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime.clone(),
                n_certs: (3, 5),
            },
            ..Default::default()
        };
        assert_eq!(ds.to_string(), "fetching authority certificates (3/5)");

        let ds = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime.clone(),
                n_mds: (30, 40),
                usable: false,
            },
            ..Default::default()
        };
        assert_eq!(ds.to_string(), "fetching microdescriptors (30/40)");

        let ds = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime,
                n_mds: (30, 40),
                usable: true,
            },
            ..Default::default()
        };
        assert_eq!(
            ds.to_string(),
            "usable, fresh until 2022-01-17 12:00:00 UTC, and valid until 2022-01-17 14:00:00 UTC"
        );
    }

    #[test]
    fn bootstrap_status() {
        use time::macros::datetime;
        let t1: SystemTime = datetime!(2022-01-17 11:00:00 UTC).into();
        let hour = Duration::new(3600, 0);
        let lifetime = netstatus::Lifetime::new(t1, t1 + hour, t1 + hour * 3).unwrap();
        let lifetime2 = netstatus::Lifetime::new(t1 + hour, t1 + hour * 2, t1 + hour * 4).unwrap();

        let dp1 = DirProgress::Validated {
            lifetime: lifetime.clone(),
            usable_lifetime: lifetime.clone(),
            n_mds: (3, 40),
            usable: true,
        };
        let dp2 = DirProgress::Validated {
            lifetime: lifetime2.clone(),
            usable_lifetime: lifetime2.clone(),
            n_mds: (5, 40),
            usable: false,
        };
        let attempt1 = AttemptId::next();
        let attempt2 = AttemptId::next();

        let bs = DirBootstrapStatus(StatusEnum::Replacing {
            current: StatusEntry {
                id: attempt1,
                status: DirStatus {
                    progress: dp1.clone(),
                    ..Default::default()
                },
            },
            next: StatusEntry {
                id: attempt2,
                status: DirStatus {
                    progress: dp2.clone(),
                    ..Default::default()
                },
            },
        });

        assert_eq!(
            bs.to_string(),
            "directory is usable, fresh until 2022-01-17 12:00:00 UTC, and valid until 2022-01-17 14:00:00 UTC; next directory is fetching microdescriptors (5/40)"
        );

        const TOL: f32 = 0.00001;
        assert_float_eq!(bs.frac_at(t1 + hour / 2), 1.0, abs <= TOL);
        assert_float_eq!(
            bs.frac_at(t1 + hour * 3 + hour / 2),
            0.35 + 0.65 * 0.125,
            abs <= TOL
        );

        // Now try updating.

        // Case 1: we have a usable directory and the updated status isn't usable.
        let mut bs = bs;
        let dp3 = DirProgress::Validated {
            lifetime: lifetime2.clone(),
            usable_lifetime: lifetime2.clone(),
            n_mds: (10, 40),
            usable: false,
        };

        bs.update_progress(attempt2, dp3);
        assert!(matches!(
            bs.next().unwrap(),
            DirStatus {
                progress: DirProgress::Validated {
                    n_mds: (10, 40),
                    ..
                },
                ..
            }
        ));

        // Case 2: The new directory _is_ usable and newer.  It will replace the old one.
        let ds4 = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime2.clone(),
                usable_lifetime: lifetime2.clone(),
                n_mds: (20, 40),
                usable: true,
            },
            ..Default::default()
        };
        bs.update_progress(attempt2, ds4.progress);
        assert!(bs.next().is_none());
        assert_eq!(
            bs.current()
                .unwrap()
                .usable_lifetime()
                .unwrap()
                .valid_after(),
            lifetime2.valid_after()
        );

        // Case 3: The new directory is usable but older. Nothing will happen.
        bs.update_progress(attempt1, dp1);
        assert!(bs.next().as_ref().is_none());
        assert_ne!(
            bs.current()
                .unwrap()
                .usable_lifetime()
                .unwrap()
                .valid_after(),
            lifetime.valid_after()
        );

        // Case 4: starting with an unusable directory, we always replace.
        let mut bs = DirBootstrapStatus::default();
        assert!(!dp2.usable());
        assert!(bs.current().is_none());
        bs.update_progress(attempt2, dp2);
        assert!(bs.current().unwrap().usable_lifetime().is_some());
    }
