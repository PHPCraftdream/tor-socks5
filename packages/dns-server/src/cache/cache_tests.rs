//! Contract oracles are hand-derived TTL arithmetic and RFC 2308, not sleeps.
use super::*;
use hickory_proto::op::{Edns, OpCode, ResponseCode};
use hickory_proto::rr::{
    rdata::{A, CNAME, SOA, TXT},
    DNSClass, Name, RData, Record,
};

#[path = "cache_disk_tests.rs"]
mod persistence;

fn query(name: &str, kind: RecordType, class: DNSClass) -> Query {
    let mut query = Query::query(Name::from_ascii(name).unwrap(), kind);
    query.set_query_class(class);
    query
}
fn q() -> Query {
    query("www.example.", RecordType::A, DNSClass::IN)
}
fn epoch() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
}
fn answer(query: &Query, ttl: u32) -> ResolvedAnswer {
    let mut message = Message::response(17, OpCode::Query);
    message.queries.push(query.clone());
    let mut record = Record::from_rdata(query.name().clone(), ttl, RData::A(A::new(1, 2, 3, 4)));
    record.dns_class = query.query_class();
    message.answers.push(record);
    ResolvedAnswer {
        message,
        ttl: Duration::from_secs(u64::from(ttl)),
        resolved_at: epoch(),
    }
}
fn negative(query: &Query, rcode: ResponseCode, ttl: u32, minimum: u32) -> ResolvedAnswer {
    let mut result = answer(query, 600);
    result.message.answers.clear();
    result.message.metadata.response_code = rcode;
    let soa = SOA::new(
        Name::from_ascii("ns.example.").unwrap(),
        Name::from_ascii("hostmaster.example.").unwrap(),
        1,
        60,
        60,
        3600,
        minimum,
    );
    let mut record =
        Record::from_rdata(Name::from_ascii("example.").unwrap(), ttl, RData::SOA(soa));
    record.dns_class = query.query_class();
    result.message.authorities.push(record);
    result
}

#[test]
fn public_cache_relative_case_and_root_equivalence_preserves_type_class() {
    let relative = query("WWW.Example", RecordType::A, DNSClass::IN);
    let absolute = q();
    let mut value = answer(&absolute, 600);
    value.resolved_at = OffsetDateTime::now_utc();
    let cache = DnsCache::new();
    cache.insert(&relative, &value);
    for spelling in ["www.example", "WWW.EXAMPLE.", "www.example."] {
        assert!(cache
            .get(&query(spelling, RecordType::A, DNSClass::IN))
            .is_some());
    }
    cache.insert(&absolute, &value);
    assert_eq!(
        cache.len(),
        1,
        "relative and absolute admission must replace one tuple"
    );
    assert!(cache
        .get(&query("www.example", RecordType::AAAA, DNSClass::IN))
        .is_none());
    assert!(cache
        .get(&query("www.example", RecordType::A, DNSClass::CH))
        .is_none());
}

#[test]
fn transport_relative_question_accepts_absolute_wire_positive_and_negative() {
    let relative = query("WWW.Example", RecordType::A, DNSClass::IN);
    let request = crate::doh_client::build_query(&relative).unwrap();
    for mut value in [
        answer(&q(), 60),
        negative(&q(), ResponseCode::NXDomain, 120, 45),
    ] {
        value.message.metadata.id = request.id;
        let parsed =
            crate::doh_client::parse_response(&request, &value.message.to_vec().unwrap()).unwrap();
        assert_eq!(
            parsed.ttl,
            Duration::from_secs(
                if parsed.message.metadata.response_code == ResponseCode::NXDomain {
                    45
                } else {
                    60
                }
            )
        );
        let cache = DnsCache::new();
        cache.insert(&relative, &parsed);
        assert!(cache.get(&relative).is_some());
        assert!(cache.get(&q()).is_some());
    }
}

#[test]
fn key_separates_type_class_and_folds_case() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&q(), &answer(&q(), 60), epoch(), instant);
    assert!(cache
        .get_at(
            &query("WWW.EXAMPLE.", RecordType::A, DNSClass::IN),
            epoch(),
            instant
        )
        .is_some());
    assert!(cache
        .get_at(
            &query("www.example.", RecordType::AAAA, DNSClass::IN),
            epoch(),
            instant
        )
        .is_none());
    assert!(cache
        .get_at(
            &query("www.example.", RecordType::A, DNSClass::CH),
            epoch(),
            instant
        )
        .is_none());
}

#[test]
fn packet_sections_age_without_mutating_original_or_edns() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    let mut original = answer(&q(), 90);
    original.message.authorities.push(Record::from_rdata(
        Name::from_ascii("example.").unwrap(),
        120,
        RData::TXT(TXT::new(vec!["authority".into()])),
    ));
    original.message.additionals.push(Record::from_rdata(
        Name::from_ascii("ns.example.").unwrap(),
        150,
        RData::A(A::new(5, 6, 7, 8)),
    ));
    original.message.edns = Some(Edns::new());
    cache.insert_at(&q(), &original, epoch(), instant);
    let later = epoch() + time::Duration::seconds(30);
    let hit = cache.get_at(&q(), later, instant).unwrap();
    assert_eq!(hit.message.answers[0].ttl, 60);
    assert_eq!(hit.message.authorities[0].ttl, 90);
    assert_eq!(hit.message.additionals[0].ttl, 120);
    assert_eq!(hit.message.edns, original.message.edns);
    assert_eq!(hit.ttl, Duration::from_secs(60));
    assert_eq!(cache.get_at(&q(), later, instant).unwrap(), hit);
    assert_eq!(
        Message::from_vec(&lock_entries(&cache.entries).values().next().unwrap().packet).unwrap(),
        original.message
    );
}

#[test]
fn exact_expiry_and_backward_wall_clock_do_not_rejuvenate() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&q(), &answer(&q(), 60), epoch(), instant);
    let backwards = epoch() - time::Duration::seconds(100);
    let hit = cache
        .get_at(&q(), backwards, instant + Duration::from_secs(30))
        .unwrap();
    assert_eq!(hit.ttl, Duration::from_secs(30));
    assert!(cache
        .get_at(&q(), backwards, instant + Duration::from_secs(60))
        .is_none());
    assert!(cache.is_empty());
}

#[test]
fn negative_minimum_and_soa_ttl_both_bound_rcode_preserving_hits() {
    for rcode in [ResponseCode::NoError, ResponseCode::NXDomain] {
        for (ttl, minimum) in [(120, 45), (45, 120)] {
            let cache = DnsCache::new();
            let instant = Instant::now();
            let value = negative(&q(), rcode, ttl, minimum);
            assert_eq!(
                cache_ttl(&q(), &value.message),
                Some(Duration::from_secs(45))
            );
            cache.insert_at(&q(), &value, epoch(), instant);
            let hit = cache
                .get_at(&q(), epoch() + time::Duration::seconds(10), instant)
                .unwrap();
            assert_eq!(hit.message.metadata.response_code, rcode);
            assert_eq!(hit.ttl, Duration::from_secs(35));
            assert!(cache
                .get_at(&q(), epoch() + time::Duration::seconds(45), instant)
                .is_none());
        }
    }
}

#[test]
fn failure_empty_referral_zero_and_unrelated_soa_are_not_cacheable() {
    let mut cases = Vec::new();
    for rcode in [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::FormErr,
    ] {
        let mut value = answer(&q(), 60);
        value.message.metadata.response_code = rcode;
        cases.push(value);
    }
    for rcode in [ResponseCode::NXDomain, ResponseCode::NoError] {
        let mut value = negative(&q(), rcode, 60, 60);
        value.message.authorities.clear();
        cases.push(value);
        let mut unrelated = negative(&q(), rcode, 60, 60);
        unrelated.message.authorities[0].name = Name::from_ascii("elsewhere.").unwrap();
        cases.push(unrelated);
    }
    cases.push(answer(&q(), 0));
    let mut truncated = answer(&q(), 60);
    truncated.message.metadata.truncation = true;
    cases.push(truncated);
    let mut mismatched = answer(&q(), 60);
    mismatched.message.queries[0].set_query_type(RecordType::AAAA);
    cases.push(mismatched);
    for value in cases {
        assert_eq!(cache_ttl(&q(), &value.message), None);
        let cache = DnsCache::new();
        cache.insert_at(&q(), &value, epoch(), Instant::now());
        assert!(cache.is_empty());
    }
}

#[test]
fn cname_terminal_negative_uses_covering_soa_and_cycles_reject() {
    let mut value = negative(&q(), ResponseCode::NXDomain, 60, 40);
    value.message.answers.push(Record::from_rdata(
        q().name().clone(),
        90,
        RData::CNAME(CNAME(Name::from_ascii("missing.example.").unwrap())),
    ));
    assert_eq!(
        cache_ttl(&q(), &value.message),
        Some(Duration::from_secs(40))
    );
    value.message.answers.push(Record::from_rdata(
        Name::from_ascii("missing.example.").unwrap(),
        90,
        RData::CNAME(CNAME(q().name().clone())),
    ));
    assert_eq!(cache_ttl(&q(), &value.message), None);
    normalize_negative_soa_ttl(&q(), &mut value.message);
    assert_eq!(
        value.message.authorities[0].ttl, 60,
        "cycle must not normalize SOA"
    );
}

#[test]
fn borrowed_terminal_traversal_accepts_full_chain_and_rejects_self_cycle() {
    let question = q();
    let mut value = negative(&question, ResponseCode::NXDomain, 60, 40);
    for (owner, target) in [
        ("www.example.", "alias.example."),
        ("alias.example.", "missing.example."),
    ] {
        value.message.answers.push(Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            90,
            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
        ));
    }
    assert_eq!(
        cache_ttl(&question, &value.message),
        Some(Duration::from_secs(40))
    );
    normalize_negative_soa_ttl(&question, &mut value.message);
    assert_eq!(value.message.authorities[0].ttl, 40);
    value.message.answers.clear();
    value.message.answers.push(Record::from_rdata(
        question.name().clone(),
        90,
        RData::CNAME(CNAME(question.name().clone())),
    ));
    assert_eq!(cache_ttl(&question, &value.message), None);
}

#[test]
fn cap_replacement_does_not_evict_peer_and_overflow_evicts_soonest() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    for index in 0..DNS_CACHE_CAP {
        let query = query(
            &format!("host-{index}.example."),
            RecordType::A,
            DNSClass::IN,
        );
        cache.insert_at(
            &query,
            &answer(&query, if index == 0 { 1 } else { 600 }),
            epoch(),
            instant,
        );
    }
    let peer = query("host-1.example.", RecordType::A, DNSClass::IN);
    cache.insert_at(&peer, &answer(&peer, 600), epoch(), instant);
    assert_eq!(cache.len(), DNS_CACHE_CAP);
    let new = q();
    cache.insert_at(&new, &answer(&new, 600), epoch(), instant);
    assert_eq!(cache.len(), DNS_CACHE_CAP);
    assert!(cache
        .get_at(
            &query("host-0.example.", RecordType::A, DNSClass::IN),
            epoch(),
            instant
        )
        .is_none());
    assert!(cache.get_at(&peer, epoch(), instant).is_some());
    assert!(cache.get_at(&new, epoch(), instant).is_some());
}

#[test]
fn non_address_positive_roundtrips_and_shortest_section_ttl_bounds_packet() {
    let query = query("text.example.", RecordType::TXT, DNSClass::IN);
    let mut value = answer(&query, 120);
    value.message.answers[0].data = RData::TXT(TXT::new(vec!["not an address".into()]));
    value.message.additionals.push(Record::from_rdata(
        Name::from_ascii("ns.example.").unwrap(),
        20,
        RData::A(A::new(5, 6, 7, 8)),
    ));
    value.message.edns = Some(Edns::new());
    assert_eq!(
        cache_ttl(&query, &value.message),
        Some(Duration::from_secs(20))
    );
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&query, &value, epoch(), instant);
    let hit = cache
        .get_at(&query, epoch() + time::Duration::seconds(10), instant)
        .unwrap();
    assert_eq!(
        hit.message.answers[0].data,
        RData::TXT(TXT::new(vec!["not an address".into()]))
    );
    assert_eq!(hit.message.answers[0].ttl, 110);
    assert!(cache
        .get_at(&query, epoch() + time::Duration::seconds(20), instant)
        .is_none());
}

#[test]
fn observed_forward_jump_cannot_be_undone_by_backward_jump() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&q(), &answer(&q(), 60), epoch(), instant);
    let later = epoch() + time::Duration::seconds(40);
    assert_eq!(
        cache.get_at(&q(), later, instant).unwrap().ttl,
        Duration::from_secs(20)
    );
    assert_eq!(
        cache.get_at(&q(), epoch(), instant).unwrap().ttl,
        Duration::from_secs(20)
    );
}

#[test]
fn future_stamps_and_oversized_packets_are_rejected() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    let mut future = answer(&q(), 60);
    future.resolved_at = epoch() + time::Duration::seconds(1);
    cache.insert_at(&q(), &future, epoch(), instant);
    assert!(cache.is_empty());
    let query = query("text.example.", RecordType::TXT, DNSClass::IN);
    let mut huge = answer(&query, 60);
    huge.message.answers.clear();
    for _ in 0..300 {
        huge.message.answers.push(Record::from_rdata(
            query.name().clone(),
            60,
            RData::TXT(TXT::new(vec!["x".repeat(250)])),
        ));
    }
    cache.insert_at(&query, &huge, epoch(), instant);
    assert!(cache.is_empty());
}

#[test]
fn negative_normalization_leaves_positive_soa_and_shorter_cache_lease_independent() {
    let query = query("example.", RecordType::SOA, DNSClass::IN);
    let mut positive = negative(&query, ResponseCode::NoError, 120, 45);
    positive.message.answers = std::mem::take(&mut positive.message.authorities);
    let before = positive.message.clone();
    normalize_negative_soa_ttl(&query, &mut positive.message);
    assert_eq!(positive.message, before);
    assert_eq!(positive.message.answers[0].ttl, 120);

    let mut negative = negative(&q(), ResponseCode::NXDomain, 120, 45);
    normalize_negative_soa_ttl(&q(), &mut negative.message);
    assert_eq!(negative.message.authorities[0].ttl, 45);
    negative.ttl = Duration::from_secs(20);
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&q(), &negative, epoch(), instant);
    let hit = cache
        .get_at(&q(), epoch() + time::Duration::seconds(10), instant)
        .unwrap();
    assert_eq!(hit.ttl, Duration::from_secs(10));
    assert_eq!(hit.message.authorities[0].ttl, 35);
}

#[test]
fn parsed_edns_packet_is_admitted_without_header_count_equality_artifacts() {
    let mut value = answer(&q(), 60);
    value.message.edns = Some(Edns::new());
    value.message.metadata.recursion_available = true;
    value.message = Message::from_vec(&value.message.to_vec().unwrap()).unwrap();
    let original = value.message.clone();
    let cache = DnsCache::new();
    let instant = Instant::now();
    cache.insert_at(&q(), &value, epoch(), instant);
    let hit = cache.get_at(&q(), epoch(), instant).unwrap();
    assert_eq!(hit.message, original);
    assert_eq!(record_ttls(&hit.message).collect::<Vec<_>>(), vec![60]);
}

#[test]
fn poisoned_entries_preserve_valid_hit() {
    let cache = DnsCache::new();
    let instant = Instant::now();
    let valid = answer(&q(), 60);
    cache.insert_at(&q(), &valid, epoch(), instant);
    let result = std::panic::catch_unwind(|| {
        let _guard = cache.entries.lock().unwrap();
        panic!("forced cache poison");
    });
    assert!(result.is_err());
    assert_eq!(cache.len(), 1);
    let hit = cache.get_at(&q(), epoch(), instant).unwrap();
    assert_eq!(hit.message, valid.message);
    assert_eq!(hit.message.answers[0].ttl, 60);
    assert!(cache.entries.is_poisoned());
}
