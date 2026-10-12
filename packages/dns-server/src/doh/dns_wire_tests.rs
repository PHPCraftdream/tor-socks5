use super::*;
use hickory_proto::rr::{DNSClass, RecordType};
use std::cell::Cell;

fn question() -> Query {
    Query::query("example.test.".parse().unwrap(), RecordType::MX)
}
fn response(query: &DnsQuery, code: ResponseCode) -> Message {
    let mut message = Message::response(query.id, OpCode::Query);
    message.add_query(query.question.clone());
    message.metadata.response_code = code;
    message
}

#[test]
fn original_question_unknown_type_and_class_round_trip() {
    let mut q = question();
    q.set_query_type(RecordType::Unknown(65400));
    q.set_query_class(DNSClass::Unknown(65200));
    let wire = build_query(&q).unwrap();
    let decoded = Message::from_vec(&wire.bytes).unwrap();
    assert_eq!(decoded.queries, vec![q]);
    assert!(decoded.metadata.recursion_desired);
}

#[test]
fn rejects_each_transaction_header_and_question_mismatch() {
    let query = build_query(&question()).unwrap();
    for mutation in 0..8 {
        let mut message = response(&query, ResponseCode::NoError);
        match mutation {
            0 => message.metadata.id ^= 1,
            1 => message.metadata.message_type = MessageType::Query,
            2 => message.metadata.op_code = OpCode::Update,
            3 => message.queries.clear(),
            4 => {
                message.add_query(question());
            }
            5 => {
                message.queries[0].set_name("other.test.".parse().unwrap());
            }
            6 => {
                message.queries[0].set_query_type(RecordType::AAAA);
            }
            7 => {
                message.queries[0].set_query_class(DNSClass::CH);
            }
            _ => unreachable!(), // finite local test table
        }
        assert!(
            parse_response(&query, &message.to_vec().unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(parse_response(&query, &[0, 1]).is_err());
    let mut message = response(&query, ResponseCode::NoError);
    message.queries[0].set_name("EXAMPLE.TEST.".parse().unwrap());
    assert!(parse_response(&query, &message.to_vec().unwrap()).is_ok());
    message.metadata.truncation = true;
    assert!(parse_response(&query, &message.to_vec().unwrap()).is_err());
}

#[tokio::test]
async fn pool_negatives_are_terminal_and_temporary_failures_fall_back_in_order() {
    let query = build_query(&question()).unwrap();
    for code in [
        ResponseCode::NXDomain,
        ResponseCode::NoError,
        ResponseCode::FormErr,
        ResponseCode::Refused,
        ResponseCode::NotImp,
    ] {
        let calls = Cell::new(0);
        let result = ordered_pool(3, |index| {
            assert_eq!(index, calls.get());
            calls.set(calls.get() + 1);
            std::future::ready(parse_response(
                &query,
                &response(&query, code).to_vec().unwrap(),
            ))
        })
        .await
        .unwrap();
        assert_eq!(result.message.metadata.response_code, code);
        assert_eq!(calls.get(), 1);
    }
    let calls = Cell::new(0);
    let answer = ordered_pool(4, |index| {
        assert_eq!(index, calls.get());
        calls.set(calls.get() + 1);
        let result = match index {
            0 => Err(DnsServerError::DohExchange("connection reset".into())),
            1 => parse_response(
                &query,
                &response(&query, ResponseCode::ServFail).to_vec().unwrap(),
            ),
            _ => parse_response(
                &query,
                &response(&query, ResponseCode::NXDomain).to_vec().unwrap(),
            ),
        };
        std::future::ready(result)
    })
    .await
    .unwrap();
    assert_eq!(calls.get(), 3);
    assert_eq!(
        answer.message.metadata.response_code,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn pool_first_negative_response_normalizes_only_covering_soa_ttl() {
    use hickory_proto::rr::rdata::{CNAME, SOA};
    use hickory_proto::rr::{RData, Record};

    let query = build_query(&question()).unwrap();
    for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
        for (soa_ttl, minimum, expected_ttl) in [(90, 45, 45), (20, 45, 20), (90, 0, 0)] {
            let mut message = response(&query, code);
            message.add_answer(Record::from_rdata(
                query.question.name().clone(),
                10,
                RData::CNAME(CNAME("absent.test.".parse().unwrap())),
            ));
            let soa = RData::SOA(SOA::new(
                "ns.test.".parse().unwrap(),
                "hostmaster.test.".parse().unwrap(),
                1,
                60,
                30,
                3600,
                minimum,
            ));
            message.add_authority(Record::from_rdata(
                "test.".parse().unwrap(),
                soa_ttl,
                soa.clone(),
            ));
            message.add_authority(Record::from_rdata(
                "unrelated.".parse().unwrap(),
                90,
                soa.clone(),
            ));
            let mut wrong_class = Record::from_rdata("test.".parse().unwrap(), 90, soa);
            wrong_class.dns_class = DNSClass::CH;
            message.add_authority(wrong_class);
            let mut expected = message.clone();
            expected.authorities[0].ttl = expected_ttl;
            let calls = Cell::new(0);
            let answer = ordered_pool(3, |_| {
                calls.set(calls.get() + 1);
                std::future::ready(parse_response(&query, &message.to_vec().unwrap()))
            })
            .await
            .unwrap();
            assert_eq!(calls.get(), 1);
            assert_eq!(answer.message, expected);
            assert_eq!(answer.message.authorities[0].ttl, expected_ttl);
            assert_eq!(answer.message.authorities[1].ttl, 90);
            assert_eq!(answer.message.authorities[2].ttl, 90);
            assert_eq!(
                answer.ttl,
                Duration::from_secs(u64::from(expected_ttl.min(10)))
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn pool_total_deadline_cancels_second_attempt_and_releases_resources() {
    struct Lease<'a>(&'a Cell<usize>);
    impl Drop for Lease<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() - 1);
        }
    }
    let calls = Cell::new(0);
    let live = Cell::new(0);
    let start = tokio::time::Instant::now();
    let result = ordered_pool(10, |_| {
        calls.set(calls.get() + 1);
        live.set(live.get() + 1);
        let lease = Lease(&live);
        async move {
            let _lease = lease;
            std::future::pending::<Result<ResolvedAnswer, DnsServerError>>().await
        }
    })
    .await;
    assert!(
        matches!(result, Err(DnsServerError::Timeout(duration)) if duration == Duration::from_secs(30))
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(live.get(), 0);
    assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(30));
}
