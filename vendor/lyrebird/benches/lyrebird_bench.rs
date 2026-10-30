use std::str::FromStr;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fast_socks5::util::target_addr::TargetAddr;

fn fast_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

fn bench_arg_string_from_creds(c: &mut Criterion) {
    // Small payload (single key=value pair, fits in username field alone).
    c.bench_function("arg_string_from_creds_small", |b| {
        let creds = Some(("cert=ABC;iat-mode=0".to_string(), "\0".to_string()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    // Mid-size: full 255-char username + small password.
    c.bench_function("arg_string_from_creds_mid", |b| {
        let username = "cert=".to_string() + &"A".repeat(250);
        let creds = Some((username, ";iat-mode=0".to_string()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    // Worst case for the spec: full 255 + 255 split.
    c.bench_function("arg_string_from_creds_full", |b| {
        let creds = Some(("u".repeat(255), "p".repeat(255)));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    // No creds path (early-return).
    c.bench_function("arg_string_from_creds_none", |b| {
        b.iter(|| lyrebird::arg_string_from_creds(black_box(None)));
    });
}

fn bench_arg_string_then_parse(c: &mut Criterion) {
    // End-to-end: reconstruct arg string from SOCKS5 fields, then parse
    // back into a kv-map — the actual production code path.
    let username = "cert=".to_string() + &"A".repeat(250);
    let creds = Some((username, ";iat-mode=0;public-key=BBB".to_string()));

    c.bench_function("arg_string_then_parse_e2e", |b| {
        b.iter(|| {
            let s = lyrebird::arg_string_from_creds(black_box(creds.clone()));
            ptrs::args::Args::from_str(&s).unwrap()
        });
    });
}

fn bench_resolve_target_addr(c: &mut Criterion) {
    let ipv4 = TargetAddr::Ip("10.0.0.1:9050".parse().unwrap());
    c.bench_function("resolve_target_addr_ipv4", |b| {
        b.iter(|| lyrebird::resolve_target_addr(black_box(&ipv4)).unwrap());
    });

    let ipv6 = TargetAddr::Ip("[::1]:443".parse().unwrap());
    c.bench_function("resolve_target_addr_ipv6", |b| {
        b.iter(|| lyrebird::resolve_target_addr(black_box(&ipv6)).unwrap());
    });

    let domain = TargetAddr::Domain("example.com".into(), 443);
    c.bench_function("resolve_target_addr_domain_rejected", |b| {
        // Always fails — but the failure-path cost is still measurable.
        b.iter(|| {
            let _ = lyrebird::resolve_target_addr(black_box(&domain));
        });
    });
}

fn bench_arg_string_from_creds_edge(c: &mut Criterion) {
    c.bench_function("arg_string_from_creds_empty_strings", |b| {
        let creds = Some((String::new(), String::new()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    c.bench_function("arg_string_from_creds_nul_password", |b| {
        let creds = Some(("cert=AABBCC".to_string(), "\0".to_string()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });
}

fn bench_bidirectional_copy(c: &mut Criterion) {
    use criterion::{BenchmarkId, Throughput};
    use tokio::io::AsyncWriteExt;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("bidirectional_copy");
    // Use a duplex buffer >= data size on both sides so backpressure
    // toward the un-drained outer halves never engages — otherwise
    // `bidirectional_copy` deadlocks because the destination pipe of
    // each direction has no reader. This measures the raw copy cost,
    // not realistic backpressure dynamics.
    // One representative size; doubling it costs ~5× wall time because
    // each iteration is ~16 ms at 1 MiB and Criterion needs a minimum
    // number of samples.
    let size: usize = 64 * 1024;
    group.throughput(Throughput::Bytes(size as u64 * 2));
    group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
        b.to_async(&rt).iter(|| async move {
            let (a_out, a_in) = tokio::io::duplex(2 * size);
            let (b_out, b_in) = tokio::io::duplex(2 * size);
            let data = vec![0u8; size];
            let d1 = data.clone();
            let d2 = data;
            let wa = tokio::spawn(async move {
                let mut a = a_out;
                a.write_all(&d1).await.unwrap();
                drop(a);
            });
            let wb = tokio::spawn(async move {
                let mut b = b_out;
                b.write_all(&d2).await.unwrap();
                drop(b);
            });
            let (mut a_in, mut b_in) = (a_in, b_in);
            // Each writer closes its end after a single write, so the copy ends
            // with a BrokenPipe once one direction hits EOF — that's normal
            // teardown for this throughput measurement, not an error.
            let _ = tokio::io::copy_bidirectional(&mut a_in, &mut b_in).await;
            wa.await.unwrap();
            wb.await.unwrap();
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = fast_criterion();
    targets = bench_arg_string_from_creds,
              bench_arg_string_then_parse,
              bench_resolve_target_addr,
              bench_arg_string_from_creds_edge,
              bench_bidirectional_copy
}
criterion_main!(benches);
