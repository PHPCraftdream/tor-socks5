use bridge_line::BridgeLine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn generate_bridges(n: usize) -> Vec<BridgeLine> {
    (0..n)
        .map(|i| {
            let a = (i >> 24) & 0xFF;
            let b = (i >> 16) & 0xFF;
            let c = (i >> 8) & 0xFF;
            let d = i & 0xFF;
            let line = format!(
                "obfs4 {a}.{b}.{c}.{d}:{} {:0>40X} cert=AAAA iat-mode=0",
                1024 + (i % 60000),
                i
            );
            line.parse().unwrap()
        })
        .collect()
}

fn generate_webtunnel_bridges(n: usize) -> Vec<BridgeLine> {
    (0..n)
        .map(|i| {
            let line = format!(
                "webtunnel 192.0.2.{}:1 {:0>40X} url=https://host-{i}.example.com/path ver=0.0.3",
                i & 0xFF,
                i
            );
            line.parse().unwrap()
        })
        .collect()
}

fn bench_probe_and_sort_fanout(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Bind a few local TCP listeners so some bridges are "reachable",
    // giving probe_and_sort actual sorting work to do.
    let listeners: Vec<std::net::TcpListener> = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let live_addrs: Vec<std::net::SocketAddr> =
        listeners.iter().map(|l| l.local_addr().unwrap()).collect();

    // Build 200 bridges: 4 pointing at live listeners, 196 at 127.0.0.1:1
    // (connect-refused). This exercises the N-way fan-out + latency sort.
    let bridges: Vec<BridgeLine> = live_addrs
        .iter()
        .map(|addr| {
            format!("obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAAA iat-mode=0")
                .parse()
                .unwrap()
        })
        .chain((0..196).map(|i| {
            format!(
                "obfs4 127.0.0.1:1 {:0>40X} cert=AAAA iat-mode=0",
                0xBEEF_0000u64 + i as u64
            )
            .parse()
            .unwrap()
        }))
        .collect();

    c.bench_function("probe_and_sort_200_bridges", |b| {
        b.to_async(&rt).iter(|| {
            let bs = bridges.clone();
            async move {
                bridge_probe::probe_and_sort(black_box(bs), std::time::Duration::from_millis(50))
                    .await
            }
        });
    });

    // Keep listeners alive for the duration of the benchmark group.
    drop(listeners);
}

fn bench_bridge_generation(c: &mut Criterion) {
    c.bench_function("generate_1000_obfs4_bridges", |b| {
        b.iter(|| generate_bridges(black_box(1000)));
    });

    c.bench_function("generate_100_webtunnel_bridges", |b| {
        b.iter(|| generate_webtunnel_bridges(black_box(100)));
    });
}

criterion_group!(
    benches,
    bench_probe_and_sort_fanout,
    bench_bridge_generation
);
criterion_main!(benches);
