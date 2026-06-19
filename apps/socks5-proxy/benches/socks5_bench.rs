use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse_bridges_from_body(c: &mut Criterion) {
    let body = generate_bridge_body(500);
    c.bench_function("parse_bridges_500_lines", |b| {
        b.iter(|| bridge_fetcher::parse_bridges_from_body(black_box(&body)));
    });

    let body_50 = generate_bridge_body(50);
    c.bench_function("parse_bridges_50_lines", |b| {
        b.iter(|| bridge_fetcher::parse_bridges_from_body(black_box(&body_50)));
    });
}

fn bench_dedup_bridges(c: &mut Criterion) {
    let body = generate_bridge_body(500);
    let bridges = bridge_fetcher::parse_bridges_from_body(&body);
    c.bench_function("dedup_500_bridges", |b| {
        b.iter(|| bridge_fetcher::dedup_bridges(black_box(bridges.clone())));
    });
}

fn generate_bridge_body(n: usize) -> String {
    (0..n)
        .map(|i| {
            let a = (i >> 24) & 0xFF;
            let b = (i >> 16) & 0xFF;
            let c_val = (i >> 8) & 0xFF;
            let d = i & 0xFF;
            format!(
                "obfs4 {a}.{b}.{c_val}.{d}:{} {:0>40X} cert=AAAA iat-mode=0",
                1024 + (i % 60000),
                i
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn bench_bridge_line_parse_single(c: &mut Criterion) {
    let line =
        "obfs4 198.51.100.7:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0";
    c.bench_function("bridge_line_parse_obfs4", |b| {
        b.iter(|| black_box(line).parse::<bridge_line::BridgeLine>().unwrap());
    });
}

criterion_group!(
    benches,
    bench_parse_bridges_from_body,
    bench_dedup_bridges,
    bench_bridge_line_parse_single,
);
criterion_main!(benches);
