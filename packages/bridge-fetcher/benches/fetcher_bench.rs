use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse_response_headers(c: &mut Criterion) {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12345\r\nServer: nginx\r\nConnection: close\r\n\r\n";
    c.bench_function("parse_response_headers", |b| {
        b.iter(|| bridge_fetcher::parse_response_headers(black_box(response)));
    });
}

fn bench_parse_https_url(c: &mut Criterion) {
    let url =
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4";
    c.bench_function("parse_https_url", |b| {
        b.iter(|| bridge_fetcher::parse_https_url(black_box(url)));
    });
}

fn bench_build_get_request(c: &mut Criterion) {
    c.bench_function("build_get_request", |b| {
        b.iter(|| {
            bridge_fetcher::build_get_request(
                black_box("raw.githubusercontent.com"),
                black_box("/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4"),
                black_box(&[]),
                black_box(&[]),
            )
        });
    });
}

criterion_group!(
    benches,
    bench_parse_response_headers,
    bench_parse_https_url,
    bench_build_get_request
);
criterion_main!(benches);
