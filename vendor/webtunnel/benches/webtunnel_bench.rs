use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ptrs::args::Args;

fn fast_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

fn make_args() -> Args {
    let mut args = Args::new();
    args.add("url", "https://example.com/K2A2utQIMou4Ia2WjVseyDjV");
    args.add("ver", "0.0.3");
    args
}

fn bench_websocket_key(c: &mut Criterion) {
    c.bench_function("generate_websocket_key", |b| {
        b.iter(webtunnel::handshake::generate_websocket_key);
    });
}

fn bench_config_from_args(c: &mut Criterion) {
    let args = make_args();
    c.bench_function("WebTunnelConfig::from_args", |b| {
        b.iter(|| webtunnel::WebTunnelConfig::from_args(black_box(&args)).unwrap());
    });
}

fn bench_build_upgrade_request(c: &mut Criterion) {
    let args = make_args();
    let config = webtunnel::WebTunnelConfig::from_args(&args).unwrap();
    c.bench_function("build_upgrade_request", |b| {
        b.iter(|| webtunnel::handshake::build_upgrade_request(black_box(&config)));
    });
}

fn bench_config_with_servername(c: &mut Criterion) {
    let mut args = make_args();
    args.add("servername", "cdn.example.com");
    c.bench_function("WebTunnelConfig::from_args_with_sni", |b| {
        b.iter(|| webtunnel::WebTunnelConfig::from_args(black_box(&args)).unwrap());
    });
}

fn bench_parse_response(c: &mut Criterion) {
    let response_small =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
    c.bench_function("parse_response_101_small", |b| {
        b.iter(|| webtunnel::handshake::parse_response(black_box(response_small)).unwrap());
    });

    let mut response_many_headers = b"HTTP/1.1 101 Switching Protocols\r\n".to_vec();
    for i in 0..20 {
        response_many_headers.extend_from_slice(format!("X-Custom-{i}: value-{i}\r\n").as_bytes());
    }
    response_many_headers.extend_from_slice(b"\r\n");
    c.bench_function("parse_response_101_20_headers", |b| {
        b.iter(|| webtunnel::handshake::parse_response(black_box(&response_many_headers)).unwrap());
    });

    let response_404 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    c.bench_function("parse_response_error_path", |b| {
        b.iter(|| {
            let _ = webtunnel::handshake::parse_response(black_box(response_404));
        });
    });
}

criterion_group! {
    name = benches;
    config = fast_criterion();
    targets = bench_websocket_key,
              bench_config_from_args,
              bench_build_upgrade_request,
              bench_config_with_servername,
              bench_parse_response
}
criterion_main!(benches);
