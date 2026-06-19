use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_compute_hash(c: &mut Criterion) {
    c.bench_function("compute_hash", |b| {
        b.iter(|| auth::compute_hash(black_box("hunter2")).unwrap());
    });
}

fn bench_verify_hash(c: &mut Criterion) {
    let hash = auth::compute_hash("hunter2").unwrap();
    c.bench_function("verify_hash_match", |b| {
        b.iter(|| auth::verify_hash(black_box(&hash), black_box("hunter2")).unwrap());
    });
    c.bench_function("verify_hash_mismatch", |b| {
        b.iter(|| auth::verify_hash(black_box(&hash), black_box("wrong")).unwrap());
    });
}

fn bench_auth_state_verify(c: &mut Criterion) {
    let user = auth::User {
        name: "alice".into(),
        hash: auth::compute_hash("secret").unwrap(),
        is_enabled: true,
        allowed_onion: false,
    };
    let state = auth::AuthState::build(&auth::UsersConfig { users: vec![user] }).unwrap();

    c.bench_function("auth_state_verify_cached", |b| {
        // First call populates the cache.
        state.verify("alice", "secret");
        b.iter(|| state.verify(black_box("alice"), black_box("secret")));
    });

    c.bench_function("auth_state_verify_wrong_password", |b| {
        b.iter(|| state.verify(black_box("alice"), black_box("wrong")));
    });
}

fn bench_auth_state_contention(c: &mut Criterion) {
    let mut users = Vec::new();
    for i in 0..10 {
        users.push(auth::User {
            name: format!("user{i}"),
            hash: auth::compute_hash(&format!("pass{i}")).unwrap(),
            is_enabled: true,
            allowed_onion: false,
        });
    }
    let state = std::sync::Arc::new(auth::AuthState::build(&auth::UsersConfig { users }).unwrap());

    // Warm up cache for all users.
    for i in 0..10 {
        state.verify(&format!("user{i}"), &format!("pass{i}"));
    }

    c.bench_function("auth_state_10_users_cached_sequential", |b| {
        b.iter(|| {
            for i in 0..10 {
                state.verify(
                    black_box(&format!("user{i}")),
                    black_box(&format!("pass{i}")),
                );
            }
        });
    });
}

criterion_group!(
    benches,
    bench_compute_hash,
    bench_verify_hash,
    bench_auth_state_verify,
    bench_auth_state_contention,
);
criterion_main!(benches);
