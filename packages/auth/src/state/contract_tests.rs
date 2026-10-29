use super::*;
use crate::{compute_hash, User};
use std::future::Future;
use std::sync::{mpsc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(15);

fn user(name: &str, hash: &str) -> User {
    User {
        name: name.into(),
        hash: hash.into(),
        is_enabled: true,
        allowed_onion: false,
        allowed_clients: None,
        pre_socks5: None,
        post_socks5: None,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "auth-contract-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("users.ktav")
}

#[test]
fn proof_rejects_foreign_invalid_disabled_and_reload() {
    let cfg = UsersConfig {
        users: vec![user("alice", &compute_hash("pw").unwrap())],
    };
    let a = AuthState::build(&cfg).unwrap();
    let b = AuthState::build(&cfg).unwrap();
    assert!(a.verify_proof("alice", "bad").is_none());
    let proof = a.verify_proof("alice", "pw").unwrap();
    assert_eq!(proof.username(), "alice");
    let rt = runtime();
    assert!(rt.block_on(b.admit(&proof)).is_none());
    assert_eq!(rt.block_on(a.admit(&proof)).unwrap().username(), "alice");
    let mut disabled = cfg.clone();
    disabled.users[0].is_enabled = false;
    a.replace_snapshot(&disabled);
    assert!(rt.block_on(a.admit(&proof)).is_none());
    assert!(a.verify_proof("alice", "pw").is_none());
}

#[test]
fn late_verification_keeps_old_generation() {
    let cfg = UsersConfig {
        users: vec![user("alice", &compute_hash("pw").unwrap())],
    };
    let state = Arc::new(AuthState::build(&cfg).unwrap());
    let (entered, wait) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let resume = Mutex::new(resume);
    state.set_verify_hook(Box::new(move || {
        entered.send(()).unwrap();
        resume.lock().unwrap().recv_timeout(LIMIT).unwrap();
    }));
    let worker = state.clone();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        done.send(worker.verify_proof("alice", "pw").unwrap())
            .unwrap();
    });
    wait.recv_timeout(LIMIT).unwrap();
    state.replace_snapshot(&cfg);
    release.send(()).unwrap();
    let proof = result.recv_timeout(LIMIT).unwrap();
    assert!(runtime().block_on(state.admit(&proof)).is_none());
}

#[test]
fn lease_blocks_queued_publication_until_dropped() {
    let cfg = UsersConfig {
        users: vec![user("alice", &compute_hash("pw").unwrap())],
    };
    let state = Arc::new(AuthState::build(&cfg).unwrap());
    let proof = state.verify_proof("alice", "pw").unwrap();
    let rt = runtime();
    let lease = rt.block_on(state.admit(&proof)).unwrap();
    let worker = state.clone();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        worker.replace_snapshot(&cfg);
        done.send(()).unwrap();
    });
    let deadline = Instant::now() + LIMIT;
    while state.gate.try_read().is_ok() {
        assert!(Instant::now() < deadline, "публикация не встала в очередь");
        std::thread::yield_now();
    }
    assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(lease);
    result.recv_timeout(LIMIT).unwrap();
    assert!(rt.block_on(state.admit(&proof)).is_none());
}

#[test]
fn publication_first_and_pending_admit_cancellation() {
    let path = path();
    let cfg = UsersConfig {
        users: vec![
            user("alice", &compute_hash("pw").unwrap()),
            user("bob", INIT_SENTINEL),
        ],
    };
    cfg.save(&path).unwrap();
    let state = Arc::new(AuthState::build_persistent(&cfg, path.clone()).unwrap());
    let proof = Arc::new(state.verify_proof("alice", "pw").unwrap());
    let (entered, wait) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let resume = Mutex::new(resume);
    state.set_save_hook(Box::new(move || {
        entered.send(()).unwrap();
        resume.lock().unwrap().recv_timeout(LIMIT).unwrap();
        Ok(())
    }));
    let worker = state.clone();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        done.send(worker.verify_proof("bob", "pw").is_some())
            .unwrap();
    });
    wait.recv_timeout(LIMIT).unwrap();
    let rt = runtime();
    rt.block_on(async {
        let worker = state.clone();
        let task_proof = proof.clone();
        let (queued, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut future = Box::pin(worker.admit(&task_proof));
            let mut queued = Some(queued);
            std::future::poll_fn(move |cx| {
                let result = future.as_mut().poll(cx);
                if result.is_pending() {
                    if let Some(queued) = queued.take() {
                        let _ = queued.send(());
                    }
                }
                result
            })
            .await
        });
        tokio::time::timeout(LIMIT, observed)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(
            matches!(tokio::time::timeout(LIMIT, task).await.unwrap(), Err(e) if e.is_cancelled())
        );
        release.send(()).unwrap();
    });
    assert!(result.recv_timeout(LIMIT).unwrap());
    assert!(rt.block_on(state.admit(&proof)).is_none());
    let fresh_proof = state.verify_proof("alice", "pw").unwrap();
    assert!(rt.block_on(state.admit(&fresh_proof)).is_some());
    assert!(state.gate.try_write().is_ok());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn task_cancellation_drops_held_lease() {
    let cfg = UsersConfig {
        users: vec![user("alice", &compute_hash("pw").unwrap())],
    };
    let state = Arc::new(AuthState::build(&cfg).unwrap());
    let proof = state.verify_proof("alice", "pw").unwrap();
    let rt = runtime();
    rt.block_on(async {
        let worker = state.clone();
        let (ready, wait) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _lease = worker.admit(&proof).await.unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        tokio::time::timeout(LIMIT, wait).await.unwrap().unwrap();
        assert!(state.gate.try_write().is_err());
        task.abort();
        assert!(tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled());
        assert!(state.gate.try_write().is_ok());
    });
}

#[test]
fn tofu_invalidates_other_account_proof_and_updates_policy() {
    let path = path();
    let cfg = UsersConfig {
        users: vec![
            user("alice", &compute_hash("pw").unwrap()),
            user("bob", INIT_SENTINEL),
        ],
    };
    cfg.save(&path).unwrap();
    let state = AuthState::build_persistent(&cfg, path.clone()).unwrap();
    let proof = state.verify_proof("alice", "pw").unwrap();
    let mut changed = cfg.clone();
    changed.users[0].allowed_onion = true;
    changed.users[0].allowed_clients = Some("192.0.2.1".parse().unwrap());
    changed.users[0].pre_socks5 = Some(client_acl::EndpointOverride::Disabled);
    changed.save(&path).unwrap();
    assert!(state.verify_proof("bob", "pw").is_some());
    let rt = runtime();
    assert!(rt.block_on(state.admit(&proof)).is_none());
    let fresh = state.verify_proof("alice", "pw").unwrap();
    let lease = rt.block_on(state.admit(&fresh)).unwrap();
    assert!(lease.allowed_onion());
    assert!(lease
        .allowed_clients()
        .unwrap()
        .allows("192.0.2.1".parse().unwrap()));
    assert_eq!(
        lease.pre_socks5(),
        Some(&client_acl::EndpointOverride::Disabled)
    );
    drop(lease);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn tofu_lost_race_proof_cannot_bind_later_reload() {
    let path = path();
    let cfg = UsersConfig {
        users: vec![user("bob", INIT_SENTINEL)],
    };
    cfg.save(&path).unwrap();
    let state = Arc::new(AuthState::build_persistent(&cfg, path.clone()).unwrap());
    let mut winner = cfg.clone();
    winner.users[0].hash = compute_hash("winner").unwrap();
    winner.save(&path).unwrap();
    let (entered, wait) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let resume = Mutex::new(resume);
    state.set_verify_hook(Box::new(move || {
        entered.send(()).unwrap();
        resume.lock().unwrap().recv_timeout(LIMIT).unwrap();
    }));
    let worker = state.clone();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        done.send(worker.verify_proof("bob", "winner").unwrap())
            .unwrap();
    });
    wait.recv_timeout(LIMIT).unwrap();
    state.reload().unwrap();
    release.send(()).unwrap();
    let proof = result.recv_timeout(LIMIT).unwrap();
    assert!(runtime().block_on(state.admit(&proof)).is_none());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn reload_after_tofu_keeps_the_persisted_password() {
    let path = path();
    let cfg = UsersConfig {
        users: vec![user("bob", INIT_SENTINEL)],
    };
    cfg.save(&path).unwrap();
    let stale = UsersConfig::load(&path).unwrap();
    assert_eq!(stale.find("bob").unwrap().hash, INIT_SENTINEL);
    let state = Arc::new(AuthState::build_persistent(&cfg, path.clone()).unwrap());
    let (entered, wait) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let resume = Mutex::new(resume);
    state.set_save_hook(Box::new(move || {
        entered.send(()).unwrap();
        resume.lock().unwrap().recv_timeout(LIMIT).unwrap();
        Ok(())
    }));
    let tofu = state.clone();
    let (tofu_done, tofu_result) = mpsc::channel();
    std::thread::spawn(move || {
        tofu_done
            .send(tofu.verify_proof("bob", "chosen").is_some())
            .unwrap();
    });
    wait.recv_timeout(LIMIT).unwrap();
    let reload = state.clone();
    let (started, start) = mpsc::channel();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        started.send(()).unwrap();
        done.send(reload.reload()).unwrap();
    });
    start.recv_timeout(LIMIT).unwrap();
    assert!(persist_lock::PathLock::acquire_bounded(&path, Duration::ZERO).is_err());
    assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
    release.send(()).unwrap();
    assert!(tofu_result.recv_timeout(LIMIT).unwrap());
    result.recv_timeout(LIMIT).unwrap().unwrap();
    let hash = UsersConfig::load(&path)
        .unwrap()
        .find("bob")
        .unwrap()
        .hash
        .clone();
    assert_ne!(hash, INIT_SENTINEL);
    assert_eq!(state.users.read().unwrap().find("bob").unwrap().hash, hash);
    assert!(state.verify("bob", "chosen"));
    assert!(!state.verify("bob", "other"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn reload_without_path_or_with_invalid_disk_keeps_snapshot() {
    let cfg = UsersConfig {
        users: vec![user("alice", &compute_hash("pw").unwrap())],
    };
    let transient = AuthState::build(&cfg).unwrap();
    let proof = transient.verify_proof("alice", "pw").unwrap();
    assert!(transient.reload().is_err());
    assert!(runtime().block_on(transient.admit(&proof)).is_some());
    let path = path();
    std::fs::write(&path, "not a ktav file {{{").unwrap();
    let persistent = AuthState::build_persistent(&cfg, path.clone()).unwrap();
    let proof = persistent.verify_proof("alice", "pw").unwrap();
    assert!(persistent.reload().is_err());
    assert!(runtime().block_on(persistent.admit(&proof)).is_some());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn tofu_save_failure_preserves_existing_proof() {
    let path = path();
    let cfg = UsersConfig {
        users: vec![
            user("alice", &compute_hash("pw").unwrap()),
            user("bob", INIT_SENTINEL),
        ],
    };
    cfg.save(&path).unwrap();
    let state = AuthState::build_persistent(&cfg, path.clone()).unwrap();
    let proof = state.verify_proof("alice", "pw").unwrap();
    state.set_save_hook(Box::new(|| Err(anyhow::anyhow!("ошибка сохранения"))));
    assert!(state.verify_proof("bob", "pw").is_none());
    assert!(runtime().block_on(state.admit(&proof)).is_some());
    assert_eq!(
        UsersConfig::load(&path).unwrap().find("bob").unwrap().hash,
        INIT_SENTINEL
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
