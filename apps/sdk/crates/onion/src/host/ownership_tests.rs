//! Регрессионная честность: этот тест проверяет ТОЛЬКО хелпер
//! [`super::join_logged`] и свойство tokio «drop JoinSet aborts children» на
//! зеркале продакшн-формы владения (managers → children). Он НЕ исполняет
//! production-цепочку `run_services`/`service_manager`; выбран минимально
//! допустимый вариант без крупного тестового шва внутри ветки запуска. Этот
//! тест сам по себе не роняет production-откат к `Vec<JoinHandle>` и не
//! подтверждает корректность production-цепочки.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct LiveGuard(Arc<AtomicUsize>);

impl LiveGuard {
    fn new(live: Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self(live)
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_aborting_parent_aborts_children_instead_of_detaching_them() {
    let live = Arc::new(AtomicUsize::new(0));
    let producer_live = live.clone();
    let producer = tokio::spawn(async move {
        let mut managers = tokio::task::JoinSet::new();
        managers.spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            children.spawn(async move {
                let _guard = LiveGuard::new(producer_live);
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
            super::join_logged(&mut children, "test child join error").await;
        });
        super::join_logged(&mut managers, "test manager join error").await;
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if live.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("descendant task started");

    producer.abort();
    let error = producer.await.expect_err("producer should be aborted");
    assert!(error.is_cancelled(), "producer ended unexpectedly: {error}");

    let dropped = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if live.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        dropped.is_ok(),
        "descendants were detached instead of aborted; live count: {}",
        live.load(Ordering::SeqCst)
    );
}
