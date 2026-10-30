use super::*;
use std::sync::atomic::AtomicBool;
use tokio::task::JoinSet;

pub(super) struct RegistryRunGuard(pub(super) Arc<owners::OwnerRegistry>);
impl Drop for RegistryRunGuard {
    fn drop(&mut self) {
        self.0.begin_close();
    }
}

pub(super) struct HandlerRunGuard(pub(super) Arc<HandlerTasks>);
impl Drop for HandlerRunGuard {
    fn drop(&mut self) {
        self.0.begin_shutdown();
    }
}

static RETAINED_HANDLERS: std::sync::Mutex<Option<Arc<HandlerTasks>>> = std::sync::Mutex::new(None);

const HANDLER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct ConnectionTracking {
    pub(super) conn_health: ConnHealthCounters,
    pub(super) next_conn_id: Arc<AtomicU64>,
}

pub(super) struct HandlerTasks {
    closed: AtomicBool,
    tasks: tokio::sync::Mutex<JoinSet<()>>,
}

impl HandlerTasks {
    pub(super) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            tasks: tokio::sync::Mutex::new(JoinSet::new()),
        }
    }

    fn report(result: std::result::Result<(), tokio::task::JoinError>) {
        if let Err(error) = result {
            if !error.is_cancelled() {
                warn!(%error, "connection task failed");
            }
        }
    }

    pub(super) async fn reap(&self) {
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.try_join_next() {
            Self::report(result);
        }
    }

    async fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.try_join_next() {
            Self::report(result);
        }
        if self.closed.load(Ordering::Acquire) || tasks.len() >= MAX_CONCURRENT_CONNECTIONS {
            warn!("connection task admission closed or full");
            return;
        }
        tasks.spawn(task);
    }

    pub(super) fn begin_shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut tasks) = self.tasks.try_lock() {
            tasks.abort_all();
        }
    }

    pub(super) fn retain(self: &Arc<Self>) -> Result<()> {
        let mut retained = RETAINED_HANDLERS
            .lock()
            .map_err(|_| anyhow!("хранилище обработчиков повреждено"))?;
        if retained.is_some() {
            bail!("предыдущие обработчики ещё удерживаются");
        }
        *retained = Some(self.clone());
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn retained() -> Option<Arc<Self>> {
        RETAINED_HANDLERS.lock().unwrap().clone()
    }

    pub(super) async fn recover() -> Result<()> {
        let retained = RETAINED_HANDLERS
            .lock()
            .map_err(|_| anyhow!("хранилище обработчиков повреждено"))?
            .clone();
        if let Some(tasks) = retained {
            tasks.shutdown().await?;
        }
        Ok(())
    }

    pub(super) async fn shutdown(&self) -> Result<()> {
        self.begin_shutdown();
        let deadline = tokio::time::Instant::now() + HANDLER_JOIN_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            let mut tasks = self.tasks.lock().await;
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                Self::report(result);
            }
        })
        .await
        .map_err(|_| anyhow!("истёк срок завершения обработчиков"))?;
        let mut retained = RETAINED_HANDLERS
            .lock()
            .map_err(|_| anyhow!("хранилище обработчиков повреждено"))?;
        if retained
            .as_ref()
            .is_some_and(|tasks| std::ptr::eq(tasks.as_ref(), self))
        {
            *retained = None;
        }
        Ok(())
    }

    /// Accept connections on `listener` forever, spawning one task per
    /// connection. Accept errors are logged and retried with a backoff, so the
    /// loop only ends by being dropped (shutdown).
    ///
    /// `next_conn_id` is the shared, monotonic per-connection identifier for
    /// log correlation — shared across every listener's accept loop, since
    /// per-loop counters would hand out colliding conn_ids once several
    /// listeners are bound. Wraps only after 2^64 connections — never, in
    /// practice.
    pub(super) async fn accept_loop_tracked(
        self: Arc<Self>,
        listener: TcpListener,
        egress: Egress,
        auth: Option<Arc<AuthState>>,
        permits: Arc<tokio::sync::Semaphore>,
        tracking: ConnectionTracking,
        security: SecurityConfig,
    ) {
        let ConnectionTracking {
            conn_health,
            next_conn_id,
        } = tracking;
        loop {
            let (client, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(?e, "accept failed; retrying in {ACCEPT_ERROR_BACKOFF:?}");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            // Глобальный ingress-ACL: deny до permit/spawn — drop без ответных байт.
            if !security.client_access.allowed_clients.allows(peer.ip()) {
                debug!(%peer, "client rejected by security.client_access.allowed_clients");
                drop(client);
                continue;
            }
            let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
            let egress = egress.clone();
            let auth = auth.clone();
            let conn_health = conn_health.clone();
            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore not closed");
            self.spawn(async move {
                debug!(conn_id, %peer, "new connection");
                // RAII gauge: moved into the task so `pending` is decremented
                // wherever the task ends — error, success, or panic.
                let pending_guard = conn_health.record_started();
                if let Err(e) = handle_client(
                    client,
                    egress,
                    auth,
                    conn_health.clone(),
                    security.block_onion,
                    conn_id,
                )
                .await
                {
                    let (stage, kind) = classify_conn_failure(&e);
                    conn_health.record_failure(stage, kind);
                    // `{:#}` (anyhow's alternate Display) prints the full cause
                    // chain ("top: cause1: cause2: ..."); plain `%e` would only
                    // print the outermost context tag (e.g. "SOCKS5 handshake")
                    // and silently swallow the real root cause.
                    warn!(
                        conn_id,
                        %peer,
                        stage = ?stage,
                        kind = ?kind,
                        error = format!("{:#}", e),
                        "connection finished with error"
                    );
                }
                drop(permit);
                drop(pending_guard);
            })
            .await;
        }
    }
}

#[cfg(test)]
pub(super) async fn accept_loop(
    listener: TcpListener,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    permits: Arc<tokio::sync::Semaphore>,
    conn_health: ConnHealthCounters,
    next_conn_id: Arc<AtomicU64>,
    security: SecurityConfig,
) {
    Arc::new(HandlerTasks::new())
        .accept_loop_tracked(
            listener,
            egress,
            auth,
            permits,
            ConnectionTracking {
                conn_health,
                next_conn_id,
            },
            security,
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_aborts_handler_releases_permit_and_rejects_late_spawn() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let handlers = HandlerTasks::new();
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let permit = permits.clone().acquire_owned().await.unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
            handlers
                .spawn(async move {
                    let _permit = permit;
                    let _ = started_tx.send(());
                    let _ = release_rx.await;
                })
                .await;
            started_rx.await.unwrap();
            assert_eq!(permits.available_permits(), 0);
            handlers.shutdown().await.unwrap();
            assert_eq!(permits.available_permits(), 1);
            let (late_tx, late_rx) = tokio::sync::oneshot::channel();
            handlers
                .spawn(async move {
                    let _ = late_tx.send(());
                })
                .await;
            assert!(late_rx.await.is_err());
        })
        .await
        .unwrap();
    }
}
