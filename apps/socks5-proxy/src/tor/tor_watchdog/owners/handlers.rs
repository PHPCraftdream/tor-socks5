use super::*;
use std::sync::atomic::AtomicBool;
use tokio::task::JoinSet;

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
        #[cfg(test)]
        {
            // Measure the actual JoinSet payload to keep handler futures boxed.
            let size = std::mem::size_of_val(&task);
            assert!(
                size <= 16 * 1024,
                "supervised handler task payload is {size} bytes; expected at most 16384"
            );
        }
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
    pub(super) fn accept_loop_tracked(
        self: Arc<Self>,
        listener: TcpListener,
        egress: Egress,
        auth: Option<Arc<AuthState>>,
        permits: Arc<tokio::sync::Semaphore>,
        tracking: ConnectionTracking,
        security: SecurityConfig,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        // Keep the handler-heavy accept-loop state off the FuturesUnordered owner stack.
        Box::pin(async move {
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
                    // Defer handler-future construction to the supervised worker task.
                    if let Err(e) = Box::pin(handle_client(
                        client,
                        egress,
                        auth,
                        conn_health.clone(),
                        security.block_onion,
                        conn_id,
                    ))
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
        })
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
    async fn accept_loop_future_is_small_and_dropping_it_releases_listener() {
        fn assert_send<T: Send>(_: &T) {}

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let future = Arc::new(HandlerTasks::new()).accept_loop_tracked(
            listener,
            Egress::Upstream(Arc::new(upstream::Upstream::new(
                "127.0.0.1:0".to_owned(),
                None,
            ))),
            None,
            Arc::new(tokio::sync::Semaphore::new(1)),
            ConnectionTracking {
                conn_health: ConnHealthCounters::default(),
                next_conn_id: Arc::new(AtomicU64::new(1)),
            },
            Default::default(),
        );

        assert_send(&future);
        let future_size = std::mem::size_of_val(&future);
        // FuturesUnordered stores this ownership handle inline, not accept-loop state.
        assert!(
            future_size <= 2 * std::mem::size_of::<usize>(),
            "accept-loop future is {future_size} bytes; expected at most two machine words"
        );
        drop(future);
        drop(TcpListener::bind(address).await.unwrap());
    }

    #[tokio::test]
    async fn accept_loop_in_futures_unordered_supervises_handler_and_releases_resources() {
        use futures::StreamExt;
        use tokio::io::AsyncReadExt;

        tokio::time::timeout(Duration::from_secs(5), async {
            let handlers = Arc::new(HandlerTasks::new());
            let permits = Arc::new(tokio::sync::Semaphore::new(1));
            let conn_health = ConnHealthCounters::default();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut accept_loops = futures::stream::FuturesUnordered::new();
            accept_loops.push(handlers.clone().accept_loop_tracked(
                listener,
                Egress::Upstream(Arc::new(upstream::Upstream::new(
                    "127.0.0.1:0".to_owned(),
                    None,
                ))),
                None,
                permits.clone(),
                ConnectionTracking {
                    conn_health: conn_health.clone(),
                    next_conn_id: Arc::new(AtomicU64::new(1)),
                },
                Default::default(),
            ));

            let mut client = TcpStream::connect(address).await.unwrap();
            // Greeting sync only; without CONNECT, this test cannot reach egress or DNS.
            let greeting = tokio::select! {
                result = accept_loops.next() => {
                    panic!("accept loop exited unexpectedly: {result:?}");
                }
                result = async {
                    client.write_all(&[5, 1, 0]).await?;
                    let mut reply = [0; 2];
                    client.read_exact(&mut reply).await?;
                    Ok::<_, std::io::Error>(reply)
                } => result.unwrap(),
            };
            assert_eq!(greeting, [5, 0]);
            assert_eq!(handlers.tasks.lock().await.len(), 1);
            assert_eq!(permits.available_permits(), 0);
            assert_eq!(conn_health.snapshot_and_reset().pending, 1);

            drop(accept_loops);
            handlers.shutdown().await.unwrap();
            assert_eq!(permits.available_permits(), 1);
            assert_eq!(conn_health.snapshot_and_reset().pending, 0);
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            drop(client);
            drop(TcpListener::bind(address).await.unwrap());
        })
        .await
        .unwrap();
    }

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
