#[cfg(feature = "experimental-server")]
use super::*;
#[cfg(feature = "experimental-server")]
use ptrs::{ServerBuilder as _, ServerTransport};
#[cfg(feature = "experimental-server")]
use tokio::sync::oneshot;

// ================================================================ //
//                            Server                                //
// ================================================================ //
//
// All server-side plumbing is gated behind the `experimental-server`
// cargo feature. The PT handshake and ExtORPort dial are not wired
// (see `server_handle_connection`), so compiling this in by default
// would risk operators standing up an unauthenticated proxy.

#[cfg(feature = "experimental-server")]
pub(super) async fn server_setup(
    statedir: &str,
    cancel_token: CancellationToken,
) -> Result<oneshot::Receiver<bool>> {
    let obfs4_name = Obfs4PT::name();

    let server_info = ptrs::ServerInfo::new()?;
    let (tx, rx) = oneshot::channel::<bool>();

    let mut listeners = Vec::new();

    for bind_addr in server_info.bind_addrs {
        info!(bind_addr.method_name);
        if bind_addr.method_name != obfs4_name {
            warn!("no such transport is supported");
            continue;
        }

        let mut builder = Obfs4PT::server_builder();
        let server = builder
            .statefile_location(statedir)?
            .options(&bind_addr.options)?
            .build();

        let listener = tokio::net::TcpListener::bind(bind_addr.addr).await?;
        listeners.push(server_listen_loop::<TcpStream, _>(
            listener,
            server,
            cancel_token.clone(),
        ));
    }

    // spawn a task that runs and monitors the progress of the listeners.
    tokio::spawn(async move {
        let total_len = listeners.len();
        let mut running = total_len;

        // launch all listener futures
        let mut pt_set = JoinSet::new();
        for fut in listeners {
            pt_set.spawn(fut);
        }

        // if any of the listeners exit, handle it
        while let Some(res) = pt_set.join_next().await {
            running -= 1;
            if let Err(e) = res {
                warn!("listener failed: {e}");
            }
            info!("{running}/{total_len} listeners running");
        }

        // if all listeners exit then we can send the tx signal.
        // Best-effort: the receiver may already be dropped if the
        // parent select! moved on (e.g. signal-driven shutdown).
        let _ = tx.send(true);
    });

    Ok(rx)
}

#[cfg(feature = "experimental-server")]
async fn server_listen_loop<In, S>(
    listener: TcpListener,
    server: S,
    cancel_token: CancellationToken,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
    S: ptrs::ServerTransport<In> + Send + Sync + ptrs::ServerTransport<TcpStream> + 'static,
    <S as ptrs::ServerTransport<In>>::OutErr: 'static,
{
    let method_name = <S as ServerTransport<In>>::method_name();
    let server = Arc::new(server);
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("{method_name} received shutdown signal - closing listener");
                break
            }
            res = listener.accept() => {
                let (conn, client_addr) = match res {
                    Err(e) => {
                       error!("{method_name} closing listener - failed to accept tcp connection {e}");
                       break;
                   }
                   Ok(c) => c,
               };
               tokio::spawn(server_handle_connection(
                   conn,
                   server.clone(),
                   client_addr,
               ));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "experimental-server")]
async fn server_handle_connection<In, S>(
    mut conn: In,
    server: Arc<S>,
    client_addr: SocketAddr,
) -> Result<()>
where
    // the provided In must be usable as a connection in an async context
    In: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    // The provided S must be usable as a Pluggable Transport Server.
    S: ptrs::ServerTransport<In> + Send + Sync + ptrs::ServerTransport<TcpStream>,
    <S as ptrs::ServerTransport<In>>::OutErr: 'static,
{
    let _ = (&mut conn, server, client_addr);
    // Two pieces are still missing here:
    //   1) server.reveal(conn) to complete the PT handshake;
    //   2) a real ExtORPort dial to the parent ORPort.
    // The previous code shipped neither and instead unconditionally
    // dialed a hardcoded 127.0.0.1:8000, which would have stood up an
    // unauthenticated TCP proxy on any host running this build.
    unimplemented!(
        "lyrebird server-side PT handshake is not implemented; \
         do not enable experimental-server in production"
    );
}
