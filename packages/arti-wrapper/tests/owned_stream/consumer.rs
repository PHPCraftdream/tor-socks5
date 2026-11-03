use std::fs;
use std::net::SocketAddrV4;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use arti_client::config::{dir, TorClientConfigBuilder};
use arti_client::isolation::StreamIsolation;
use arti_wrapper::TorTunnel;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

#[path = "protocol.rs"]
mod protocol;

#[path = "mechanisms.rs"]
mod mechanisms;

type Result<T> = std::result::Result<T, &'static str>;

struct Launch {
    control: PathBuf,
    storage: PathBuf,
    parent_pid: u32,
    parent_uid: u32,
}

fn environment(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| "launch-environment")
}

fn private_directory(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "private-directory")?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err("private-directory");
    }
    Ok(())
}

impl Launch {
    fn load() -> Result<Self> {
        if environment("GITHUB_ACTIONS")? != "true" || environment("TOR_REAL_ISOLATED")? != "yes" {
            return Err("isolated-ci-required");
        }
        let parent_pid = protocol::decimal(&environment("TOR_REAL_STREAM_PARENT_PID")?)?;
        let parent_uid = protocol::decimal(&environment("TOR_REAL_STREAM_PARENT_UID")?)?;
        if parent_pid == 0 {
            return Err("parent-identity");
        }
        let control = PathBuf::from(environment("TOR_REAL_STREAM_CONTROL")?);
        let storage = PathBuf::from(environment("TOR_REAL_STREAM_STORAGE")?);
        if !control.is_absolute() || !storage.is_absolute() {
            return Err("absolute-capability-path");
        }
        private_directory(control.parent().ok_or("control-parent")?, parent_uid)?;
        private_directory(&storage, parent_uid)?;
        if fs::read_dir(&storage)
            .map_err(|_| "fresh-storage")?
            .next()
            .is_some()
        {
            return Err("fresh-storage");
        }
        for name in ["state", "cache"] {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(storage.join(name))
                .map_err(|_| "fresh-storage")?;
        }
        Ok(Self {
            control,
            storage,
            parent_pid,
            parent_uid,
        })
    }
}

fn configuration(
    launch: &Launch,
    capabilities: &protocol::Capabilities,
) -> Result<arti_client::TorClientConfig> {
    let mut builder = TorClientConfigBuilder::from_directories(
        launch.storage.join("state"),
        launch.storage.join("cache"),
    );
    let mut authorities = dir::AuthorityContacts::builder();
    authorities.v3idents().clear();
    authorities.uploads().clear();
    for authority in &capabilities.authorities {
        authorities.v3idents().push(authority.identity.into());
    }
    *builder.tor_network().authorities() = authorities;

    let mut fallbacks = Vec::with_capacity(3);
    for relay in &capabilities.relays {
        let mut fallback = dir::FallbackDir::builder();
        fallback
            .rsa_identity(relay.rsa.into())
            .ed_identity(relay.ed.into());
        fallback
            .orports()
            .push(SocketAddrV4::new(relay.address, relay.port).into());
        fallbacks.push(fallback);
    }
    builder.tor_network().set_fallback_caches(fallbacks);
    builder.path_rules().ipv4_subnet_family_prefix(32);
    builder.path_rules().circuit_hops(3);
    builder.address_filter().allow_local_addrs(true);
    builder.build().map_err(|_| "private-client-config")
}

/// cancel-safe: NO — partial writes and reads are externally observable.
/// Cancellation leaves the borrowed stream with its caller; do not retry.
async fn exchange<S>(stream: &mut S, nonce: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("owned-request:{nonce}\n");
    let expected = format!("owned-response:{nonce}\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| "stream-request")?;
    stream.flush().await.map_err(|_| "stream-flush")?;

    let mut response = vec![0; expected.len()];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| "stream-response")?;
    if response != expected.as_bytes() {
        return Err("stream-response");
    }

    let mut extra = [0_u8; 1];
    if stream
        .read(&mut extra)
        .await
        .map_err(|_| "stream-terminal")?
        != 0
    {
        return Err("stream-response-suffix");
    }

    stream.close().await.map_err(|_| "stream-close")?;
    Ok(())
}

trait ProofControl: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    fn check_pending_input(&self) -> Result<()>;
}

impl ProofControl for UnixStream {
    fn check_pending_input(&self) -> Result<()> {
        protocol::no_pending_input(self)
    }
}

/// cancel-safe: NO — receipt writes may be partial and must not be retried.
/// Before valid acknowledgment, cancellation retains the caller's owners.
async fn terminal_proof<C, O>(control: &mut C, owners: &mut Option<O>) -> Result<()>
where
    C: ProofControl,
{
    if owners.is_none() {
        return Err("missing-proof-owners");
    }

    control.check_pending_input()?;
    control
        .write_all(b"STREAM_VERIFIED\n")
        .await
        .map_err(|_| "control-write")?;
    protocol::terminal_ack(control).await?;

    drop(owners.take());
    control
        .write_all(b"CONSUMER_DONE\n")
        .await
        .map_err(|_| "control-write")?;
    Ok(())
}

async fn consume(launch: &Launch) -> Result<()> {
    let mut control = UnixStream::connect(&launch.control)
        .await
        .map_err(|_| "control-connect")?;
    let credentials = control.peer_cred().map_err(|_| "control-credentials")?;
    let actual_pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("control-credentials")?;
    protocol::authenticate(
        actual_pid,
        credentials.uid(),
        launch.parent_pid,
        launch.parent_uid,
    )?;

    let input = protocol::initial_input(&mut control).await?;
    let capabilities = protocol::parse(&input, launch.parent_pid, launch.parent_uid)?;
    let config = configuration(launch, &capabilities)?;
    let client = TorTunnel::create_unbootstrapped(config).map_err(|_| "client-construction")?;

    let work = async {
        client
            .wait_bootstrapped()
            .await
            .map_err(|_| "client-bootstrap")?;
        let provider = client.raw().dirmgr().map_err(|_| "directory-provider")?;
        let directory = provider.timely_netdir().map_err(|_| "timely-directory")?;
        let manager = client.raw().circmgr().map_err(|_| "circuit-manager")?;
        let tunnel = manager
            .get_or_launch_exit(
                directory.as_ref().into(),
                &[],
                StreamIsolation::no_isolation(),
            )
            .await
            .map_err(|_| "exit-circuit")?;
        if tunnel.n_hops().map_err(|_| "circuit-hop-count")? != 3 {
            return Err("circuit-hop-count");
        }
        let address = capabilities.target_address.to_string();
        let mut stream: arti_client::DataStream = tunnel
            .begin_stream(&address, capabilities.target_port, None)
            .await
            .map_err(|_| "exit-stream")?;
        exchange(&mut stream, &capabilities.nonce).await?;
        Ok((provider, directory, manager, tunnel, stream))
    };
    let mut unexpected = [0_u8; 1];
    let owners = tokio::select! {
        result = work => result?,
        _ = control.read(&mut unexpected) => return Err("early-control"),
    };

    let mut retained = Some((owners, client));
    terminal_proof(&mut control, &mut retained).await
}
fn failure_label(label: &str) -> &'static str {
    match label {
        "launch-environment" => "launch-environment",
        "isolated-ci-required" => "isolated-ci-required",
        "parent-identity" => "parent-identity",
        "decimal-field" => "decimal-field",
        "absolute-capability-path" => "absolute-capability-path",
        "control-parent" => "control-parent",
        "private-directory" => "private-directory",
        "fresh-storage" => "fresh-storage",
        "runtime-construction" => "runtime-construction",
        "control-connect" => "control-connect",
        "control-credentials" => "control-credentials",
        "control-input" => "control-input",
        "control-framing" => "control-framing",
        "control-record" => "control-record",
        "identity-field" => "identity-field",
        "loopback-address" => "loopback-address",
        "port-field" => "port-field",
        "authority-record" => "authority-record",
        "fallback-record" => "fallback-record",
        "authority-relay-identity-overlap" => "authority-relay-identity-overlap",
        "nonce-field" => "nonce-field",
        "private-client-config" => "private-client-config",
        "client-construction" => "client-construction",
        "client-bootstrap" => "client-bootstrap",
        "directory-provider" => "directory-provider",
        "timely-directory" => "timely-directory",
        "circuit-manager" => "circuit-manager",
        "exit-circuit" => "exit-circuit",
        "circuit-hop-count" => "circuit-hop-count",
        "exit-stream" => "exit-stream",
        "stream-request" => "stream-request",
        "stream-flush" => "stream-flush",
        "stream-response" => "stream-response",
        "stream-terminal" => "stream-terminal",
        "stream-response-suffix" => "stream-response-suffix",
        "stream-close" => "stream-close",
        "early-control" => "early-control",
        "control-write" => "control-write",
        "target-terminal-ack" => "target-terminal-ack",
        "missing-proof-owners" => "missing-proof-owners",
        _ => "unknown-component-failure",
    }
}

#[test]
#[ignore = "requires the retained isolated Tor fixture and authenticated parent"]
fn owned_three_hop_round_trip() {
    let result = (|| {
        let launch = Launch::load()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "runtime-construction")?;
        runtime.block_on(consume(&launch))
    })();
    if let Err(label) = result {
        panic!(
            "private owned-stream component failed: {}",
            failure_label(label)
        );
    }
}
