use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::time::sleep;

pub(super) const RETRY_DELAY: Duration = Duration::from_secs(30);

/// cancel-safe: yes — pending bind and sleep futures own no shared state.
pub(in crate::server) async fn retry_address_with<T, B, F>(
    address: String,
    mut binder: B,
) -> (String, T)
where
    B: FnMut(String) -> F,
    F: Future<Output = io::Result<T>>,
{
    loop {
        sleep(RETRY_DELAY).await;
        match binder(address.clone()).await {
            Ok(resource) => return (address, resource),
            Err(error) => {
                tracing::debug!(listen_addr = %address, %error, "listen address remains unavailable");
            }
        }
    }
}
