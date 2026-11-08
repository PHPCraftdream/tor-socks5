//! SDK authentication policy for a per-handshake host verifier.

use std::future::Future;

use resocks5_net::secure_auth::{PasswordCheck, SecretStore, StoredUser, UserSecret};
use resocks5_net::server::{self, AuthMethods, IncomingRequest, ServerError, ServerOptions};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

struct HostStore<F>(F);

impl<F, Fut> SecretStore for HostStore<F>
where
    F: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = bool> + Send,
{
    // This adapter enables cleartext_only, never the secure-auth exchange.
    async fn lookup(&self, _user: &str) -> Option<StoredUser> {
        None
    }

    async fn claim(&self, _user: &str, _secret: UserSecret) -> bool {
        false
    }

    fn check_password(
        &self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = PasswordCheck> + Send {
        let checked = (self.0)(user.to_owned(), password.to_owned());
        async move {
            if checked.await {
                PasswordCheck::Accepted
            } else {
                PasswordCheck::Rejected
            }
        }
    }
}

/// Keep credentials and captured host proofs scoped to this handshake.
/// cancel-safe: NO — discard partial framing; the verifier owns any surviving work.
pub(crate) async fn accept_checked<S, F, Fut>(
    stream: &mut S,
    deadline: Instant,
    configured: bool,
    check: F,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = bool> + Send,
{
    let options = ServerOptions::new(deadline)
        .allow_anonymous(!configured)
        .allow_cleartext(configured);
    if !configured {
        return server::accept(stream, &options).await;
    }
    let store = HostStore(check);
    server::accept_with(stream, &options, &AuthMethods::cleartext_only(&store)).await
}
