//! Адаптер подтверждений для входящих запросов SDK.

use std::sync::{Arc, Mutex};

use resocks5_net::server::{self, Credentials, IncomingRequest, ServerError, ServerOptions};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

/// Проверка учётных данных и получение непрозрачного подтверждения.
pub trait ProofVerifier: Send + Sync {
    /// Подтверждение должно быть пригодно для передачи между потоками.
    type Proof: Send + 'static;

    /// Выполняется в блокирующем пуле; отмена не останавливает проверку.
    fn verify_proof(&self, username: &str, password: &str) -> Option<Self::Proof>;

    /// Имя, привязанное к подтверждению.
    fn username<'a>(&self, proof: &'a Self::Proof) -> &'a str;
}

/// Результат успешного рукопожатия; создать его извне нельзя.
pub struct VerifiedRequest<P> {
    request: IncomingRequest,
    proof: Option<P>,
}

impl<P> VerifiedRequest<P> {
    /// Запрос SDK.
    pub fn request(&self) -> &IncomingRequest {
        &self.request
    }

    /// Извлекает запрос и подтверждение, полученные в одном рукопожатии.
    pub fn into_parts(self) -> (IncomingRequest, Option<P>) {
        (self.request, self.proof)
    }
}

/// Ошибка SDK или нарушение соответствия подтверждения запросу.
#[derive(Debug)]
pub enum VerifiedError {
    /// Ошибка рукопожатия SDK.
    Handshake(ServerError),
    /// SDK вернул запрос без соответствующего подтверждения.
    IdentityMismatch,
}

impl std::fmt::Display for VerifiedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(error) => write!(f, "ошибка рукопожатия: {error}"),
            Self::IdentityMismatch => f.write_str("подтверждение не соответствует запросу"),
        }
    }
}

impl std::error::Error for VerifiedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handshake(error) => Some(error),
            Self::IdentityMismatch => None,
        }
    }
}

/// Принимает запрос и возвращает подтверждение только после успеха SDK.
///
/// cancel-safe: NO — чтение и запись SDK могут завершиться частично; после
/// ошибки, истечения срока или отмены поток и его буфер следует отбросить.
/// Уже запущенная или ожидающая блокирующая проверка продолжится после отмены,
/// удерживая слот до выхода; её результат будет отброшен.
pub async fn accept_verified<S, V>(
    stream: &mut S,
    deadline: Instant,
    auth: Option<Arc<V>>,
) -> Result<VerifiedRequest<V::Proof>, VerifiedError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: ProofVerifier + ?Sized + 'static,
{
    let configured = auth.is_some();
    let options = ServerOptions::new(deadline, !configured, configured);
    let capture = Arc::new(Mutex::new(None));
    let callback_capture = Arc::clone(&capture);
    let slots = super::verification_slots();
    let request = server::accept(
        stream,
        &options,
        move |credentials: Credentials| async move {
            let Some(verifier) = auth else { return false };
            let Ok(permit) = slots.try_acquire_owned() else {
                return false;
            };
            // fire-and-forget: detached by design только при отмене ожидания;
            // блокирующая проверка сохраняет слот до выхода, результат отбрасывается.
            let result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let proof =
                    verifier.verify_proof(credentials.username(), credentials.password())?;
                if verifier.username(&proof) != credentials.username() {
                    return None;
                }
                Some((credentials.username().to_owned(), proof))
            })
            .await;
            let Ok(Some(value)) = result else {
                return false;
            };
            let Ok(mut slot) = callback_capture.lock() else {
                return false;
            };
            if slot.is_some() {
                return false;
            }
            *slot = Some(value);
            true
        },
    )
    .await
    .map_err(VerifiedError::Handshake)?;
    let captured = capture
        .lock()
        .map_err(|_| VerifiedError::IdentityMismatch)?
        .take();
    let proof = match (configured, request.username(), captured) {
        (false, None, None) => None,
        (true, Some(username), Some((verified, proof))) if username == verified => Some(proof),
        _ => return Err(VerifiedError::IdentityMismatch),
    };
    Ok(VerifiedRequest { request, proof })
}
