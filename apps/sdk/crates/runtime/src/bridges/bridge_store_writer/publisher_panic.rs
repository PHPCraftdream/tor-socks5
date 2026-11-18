//! Typed error for a panicking publisher: the raw panic payload moves into
//! the registry without formatting; the actor only sees this safe error.

use std::any::Any;
use std::sync::Mutex;

pub(crate) struct PublisherPanic {
    _payload: Mutex<Box<dyn Any + Send>>,
}

impl PublisherPanic {
    pub(super) fn new(payload: Box<dyn Any + Send>) -> Self {
        Self {
            _payload: Mutex::new(payload),
        }
    }
    #[cfg(test)]
    pub(super) fn payload_is<T: Any>(&self, predicate: impl FnOnce(&T) -> bool) -> bool {
        let payload = self
            ._payload
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        payload.downcast_ref::<T>().is_some_and(predicate)
    }
}

impl std::fmt::Display for PublisherPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bridge health store publisher panicked")
    }
}

impl std::fmt::Debug for PublisherPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for PublisherPanic {}
