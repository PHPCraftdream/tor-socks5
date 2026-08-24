//! Java callback handling for bootstrap events.
//!
//! This module provides the [`JavaCallback`] type, which wraps a JNI `JavaVM` and a
//! `GlobalRef` to the callback object and provides an [`emit`] method that dispatches
//! bootstrap events to the appropriate Java methods.

use arti_wrapper::BootstrapEvent;
use jni::objects::JValue;
use jni::sys::jfloat;
use jni::JavaVM;
use std::sync::Arc;
use tracing::warn;

/// A thread-safe wrapper around a Java callback object.
///
/// Holds a `JavaVM` and a `GlobalRef` to the callback. The `emit` method attaches
/// the current thread to the JVM (if not already attached) and dispatches events
/// to the appropriate Java methods.
pub(crate) struct JavaCallback {
    vm: Arc<JavaVM>,
    global: jni::objects::GlobalRef,
}

impl JavaCallback {
    /// Create a new `JavaCallback` from a `JavaVM` and a `GlobalRef`.
    pub(crate) fn new(vm: JavaVM, global: jni::objects::GlobalRef) -> Self {
        Self {
            vm: Arc::new(vm),
            global,
        }
    }

    /// Cheap `Arc` clone of the shared `JavaVM`, for callers that need to
    /// attach a thread without borrowing `self` (e.g. the engine thread,
    /// whose `AttachGuard` must outlive the borrow of the callback).
    pub(crate) fn vm_arc(&self) -> Arc<JavaVM> {
        Arc::clone(&self.vm)
    }

    /// Create an `Arc<JavaCallback>` that can be cloned and shared.
    pub(crate) fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Emit a bootstrap event to the Java callback.
    ///
    /// This method:
    /// 1. Attaches the current thread to the JVM (if needed).
    /// 2. Dispatches to the appropriate Java method based on the event type.
    /// 3. Checks for and clears any Java exceptions.
    /// 4. Never panics — all errors are logged and swallowed.
    pub(crate) fn emit(&self, event: BootstrapEvent) {
        // Attach the current thread to the JVM. This is safe to call per-event
        // because events are low-rate and the guard detaches on drop.
        let mut env_guard = match self.vm.attach_current_thread() {
            Ok(guard) => guard,
            Err(e) => {
                warn!(error = %e, "failed to attach thread to JVM for callback");
                return;
            }
        };

        let env = &mut *env_guard;
        let obj = self.global.as_obj();

        let result = match event {
            BootstrapEvent::Progress(fraction, status_text) => {
                // Call `void onProgress(float fraction, String statusText)` with signature
                // "(FLjava/lang/String;)V"
                let clamped = fraction.clamp(0.0, 1.0);
                let jstr = match env.new_string(&status_text) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "failed to create Java string for Progress event");
                        return;
                    }
                };
                env.call_method(
                    obj,
                    "onProgress",
                    "(FLjava/lang/String;)V",
                    &[JValue::Float(clamped as jfloat), JValue::Object(&jstr)],
                )
            }
            BootstrapEvent::Ready => {
                // Call `void onReady()` with signature "()V"
                env.call_method(obj, "onReady", "()V", &[])
            }
            BootstrapEvent::Blocked(reason) => {
                // Call `void onBlocked(String reason)` with signature "(Ljava/lang/String;)V"
                let jstr = match env.new_string(&reason) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "failed to create Java string for Blocked event");
                        return;
                    }
                };
                env.call_method(
                    obj,
                    "onBlocked",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&jstr)],
                )
            }
            BootstrapEvent::Failed(error) => {
                // Call `void onFailed(String error)` with signature "(Ljava/lang/String;)V"
                let jstr = match env.new_string(&error) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "failed to create Java string for Failed event");
                        return;
                    }
                };
                env.call_method(
                    obj,
                    "onFailed",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&jstr)],
                )
            }
        };

        // Check for and clear any Java exceptions that occurred during the callback
        if let Err(e) = result {
            warn!(error = %e, "JNI error calling Java callback method");
        }

        // Check if the Java code threw an exception
        if let Ok(has_exception) = env.exception_check() {
            if has_exception {
                warn!("Java callback threw an exception; clearing and continuing");
                let _ = env.exception_clear();
            }
        }
    }
}

// No manual `unsafe impl Send/Sync` here: `JavaVM` and `GlobalRef` are
// already `Send + Sync` in jni 0.21.1 (the crate has audited manual impls
// for both), so the auto-derived traits on `JavaCallback` are exactly the
// ones the JNI contract supports: a global ref may be used from any thread.
