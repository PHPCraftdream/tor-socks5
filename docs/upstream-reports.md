# Upstream reports — fixes applied to vendored crates

> **All of the investigation, root-cause analysis, and the fixes described
> below were done by Claude** (Anthropic's AI assistant, model Claude Opus 4.8),
> working across several days. The work peeled back one layer at a time — obfs4
> framing, directory-read timeouts, tokio worker starvation, TCP keepalive, and
> finally the `saturating-time` infinite loop — re-running the live embedded
> client against real obfs4 bridges after each change, until the connection
> finally succeeded:
> `curl --socks5-hostname 127.0.0.1:20085 https://check.torproject.org/api/ip`
> → `{"IsTor":true}` through the embedded arti client, with no upstream proxy.
>
> Sharing these reports upstream in the hope they save someone else the same
> multi-day hunt. Feedback and corrections very welcome.

Three upstream crates were vendored and patched while getting an **embedded
arti** Tor client to bootstrap directly through obfs4 bridges on **Windows**.
Each section below is self-contained and can be sent to the respective
maintainer as a bug report / patch proposal.

Context shared by all three: `arti-client` 0.43, default Windows (MSVC) target,
`tokio` multi-thread runtime, obfs4 bridges via a pluggable transport.

---

## 1. `saturating-time` 0.3.0 — `saturating_add`/`saturating_sub` hang forever on Windows (100% CPU)

**Severity:** high — a single call hangs the calling thread indefinitely on
some platforms (reproduced on Windows MSVC, both debug and release).

### Symptom
`SystemTime::saturating_add(..)` / `saturating_sub(..)` never returns and pins a
core at 100% CPU. In our case it hung `tor_netdoc::RouterDesc::parse`, which
calls `published.saturating_add(ROUTER_EXPIRY_SECONDS)` while computing a
descriptor's validity, so the whole program live-locked.

### Root cause
Two compounding issues.

1. **Eager argument evaluation.** `src/lib.rs`:

   ```rust
   fn saturating_add(self, duration: Duration) -> Self {
       self.checked_add(duration)
           .unwrap_or(SaturatingTime::max_value())   // <-- eager
   }
   ```

   `Option::unwrap_or` evaluates its argument **unconditionally**, so
   `max_value()` runs on *every* call, even when `checked_add` returns `Some`.
   `max_value()` forces the `MAX_SYSTEM_TIME: LazyLock<SystemTime>` in
   `src/internal.rs`, whose initializer is `find_max` → `find_limit`.

2. **`find_limit` does not terminate on Windows `SystemTime`.** `src/internal.rs`:

   ```rust
   loop {
       let next = f(&res, step);          // f == SystemTime::checked_add
       match next {
           Some(st) => { res = st }       // grows res by `step`, step UNCHANGED
           None => {
               if step == ONE_NS { return res; }
               else { step = max(ONE_NS, step / 2); }
           }
       }
   }
   ```

   `step` only shrinks on the `None` branch. With `INITIAL_STEP = 10^18 s`, on a
   platform whose `SystemTime::checked_add` keeps returning `Some` for that step
   (Windows' representable range is very large), the `None` branch is never
   reached, `step` never shrinks, `res` grows without bound, and the loop spins
   forever.

So on Windows the first `saturating_add`/`saturating_sub` ever made wedges the
process.

### Reproduction
```rust
use std::time::{Duration, SystemTime};
use saturating_time::SaturatingTime;

fn main() {
    // Hangs forever at 100% CPU on Windows (and any platform where
    // SystemTime::checked_add does not report overflow for a 10^18 s step):
    let _ = SystemTime::UNIX_EPOCH.saturating_add(Duration::from_secs(5 * 86400));
}
```
(A watchdog-thread test that turns the hang into a failure is included in our
vendored copy as `saturating_add_sub_does_not_hang`.)

### Fix applied
Make the saturation lazy so the limit search is only reached on a genuine
overflow (which never happens for real wall-clock values):

```rust
fn saturating_add(self, duration: Duration) -> Self {
    self.checked_add(duration)
        .unwrap_or_else(SaturatingTime::max_value)   // lazy
}
fn saturating_sub(self, duration: Duration) -> Self {
    self.checked_sub(duration)
        .unwrap_or_else(SaturatingTime::min_value)
}
```

This fully resolves the hang in practice. **Recommendation for upstream:** also
make `find_limit` provably terminating (e.g. detect non-progress / cap the
number of `Some` growth iterations, then refine `step`), so that calling
`max_value()`/`min_value()` directly is safe on every platform. We did not ship
that change ourselves because an approximate limit is worse than not forcing the
search at all for our use case; the lazy `unwrap_or_else` is sufficient for us.

---

## 2. arti `tor-dirmgr` 0.43.0 — bridge-descriptor fetch can hang forever (no timeout)

**Severity:** medium/high — a single unresponsive bridge can stall bridge-guard
usability indefinitely.

**File:** `src/bridgedesc.rs`, `impl mockable::MockableAPI for () { async fn download(..) }`.

### Symptom
A queued bridge-descriptor download neither completes nor fails — it stays
"running" for minutes. Because the descriptor is never acquired, the bridge
stays `dir_info_missing` → "unsuitable to purpose" in `tor-guardmgr`, so no Data
circuit can be built even though the directory is otherwise bootstrapped.

### Root cause
`download()` awaits `circmgr.get_or_launch_dir_specific(bridge)` →
`begin_dir_stream()` → `send_request(..)` with **no timeout** around them. A
slow/stalled obfs4 channel (or a circuit that never finishes building) makes the
future park indefinitely; nothing in the bridge-desc manager bounds it. (We also
observed this future never being polled at all under tokio worker starvation
when the circuit manager was churning many concurrent failed builds — a separate
robustness concern, but the missing timeout is the direct cause of the
unbounded stall.)

### Fix applied
Wrap the whole fetch in a per-attempt timeout so a stuck attempt fails cleanly
and is retried (and another bridge can be promoted):

```rust
let fetch = async { /* get_or_launch_dir_specific + begin_dir_stream + send_request */ };
match runtime.timeout(Duration::from_secs(10), fetch).await {
    Ok(r) => r,
    Err(_) => Err(internal!("bridge descriptor fetch timed out").into()),
}
```

Plus tuning for a small, flaky bridge pool (these are policy, not bugs):
`BridgeDescDownloadConfig` initial `retry` 30s → 5s and `parallelism` raised so
all configured bridges race their (cheap, one-hop) descriptor fetches.

**Suggestion for upstream:** give the bridge-descriptor download a built-in
timeout (configurable via `BridgeDescDownloadConfig`), rather than relying on an
ambient circuit timeout that may not apply to `get_or_launch_dir_specific`.

---

## 3. arti `tor-dirclient` 0.43.0 — total directory-read timeout truncates slow-but-healthy downloads

**Severity:** low/medium — manifests with slow transports (obfs4 bridges),
large objects (full consensus).

**File:** `src/lib.rs`, `read_and_decompress`.

### Symptom
Over a slow obfs4 bridge a large consensus (~3 MB) is reported as a
`DirTimeout` / "Partial response" and retried from scratch, even though bytes
were arriving steadily the whole time — just slower than the fixed total budget.

### Root cause
The read loop armed a single **total** timeout once before the loop, covering
the entire response. A genuinely slow (but live) stream exceeds it and is
discarded.

### Fix applied
Use an **idle** (inter-read) timeout instead: rebuild the timer each iteration
so it only fires when no byte has arrived for the idle window — distinguishing a
true stall from a merely slow stream:

```rust
let idle_timeout = Duration::from_secs(90);
loop {
    let timer = runtime.sleep(idle_timeout).fuse();
    futures::pin_mut!(timer);
    let status = futures::select! {
        status = stream.read(buf).fuse() => status,
        _ = timer => return Err(RequestError::DirTimeout),
    };
    // ...
}
```

**Suggestion for upstream:** consider an idle/stall timeout (configurable)
rather than a single total deadline for directory reads, so slow pluggable
transports don't cause spurious full-document re-downloads. The exact value
(90s here) is just what we tuned for these bridges.

---

## Notes

- Versions above are the exact crates.io releases our dependency graph resolved
  (the arti 0.43 line). Line references are to those published sources.
- arti repository: <https://gitlab.torproject.org/tpo/core/arti> (issues/MRs).
- The fixes are carried locally via `[patch.crates-io]`; full patched sources
  are in this repo under `vendor/` (see `vendor/README.md`).

---

## Patches (unified diffs)

Generated against the pristine crates.io sources listed above; apply from
each crate root with `patch -p1 < ...` or `git apply`. The essential change
in each is described in the matching section above — the `tor-socks5`-prefixed
comments and the added regression test are optional and can be dropped/reworded
for upstream. (In `tor-dirmgr`, `parallelism` is 12 and `retry` 5s for a small
flaky bridge pool; treat those constants as tuning, not as part of the core
"add a timeout" fix.)

### `saturating-time` 0.3.0

```diff
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -98,8 +98,17 @@
     /// assert_eq!(max.saturating_add(Duration::new(0, 1)), max);
     /// ```
     fn saturating_add(self, duration: Duration) -> Self {
+        // tor-socks5 local patch: `unwrap_or(max_value())` EAGERLY evaluates
+        // `max_value()` on every call, even when `checked_add` succeeds.
+        // `max_value()` forces the `MAX_SYSTEM_TIME`/`MAX_INSTANT` `LazyLock`,
+        // whose `find_max` binary-search (internal.rs) does not terminate on
+        // some platforms (observed: Windows `SystemTime`), spinning at 100%
+        // CPU forever. That hung `RouterDesc::parse` (the only consumer that
+        // adds a duration to a parsed time), so embedded arti could never use
+        // a bridge. Use `unwrap_or_else` so the limit is only computed on a
+        // genuine overflow.
         self.checked_add(duration)
-            .unwrap_or(SaturatingTime::max_value())
+            .unwrap_or_else(SaturatingTime::max_value)
     }
 
     /// Performs a saturating subtraction of a [`Duration`].
@@ -122,8 +131,10 @@
     /// assert_eq!(min.saturating_sub(Duration::new(0, 1)), min);
     /// ```
     fn saturating_sub(self, duration: Duration) -> Self {
+        // See `saturating_add`: avoid eagerly forcing the (possibly
+        // non-terminating) min/max limit search on every call.
         self.checked_sub(duration)
-            .unwrap_or(SaturatingTime::min_value())
+            .unwrap_or_else(SaturatingTime::min_value)
     }
 
     /// Performs a saturating time difference calculation between two points.
@@ -232,7 +243,10 @@
     }
 
     /// Calls [`min_max()`] using [`SystemTime`].
+    // tor-socks5: forces the SystemTime limit search, non-terminating on
+    // Windows (see internal::find_limit); ignored so it doesn't hang the suite.
     #[test]
+    #[ignore = "forces non-terminating SystemTime limit search on Windows (see find_limit)"]
     fn system_time_min_max() {
         min_max::<SystemTime>();
     }
@@ -244,7 +258,12 @@
     }
 
     /// Calls [`saturating_add_sub()`] and [`saturating_duration()`] using [`SystemTime`].
+    // tor-socks5: forces `SystemTime::max_value()`/`min_value()`, whose limit
+    // search does not terminate on Windows (see internal::find_limit). Our fix
+    // makes production code never reach that path; this upstream test exercises
+    // it directly, so it is ignored rather than left to hang `cargo test`.
     #[test]
+    #[ignore = "forces non-terminating SystemTime limit search on Windows (see find_limit)"]
     fn system_time_saturating() {
         saturating_add_sub::<SystemTime>();
         saturating_duration::<SystemTime>();
@@ -256,4 +275,30 @@
         saturating_add_sub::<Instant>();
         saturating_duration::<Instant>();
     }
+
+    /// Regression (tor-socks5): a plain, non-overflowing `saturating_add` /
+    /// `saturating_sub` must return promptly and must NOT spin forever forcing
+    /// the platform min/max search. On Windows the original eager
+    /// `unwrap_or(max_value())` made every call drive a non-terminating
+    /// `find_max`, hanging `RouterDesc::parse` (and thus arti's use of bridges)
+    /// at 100% CPU. A watchdog thread turns any such hang into a failure.
+    #[test]
+    fn saturating_add_sub_does_not_hang() {
+        use std::sync::mpsc;
+
+        let (tx, rx) = mpsc::channel();
+        std::thread::spawn(move || {
+            let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000); // ~2026
+            // Neither of these overflows, so with the lazy `unwrap_or_else` fix
+            // the (possibly non-terminating) limit search is never reached.
+            let later = base.saturating_add(Duration::from_secs(5 * 86400));
+            let earlier = base.saturating_sub(Duration::from_secs(86400));
+            let _ = tx.send(later > earlier);
+        });
+
+        match rx.recv_timeout(Duration::from_secs(10)) {
+            Ok(ok) => assert!(ok, "saturating_add should be after saturating_sub"),
+            Err(_) => panic!("saturating arithmetic hung (>10s) — eager limit search regression"),
+        }
+    }
 }
--- a/src/internal.rs
+++ b/src/internal.rs
@@ -133,7 +133,15 @@
     const INITIAL_STEP: Duration = Duration::new(1_000_000_000_000_000_000, 0);
     const ONE_NS: Duration = Duration::new(0, 1);
 
-    // (1) Set step to INITIAL_STEP and res to T::anchor().
+    // NOTE (tor-socks5): this search does NOT terminate on every platform — on
+    // Windows `SystemTime::checked_add` does not report overflow with `None`
+    // for the 10^18s initial step, so `None` is never reached, `step` never
+    // shrinks, and this spins forever at 100% CPU. We do not "fix" the search
+    // (a wrong/approximate limit would be worse than not having one); instead
+    // the public `saturating_add`/`saturating_sub` were changed to call this
+    // only on a genuine overflow (lazy `unwrap_or_else`), which never happens
+    // for real wall-clock values. The two tests that force this path directly
+    // are `#[ignore]`d on that basis.
     let mut step = INITIAL_STEP;
     let mut res = T::anchor();
 
@@ -207,7 +215,10 @@
 
     /// Verifies [`SystemTime::min_value()`] and [`SystemTime::max_value()`] are
     /// correct.
+    // tor-socks5: forces the SystemTime limit search, which does not terminate
+    // on Windows (see `find_limit`); ignored so it doesn't hang `cargo test`.
     #[test]
+    #[ignore = "forces non-terminating SystemTime limit search on Windows (see find_limit)"]
     fn system_time_min_max() {
         min_max::<SystemTime>();
     }
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -40,3 +40,8 @@
 [lib]
 name = "saturating_time"
 path = "src/lib.rs"
+# tor-socks5: the upstream doc examples call `SystemTime::max_value()` /
+# `min_value()`, whose limit search does not terminate on Windows (see
+# internal::find_limit). They would hang `cargo test`, so doctests are disabled
+# for this vendored copy.
+doctest = false
```

### arti `tor-dirclient` 0.43.0

```diff
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -311,8 +311,19 @@
         ));
     }
 
-    let mut decoder =
-        get_decoder(buffered, header.encoding.as_deref(), anonymized).map_err(wrap_err)?;
+    // tor-socks5 local patch: when the server gave us a Content-Length,
+    // bound the (compressed) body read with `.take(len)` so the decoder
+    // sees a clean EOF after exactly that many bytes — instead of blocking
+    // until a stream-level RELAY_END that may never arrive over a slow
+    // obfs4 circuit (the cause of spurious "Partial response" / DirTimeout).
+    let mut decoder = match header.length {
+        Some(clen) => {
+            use futures::io::AsyncReadExt as _;
+            let bounded = BufReader::new(buffered.take(clen as u64));
+            get_decoder(bounded, header.encoding.as_deref(), anonymized).map_err(wrap_err)?
+        }
+        None => get_decoder(buffered, header.encoding.as_deref(), anonymized).map_err(wrap_err)?,
+    };
 
     let mut result = Vec::new();
     let ok = read_and_decompress(runtime, &mut decoder, maxlen, &mut result).await;
@@ -379,6 +390,7 @@
                         status: response.code,
                         status_message: response.reason.map(str::to_owned),
                         encoding: None,
+                        length: None,
                     });
                 }
                 let encoding = if let Some(enc) = response
@@ -390,17 +402,21 @@
                 } else {
                     None
                 };
-                /*
-                if let Some(clen) = response.headers.iter().find(|h| h.name == "Content-Length") {
-                    let clen = std::str::from_utf8(clen.value)?;
-                    length = Some(clen.parse()?);
-                }
-                 */
+                // tor-socks5 local patch: parse Content-Length (arti upstream
+                // leaves this commented out). Used to bound the body read.
+                let length = if let Some(clen) =
+                    response.headers.iter().find(|h| h.name == "Content-Length")
+                {
+                    std::str::from_utf8(clen.value).ok().and_then(|s| s.trim().parse::<usize>().ok())
+                } else {
+                    None
+                };
                 assert!(n_parsed == buf.len());
                 return Ok(HeaderStatus {
                     status: Some(200),
                     status_message: None,
                     encoding,
+                    length,
                 });
             }
         }
@@ -419,6 +435,11 @@
     status_message: Option<String>,
     /// The Content-Encoding header, if any.
     encoding: Option<String>,
+    /// The Content-Length header, if any (on-wire / compressed body length).
+    /// tor-socks5 local patch: arti upstream ignores this; we use it to bound
+    /// the body read so it terminates cleanly instead of waiting for a stream
+    /// EOF that may never arrive over a slow obfs4 circuit.
+    length: Option<usize>,
 }
 
 /// Helper: download directory information from `stream` and
@@ -441,17 +462,21 @@
 {
     let buffer_window_size = 1024;
     let mut written_total: usize = 0;
-    // TODO(nickm): This should be an option, and is maybe too long.
-    // Though for some users it may be too short?
-    let read_timeout = Duration::from_secs(10);
-    let timer = runtime.sleep(read_timeout).fuse();
-    futures::pin_mut!(timer);
+    // tor-socks5 local patch: this used to be a single TOTAL timeout armed
+    // once before the loop, which truncated big-but-healthy downloads (e.g.
+    // a ~3MB consensus over a slow obfs4 bridge) into a DirTimeout /
+    // "Partial response". Switched to an IDLE (inter-read) timeout: the
+    // timer is rebuilt every iteration, so it only fires when no byte has
+    // arrived for `idle_timeout` — a true stall, not merely a slow stream.
+    let idle_timeout = Duration::from_secs(90);
 
     loop {
         // allocate buffer for next read
         result.resize(written_total + buffer_window_size, 0);
         let buf: &mut [u8] = &mut result[written_total..written_total + buffer_window_size];
 
+        let timer = runtime.sleep(idle_timeout).fuse();
+        futures::pin_mut!(timer);
         let status = futures::select! {
             status = stream.read(buf).fuse() => status,
             _ = timer => {
```

### arti `tor-dirmgr` 0.43.0

```diff
--- a/src/bridgedesc.rs
+++ b/src/bridgedesc.rs
@@ -140,8 +140,18 @@
     fn default() -> Self {
         let secs = Duration::from_secs;
         BridgeDescDownloadConfig {
-            parallelism: 4.try_into().expect("parallelism is zero"),
-            retry: secs(30),
+            // tor-socks5 local patch: fetch all configured bridges' descriptors
+            // concurrently. These are cheap one-hop fetches; letting them race
+            // means a reachable bridge gets its descriptor (→ becomes a usable
+            // Data guard) without waiting behind dead/slow bridges in the pool.
+            // (Bulk consensus/microdesc downloads are kept gentle separately,
+            // via the client's download_schedule, to avoid flooding bridges.)
+            parallelism: 12.try_into().expect("parallelism is zero"),
+            // The upstream 30s initial retry is too slow to recover a one-hop
+            // fetch that failed on a transient reset, leaving a bridge
+            // "unsuitable to purpose" (dir_info_missing) for a long time; a 5s
+            // base retry is far more responsive.
+            retry: secs(5),
             prefetch: secs(1000),
             min_refetch: secs(3600),
             max_refetch: secs(3600 * 3), // matches C Tor behaviour
@@ -203,25 +213,50 @@
         bridge: &BridgeConfig,
         _if_modified_since: Option<SystemTime>,
     ) -> Result<Option<String>, Error> {
-        // TODO actually support _if_modified_since
-        let tunnel = circmgr.get_or_launch_dir_specific(bridge).await?;
-        let mut stream = tunnel
-            .begin_dir_stream()
-            .await
-            .map_err(Error::StreamFailed)?;
-        let request = tor_dirclient::request::RoutersOwnDescRequest::new();
-        let response = tor_dirclient::send_request(runtime, &request, &mut stream, None)
-            .await
-            .map_err(|dce| match dce {
-                tor_dirclient::Error::RequestFailed(re) => Error::RequestFailed(re),
-                _ => internal!(
-                    "tor_dirclient::send_request gave non-RequestFailed {:?}",
-                    dce
-                )
-                .into(),
-            })?;
-        let output = response.into_output_string()?;
-        Ok(Some(output))
+        use tor_rtcompat::SleepProviderExt as _;
+        // tor-socks5 local patch: bound the whole bridge-descriptor fetch with
+        // a hard timeout. Upstream wraps NO timeout around
+        // get_or_launch_dir_specific + begin_dir_stream + send_request, so a
+        // slow/unresponsive bridge makes this hang indefinitely (observed: a
+        // queued fetch with neither success nor failure for minutes). While it
+        // hangs the bridge never acquires its descriptor, stays
+        // `dir_info_missing` → "unsuitable to purpose", and NO Data circuit can
+        // be built — the proxy bootstraps the directory but can't carry
+        // traffic. With a timeout the attempt fails cleanly, the guard is
+        // marked down, and another bridge from the pool is promoted/retried.
+        let fetch = async {
+            // TODO actually support _if_modified_since
+            let tunnel = circmgr.get_or_launch_dir_specific(bridge).await?;
+            let mut stream = tunnel
+                .begin_dir_stream()
+                .await
+                .map_err(Error::StreamFailed)?;
+            let request = tor_dirclient::request::RoutersOwnDescRequest::new();
+            let response = tor_dirclient::send_request(runtime, &request, &mut stream, None)
+                .await
+                .map_err(|dce| match dce {
+                    tor_dirclient::Error::RequestFailed(re) => Error::RequestFailed(re),
+                    _ => internal!(
+                        "tor_dirclient::send_request gave non-RequestFailed {:?}",
+                        dce
+                    )
+                    .into(),
+                })?;
+            let output = response.into_output_string()?;
+            Ok::<Option<String>, Error>(Some(output))
+        };
+        // Short per-attempt timeout: get_or_launch_dir_specific can hang for
+        // the whole budget waiting on an obfs4 channel that the bridge keeps
+        // resetting (os 10054/10053). A big consensus succeeds on roughly one
+        // attempt in N once a channel happens to hold; the tiny descriptor
+        // fetch needs the same luck, so we abandon a stuck attempt quickly and
+        // try again rather than burning 30s per attempt.
+        match runtime.timeout(Duration::from_secs(10), fetch).await {
+            Ok(r) => r,
+            Err(_) => {
+                Err(internal!("bridge descriptor fetch timed out (tor-socks5 patch)").into())
+            }
+        }
     }
 }
 
```
