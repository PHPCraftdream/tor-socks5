# Logging

Logging is built on [`tracing`](https://crates.io/crates/tracing) and is **non-blocking**:
records are handed to a dedicated writer thread, so a slow or full sink (a file on a busy disk,
a piped terminal) never stalls a request-handling task.

## Configuration

```ktav
## default level for unmatched targets
log.default: info
## output sink: stderr (default) | stdout | file
log.output: stderr
## path used when output: file
log.file:
## colorize; forced off for a file sink
log.ansi: true
log.targets.socks5_proxy: debug
log.targets.arti_wrapper: debug
log.targets.tor_: warn
log.targets.arti_: warn
```

> Ktav comments are `##` at the **start of a line**; a single `#` is content and there are no
> trailing/inline comments (the value runs verbatim to end of line).

- **`default`** is the baseline level. **`targets`** are per-module overrides; they are applied
  in insertion order, producing a stable `tracing-subscriber` env-filter directive
  (e.g. `info,socks5_proxy=debug,tor_=warn`).
- **`output`** selects the sink. `file` writes to **`file`**; if the path is empty or cannot be
  opened, it falls back to stderr (with a message on the original stderr).
- **`ansi`** toggles colour for stdout/stderr; a file sink never gets ANSI escapes.

## RUST_LOG override

The `RUST_LOG` environment variable, when set, **overrides** the config's level/target settings
(it does not change the sink). It uses the standard `tracing-subscriber` `EnvFilter` syntax:

```bash
RUST_LOG=debug tor-socks5
RUST_LOG="socks5_proxy=trace,arti_=warn" tor-socks5
```

## Service / file logging

Under an OS service there is no console to attach to, so point logs at a file:

```ktav
log.output: file
log.file: /var/log/tor-socks5.log
```

The non-blocking writer flushes on clean shutdown (the flush guard is held for the whole run).
