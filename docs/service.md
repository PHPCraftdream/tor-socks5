# Running as a service

`tor-socks5` installs and manages itself as an OS service via the
[`service-manager`](https://crates.io/crates/service-manager) crate, which targets **systemd**,
**OpenRC**, **launchd** (macOS), the **Windows SCM**, and BSD **`rc.d`**.

```bash
tor-socks5 service install     # register with the OS supervisor, enable start-on-boot
tor-socks5 service start
tor-socks5 service status      # not installed | running | stopped
tor-socks5 service stop
tor-socks5 service uninstall
```

Add `--user` to operate on a per-user service instead of a system-wide one (systemd `--user`,
launchd `LaunchAgent`), where the platform supports it:

```bash
tor-socks5 service install --user
```

## What `install` does

- Resolves the binary path (`current_exe`) and an **absolute** config path. Because a service
  has an unpredictable working directory, the config path is pinned into the service definition;
  if no `--config` is given, `tor-socks5.ktav` in the current directory is used. A default
  config is created there if none exists, so the service can start.
- Enables start-on-boot and an on-failure restart policy.

So install from the directory holding your config, or pass `--config`:

```bash
tor-socks5 --config /etc/tor-socks5/tor-socks5.ktav service install
```

## Stopping semantics

- **Linux / macOS / BSD:** the supervisor sends `SIGTERM`, which the proxy already treats as a
  clean shutdown (it stops the Tor client and tears down pluggable-transport subprocesses).
- **Windows:** the binary runs under the Service Control Manager dispatcher and shuts down on the
  SCM **Stop** control. The installed image path carries an internal marker argument so the
  binary enters SCM mode automatically; you never pass it by hand.

## Privileges

Installing a system-wide service requires administrator/root privileges (the underlying
`systemctl` / `launchctl` / `sc.exe` calls do). `status` generally does not.

## Logging under a service

A service has no console, so configure a file sink in the config:

```ktav
log.output: file
log.file: /var/log/tor-socks5.log
```

See [logging](logging.md).

## Daemon mode (Unix only)

`--daemon` (short form `-d`) is an alternative to `service install` for running the proxy in the
background **without** a supervisor. It is **Unix-only**: on Windows, `--daemon` errors out —
install a service instead (`tor-socks5 service install`).

```bash
tor-socks5 --daemon
tor-socks5 --daemon --pid-file /run/tor-socks5.pid
```

`--daemon` detaches from the controlling terminal (double-fork + `setsid`), redirects stdin,
stdout, and stderr to `/dev/null`, and `chdir`s to `/`. `--pid-file <PATH>` writes the daemon's
PID to a file, useful for `kill` or an init script. Because stdio is sent to `/dev/null`, set a
file log sink in the config so daemon logs are captured — otherwise the proxy prints a warning on
the original stderr before detaching and the records are lost:

```ktav
log.output: file
log.file: /var/log/tor-socks5.log
```

### `--daemon` vs `service install`

| | `--daemon` | `service install` |
|---|---|---|
| Backgrounds itself | yes | runs foreground under a supervisor |
| Restart on crash | no | yes (supervisor policy) |
| Start on boot | no | yes |
| Windows | not supported | yes (SCM) |

`service install` registers with systemd / launchd / `rc.d` / the Windows SCM, which handles
supervision, automatic restart, and start-on-boot. For most servers, prefer `service install`.
Reach for `--daemon` for quick background runs on a host where you do not want (or cannot) install
a full service unit — e.g. an ad-hoc run from a shell, a container entrypoint without an init
system, or a one-off behind a process supervisor that only needs a PID file.
