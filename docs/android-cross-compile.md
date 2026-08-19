# Android cross-compilation (NDK + cargo-ndk)

## Status

All 4 ABIs build in release mode on Windows host (branch `android-ffi`).

| ABI | Rust triple | cargo-ndk -t value | Status |
|-----|-------------|-------------------|--------|
| aarch64-linux-android | aarch64-linux-android | arm64-v8a | verified built & ELF-checked |
| armv7-linux-androideabi | armv7-linux-androideabi | armeabi-v7a | verified built & ELF-checked |
| x86_64-linux-android | x86_64-linux-android | x86_64 | verified built & ELF-checked |
| i686-linux-android | i686-linux-android | x86 | verified built & ELF-checked |

ELF check (`file`) for each binary confirms the expected architecture, PIE,
dynamic linking against `/system/bin/linker(64)`, `for Android 21`, and
`built by NDK r27c (12479018)`.

## Toolchain

- NDK r27c (27.2.12479018, latest 27.x LTS)
- cargo-ndk 4.1.2
- Rust 1.97.0
- SDK: D:\system_artefact\android-sdk
- Min API level: 21 (cargo-ndk default)

## Working command

```powershell
$env:ANDROID_NDK_HOME = 'D:\system_artefact\android-sdk\ndk\27.2.12479018'
$env:ANDROID_HOME = 'D:\system_artefact\android-sdk'
cargo ndk -t arm64-v8a build -p socks5-proxy --release
```

The wrapper script `scripts/build-android.ps1` automates building all four ABIs.

## Why no .cargo/config.toml

cargo-ndk injects `CARGO_TARGET_<TRIPLE>_LINKER` plus `CC`/`AR`/`CXX` environment variables pointing at the NDK clang wrappers per invocation. This also covers `cc`-based build scripts (ring, libsqlite3-sys bundled sqlite, zstd-sys). A static config would hardcode machine-specific absolute NDK paths and is unnecessary.

## Pitfall

`cargo ndk -o <dir>` is intended for cdylib crates (jniLibs). With the socks5-proxy *binary* crate the build succeeds but cargo-ndk then fails with "No usable artifacts produced by cargo". Omit `-o` for this crate.

## Risk items verified by real build

These items were the focus of this task, confirmed by compiling all 4 ABIs and ELF-checking each `socks5-proxy` binary (e.g. aarch64: "ELF 64-bit LSB pie executable, ARM aarch64, ... for Android 21, built by NDK r27c"):

- ring 0.17.14 (pregenerated asm + NDK clang) — OK
- libsqlite3-sys/rusqlite bundled sqlite3.c via cc — OK
- zstd-sys via cc — OK
- daemonize 0.5 + service-manager 0.11 compile under cfg(unix) — OK (Android is cfg(unix); runtime behaviour untested)
- vendored crates: tor-dirclient, tor-dirmgr, tor-chanmgr, tor-guardmgr, arti-client, saturating-time — OK
- ptrs-gesher: lyrebird/obfs4/webtunnel 0.5.2 — OK

## Artifacts note

Builds land in the shared `CARGO_TARGET_DIR=D:\dev\rust\.cargo-target\<triple>\release\socks5-proxy` on this machine (global cargo config), not `target\` in the repo.

## Runtime testing

None done — compile/link validation only (per task scope).
