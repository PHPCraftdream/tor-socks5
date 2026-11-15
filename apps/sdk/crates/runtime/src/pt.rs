//! Pluggable-transport (PT) binary resolution: the PT entry point for an
//! embedding host.
//!
//! Bridges with an `obfs4`/`webtunnel` transport need a PT executable that
//! arti's `tor-ptmgr` spawns. The `tor-socks5` CLI binary is that executable
//! itself: when arti re-spawns it with the standard `TOR_PT_*` variables
//! (including `TOR_PT_MANAGED_TRANSPORT_VER`), the busybox dispatch at the
//! top of `main()` runs the in-process lyrebird PT loop instead of the
//! proxy. The resolution therefore defaults to the current process
//! executable, with the documented `TOR_PT_BINARY` environment variable as
//! the override (packaging layouts that rename/split the binary, embedding
//! hosts that control the process environment).
//!
//! An embedding host that has no such dispatch (e.g. a cdylib on Android,
//! see `packages/android-ffi`) must NOT let arti spawn itself back. Pass
//! [`PtBinary::Explicit`] through `tor_setup::build_tor_settings_with_pt`,
//! pointing at your own PT-mode-dispatching binary or a standalone PT
//! helper — this repository builds one as `pt-helper` (see
//! `apps/pt-helper`). Neither `TOR_PT_BINARY` nor `current_exe()` is
//! consulted for an explicit policy.
//!
//! Only the *decision* lives here. The path is not stat'ed: existence is
//! validated later by `arti_wrapper::build_config`, which rejects a
//! non-existent PT binary with `TorError::InvalidPt`.

/// How the Tor-client setup picks the executable that carries the
/// pluggable transports (obfs4, webtunnel) when any configured bridge
/// needs one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PtBinary {
    /// Resolve the way the `tor-socks5` CLI binary does (the default of
    /// `tor_setup::build_tor_settings`): the documented `TOR_PT_BINARY`
    /// environment variable wins when set and non-empty; otherwise the
    /// current process executable is used, which must itself dispatch PT
    /// mode (busybox style) when arti spawns it with `TOR_PT_*` variables.
    #[default]
    Environment,
    /// Use this exact executable as the PT dispatcher. Point it at your own
    /// PT-mode-dispatching binary or a standalone PT helper (this repository
    /// builds one as `pt-helper`). Neither `TOR_PT_BINARY` nor
    /// `current_exe()` is consulted.
    Explicit(std::path::PathBuf),
}

/// Pure decision: extract a PT binary path from an optional env var value.
/// `None` for `None` or an empty value; `Some(PathBuf)` otherwise.
pub(crate) fn pt_binary_override_from(
    value: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    match value {
        Some(v) if !v.is_empty() => Some(std::path::PathBuf::from(v)),
        _ => None,
    }
}

/// Resolve the PT binary per the policy. Logging matches the old
/// `tor_setup::resolve_pt_binary` exactly (same two info! lines for the
/// Environment branch). Returns an error only for a failing
/// `current_exe()` on the Environment branch; existence is validated later
/// by `arti_wrapper::build_config` (`TorError::InvalidPt`).
pub(crate) fn resolve_pt_binary(pt: &PtBinary) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context;
    match pt {
        PtBinary::Explicit(path) => Ok(path.clone()),
        PtBinary::Environment => {
            if let Some(path) =
                pt_binary_override_from(std::env::var_os("TOR_PT_BINARY").as_deref())
            {
                tracing::info!(path = %path.display(), "using TOR_PT_BINARY override as PT binary");
                return Ok(path);
            }

            let exe = std::env::current_exe().context("resolving current_exe for PT")?;
            tracing::info!(path = %exe.display(), "using own binary as PT (busybox dispatch)");
            Ok(exe)
        }
    }
}

/// The `Settings::extra_pt_protocols` list for the chosen policy:
/// an explicit binary or an env override is assumed to support exactly the
/// configured preferred transport (today's override behavior); otherwise
/// the CLI default `["obfs4", "webtunnel"]`. `env_override` is passed in
/// (not read from the process) so the decision is testable purely.
pub(crate) fn extra_pt_protocols(
    env_override: Option<&std::ffi::OsStr>,
    pt: &PtBinary,
    cfg: &crate::config::Config,
) -> Vec<String> {
    let assume_single_transport =
        matches!(pt, PtBinary::Explicit(_)) || pt_binary_override_from(env_override).is_some();
    if assume_single_transport {
        cfg.bridges
            .preferred_transport()
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        vec!["obfs4".into(), "webtunnel".into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_pt_binary_override_from_set() {
        let path = std::path::PathBuf::from("/usr/bin/obfs4proxy");
        let result = pt_binary_override_from(Some(path.as_os_str()));
        assert_eq!(result, Some(path));
    }

    #[test]
    fn test_pt_binary_override_from_none() {
        let result = pt_binary_override_from(None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_pt_binary_override_from_empty() {
        let result = pt_binary_override_from(Some(std::ffi::OsStr::new("")));
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_pt_binary_explicit_returns_exact_path() {
        let path = std::path::PathBuf::from("/system/bin/pt-helper");
        assert_eq!(
            resolve_pt_binary(&PtBinary::Explicit(path.clone())).unwrap(),
            path
        );
    }

    fn cfg_with_transport(transport: &str) -> Config {
        Config {
            bridges: proxy_config::BridgesConfig {
                transport: transport.to_owned(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn extra_pt_protocols_environment_without_override_is_cli_default() {
        assert_eq!(
            extra_pt_protocols(
                None,
                &PtBinary::Environment,
                &cfg_with_transport("webtunnel")
            ),
            vec!["obfs4".to_owned(), "webtunnel".to_owned()]
        );
    }

    #[test]
    fn extra_pt_protocols_env_override_assumes_preferred_transport() {
        assert_eq!(
            extra_pt_protocols(
                Some(std::ffi::OsStr::new("/usr/bin/obfs4proxy")),
                &PtBinary::Environment,
                &cfg_with_transport("webtunnel")
            ),
            vec!["webtunnel".to_owned()]
        );
    }

    #[test]
    fn extra_pt_protocols_explicit_assumes_preferred_transport() {
        assert_eq!(
            extra_pt_protocols(
                None,
                &PtBinary::Explicit(std::path::PathBuf::from("pt-helper")),
                &cfg_with_transport("webtunnel")
            ),
            vec!["webtunnel".to_owned()]
        );
    }

    #[test]
    fn extra_pt_protocols_explicit_without_preferred_transport_is_empty() {
        assert_eq!(
            extra_pt_protocols(
                None,
                &PtBinary::Explicit(std::path::PathBuf::from("pt-helper")),
                &Config::default()
            ),
            Vec::<String>::new()
        );
    }
}
