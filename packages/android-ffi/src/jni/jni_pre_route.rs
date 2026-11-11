//! What the Android engine can serve of the configured pre routes.

use auth::UsersConfig;
use bridge_line::BridgeLine;
use proxy_config::{resolve_pool, Config, ProxyPool, Socks5Endpoint};

/// The one global pre proxy the Android engine can serve, if the config has it.
///
/// The engine runs a single Tor client, so a pre route is possible only when
/// every connection uses the same endpoint. Anything else is refused at start,
/// never carried out as a direct connection: a pool of several endpoints (one
/// client per member), pluggable-transport bridges (Android runs the transport
/// as a separate helper that cannot be shown to honour the proxy), no explicit
/// bridge, and `auto_fetch` (which the pre mode does not run).
pub(super) fn global_pre_endpoint(
    config: &Config,
    bridges: &[BridgeLine],
) -> Result<Option<Socks5Endpoint>, String> {
    let Some(pool) = config.pre_proxies.as_ref() else {
        return Ok(None);
    };
    let member = pool.sole_member().ok_or_else(|| {
        "Android runs one Tor client, so global pre_proxies must be a single endpoint".to_owned()
    })?;
    if bridges.is_empty() {
        return Err(
            "global pre_proxies needs at least one explicitly configured bridge".to_owned(),
        );
    }
    if bridges.iter().any(|bridge| bridge.transport.is_some()) {
        return Err("Android cannot route pluggable-transport bridges through a pre proxy; use plain bridges or remove pre_proxies".to_owned());
    }
    if config.bridges.auto_fetch {
        return Err("global pre_proxies requires bridges.auto_fetch to be disabled".to_owned());
    }
    Ok(Some(member.clone()))
}

/// Accounts may only restate the global pre route: another endpoint, or none
/// next to a global one, would need a second Tor client.
pub(super) fn reject_unserved_account_pre_routes(
    global: Option<&ProxyPool>,
    users: &UsersConfig,
) -> Result<(), String> {
    for user in users.users.iter().filter(|user| user.is_enabled) {
        let effective = resolve_pool(global, user.pre_proxies.as_ref());
        if effective.as_ref() != global {
            return Err("an account's pre_proxies differs from the global route; Android runs one Tor client".to_owned());
        }
    }
    Ok(())
}
