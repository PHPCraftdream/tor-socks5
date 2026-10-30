// Уровень проверки: производственная граница OwnerRegistry/admission с реальными
// штатными дочерними процессами lyrebird (obfs4), запущенными настоящим менеджером
// tor-ptmgr. Это НЕ полный путь supplied-CLI/конфиг -> обработчик и НЕ сквозной
// тест Tor. WebTunnel покрывается отдельно на уровне дочернего процесса в
// .github/pt_proxy/contract.py.
#[path = "../src/commands/angel.rs"]
mod angel;
#[path = "../src/tor/arti_observability.rs"]
mod arti_observability;
#[path = "../src/bridges/bridge_maintenance.rs"]
mod bridge_maintenance;
#[path = "../src/bridges/bridge_store_writer.rs"]
mod bridge_store_writer;
#[path = "../src/bridges/bridge_verifier.rs"]
mod bridge_verifier;
#[path = "../src/bridges/bridge_warmer.rs"]
mod bridge_warmer;
#[path = "../src/fetch/bridges_cmd.rs"]
mod bridges_cmd;
#[path = "../src/bridges/candidate_pool.rs"]
mod candidate_pool;
#[path = "../src/commands/cli.rs"]
mod cli;
#[path = "../src/config.rs"]
mod config;
#[path = "../src/commands/config_cmd.rs"]
mod config_cmd;
#[path = "../src/tor/conn_health.rs"]
mod conn_health;
#[path = "../src/server/dns_wiring.rs"]
mod dns_wiring;
#[path = "../src/fetch/fetch_merge/fetch_merge.rs"]
mod fetch_merge;
#[path = "../src/commands/help_cmd.rs"]
mod help_cmd;
// Onion helpers: the address/vanity core is not wired into the CLI yet.
#[allow(dead_code)]
#[path = "../src/commands/onion/mod.rs"]
mod onion;
#[path = "../src/fetch/seed.rs"]
mod seed;
#[path = "../src/server/server.rs"]
mod server;
#[path = "../src/commands/service.rs"]
mod service;
#[path = "../src/server/shutdown.rs"]
mod shutdown;
#[path = "../src/server/startup.rs"]
mod startup;
#[cfg(test)]
#[path = "../src/tor/test_seams.rs"]
mod test_seams;
#[path = "../src/tor/tor_setup.rs"]
mod tor_setup;
#[path = "../src/tor/tor_watchdog/tor_watchdog.rs"]
mod tor_watchdog;
#[cfg(test)]
#[path = "../src/tor/ts19_tests.rs"]
mod ts19_tests;
#[path = "../src/server/upstream.rs"]
mod upstream;
#[path = "../src/commands/users_cli/mod.rs"]
mod users_cli;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::var_os("TOR_PT_MANAGED_TRANSPORT_VER").is_some() {
        let state = std::path::PathBuf::from(
            std::env::var_os("TOR_PT_STATE_LOCATION").expect("PT state location"),
        );
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("owner-contract-pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(lyrebird::run()).unwrap();
        return;
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("PT_PROXY_ISOLATED").as_deref() != Ok("yes")
    {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(server::owners::handler_tests::run_pt_owner_contract());
}

#[cfg(not(target_os = "linux"))]
fn main() {}
