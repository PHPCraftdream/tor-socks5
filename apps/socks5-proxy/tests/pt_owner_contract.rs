// Уровень проверки: производственная граница OwnerRegistry/admission с реальными
// штатными дочерними процессами lyrebird (obfs4), запущенными настоящим менеджером
// tor-ptmgr. Это НЕ полный путь supplied-CLI/конфиг -> обработчик и НЕ сквозной
// тест Tor. WebTunnel покрывается отдельно на уровне дочернего процесса в
// .github/pt_proxy/contract.py.
// При harness=false у скопированных бинарных entrypoint-ов и тестовых элементов нет потребителей.
// Подавляем dead_code/unused_imports только для этих Linux-копий; production и другие тесты
// сохраняют обычную проверку lint-ами.
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/commands/angel.rs"]
mod angel;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/tor/arti_observability.rs"]
mod arti_observability;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/bridges/bridge_maintenance.rs"]
mod bridge_maintenance;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/bridges/bridge_store_writer.rs"]
mod bridge_store_writer;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/bridges/bridge_verifier.rs"]
mod bridge_verifier;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/bridges/bridge_warmer.rs"]
mod bridge_warmer;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/fetch/bridges_cmd.rs"]
mod bridges_cmd;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/bridges/candidate_pool.rs"]
mod candidate_pool;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/commands/cli.rs"]
mod cli;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/config.rs"]
mod config;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/commands/config_cmd.rs"]
mod config_cmd;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/tor/conn_health.rs"]
mod conn_health;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/server/dns_wiring.rs"]
mod dns_wiring;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/fetch/fetch_merge/fetch_merge.rs"]
mod fetch_merge;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/commands/help_cmd.rs"]
mod help_cmd;
// Onion helpers: the address/vanity core is not wired into the CLI yet.
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/commands/onion/mod.rs"]
mod onion;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/fetch/seed.rs"]
mod seed;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/server/server.rs"]
mod server;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/commands/service.rs"]
mod service;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/server/shutdown.rs"]
mod shutdown;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/server/startup.rs"]
mod startup;
#[cfg(all(target_os = "linux", test))]
#[allow(dead_code, unused_imports)]
#[path = "../src/tor/test_seams.rs"]
mod test_seams;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/tor/tor_setup.rs"]
mod tor_setup;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/tor/tor_watchdog/tor_watchdog.rs"]
mod tor_watchdog;
#[cfg(all(target_os = "linux", test))]
#[allow(dead_code, unused_imports)]
#[path = "../src/tor/ts19_tests.rs"]
mod ts19_tests;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/server/upstream.rs"]
mod upstream;
#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
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
    rt.block_on(server::owners::handler_tests::carrier_oracle::run_reuse_and_rejection_controls());
    rt.block_on(server::owners::handler_tests::run_pt_owner_contract());
    rt.block_on(server::owners::handler_tests::run_supplied_config_positive());
    rt.block_on(server::owners::handler_tests::run_supplied_config_negative());
    rt.block_on(server::owners::handler_tests::run_supplied_config_seeds_rejected());
}

#[cfg(not(target_os = "linux"))]
fn main() {}
