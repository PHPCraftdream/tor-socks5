//! Регрессия задачи #28: установленный бинарник разрешает конфиг по
//! умолчанию (`tor-socks5.ktav`) из **каталога запуска**, а не из каталога
//! самого бинарника.
//!
//! Проверяется foreground-цепочка реального установленного бинарника через
//! `tor-socks5 config migrate` — сетенезависимую подкоманду, которая
//! разрешает эффективный конфиг по точной производственной приоритетной
//! цепочке (`--config` > `$TOR_SOCKS5_CONFIG` > `tor-socks5.ktav` в CWD,
//! `packages/proxy-config/src/lib.rs`, `load_with_override`/`resolve_path`)
//! и печатает разрешённый путь. Каждый кейс запускает копию бинарника в
//! собственном `Command`-потомке со своим CWD/env — никаких глобальных
//! `set_current_dir`/`set_var` в этом (параллельном) тестовом процессе, без
//! Tor bootstrap и сокетов.
//!
//! Охват ограничен: реальный runtime фонового `--angel` здесь **не**
//! проверяется — интеграционный harness libtest многопоточный, а форк должен
//! случиться до Tokio в однопоточном процессе; отдельный OS-хелпер для
//! detach-проверки возможен, но не входит в эти 5 CLI-кейсов. Сам фикс
//! владельца (`working_directory` = каталог запуска, захваченный до fork, в
//! `apps/socks5-proxy/src/commands/angel.rs`) компилируется в CI и
//! проверен по использованию launch-CWD во внешнем билдере; его runtime
//! покрытие здесь не заявляется. Ниже проверяется та же цепочка
//! `resolve_path`, которую ангел использует уже после fork.
//!
//! Почему каждое утверждение падает при баге, от которого защищаемся:
//! - `default_config_comes_from_cwd_not_bin_dir`: при поиске по каталогу exe
//!   бинарник прочитал бы намеренно битую приманку `tor-socks5.ktav`,
//!   лежащую рядом с реальной копией бинарника, и упал бы; валидный
//!   old-layout конфиг из CWD никогда бы не мигрировался.
//! - `default_config_missing_in_cwd_is_an_error_not_exe_dir_fallback`:
//!   при exe-dir fallback возникла бы ошибка парсинга приманки вместо
//!   ожидаемой ошибки «not found».
//! - `cli_flag_overrides_cwd` / `env_var_overrides_cwd`: при победе CWD
//!   миграция тронула бы конфиг в CWD, и утверждение, что мигрирован именно
//!   override-цель (а файл CWD не тронут), падает.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Конфиг в старом формате (inline-секция `bridges`), как его писала
/// предыдущая версия: валиден для `config migrate`, который переводит его
/// в текущий layout. Скопирован с `packages/proxy-config/src/layout/migrate_tests.rs`
/// (продукционная миграция принимает ровно такую форму).
const OLD_LAYOUT_CONFIG: &str = "\
listen: 127.0.0.1:1080
bridges.lines: [
\tobfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0
]
bridges.min_alive: 12
";

/// Намеренно нечитаемый как Ktav: если какая-либо ветка кода станет искать
/// конфиг рядом с исполняемым файлом, этот файл проявится жёсткой ошибкой
/// миграции (parse failure), а не «not found».
const BROKEN_DECOY_CONFIG: &str = "this is not a ktav file \u{0}\u{1}\n";

/// Жёсткий предел жизни потомка: `config migrate` быстрый и несетевой,
/// зависание дольше этого — ошибка, а не повод вечно ждать в CI.
const CHILD_DEADLINE: Duration = Duration::from_secs(30);
/// Интервал опроса `try_wait` внутри дедлайна.
const CHILD_POLL: Duration = Duration::from_millis(50);

/// Имя файла бинарника в «установленном» каталоге, как его кладёт install-скрипт.
#[cfg(windows)]
fn installed_binary_name() -> &'static str {
    "tor-socks5.exe"
}

#[cfg(not(windows))]
fn installed_binary_name() -> &'static str {
    "tor-socks5"
}

/// Каталог «установки» узла: атомарно созданный (единственный владелец),
/// содержащий **реальную копию** cargo-бинарника (переименованную, как
/// ставит инсталлятор) и битую приманку конфига рядом с ней. Исходный
/// cargo-таргет не трогается: работает только с копией.
struct Case {
    root: PathBuf,
    /// Каталог установки: <root>/bin/tor-socks5(.exe) + битая приманка.
    bin_dir: PathBuf,
    /// Каталог запуска: <root>/node — CWD каждого потомка.
    node_dir: PathBuf,
    /// Путь к запускаемой копии бинарника.
    installed_binary: PathBuf,
}

/// Атомарно создаёт уникальный каталог: только `create_dir` (не
/// `create_dir_all`), при `AlreadyExists` — следующая попытка со свежим
/// счётчиком; чужой существующий каталог никогда не переиспользуется и
/// не удаляется заранее. Прочая ошибка — паника с контекстом.
fn unique_owned_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let candidate = std::env::temp_dir().join(format!(
            "tor-socks5-cwd-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("не удалось создать уникальный каталог {candidate:?}: {e}"),
        }
    }
}

impl Case {
    fn new(tag: &str) -> Self {
        let root = unique_owned_dir(tag);
        let case = Self {
            bin_dir: root.join("bin"),
            node_dir: root.join("node"),
            installed_binary: root.join("bin").join(installed_binary_name()),
            root,
        };
        // Guard уже владеет корнем, в том числе при ошибке подготовки.
        fs::create_dir(&case.bin_dir)
            .unwrap_or_else(|e| panic!("создание bin-каталога в {:?}: {e}", case.root));
        fs::create_dir(&case.node_dir)
            .unwrap_or_else(|e| panic!("создание node-каталога в {:?}: {e}", case.root));

        fs::copy(env!("CARGO_BIN_EXE_socks5-proxy"), &case.installed_binary)
            .unwrap_or_else(|e| panic!("копирование бинарника в {:?}: {e}", case.installed_binary));
        fs::write(case.bin_dir.join("tor-socks5.ktav"), BROKEN_DECOY_CONFIG)
            .unwrap_or_else(|e| panic!("запись приманки в {:?}: {e}", case.bin_dir));
        case
    }

    /// Команда потомка: запускается именно установленная копия, CWD — каталог
    /// узла, `TOR_SOCKS5_CONFIG` убран, чтобы кейс начинался с известного env
    /// независимо от CI-раннера.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.installed_binary);
        cmd.args(args)
            .current_dir(&self.node_dir)
            .env_remove("TOR_SOCKS5_CONFIG");
        cmd
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        // Удаляем только СВОЙ атомарно созданный корень.
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Потомок с дедлайном: если дочерний процесс не завершился за
/// [`CHILD_DEADLINE`], он убивается (только известный потомок) при drop,
/// чтобы паника assert'а не оставила сироту в CI.
struct BoundedChild {
    child: Child,
    started: Instant,
}

impl BoundedChild {
    fn spawn(cmd: &mut Command) -> Self {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("запуск {:?}: {e}", cmd.get_program()));
        Self {
            child,
            started: Instant::now(),
        }
    }

    /// Ждёт выхода в пределах дедлайна (poll `try_wait`, не «гадание» по
    /// фиксированному сну) и возвращает вывод. Просрочка — kill + паника
    /// с собранным к этому моменту выводом.
    fn finish(mut self) -> Output {
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return self.collect(),
                Ok(None) if self.started.elapsed() < CHILD_DEADLINE => sleep(CHILD_POLL),
                _ => {
                    let _ = self.child.kill();
                    let output = self.collect();
                    panic!(
                        "потомок не завершился за {CHILD_DEADLINE:?}; status {:?}\nstdout: {}\nstderr: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    );
                }
            }
        }
    }

    fn collect(mut self) -> Output {
        // Child остаётся в guard: нельзя перемещать поле из типа с Drop.
        let status = self.child.wait().expect("ожидание потомка");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut pipe) = self.child.stdout.take() {
            pipe.read_to_end(&mut stdout).expect("чтение stdout");
        }
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_end(&mut stderr).expect("чтение stderr");
        }
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for BoundedChild {
    fn drop(&mut self) {
        // Завершаем только своего потомка; завершённый Child хранит статус.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Запуск с дедлайном и диагностикой: при провале статуса паникуем с полным
/// captured stdout/stderr.
fn run_bounded(cmd: &mut Command) -> Output {
    BoundedChild::spawn(cmd).finish()
}

fn assert_ok_output(output: &Output) -> String {
    assert!(
        output.status.success(),
        "config migrate завершился ошибкой: status {:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Файл не появился: убеждаемся и по отсутствию файла (надёжнее разбора
/// вывода), и читаем содержимое для диагностических сообщений.
fn assert_absent(path: &Path, what: &str) {
    assert!(!path.exists(), "{what} не должен был появиться: {path:?}");
}

fn read_ok(path: &Path) -> Vec<u8> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .unwrap_or_else(|e| panic!("открытие {path:?}: {e}"))
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("чтение {path:?}: {e}"));
    buf
}

#[test]
fn default_config_comes_from_cwd_not_bin_dir() {
    let case = Case::new("default-cwd");
    fs::write(case.node_dir.join("tor-socks5.ktav"), OLD_LAYOUT_CONFIG).unwrap();

    let stdout = assert_ok_output(&run_bounded(&mut case.command(&["config", "migrate"])));

    // По умолчанию разрешается относительный `tor-socks5.ktav` — привязку к
    // CWD доказывают файлы: бэкап миграции появился в каталоге запуска, а
    // приманка рядом с exe осталась байт-в-байт (см. ниже).
    assert!(
        stdout.contains("tor-socks5.ktav"),
        "разрешён не относительный путь по умолчанию: {stdout}"
    );
    // Побочные эффекты миграции легли в CWD…
    assert!(case.node_dir.join("tor-socks5.ktav.bak-1").exists());
    // …а рядом с установленной копией бинарника ничего не изменилось: читал
    // бы бинарник exe-dir приманку — упал бы на parse, а приманка обязана
    // остаться нетронутой.
    assert_eq!(
        read_ok(&case.bin_dir.join("tor-socks5.ktav")),
        BROKEN_DECOY_CONFIG.as_bytes()
    );
}

#[test]
fn default_config_missing_in_cwd_is_an_error_not_exe_dir_fallback() {
    let case = Case::new("missing-cwd");
    let output = run_bounded(&mut case.command(&["config", "migrate"]));
    assert!(
        !output.status.success(),
        "случился exe-dir fallback: migrate прошёл без конфига в CWD\nstdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Ровно ошибка «not found» дефолтного пути: при exe-dir fallback файл
    // рядом с копией бинарника существует (битая приманка), и ошибка была бы
    // parse-ошибкой, а не этой.
    assert!(
        stderr.contains("tor-socks5.ktav not found"),
        "ожидается ошибка отсутствия дефолтного конфига CWD, получено: {stderr}"
    );
}

#[test]
fn cli_flag_overrides_cwd() {
    let case = Case::new("cli-override");
    let cwd_config = case.node_dir.join("tor-socks5.ktav");
    fs::write(&cwd_config, OLD_LAYOUT_CONFIG).unwrap();
    // Override указывает на файл в каталоге установки (не на приманку) —
    // миграция должна лечь туда, а не в CWD.
    let override_config = case.bin_dir.join("explicit.ktav");
    fs::write(&override_config, OLD_LAYOUT_CONFIG).unwrap();

    let stdout = assert_ok_output(&run_bounded(
        &mut case
            .command(&["config", "migrate", "--config"])
            .arg(&override_config),
    ));
    assert!(
        stdout.contains(&override_config.display().to_string()),
        "разрешён не --config target: {stdout}"
    );
    // Реальные файловые следы: бэкап у override-цели есть, у CWD-файла нет.
    assert!(case.bin_dir.join("explicit.ktav.bak-1").exists());
    assert_absent(
        &case.node_dir.join("tor-socks5.ktav.bak-1"),
        "бэкап CWD-конфига",
    );
}

#[test]
fn env_var_overrides_cwd() {
    let case = Case::new("env-override");
    fs::write(case.node_dir.join("tor-socks5.ktav"), OLD_LAYOUT_CONFIG).unwrap();
    let env_config = case.bin_dir.join("from-env.ktav");
    fs::write(&env_config, OLD_LAYOUT_CONFIG).unwrap();

    let stdout = assert_ok_output(&run_bounded(
        &mut case
            .command(&["config", "migrate"])
            .env("TOR_SOCKS5_CONFIG", &env_config),
    ));
    assert!(
        stdout.contains(&env_config.display().to_string()),
        "разрешён не TOR_SOCKS5_CONFIG target: {stdout}"
    );
    assert!(case.bin_dir.join("from-env.ktav.bak-1").exists());
    assert_absent(
        &case.node_dir.join("tor-socks5.ktav.bak-1"),
        "бэкап CWD-конфига",
    );
}

#[test]
fn cli_flag_beats_env_var() {
    let case = Case::new("flag-beats-env");
    let env_config = case.node_dir.join("from-env.ktav");
    fs::write(&env_config, OLD_LAYOUT_CONFIG).unwrap();
    let flag_config = case.bin_dir.join("from-flag.ktav");
    fs::write(&flag_config, OLD_LAYOUT_CONFIG).unwrap();

    let stdout = assert_ok_output(&run_bounded(
        &mut case
            .command(&["config", "migrate", "--config"])
            .arg(&flag_config)
            .env("TOR_SOCKS5_CONFIG", &env_config),
    ));
    assert!(
        stdout.contains(&flag_config.display().to_string()),
        "--config обязан победить TOR_SOCKS5_CONFIG: {stdout}"
    );
    assert!(case.bin_dir.join("from-flag.ktav.bak-1").exists());
    assert_absent(
        &case.node_dir.join("from-env.ktav.bak-1"),
        "бэкап env-конфига",
    );
}
