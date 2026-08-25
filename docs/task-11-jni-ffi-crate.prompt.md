Работай в D:\dev\rust\tor-socks5, ветка `android-ffi` (уже активна, содержит все P0-патчи: f147014, 623fc6b, 49d9594). Кросс-компиляция под Android подтверждена (304ecb0).

ВАЖНО про git-гигиену: НЕ трогай/не коммить чужие файлы: `docs/upstream-reports.md`, `docs/upstream/`, любые `*.prompt.md` в корне. `git add <конкретные пути>`, никогда `-A`/`.`.

## Готовое API из предыдущих задач (использовать как есть)

```rust
// packages/arti-wrapper
pub enum BootstrapEvent {
    Progress(f32),   // 0.0..=1.0
    Ready,
    Blocked(String),
    Failed(String),
}
pub type BootstrapEventCallback = std::sync::Arc<dyn Fn(BootstrapEvent) + Send + Sync>;
impl TorTunnel {
    pub fn forward_bootstrap_events(&self, on_event: BootstrapEventCallback);
    pub async fn bootstrap_with_notify(settings: Settings, on_event: Option<BootstrapEventCallback>) -> Result<Self>;
}
// Settings::pt_binary — программный override PT-бинарника
```

## Задача

Создай новый workspace-член `packages/android-ffi`:
- `Cargo.toml`: `crate-type = ["cdylib"]`, имя библиотеки `torsocks5` (итоговый файл `libtorsocks5.so`). Зависимости: `jni` (последняя 0.21.x), `arti-wrapper` (path-зависимость на `packages/arti-wrapper`), `tokio`, остальное по необходимости из workspace.dependencies.
- Добавь `"packages/android-ffi"` в `[workspace] members` корневого `Cargo.toml`.

### JNI-функции

Namespace ещё не согласован с Kotlin-стороной (она появится позже) — используй рабочее предположение `org.torproject.android.service.TorSocks5Bridge` (Java-класс с native-методами). Задокументируй это ЯВНО и заметно в rustdoc над каждой extern-функцией и в финальном отчёте — следующая задача (Kotlin TorService) должна либо использовать это имя, либо кто-то поправит JNI-сигнатуры.

1. `nativeStart(env: JNIEnv, _class: JClass, config_path: JString, callback: JObject)`:
   - Прочитать `Config` (переиспользовать `Config::load_with_override` из `apps/socks5-proxy/src/config.rs` — если она сейчас приватна/не переиспользуема из другого крейта, вынеси нужную часть в публичный API — например через `pub` в `arti-wrapper` или отдельный небольшой общий модуль, реши по месту в коде и задокументируй решение).
   - Построить `Settings` для `TorTunnel::bootstrap_with_notify`.
   - Запустить Tokio runtime на отдельном native-потоке с небольшим числом воркеров (например 4 — НЕ копируй захардкоженные 32 из `apps/socks5-proxy/main.rs`, это для мобильных избыточно).
   - Получить `GlobalRef` на `callback` через `env.new_global_ref(callback)`, вызвать `bootstrap_with_notify` с callback-замыканием, которое через `JNIEnv::call_method` (нужен свежий `JNIEnv` на каждый вызов — используй `JavaVM::attach_current_thread` если коллбек летит из другого потока) дёргает метод на Java-объекте, транслируя `BootstrapEvent` в разумный набор аргументов (например строка статуса + float-прогресс, или отдельные методы `onProgress(float)`/`onReady()`/`onBlocked(String)`/`onFailed(String)` — выбери простую и явную схему, задокументируй).
   - После успешного бутстрапа — поднять SOCKS5-listener (переиспользуй логику из `apps/socks5-proxy/src/server.rs`, вынеси в вызываемую функцию, если сейчас завязана на CLI/main).
2. `nativeStop(env: JNIEnv, _class: JClass)` — корректно остановить (снять lock с state-dir, остановить listener, drop TorTunnel и runtime).
3. `nativeGetStatus(env: JNIEnv, _class: JClass) -> jstring` — вернуть текущее состояние строкой (Off/Starting:<percent>/On/Error:<msg> — простой текстовый протокол, задокументируй формат).

Состояние между вызовами — глобальная статика (`once_cell::sync::Lazy<Mutex<Option<EngineState>>>` или `std::sync::OnceLock` + `Mutex`) внутри крейта.

## Сборка

`cargo ndk -t arm64-v8a -o <куда-нибудь-временное> build -p android-ffi --release` — для cdylib флаг `-o` должен сработать (в отличие от бинарника socks5-proxy, где он не работал — см. предыдущий ресёрч). Прогони для всех 4 ABI (arm64-v8a, armeabi-v7a, x86_64, x86). Итоговые `.so` не обязательно коммитить в git (это будет решаться в задаче про packaging в Orbot) — просто подтверди, что сборка проходит на каждом ABI (`file` на итоговый .so для проверки архитектуры/типа).

## Коммит

`feat: Android JNI FFI crate for in-process embedding` — точечный git add (новая директория packages/android-ffi/, правки корневого Cargo.toml/Cargo.lock, любые правки в arti-wrapper/apps/socks5-proxy если понадобились для переиспользования кода).

## Отчёт

Точное имя Java-класса/пакета и всех native-методов с сигнатурами, формат передачи статуса/прогресса в callback, статус сборки по всем 4 ABI, хэш(и) коммита.
