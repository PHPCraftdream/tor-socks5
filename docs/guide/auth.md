# Authentication

Both CLI and Android JNI accept SOCKS5 CONNECT and HTTP CONNECT on the same port
(no ordinary HTTP forwarding). Credentials use RFC 1929 username/password for
SOCKS5 or Proxy-Authorization Basic for HTTP CONNECT. The CLI enables
authentication when at least one user exists; Android requires a nonempty registry
when `auth.enabled` is true and permits anonymous access only when explicitly disabled.

`resocks5-net` owns inbound framing and authentication responses. The shared
`socks5_proto::accept` adapter takes a host-owned `PasswordVerifier` and returns
SDK `IncomingRequest` / `ServerError`, preserving the authenticated username.
`Some(verifier)` requires credentials and disables anonymous access; `None`
enables anonymous access only. Credentials travel in plaintext unless transport
protection is provided; do not log credentials or whole requests/errors containing identity.

## Storage

Accounts live in `tor-socks5.users.ktav`, next to the main config (same directory, same stem,
`.users.ktav` suffix). Each record:

```ktav
users: [
    { name: alice, hash: $argon2id$v=19$m=5120,t=2,p=1$...$..., is_enabled: true, allowed_onion: false }
    { name: bob,   hash: init,                                  is_enabled: true, allowed_onion: true }
]
```

- `hash` — an Argon2id PHC string, or the literal `init` sentinel (see TOFU below).
- `is_enabled` — a disabled account fails authentication **indistinguishably** from a missing
  one (no account-existence leak).
- `allowed_onion` — whether the account may open connections to `.onion` hidden services.
  **Defaults to `false`**; registry files written before this field existed load as `false`
  (see *Onion access* below).
- `allowed_clients` — необязательный per-account allow-список IP-адресов
  клиентов (грамматика та же, что у `security.client_access.allowed_clients`).
  Когда поля нет — аккаунт не имеет дополнительных ограничений сверх
  глобальной политики слушателя; явный `*` НЕ обходит глобальный deny;
  явно пустая строка — ошибка загрузки. Файл `tor-socks5.users.ktav`
  правится вручную — CLI-команды `users` создают аккаунты без этого поля
  и сохраняют его при мутациях password/onion/enable. Новых CLI-флагов нет.

Passwords are hashed with **Argon2id** (per-user random salt). The file is written atomically
(temp file + rename), and concurrent writers serialise on a per-file lock (see *Cross-process
serialisation of the registry* below).

## Managing users

```bash
tor-socks5 users add <name>              # prompt for a password, store its Argon2id hash
tor-socks5 users add --init <name>       # create in trust-on-first-use mode (no password yet)
tor-socks5 users add --allow-onion <name> # add an account permitted to reach .onion
tor-socks5 users set-password <name>     # change the password
tor-socks5 users remove <name>
tor-socks5 users enable <name>
tor-socks5 users disable <name>
tor-socks5 users allow-onion <name>      # grant .onion access to an existing account
tor-socks5 users disallow-onion <name>   # revoke .onion access
tor-socks5 users list
```

All commands accept `--config <path>` to locate the registry. `--allow-onion` also works with
`--init` (`tor-socks5 users add --init --allow-onion <name>`).

## Onion access

The global `security.block_onion` policy is checked before account-level permissions. It defaults
to `true`, so new and legacy configurations refuse `.onion` destinations unless the operator
explicitly sets `security.block_onion: false`. With the global switch off, the per-account
`allowed_onion` rules below apply.

The CLI checks each account's `allowed_onion` flag (**default `false`**) using
the SDK request's **authenticated username**, for either inbound protocol:

- account with `allowed_onion: true` (and enabled) → the onion connection proceeds;
- any other account → SDK `Reply::Forbidden` (SOCKS5 `0x02` / HTTP 403);
  clearnet destinations are unaffected.

With the global switch off and CLI authentication disabled (no users), there is
no account to gate on, so anonymous clients may reach `.onion`. JNI applies only
the global `security.block_onion` policy, not CLI per-account permissions.
Both hosts use shared `is_onion` matching on the parsed host's final DNS label,
case-insensitively and with trailing-dot tolerance.

## Контроль доступа клиентов

Кроме per-account флага `allowed_onion`, действуют две политики
IP-allow-списков:

1. **Глобальный шлюз** — `security.client_access.allowed_clients`
   проверяется по реальному IP пира до handshake, до аутентификации и до
   любого разбора запроса; отклонённому пиру соединение тихо закрывается.
2. **Per-account шлюз** — после успешного логина (RFC 1929 / HTTP Basic)
   необязательное поле `allowed_clients` аккаунта проверяется до любого
   исходящего трафика или трафика Tor; отклонённому аккаунту —
   Forbidden/403.

Запись пользователя с полем (поле опционально: если оно опущено —
дополнительного условия нет; явная пустая строка `allowed_clients::` —
ошибка загрузки ACL, а не «унаследовать» глобальную политику):

```ktav
users: [
    { name: alice, hash: init, is_enabled: true, allowed_onion: false, allowed_clients: 127.0.0.1 }
]
```

В примере `hash: init` включает TOFU: первый разрешённый вход задаёт пароль
учётки. Для уже настроенного пользователя сохраните действующий хеш.

Политики пересекаются (логическое AND), а не объединяются. Глобальный
список и per-user список:

```ktav
security.client_access.allowed_clients: 127.*, ::1
```

при per-user `allowed_clients: 127.0.0.1`: пир 127.8.0.1 проходит
ГЛОБАЛЬНУЮ политику (127/8), но ОТКЛОНЯЕТСЯ per-user (там только
127.0.0.1). Правило: разрешить должны обе политики; user `*` не
расширяет глобальный deny. При выключенной аутентификации действует
только глобальная политика. Политика DNS отдельна, например
`dns_server.client_access.allowed_clients: loopback`.

Применение изменений: обычные правки users-файла через CLI сами по себе
НЕ включают live-reload уже загруженного auth state. Существующий
TOFU-путь (`resolve_init`) при первом входе init-аккаунта авторитетно
перечитывает users registry и переносит ACL и credentials одним
snapshot. Полный live/hot reload политик не предусмотрен: перезапуск
сервера применяет изменения конфига и users-файла.

Когда аутентификация выключена (нет пользователей или
`auth.enabled: false`), действует только глобальный шлюз. Неизвестные и
выключенные аккаунты отклоняются как прежде. Обе политики применяются к
SOCKS5 и HTTP CONNECT на общем слушателе в CLI и Android FFI.

## Trust on first use (`--init`)

An account whose stored `hash` is the literal `init` has **not chosen a password yet**. The
**first non-empty password** presented for that account at login is adopted, hashed with
Argon2id, and **written back to disk** as the real hash — and the login is accepted only once
that write-back is **confirmed** (fsync + atomic rename). If persisting fails, the login is
refused, nothing is cached, and the account remains in `init`, so a later client (possibly with
a different password) can still claim it. The first connection to arrive wins; a concurrent
connection offering a different password is then checked against the freshly set hash (and
rejected if it differs).

### Cross-process serialisation of the registry

Every writer of the registry — the daemon's TOFU write-back above and every mutating
`tor-socks5 users ...` CLI command — holds a **cross-process advisory write lock** (sibling
`<users-file>.lock` file) across its **entire read-modify-write**: from the load that reads the
file to the atomic temp-file+rename publish that writes it. Overlapping writers are therefore
serialised rather than last-write-wins: a CLI `disable` issued while the daemon is
mid-provisioning (or vice versa) waits for the running transaction to publish and then edits
the published state, so neither mutation is lost. The atomic rename alone protects the bytes of
one write, not the read-modify-write around it — the lock closes that remaining window.

- The daemon takes the lock with an **unbounded wait**: a refused login cannot be retried by
  the client, so its provisioning must not fail just because another writer happened to be
  mid-transaction.
- CLI commands wait at most **60 seconds** and then fail with a clear
  `... .lock is busy: another process holds the write lock` error instead of hanging behind a
  busy daemon.
- Expensive work happens **before** the lock is taken (Argon2id hashing in the daemon,
  password prompts and hashing in the CLI), so the critical section stays short.
- The lock file is never deleted; the kernel releases it if a holding process dies, so a
  crashed writer cannot leave the registry permanently locked.

This lets an operator provision accounts without handling plaintext passwords — hand out the
username, and the user's client sets the password on first connect.

Empty passwords never claim an `init` account.

## Verification performance

A successful `(name, password)` is remembered in a process-local **HMAC-SHA256 cache** keyed by
username, so repeated logins skip the expensive Argon2id verify. Failures are never cached, so a
brute-force attempt gains no speed-up. The Argon2id verify runs on a blocking thread pool, so it
never stalls the async runtime under a connection flood. The cache key is drawn from the OS RNG
once per process and is never persisted.

Both hosts supply one absolute 30-second handshake deadline covering SDK detection,
framing, and waiting for verification; progress never renews it. The adapter admits
at most 256 queued/running blocking verifications process-wide, matching the host
connection cap and rejecting the newest attempt immediately when full. The owned
admission slot remains in the blocking closure across cancellation or timeout until
it exits. A deadline stops waiting,
not verification or TOFU persistence. Discard the socket and any buffered wrapper
on error, timeout, or cancellation; partial framing cannot be resumed.

Authentication acceptance is not tunnel success. Hosts apply policy and establish
real egress before sending SDK `Reply::Established`, then forward SDK pipeline
bytes exactly once before unread client bytes.

## Android (`packages/android-ffi`)

The Android JNI FFI crate (`libtorsocks5.so`) shares this exact authenticator with the CLI — same
`AuthState`, same Argon2id/HMAC-cache/TOFU semantics described above — but resolves its
configuration differently, since `nativeStart(configPath, callback)` is handed a config path by
the Kotlin side rather than discovering one via `--config`/`$TOR_SOCKS5_CONFIG`.

`proxy-config::Config` (the schema shared by the CLI and the FFI crate) carries an explicit,
serialisable `auth` section for this purpose:

```ktav
auth.enabled: true
auth.users_file: ""
```

- `auth.enabled` (default `true`) — master switch. Set to `false` to force anonymous NO_AUTH even
  if a users registry is present, without deleting it.
- `auth.users_file` (default `""`, meaning "not set") — optional explicit path to the
  `.users.ktav` registry. Empty falls back to the standard CLI convention:
  `auth::UsersConfig::resolve_path(configPath)` — same directory and filename stem as
  `configPath`, `.users.ktav` suffix (e.g. `configPath = ".../tor-socks5.ktav"` resolves to
  `.../tor-socks5.users.ktav`).

At `nativeStart`, the engine:

1. Loads `Config` from `configPath` as usual.
2. If `auth.enabled` is `false`, skips straight to anonymous NO_AUTH and logs that decision.
3. Otherwise resolves the registry path (`auth.users_file` if set, else the sibling-file
   convention above) and loads it with `auth::UsersConfig::load` — a missing file is **not** an
   error, it just means "no users configured".
4. If the registry is empty or missing, startup fails with a
   `java.lang.RuntimeException` before the engine thread is spawned, rather than
   exposing an anonymous loopback proxy. Anonymous access is permitted only with
   `auth.enabled: false`.
5. Otherwise builds `auth::AuthState::build_persistent(&users, users_path)` (so a TOFU `init`
   account provisioned from an Android client gets its real hash written back to the same file)
   and requires RFC 1929 or HTTP Basic credentials for every accepted connection.

The host implements `PasswordVerifier` over this state and passes it to
`socks5_proto::accept` per connection with the absolute deadline. CLI and JNI
share SDK framing and the same adapter verification path; only host configuration
and destination policy differ.

The exact Ktav key names for the users-registry file itself (`users:` array schema — see
*Storage* above) are unchanged; only the **Android-side pointer to that file** is new. Aligning
the on-device Kotlin config-writer with `auth.enabled`/`auth.users_file` is tracked as a follow-up
task on the `orbot` side.
