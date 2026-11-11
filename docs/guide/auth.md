# Authentication

Both CLI and Android JNI accept SOCKS5 CONNECT and HTTP CONNECT on the same port
(no ordinary HTTP forwarding). Credentials use RFC 1929 username/password for
SOCKS5 or Proxy-Authorization Basic for HTTP CONNECT. The CLI enables
authentication when at least one user exists; Android requires a nonempty registry
when `auth.enabled` is true and permits anonymous access only when explicitly disabled.

`resocks5-net` обрабатывает входящий протокол и ответы аутентификации. Android
использует `socks5_proto::accept` с `PasswordVerifier`; CLI применяет политику
только после допуска подтверждения через `accept_verified`. `Some(verifier)`
требует учётные данные, `None` разрешает только анонимный доступ. Без защиты
транспорта учётные данные передаются открытым текстом; не записывайте их или
целые запросы и ошибки с идентификационными данными в журнал.

## Storage

Accounts live in `tor-socks5.users.ktav`, next to the main config (same directory, same stem,
`.users.ktav` suffix). The CLI derives this path from `--config`; it does not
use `auth.users_file` to select a different registry. The `auth` fields described
in the Android section below do not replace this CLI convention. A missing or
empty CLI registry means anonymous access, so confirm the startup message
`SOCKS5 will require USER/PASS authentication` before testing account routes.
Each record:

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

## CLI pre/post routing

The CLI route is:

```text
client → pre proxy → existing WebTunnel/Tor → post proxy → target
```

`pre_proxies` and `post_proxies` are arrays of proxy endpoints. Each member
independently selects SOCKS5 or plain HTTP CONNECT, globally or per account, and
one pool may mix both:

| Account field | Effective value for that hop |
| --- | --- |
| Omitted | Inherit the corresponding global pool |
| `none` | Explicitly disable that hop, even if globally configured |
| Array | Replace that hop with the account's own pool |

The member grammar is `[socks5://|http://]IP:port[|username:password]`.
No scheme means SOCKS5. Endpoints must be IP literals with a nonzero port;
credentials are optional, paired, nonempty and at most 255 bytes each, with the
existing delimiter restrictions. HTTP Basic usernames cannot contain a colon,
and HTTP credentials cannot contain control characters. HTTPS-to-proxy and
ordinary HTTP forwarding are not supported. Listener account passwords and
outbound proxy credentials are separate identities; neither SOCKS5 nor plain
HTTP CONNECT encrypts its credential-bearing hop.

Every distinct pre endpoint runs its own Tor client, so the whole configuration
(global pool and all enabled accounts together) may name at most 16 distinct pre
endpoints: the main client's plus 15 more. A direct route next to a global pre
pool (`pre_proxies: none` on an account) counts as one of the 15. Startup fails
when the limit is exceeded. See
[Pre/post proxy pools](../../README.md#prepost-proxy-pools).

For example, the main config can select:

```ktav
pre_proxies: [
    socks5://192.0.2.10:1080|pre_user:pre_password
]
post_proxies: [
    http://192.0.2.11:8080|post_user:post_password
    socks5://192.0.2.13:1080
]
```

A bracketed IPv6 member must be written as a literal item (`:: [2001:db8::2]:1080`).

A sibling users registry can then inherit or override the hops independently:

```ktav
users: [
    { name: alice, hash: init, is_enabled: true }
    {
        name: bob
        hash: init
        is_enabled: true
        pre_proxies: [
            http://192.0.2.12:8080|other_user:other_password
        ]
        post_proxies: none
    }
]
```

These TEST-NET addresses and credentials are illustrative, not usable proxy
inputs. `init` is real trust-on-first-use provisioning, not an existing password;
use it only when the first login can be controlled, or create an account with
`users add` and its password prompt. Preserve existing hashes when editing real
accounts. Keep credential-bearing config files private and out of Git and public
logs; prefer editing the protected registry over putting proxy credentials in CLI
arguments or shell history.

The CLI also accepts `users set-proxies <name> <pre|post> <inherit|none|endpoint...>`.
`inherit` removes the account override; `none` disables just the selected hop;
one or more endpoints replace the pool. The endpoint format above also applies to
`users add --pre-proxies` / `--post-proxies`. Apply running CLI configuration
changes by restarting; there is no automatic users-file watcher.

The pre proxy supplies the carrier before the existing bundled WebTunnel TLS/PT
handshake; it does not replace that transport. Post negotiation runs inside a
Tor-opened stream and forwards the target hostname to the post proxy, not a local
resolver. A configured proxy failure never selects a direct route or another
proxy protocol. Explicit `none` is a requested route change, not error fallback.

Different effective pre identities (protocol, address and credentials) select
different retained Tor/PT owners; identical pre identities may share an owner.
Post selection is independent and is applied per admitted connection:
the pool's member is chosen by the target's registrable domain (see
[post pools](../../README.md#prepost-proxy-pools)). Accounts whose effective post
pools hold the same members share one rotation state, so they also share which
member serves a site. TOFU can
publish a new policy snapshot: routes and ACLs come from the admitted credential
proof, never an unverified request username. A failed or incompatible reload
preserves the active route; pre protocol/endpoint/credential changes require a
restart. This CLI support does not enable new Android routing behavior.

Pre routes require explicitly configured usable bridges and support only the
trusted bundled obfs4/WebTunnel PT. Discovery, seed bridges, direct probes, the
warm pool and alternative-owner automatic recovery are restricted; see the
[global pre routing limitations](../../README.md#global-pre_proxies-routing).
Effective post routes cannot be combined with a DNS listener or upstream egress
instead of Tor; startup and request checks fail closed. A global post endpoint
also fails startup with those modes even if every account disables it.

Local Windows acceptance exercised all four pre/post protocol combinations,
wrong-auth and closed-endpoint failures, overlapping inherited SOCKS5/SOCKS5 and
explicit HTTP/HTTP authenticated account routes with two active PT owners, and
normal CLI/PT shutdown without forced termination. The account run provisioned
its two hashes through TOFU. It was not a password-rejection matrix, exhaustive
account-isolation test, or packet capture. Hostname-preserving handshake tests and
route construction support the no-local-target-DNS property; no DNS packet-capture
result is claimed. See the [temporary build bindings](../../README.md#build)
before treating this local candidate as reproducible from registry dependencies.

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

CLI проверяет флаг `allowed_onion` аккаунта (**по умолчанию `false`**)
по допущенному подтверждению учётных данных для обоих входящих протоколов:

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

Подтверждение CLI не содержит пароль или хеш и связано с успешно завершённым
handshake, идентичностью `AuthState` и опубликованным снимком. Шлюз публикации /
допуска чтения удерживается до завершения исходящего dial: уже допущенный dial
может завершиться до публикации, а новое устаревшее или чужое подтверждение
отклоняется. Шлюз освобождается до ответа `Established` и relay, поэтому
публикация может произойти после успешного dial, но до ответа клиенту. Уже
установленные туннели не отзываются. При отмене lease допуска освобождается;
блокирующая проверка или TOFU могут завершиться и сохранить данные после отмены
сокета.

Правки users-файла видны загруженному auth state только после reload или
публикации TOFU. API reload — блокирующий backend; автоматического watcher и
CLI hot reload нет. Перезапуск сервера также применяет изменения конфига и
users-файла.

When CLI authentication is disabled because its registry has no users, only the
global client gate applies. The Android `auth.enabled` switch is described below;
it is not a CLI override for the sibling users registry. With authentication
active, unknown and disabled accounts are rejected. The shared listener policies
apply to SOCKS5 and HTTP CONNECT; this does not extend CLI pre/post routing to JNI.

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

Every writer of the registry — the angel's TOFU write-back above and every mutating
`tor-socks5 users ...` CLI command — holds a **cross-process advisory write lock** (sibling
`<users-file>.lock` file) across its **entire read-modify-write**: from the load that reads the
file to the atomic temp-file+rename publish that writes it. Overlapping writers are therefore
serialised rather than last-write-wins: a CLI `disable` issued while the angel is
mid-provisioning (or vice versa) waits for the running transaction to publish and then edits
the published state, so neither mutation is lost. The atomic rename alone protects the bytes of
one write, not the read-modify-write around it — the lock closes that remaining window.

- The angel takes the lock with an **unbounded wait**: a refused login cannot be retried by
  the client, so its provisioning must not fail just because another writer happened to be
  mid-transaction.
- CLI commands wait at most **60 seconds** and then fail with a clear
  `... .lock is busy: another process holds the write lock` error instead of hanging behind a
  busy angel.
- Expensive work happens **before** the lock is taken (Argon2id hashing in the angel,
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

Android использует `PasswordVerifier` и `socks5_proto::accept`; CLI использует
`socks5_proto::accept_verified` и допуск подтверждения перед выбором маршрута.

The exact Ktav key names for the users-registry file itself (`users:` array schema — see
*Storage* above) are unchanged; only the **Android-side pointer to that file** is new. Aligning
the on-device Kotlin config-writer with `auth.enabled`/`auth.users_file` is tracked as a follow-up
task on the `orbot` side.
