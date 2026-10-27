//! Контроль доступа клиентов для локальных слушателей SOCKS5 и DNS.
//!
//! [`AllowedClients`] — валидированный allow-список IP-адресов клиентов,
//! хранимый одной скалярной строкой: исходный текст оператора сохраняется
//! ([`AllowedClients::as_str`]), компилированные правила применяются
//! через [`AllowedClients::allows`]. Разбор — энергичный (через [`FromStr`]
//! или кастомный serde в конфиге): невалидный список отвергается до старта
//! слушателя, а не при соединении.
//!
//! # Грамматика
//!
//! Токены разделяются `,` и обрезаются; каждый валидируется, включая
//! токены после `*` (`*, invalid` — ошибка, а не неявный allow-all).
//! Дубликаты допустимы (второе идентичное правило).
//!
//! - `*` — разрешить всех.
//! - `loopback` (строго в нижнем регистре) — только `127.0.0.0/8` и `::1`;
//!   прочие локальные классы (приватная LAN, link-local, `::2`) не входят.
//!   `Loopback`/`LOOPBACK` — не ключевые слова, отвергаются как невалидные
//!   IP-литералы.
//! - Точный IPv4/IPv6 литерал через `std::net::IpAddr` — семантическое
//!   равенство: `2001:db8:0:0:0:0:0:1` и `2001:db8::1` — одно правило.
//! - IPv4-wildcard: октеты через `.`, каждый — десятичный `0..=255` или
//!   целый `*`; ровно 4 компонента или terminal-`*` shorthand
//!   (`192.168.*` == `192.168.*.*`). Меньше 4 компонентов без `*` в конце
//!   — ошибка (`127.1`). Ведущие нули запрещены (`01`); смесь цифр и `*`
//!   (`1*2`) запрещена.
//! - IPv6-wildcard: hextet'ы через `:`, каждый — 1–4 hex-цифры или целый
//!   `*`. Без `::` — ровно 8 hextet'ов или terminal-`*` shorthand до 8
//!   (`2001:db8:*` = префикс `2001:db8`, хвост любой). `::` — не более
//!   одной; сжатые hextet'ы разворачиваются в точные нули, никогда в
//!   wildcards: `2001:db8::*` == `2001:db8:0:0:0:0:0:*`. Несколько `::`,
//!   тройное `:`, больше 8 hextet'ов или значение выше `0xffff` — ошибка.
//! - Mapped-wildcards: `::ffff:` + IPv4-маска (`::ffff:192.168.*.*`)
//!   и полная форма `0:0:0:0:0:ffff:192.168.*.*` компилируются в
//!   эквивалентное IPv4-правило. Любая другая IPv6-маска остаётся чисто
//!   IPv6-правилом и никогда не матчит IPv4-пира — нормализуется только
//!   точный префикс из шести верхних hextet'ов `::ffff:`.
//!
//! Имена хостов, CIDR (`/`), порты (`:` в IPv4-токене), zone ID (`%`),
//! диапазоны и частичные `*` в октетах — ошибки разбора.
//!
//! # Нормализация пира
//!
//! [`AllowedClients::allows`] сначала нормализует пира: IPv4-mapped IPv6
//! (`::ffff:a.b.c.d`) превращается в обычный IPv4; IPv4-compatible IPv6
//! (`::a.b.c.d` без `ffff`) не маппится и остаётся IPv6-пиром.
//!
//! Контракт Ktav/serde: значение — одна скалярная строка; явная пустая
//! строка — ошибка (нет орфографии «запретить всем» — удалите слушателя),
//! отсутствующий ключ даёт `*` через `Default`.
#![warn(missing_docs)]

mod matcher;
#[cfg(test)]
mod tests;

mod parser;
mod socks5;
pub use socks5::endpoint_field as socks5_endpoint_field;
pub use socks5::{resolve_endpoint, EndpointOverride, Socks5Endpoint};

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use matcher::Rule;

/// Валидированный allow-список IP-адресов клиентов, разбираемый из одной
/// скалярной строки вроде `"127.*, ::1"`.
///
/// Создаётся только через [`FromStr`] (или [`AllowedClients::default`] для
/// `*`) и десериализацию: каждый экземпляр валиден по построению,
/// [`AllowedClients::allows`] ничего не переразбирает.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedClients {
    /// Исходный текст дословно: сериализация возвращает орфографию оператора.
    source: String,
    /// Компилированные правила; никогда не пусты (разбор отвергает пустой
    /// ввод, `Default` — правило `*`).
    rules: Vec<Rule>,
}

impl Default for AllowedClients {
    fn default() -> Self {
        Self {
            source: "*".to_owned(),
            rules: vec![Rule::Any],
        }
    }
}

impl AllowedClients {
    /// Разрешён ли адрес пира. IPv4-mapped IPv6-пир (`::ffff:a.b.c.d`)
    /// сначала нормализуется в обычный IPv4; прочие IPv6-пиры, включая
    /// IPv4-compatible `::a.b.c.d`, остаются IPv6.
    pub fn allows(&self, ip: IpAddr) -> bool {
        matcher::allows(&self.rules, ip)
    }

    /// Исходный текст, из которого разобран список, например `"127.*, ::1"`;
    /// `"*"` для значения по умолчанию. Сериализация пишет ровно эту строку.
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

impl FromStr for AllowedClients {
    type Err = AllowedClientsError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        let rules = parser::parse(source)?;
        Ok(Self {
            source: source.to_owned(),
            rules,
        })
    }
}

/// Причина отвержения токена списка [`AllowedClients`]: токен и точная
/// причина; `Display` выводит обе, например «invalid `allowed_clients`
/// token `192.168.1*`: …».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedClientsError {
    /// Обрезанный токен, не прошедший валидацию.
    token: String,
    /// Почему токен не является валидным правилом.
    reason: String,
}

impl AllowedClientsError {
    pub(crate) fn new(token: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for AllowedClientsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid `allowed_clients` token `{}`: {}",
            self.token, self.reason
        )
    }
}

impl std::error::Error for AllowedClientsError {}

impl<'de> Deserialize<'de> for AllowedClients {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AllowedClientsVisitor;

        impl<'de> Visitor<'de> for AllowedClientsVisitor {
            type Value = AllowedClients;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a comma-separated client allow-list string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value
                    .parse::<AllowedClients>()
                    .map_err(|err| E::custom(err.to_string()))
            }
        }

        deserializer.deserialize_str(AllowedClientsVisitor)
    }
}

impl Serialize for AllowedClients {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Политика доступа клиентов для одного слушателя: какие IP-адреса
/// источников могут подключаться.
///
/// Ключ Ktav `client_access.allowed_clients` (под `security.` или
/// `dns_server.`), одна скалярная строка в грамматике [`AllowedClients`].
/// По умолчанию `*` (разрешить всё) — старые конфиги без ключа сохраняют
/// поведение. Явно пустая строка — ошибка загрузки, а не «запретить всем».
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientAccessConfig {
    /// Allow-список; грамматика — см. [`AllowedClients`].
    pub allowed_clients: AllowedClients,
}
