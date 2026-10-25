//! Компилированные правила allow-списка и сопоставление пиров.
//!
//! Правила из [`crate::parser`] — ограниченное представление без аллокаций:
//! сопоставление — линейный проход по нескольким правилам с целочисленными
//! масками. Никакого парсинга внутри [`allows`].

use std::net::IpAddr;

/// Одно компилированное правило allow-списка. Список никогда не пуст:
/// парсер отвергает пустой ввод, `Default` — [`Rule::Any`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Rule {
    /// `*`: разрешён каждый пир.
    Any,
    /// `loopback`: только `127.0.0.0/8` и `::1`.
    Loopback,
    /// Точный адрес IPv4 или маска-wildcard.
    V4 {
        /// Биты сети (wildcard-биты здесь нулевые).
        network: u32,
        /// Единицы там, где правило фиксирует октет.
        mask: u32,
    },
    /// Точный адрес IPv6 или маска-wildcard.
    V6 {
        /// Биты сети (wildcard-биты здесь нулевые).
        network: u128,
        /// Единицы там, где правило фиксирует hextet.
        mask: u128,
    },
}

/// Нормализация адреса пира перед сопоставлением: IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`) становится обычным IPv4; IPv4-compatible IPv6
/// (`::a.b.c.d`) и остальное остаются как записано.
fn normalize_peer(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Совпадает ли адрес пира хотя бы с одним правилом списка.
pub(crate) fn allows(rules: &[Rule], ip: IpAddr) -> bool {
    let peer = normalize_peer(ip);
    rules.iter().any(|rule| matches(rule, peer))
}

fn matches(rule: &Rule, peer: IpAddr) -> bool {
    match (rule, peer) {
        (Rule::Any, _) => true,
        (Rule::Loopback, IpAddr::V4(v4)) => v4.is_loopback(),
        (Rule::Loopback, IpAddr::V6(v6)) => v6.is_loopback(),
        (Rule::V4 { network, mask }, IpAddr::V4(v4)) => {
            let bits = u32::from(v4);
            bits & mask == *network & mask
        }
        (Rule::V4 { .. }, IpAddr::V6(_)) => false,
        (Rule::V6 { network, mask }, IpAddr::V6(v6)) => {
            let bits = u128::from(v6);
            bits & mask == *network & mask
        }
        (Rule::V6 { .. }, IpAddr::V4(_)) => false,
    }
}

/// Скомпилировать маску IPv4-wildcard (октеты уже разбиты, `None` = `*`)
/// в [`Rule::V4`].
pub(crate) fn rule_from_v4_slots(slots: [Option<u8>; 4]) -> Rule {
    let mut network = 0u32;
    let mut mask = 0u32;
    for (i, slot) in slots.iter().enumerate() {
        let shift = 24 - 8 * i;
        // None (wildcard) — ничего не делаем
        if let Some(octet) = slot {
            network |= u32::from(*octet) << shift;
            mask |= 0xffu32 << shift;
        }
    }
    Rule::V4 { network, mask }
}

/// Скомпилировать маску IPv6-wildcard (hextet'ы уже разбиты, `None` = `*`)
/// в [`Rule::V6`].
pub(crate) fn rule_from_v6_slots(slots: [Option<u16>; 8]) -> Rule {
    let mut network = 0u128;
    let mut mask = 0u128;
    for (i, slot) in slots.iter().enumerate() {
        let shift = 112 - 16 * i;
        if let Some(hextet) = slot {
            network |= u128::from(*hextet) << shift;
            mask |= 0xffffu128 << shift;
        }
    }
    Rule::V6 { network, mask }
}

/// `Some(октеты)`, если слоты — точный IPv4-mapped префикс `::ffff:`
/// (шесть фиксированных hextet'ов, без wildcards). Два младших hextet'а
/// разворачиваются в пары октетов IPv4: `Some(v)` — пара
/// `(v >> 8) as u8, v as u8`, `None` — два wildcard-октета.
pub(crate) fn split_mapped_v4(slots: &[Option<u16>; 8]) -> Option<[Option<u8>; 4]> {
    let fixed_prefix = [Some(0u16), Some(0), Some(0), Some(0), Some(0), Some(0xffff)];
    if slots[..6] != fixed_prefix {
        return None;
    }
    let to_octets = |h: Option<u16>| -> Option<[Option<u8>; 2]> {
        match h {
            None => Some([None, None]),
            Some(v) => Some([Some((v >> 8) as u8), Some(v as u8)]),
        }
    };
    let hi = to_octets(slots[6])?;
    let lo = to_octets(slots[7])?;
    Some([hi[0], hi[1], lo[0], lo[1]])
}
