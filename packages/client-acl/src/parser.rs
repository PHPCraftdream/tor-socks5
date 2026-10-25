//! Разбор скалярной грамматики `allowed_clients` в компилированные правила.
//!
//! Грамматика (полный контракт в доках крейта): токены через запятую,
//! каждый обрезается и валидируется — включая токены после `*`.

use std::net::IpAddr;
use std::str::FromStr;

use crate::matcher::{rule_from_v4_slots, rule_from_v6_slots, split_mapped_v4, Rule};
use crate::AllowedClientsError;

/// Разобрать целиком значение `allowed_clients`: каждый токен через запятую
/// валидируется; пустой список или пустой токен — ошибка.
pub(crate) fn parse(source: &str) -> Result<Vec<Rule>, AllowedClientsError> {
    let tokens: Vec<&str> = source.split(',').map(str::trim).collect();
    if tokens.len() == 1 && tokens[0].is_empty() {
        return Err(AllowedClientsError::new(
            source.trim(),
            "the list is empty; use `*` to allow every client",
        ));
    }
    tokens.iter().map(|token| parse_token(token)).collect()
}

fn parse_token(token: &str) -> Result<Rule, AllowedClientsError> {
    match token {
        "" => Err(AllowedClientsError::new(
            token,
            "empty token between commas",
        )),
        "*" => Ok(Rule::Any),
        "loopback" => Ok(Rule::Loopback),
        _ => {
            // Точный IP-литерал: семантическое равенство; точный mapped-адрес
            // (`::ffff:127.0.0.1`) компилируется в эквивалентное IPv4-правило,
            // чтобы совпадать с нормализованным пиром.
            if let Ok(ip) = IpAddr::from_str(token) {
                return Ok(match ip {
                    IpAddr::V4(v4) => Rule::V4 {
                        network: u32::from(v4),
                        mask: u32::MAX,
                    },
                    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                        Some(v4) => Rule::V4 {
                            network: u32::from(v4),
                            mask: u32::MAX,
                        },
                        None => Rule::V6 {
                            network: u128::from(v6),
                            mask: u128::MAX,
                        },
                    },
                });
            }
            if token.contains(':') {
                parse_ipv6_wildcard(token)
            } else if token.contains('.') {
                parse_ipv4_wildcard(token)
            } else {
                Err(AllowedClientsError::new(
                    token,
                    "not `*`, `loopback`, an IP literal or a wildcard mask",
                ))
            }
        }
    }
}

/// Один десятичный октет IPv4: `0..=255`, без ведущих нулей (сам `0` допустим),
/// без знаков, без hex.
fn parse_v4_octet(component: &str) -> Option<u8> {
    if component.is_empty() || component.len() > 3 {
        return None;
    }
    if component.len() > 1 && component.starts_with('0') {
        return None;
    }
    if !component.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    component.parse::<u8>().ok()
}

/// Токен-маска IPv4 (`a.b.c.d`, каждый октет — десятичный или целый `*`),
/// с terminal-`*` shorthand (`192.168.*` == `192.168.*.*`).
fn parse_ipv4_wildcard(token: &str) -> Result<Rule, AllowedClientsError> {
    let bad = |reason: &str| AllowedClientsError::new(token, reason);
    let components: Vec<&str> = token.split('.').collect();
    if components.len() > 4 {
        return Err(bad("more than 4 IPv4 components"));
    }
    if components.len() < 4 && components[components.len() - 1] != "*" {
        return Err(bad(
            "shorthand with fewer than 4 components must end in `*`",
        ));
    }
    let mut slots: [Option<u8>; 4] = [None; 4];
    for (i, component) in components.iter().enumerate() {
        if *component == "*" {
            continue;
        }
        let octet = parse_v4_octet(component).ok_or_else(|| {
            bad("not a decimal octet 0-255 or a whole `*` (leading zeros forbidden)")
        })?;
        slots[i] = Some(octet);
    }
    Ok(rule_from_v4_slots(slots))
}

/// Один hextet IPv6: 1-4 чисто hex-цифры (`Some(value)`) или целый `*`
/// (`None`, маркер wildcard). Знаки, разделители `_` и встроенный `*` (`1*2`)
/// отвергаются.
fn parse_v6_hextet(group: &str) -> Option<Option<u16>> {
    if group == "*" {
        return Some(None);
    }
    if group.is_empty() || group.len() > 4 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(group, 16).ok().map(Some)
}

/// Токен-маска IPv6: ровно 8 hextet'ов, terminal-`*` shorthand или одна
/// компрессия `::` (сжатые hextet'ы разворачиваются в точные нули, никогда
/// в wildcards). Точечный IPv4-хвост разрешён только в точном mapped-префиксе
/// `::ffff:` и отдаётся ipv4-парсеру; точный префикс `::ffff:` компилируется
/// в IPv4-правило.
fn parse_ipv6_wildcard(token: &str) -> Result<Rule, AllowedClientsError> {
    let bad = |reason: &str| AllowedClientsError::new(token, reason);

    if token.contains(":::") {
        return Err(bad("triple `:` is not a valid compression"));
    }

    // Проверяем формат head через std, хвост отдаём ipv4-парсеру как есть:
    // так сохраняются все 8-битовые маски и shorthand без потери октетов.
    if let Some(colon) = token.rfind(':') {
        let tail = &token[colon + 1..];
        if tail.contains('.') {
            // prefix: head + "0:0" (head уже с завершающим ':', новых двоеточий не добавляем)
            let prefix = format!("{}0:0", &token[..=colon]);
            let v6: std::net::Ipv6Addr = prefix
                .parse()
                .map_err(|_| bad("не является валидным IPv6-префиксом перед IPv4-хвостом"))?;
            let s = v6.segments();
            // Разрешён ТОЛЬКО точный mapped-префикс ::ffff: с нулевыми младшими hextet'ами.
            if s[0..6] != [0, 0, 0, 0, 0, 0xffff] || s[6] != 0 || s[7] != 0 {
                return Err(bad(
                    "точечный IPv4-хвост разрешён только в точном mapped-префиксе ::ffff:",
                ));
            }
            return parse_ipv4_wildcard(tail);
        }
    }

    let mut slots: [Option<u16>; 8] = [None; 8];

    match token.split_once("::") {
        None => {
            let groups: Vec<&str> = token.split(':').collect();
            if groups.len() > 8 {
                return Err(bad("more than 8 hextets"));
            }
            if groups.len() < 8 && groups[groups.len() - 1] != "*" {
                return Err(bad("shorthand with fewer than 8 hextets must end in `*`"));
            }
            for (i, group) in groups.iter().enumerate() {
                slots[i] = parse_v6_hextet(group)
                    .ok_or_else(|| bad("not a hex hextet 0-ffff or a whole `*`"))?;
            }
            // Terminal-`*` shorthand: незаполненные хвостовые слоты
            // остаются None (wildcards).
        }
        Some((left, right)) => {
            let left_groups: Vec<&str> = if left.is_empty() {
                Vec::new()
            } else {
                left.split(':').collect()
            };
            let right_groups: Vec<&str> = if right.is_empty() {
                Vec::new()
            } else {
                right.split(':').collect()
            };
            let _zeros = 8usize
                .checked_sub(left_groups.len() + right_groups.len())
                .filter(|z| *z >= 1)
                .ok_or_else(|| bad("`::` must compress at least one hextet (8 hextets max)"))?;
            let mut pos = 0usize;
            for group in left_groups.iter().chain(right_groups.iter()) {
                slots[pos] = parse_v6_hextet(group)
                    .ok_or_else(|| bad("not a hex hextet 0-ffff or a whole `*`"))?;
                pos += 1;
            }
            // Сжатые hextet'ы — точные нули: wildcard никогда не прячется
            // внутри `::`. Фиксированные hextet'ы разложены подряд, поэтому
            // правые сдвигаются в хвост, а середина заполняется нулями.
            let right_len = right_groups.len();
            let fixed_end = pos - right_len;
            slots.copy_within(fixed_end..pos, 8 - right_len);
            for slot in slots[fixed_end..8 - right_len].iter_mut() {
                *slot = Some(0);
            }
        }
    }

    // Точный mapped-префикс `::ffff:` (шесть фиксированных hextet'ов:
    // нули и 0xffff, без wildcards сверху) нормализуется в эквивалентное
    // IPv4-правило. Любая другая wildcard-маска остаётся чисто IPv6-маской
    // и просто никогда не матчит IPv4-пира.
    if let Some(v4_slots) = split_mapped_v4(&slots) {
        return Ok(rule_from_v4_slots(v4_slots));
    }
    Ok(rule_from_v6_slots(slots))
}
