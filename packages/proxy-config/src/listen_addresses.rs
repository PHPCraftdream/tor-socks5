use std::collections::HashSet;
use std::net::Ipv6Addr;

/// Expand comma-separated hosts using the entry's final port. Plain entries
/// deliberately retain their legacy spelling and validation behavior.
fn expand_entry(entry: &str) -> Result<Vec<String>, String> {
    if !entry.contains(',') {
        return Ok(vec![entry.to_owned()]);
    }
    let invalid = |reason: &str| format!("invalid listen entry `{entry}`: {reason}");
    let (hosts, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| invalid("missing shared port"))?;
    let port = port.trim();
    if port.is_empty() {
        return Err(invalid("missing shared port"));
    }
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("shared port must be numeric (decimal)"));
    }
    let number = port
        .parse::<u16>()
        .map_err(|_| invalid("shared port must be in 1..=65535"))?;
    if number == 0 {
        return Err(invalid("shared port must be in 1..=65535 (not zero)"));
    }
    let mut expanded = Vec::new();
    for host in hosts.split(',').map(str::trim) {
        if host.is_empty() {
            return Err(invalid("empty host in shorthand"));
        }
        if host.contains(['[', ']']) {
            let literal = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .ok_or_else(|| invalid("IPv6 hosts must be bracketed as [address]"))?;
            literal
                .parse::<Ipv6Addr>()
                .map_err(|_| invalid("invalid bracketed IPv6 host"))?;
        } else if host.contains(':') {
            return Err(invalid(
                "IPv6 hosts must be bracketed; shorthand hosts cannot include ports",
            ));
        } else if host.chars().any(char::is_whitespace) {
            return Err(invalid("host cannot contain whitespace"));
        }
        expanded.push(format!("{host}:{number}"));
    }
    Ok(expanded)
}

fn append_entry<E: serde::de::Error>(
    entry: &str,
    addresses: &mut Vec<String>,
    seen: &mut HashSet<String>,
) -> Result<(), E> {
    for address in expand_entry(entry).map_err(E::custom)? {
        // Membership only: output order comes from the original entries.
        if seen.insert(address.clone()) {
            addresses.push(address);
        }
    }
    Ok(())
}

pub(super) fn listen_addresses<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ListenAddresses;

    impl<'de> serde::de::Visitor<'de> for ListenAddresses {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an address string or a list of address strings")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            expand_entry(value).map_err(E::custom).map(|mut addresses| {
                let mut seen = HashSet::new();
                addresses.retain(|address| seen.insert(address.clone()));
                addresses
            })
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut addresses = Vec::new();
            let mut seen = HashSet::new();
            while let Some(entry) = seq.next_element::<String>()? {
                append_entry::<A::Error>(&entry, &mut addresses, &mut seen)?;
            }
            Ok(addresses)
        }
    }

    deserializer.deserialize_any(ListenAddresses)
}

#[cfg(test)]
#[path = "listen_addresses_tests.rs"]
mod tests;
