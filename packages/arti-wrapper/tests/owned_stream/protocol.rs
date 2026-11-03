use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

use super::Result;

pub(super) struct Authority {
    pub(super) identity: [u8; 20],
}

pub(super) struct Relay {
    pub(super) rsa: [u8; 20],
    pub(super) ed: [u8; 32],
    pub(super) address: Ipv4Addr,
    pub(super) port: u16,
}

pub(super) struct Capabilities {
    pub(super) authorities: Vec<Authority>,
    pub(super) relays: Vec<Relay>,
    pub(super) target_address: Ipv4Addr,
    pub(super) target_port: u16,
    pub(super) nonce: String,
}

pub(super) fn decimal(value: &str) -> Result<u32> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err("decimal-field");
    }
    value.parse().map_err(|_| "decimal-field")
}

fn hexadecimal<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("identity-field");
    }
    let mut result = [0_u8; N];
    for (index, output) in result.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "identity-field")?;
    }
    Ok(result)
}

fn address(value: &str) -> Result<Ipv4Addr> {
    let parsed: Ipv4Addr = value.parse().map_err(|_| "loopback-address")?;
    if !parsed.is_loopback() || parsed.to_string() != value {
        return Err("loopback-address");
    }
    Ok(parsed)
}

fn port(value: &str) -> Result<u16> {
    let parsed = u16::try_from(decimal(value)?).map_err(|_| "port-field")?;
    if parsed == 0 {
        return Err("port-field");
    }
    Ok(parsed)
}

fn fields<'a>(line: &'a str, tag: &str, count: usize) -> Result<Vec<&'a str>> {
    let parts: Vec<_> = line.split(' ').collect();
    if parts.len() != count
        || parts.first().copied() != Some(tag)
        || parts.iter().any(|part| part.is_empty())
    {
        return Err("control-record");
    }
    Ok(parts)
}

pub(super) fn authenticate(
    actual_pid: u32,
    actual_uid: u32,
    expected_pid: u32,
    expected_uid: u32,
) -> Result<()> {
    if expected_pid == 0 || actual_pid != expected_pid || actual_uid != expected_uid {
        return Err("control-credentials");
    }
    Ok(())
}

pub(super) fn parse(input: &[u8], expected_pid: u32, expected_uid: u32) -> Result<Capabilities> {
    if input.len() > 4096
        || !input.ends_with(b"\n")
        || input
            .iter()
            .any(|byte| !byte.is_ascii() || *byte == 0 || *byte == b'\r')
    {
        return Err("control-framing");
    }
    let text = std::str::from_utf8(input).map_err(|_| "control-framing")?;
    let lines: Vec<_> = text.split_terminator('\n').collect();
    if lines.len() != 11
        || lines.iter().any(|line| line.len() + 1 > 512)
        || lines[0] != "TOR_OWNED_STREAM_V2"
        || lines[10] != "END"
    {
        return Err("control-framing");
    }
    let parent = fields(lines[1], "PARENT", 3)?;
    authenticate(
        decimal(parent[1])?,
        decimal(parent[2])?,
        expected_pid,
        expected_uid,
    )?;

    let mut authorities = Vec::with_capacity(3);
    let mut relays = Vec::with_capacity(3);
    let mut names = BTreeSet::new();
    let mut authority_ids = BTreeSet::new();
    let mut relay_ids = BTreeSet::new();
    let mut ed_ids = BTreeSet::new();
    let mut relay_addresses = BTreeSet::new();
    for index in 0..3 {
        let auth = fields(lines[2 + index * 2], "AUTH", 3)?;
        if auth[1].is_empty()
            || auth[1].len() > 19
            || !auth[1].bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !names.insert(auth[1])
        {
            return Err("authority-record");
        }
        let identity = hexadecimal::<20>(auth[2])?;
        if !authority_ids.insert(identity) {
            return Err("authority-record");
        }
        authorities.push(Authority { identity });

        let fallback = fields(lines[3 + index * 2], "FALLBACK", 5)?;
        let rsa = hexadecimal::<20>(fallback[1])?;
        let ed = hexadecimal::<32>(fallback[2])?;
        let address = address(fallback[3])?;
        let port = port(fallback[4])?;
        if !relay_ids.insert(rsa) || !ed_ids.insert(ed) || !relay_addresses.insert(address) {
            return Err("fallback-record");
        }
        relays.push(Relay {
            rsa,
            ed,
            address,
            port,
        });
    }
    if !authority_ids.is_disjoint(&relay_ids) {
        return Err("authority-relay-identity-overlap");
    }
    let target = fields(lines[8], "TARGET", 3)?;
    let target_address = address(target[1])?;
    let target_port = port(target[2])?;
    let nonce = fields(lines[9], "NONCE", 2)?[1];
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("nonce-field");
    }
    Ok(Capabilities {
        authorities,
        relays,
        target_address,
        target_port,
        nonce: nonce.to_owned(),
    })
}

pub(super) async fn initial_input(control: &mut UnixStream) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(512);
    let mut line_start = 0;
    loop {
        let mut byte = [0_u8; 1];
        control
            .read_exact(&mut byte)
            .await
            .map_err(|_| "control-input")?;
        if input.len() == 4096 || !byte[0].is_ascii() || byte[0] == 0 || byte[0] == b'\r' {
            return Err("control-framing");
        }
        input.push(byte[0]);
        if input.len() - line_start > 512 {
            return Err("control-framing");
        }
        if byte[0] == b'\n' {
            if &input[line_start..] == b"END\n" {
                return Ok(input);
            }
            line_start = input.len();
        }
    }
}

pub(super) fn no_pending_input(control: &UnixStream) -> Result<()> {
    let mut byte = [0_u8; 1];
    match control.try_read(&mut byte) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        _ => Err("early-control"),
    }
}

pub(super) async fn terminal_ack<C>(control: &mut C) -> Result<()>
where
    C: super::ProofControl,
{
    let expected = b"TARGET_TERMINATED\n";
    let mut actual = [0_u8; 18];
    control
        .read_exact(&mut actual[..expected.len()])
        .await
        .map_err(|_| "target-terminal-ack")?;
    if &actual[..expected.len()] != expected {
        return Err("target-terminal-ack");
    }
    control.check_pending_input()
}
