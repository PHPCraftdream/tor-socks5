//! A deliberately bounded parser for the Rust `use`-tree subset used by the
//! SDK runtime facade. It is not a Rust parser: it handles public `use` items,
//! paths, aliases, nested brace groups, `self`, and globs, while rejecting
//! unsupported syntax in those use trees. Comments and string/character
//! literals are lexically skipped so examples in them are not treated as API.
//! The check intentionally resolves only paths directly rooted at the literal
//! `tor_socks5_runtime` crate name. It does not perform Rust name resolution
//! or follow private import aliases/re-export chains; use-tree grammar is ASCII
//! identifiers plus `::`, aliases, nested braces, `self`, and `*` only.

#[derive(Debug, PartialEq, Eq)]
struct Import {
    path: Vec<String>,
    alias: Option<String>,
    glob: bool,
}

const RUNTIME_CRATE: &str = "tor_socks5_runtime";

// This is the explicitly curated API: adding an item requires an intentional
// test update. Module names themselves are discovered from runtime/src/lib.rs.
const ALLOWED_RUNTIME_ITEMS: &[&str] = &[
    "conn_health::spawn_conn_health_logger",
    "conn_health::ConnErrorKind",
    "conn_health::ConnHealthCounters",
    "conn_health::ConnHealthSnapshot",
    "conn_health::ConnStage",
    "conn_health::PendingConnectionGuard",
    "host::bind_child_processes_to_self",
    "host::logging::log_layer",
    "pt::PtBinary",
    "tor_setup::arti_base_dir",
    "tor_setup::arti_keystore_dir",
    "tor_setup::build_tor_settings",
    "tor_setup::build_tor_settings_with_pt",
    "tor_watchdog::classify_and_record",
    "tor_watchdog::spawn_bridge_failover_watchdog",
    "tor_watchdog::spawn_tor_watchdog",
    "tor_watchdog::BridgeRefresh",
    "tor_watchdog::HealOutcome",
    "tor_watchdog::TorHandle",
    "tor_watchdog::TorHealth",
    "tor_watchdog::WatchdogRun",
    "tor_watchdog::WatchdogStatus",
    "bridge_store_writer::close_global",
    "bridge_store_writer::init_global",
    "bridge_store_writer::StoreWriter",
    "arti_observability::observation_layer",
    "arti_observability::GuardObservabilityLayer",
    "arti_observability::GuardObservation",
    "arti_observability::ObservationSink",
    "bridge_manager::fetch_bridges",
    "bridge_manager::start",
    "bridge_manager::start_with_parent_token",
    "bridge_manager::BridgeManagerConfig",
    "bridge_manager::BridgeManagerHandle",
    "bridge_manager::BridgeManagerStatus",
    "bridge_manager::FetchBridgesOutcome",
    "bridge_manager::FetchBridgesParams",
];

/// Check the actual runtime facade block against explicit leaves and the
/// runtime crate's current public module list.
pub(super) fn check_facade(facade: &str, runtime_lib: &str) -> Result<(), String> {
    let module_names = public_module_names(runtime_lib)?;
    let imports = runtime_facade_imports(facade)?;

    for import in imports {
        if import.path.first().map(String::as_str) != Some(RUNTIME_CRATE) {
            continue;
        }
        if import.glob {
            return Err(format!("runtime facade re-exports a glob: {import:?}"));
        }
        if import.path.len() == 1 {
            return Err(format!(
                "runtime facade re-exports the whole crate: {import:?}"
            ));
        }

        let module = &import.path[1];
        if !module_names.iter().any(|name| name == module) {
            return Err(format!("unknown runtime module `{module}` in {import:?}"));
        }
        if import.path.len() == 2 {
            return Err(format!(
                "runtime facade re-exports whole module `{module}`: {import:?}"
            ));
        }

        let item_path = import.path[1..].join("::");
        if !ALLOWED_RUNTIME_ITEMS.contains(&item_path.as_str()) {
            return Err(format!(
                "runtime item is not explicitly allowed: {item_path}"
            ));
        }
    }
    Ok(())
}

fn public_module_names(source: &str) -> Result<Vec<String>, String> {
    let tokens = tokenize(source)?;
    let mut names = Vec::new();
    for window in tokens.windows(3) {
        if window[0] == "pub" && window[1] == "mod" && is_identifier(&window[2]) {
            names.push(window[2].clone());
        }
    }
    if names.is_empty() {
        return Err("runtime crate has no recognized `pub mod name` declarations".into());
    }
    Ok(names)
}

fn runtime_facade_imports(source: &str) -> Result<Vec<Import>, String> {
    let tokens = tokenize(source)?;
    let mut module_opens = Vec::new();
    for index in 0..tokens.len().saturating_sub(3) {
        if tokens[index] == "pub"
            && tokens[index + 1] == "mod"
            && tokens[index + 2] == "runtime"
            && tokens[index + 3] == "{"
        {
            module_opens.push(index + 4);
        }
    }
    if module_opens.len() != 1 {
        return Err(format!(
            "expected one tokenized `pub mod runtime {{` block, found {}",
            module_opens.len()
        ));
    }

    let start = module_opens[0];
    let mut depth = 1usize;
    let mut end = None;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.as_str() {
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth == 0 {
                    end = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.ok_or_else(|| "unterminated runtime facade module".to_string())?;

    let mut imports = Vec::new();
    let mut index = start;
    let mut brace_depth = 0usize;
    while index < end {
        if tokens[index] == "{" {
            brace_depth += 1;
            index += 1;
            continue;
        }
        if tokens[index] == "}" {
            brace_depth = brace_depth.saturating_sub(1);
            index += 1;
            continue;
        }
        if brace_depth == 0 && tokens[index] == "pub" {
            let mut use_index = index + 1;
            let mut unrestricted = true;
            if tokens.get(use_index).map(String::as_str) == Some("(") {
                unrestricted = false;
                let mut visibility_depth = 0usize;
                while use_index < end {
                    match tokens[use_index].as_str() {
                        "(" => visibility_depth += 1,
                        ")" => {
                            visibility_depth -= 1;
                            use_index += 1;
                            if visibility_depth == 0 {
                                break;
                            }
                            continue;
                        }
                        _ => {}
                    }
                    use_index += 1;
                }
            }
            if tokens.get(use_index).map(String::as_str) == Some("use") {
                let mut cursor = use_index + 1;
                let mut found = parse_use_tree(&tokens, &mut cursor, &[])?;
                if tokens.get(cursor).map(String::as_str) != Some(";") {
                    return Err(format!(
                        "expected `;` after public use tree near token {cursor}"
                    ));
                }
                if unrestricted {
                    imports.append(&mut found);
                }
                index = cursor + 1;
                continue;
            }
        }
        index += 1;
    }
    Ok(imports)
}

fn parse_use_tree(
    tokens: &[String],
    cursor: &mut usize,
    prefix: &[String],
) -> Result<Vec<Import>, String> {
    if tokens.get(*cursor).map(String::as_str) == Some("{") {
        return parse_group(tokens, cursor, prefix);
    }

    let mut path = prefix.to_vec();
    if tokens.get(*cursor).map(String::as_str) == Some("::") {
        *cursor += 1; // Leading absolute path marker.
    }

    if tokens.get(*cursor).map(String::as_str) == Some("*") {
        *cursor += 1;
        return Ok(vec![Import {
            path,
            alias: None,
            glob: true,
        }]);
    }

    let first = tokens
        .get(*cursor)
        .ok_or_else(|| "missing path in use tree".to_string())?
        .clone();
    if first == "self" {
        *cursor += 1;
        if tokens.get(*cursor).map(String::as_str) == Some("::") {
            path.push(first);
        } else {
            let alias = parse_alias(tokens, cursor)?;
            return Ok(vec![Import {
                path,
                alias,
                glob: false,
            }]);
        }
    } else if is_identifier(&first) {
        path.push(first);
        *cursor += 1;
    } else {
        return Err(format!("unsupported token `{first}` in use-tree path"));
    }

    loop {
        if tokens.get(*cursor).map(String::as_str) != Some("::") {
            break;
        }
        *cursor += 1;
        if tokens.get(*cursor).map(String::as_str) == Some("{") {
            return parse_group(tokens, cursor, &path);
        }
        if tokens.get(*cursor).map(String::as_str) == Some("*") {
            *cursor += 1;
            return Ok(vec![Import {
                path,
                alias: None,
                glob: true,
            }]);
        }
        let segment = tokens
            .get(*cursor)
            .ok_or_else(|| "missing path segment after `::`".to_string())?
            .clone();
        if !is_identifier(&segment) {
            return Err(format!("unsupported path segment `{segment}` in use tree"));
        }
        path.push(segment);
        *cursor += 1;
    }

    let alias = parse_alias(tokens, cursor)?;
    Ok(vec![Import {
        path,
        alias,
        glob: false,
    }])
}

fn parse_group(
    tokens: &[String],
    cursor: &mut usize,
    prefix: &[String],
) -> Result<Vec<Import>, String> {
    if tokens.get(*cursor).map(String::as_str) != Some("{") {
        return Err("expected `{` for use-tree group".into());
    }
    *cursor += 1;
    let mut imports = Vec::new();
    if tokens.get(*cursor).map(String::as_str) == Some("}") {
        return Err("empty use-tree groups are not supported".into());
    }
    loop {
        imports.extend(parse_use_tree(tokens, cursor, prefix)?);
        match tokens.get(*cursor).map(String::as_str) {
            Some(",") => {
                *cursor += 1;
                if tokens.get(*cursor).map(String::as_str) == Some("}") {
                    *cursor += 1;
                    return Ok(imports);
                }
            }
            Some("}") => {
                *cursor += 1;
                return Ok(imports);
            }
            other => {
                return Err(format!(
                    "expected `,` or `}}` in use-tree group, got {other:?}"
                ))
            }
        }
    }
}

fn parse_alias(tokens: &[String], cursor: &mut usize) -> Result<Option<String>, String> {
    if tokens.get(*cursor).map(String::as_str) != Some("as") {
        return Ok(None);
    }
    *cursor += 1;
    let alias = tokens
        .get(*cursor)
        .ok_or_else(|| "missing alias after `as`".to_string())?
        .clone();
    if !is_identifier(&alias) && alias != "_" {
        return Err(format!("unsupported use-tree alias `{alias}`"));
    }
    *cursor += 1;
    Ok(Some(alias))
}

fn is_identifier(token: &str) -> bool {
    let mut bytes = token.bytes();
    match bytes.next() {
        Some(first) if first == b'_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// Tokenize only what this test needs. Whitespace/comments/literals are
/// discarded; this is intentionally not a complete Rust lexer or parser.
fn tokenize(source: &str) -> Result<Vec<String>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index = skip_block_comment(bytes, index)?;
        } else if let Some(end) = raw_string_end(bytes, index)? {
            index = end;
        } else if bytes[index] == b'"'
            || ((bytes[index] == b'b' || bytes[index] == b'c')
                && bytes.get(index + 1) == Some(&b'"'))
        {
            let quote = if bytes[index] == b'"' {
                index
            } else {
                index + 1
            };
            index = skip_quoted(bytes, quote, b'"')?;
        } else if bytes[index] == b'\'' {
            if let Some(end) = char_literal_end(bytes, index) {
                index = end;
            } else {
                tokens.push("'".into());
                index += 1;
            }
        } else if bytes[index] == b':' && bytes.get(index + 1) == Some(&b':') {
            tokens.push("::".into());
            index += 2;
        } else if bytes[index] == b'_' || bytes[index].is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index] == b'_' || bytes[index].is_ascii_alphanumeric())
            {
                index += 1;
            }
            tokens.push(String::from_utf8(bytes[start..index].to_vec()).expect("ASCII identifier"));
        } else if bytes[index].is_ascii() {
            tokens.push((bytes[index] as char).to_string());
            index += 1;
        } else {
            return Err(format!("unsupported non-ASCII token at byte {index}"));
        }
    }
    Ok(tokens)
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> Result<usize, String> {
    let mut depth = 1usize;
    index += 2;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"/*") {
            depth += 1;
            index += 2;
        } else if bytes[index..].starts_with(b"*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index += 1;
        }
    }
    Err("unterminated block comment".into())
}

fn raw_string_end(bytes: &[u8], index: usize) -> Result<Option<usize>, String> {
    let mut quote = index;
    if bytes.get(quote) == Some(&b'b') && bytes.get(quote + 1) == Some(&b'r') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'r') {
        return Ok(None);
    }
    quote += 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return Ok(None);
    }
    let hashes = quote - index - usize::from(bytes.get(index) == Some(&b'b')) - 1;
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let mut after = cursor + 1;
            let mut count = 0usize;
            while bytes.get(after) == Some(&b'#') && count < hashes {
                after += 1;
                count += 1;
            }
            if count == hashes {
                return Ok(Some(after));
            }
        }
        cursor += 1;
    }
    Err("unterminated raw string literal".into())
}

fn skip_quoted(bytes: &[u8], quote: usize, delimiter: u8) -> Result<usize, String> {
    let mut index = quote + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = (index + 2).min(bytes.len()),
            byte if byte == delimiter => return Ok(index + 1),
            b'\n' => return Err("newline in quoted literal".into()),
            _ => index += 1,
        }
    }
    Err("unterminated quoted literal".into())
}

fn char_literal_end(bytes: &[u8], quote: usize) -> Option<usize> {
    let start = quote + 1;
    if bytes.get(start) == Some(&b'\\') {
        let mut cursor = start + 1;
        while cursor < bytes.len() && bytes[cursor] != b'\'' && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        return (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1);
    }
    let first = *bytes.get(start)?;
    if first < 0x80 {
        return (bytes.get(start + 1) == Some(&b'\'')).then_some(start + 2);
    }
    let width = if first & 0b1110_0000 == 0b1100_0000 {
        2
    } else if first & 0b1111_0000 == 0b1110_0000 {
        3
    } else if first & 0b1111_1000 == 0b1111_0000 {
        4
    } else {
        return None;
    };
    (bytes.get(start + width) == Some(&b'\'')).then_some(start + width + 1)
}

#[cfg(test)]
mod tests {
    use super::check_facade;

    const RUNTIME_LIB: &str = "pub mod conn_health; pub mod bridge_manager;";

    fn facade(body: &str) -> String {
        format!("pub mod runtime {{ {body} }}")
    }

    fn accepts(body: &str) -> Result<(), String> {
        check_facade(&facade(body), RUNTIME_LIB)
    }

    #[test]
    fn accepts_explicit_paths_with_absolute_prefixes_and_aliases() {
        assert!(accepts(
            "pub use ::tor_socks5_runtime::conn_health::ConnHealthCounters as Counters;"
        )
        .is_ok());
        assert!(accepts(
            "pub use tor_socks5_runtime::{conn_health::{ConnHealthCounters, ConnStage as Stage}};"
        )
        .is_ok());
    }

    #[test]
    fn rejects_unaliased_or_aliased_internal_modules() {
        assert!(accepts("pub use ::tor_socks5_runtime::{conn_health};").is_err());
        assert!(accepts("pub use tor_socks5_runtime::conn_health as x;").is_err());
        assert!(accepts("pub use tor_socks5_runtime::bridge_manager::{self};").is_err());
        assert!(accepts("pub use tor_socks5_runtime::{pt::PtBinary, conn_health};").is_err());
    }

    #[test]
    fn rejects_whole_crate_and_globs_at_any_group_depth() {
        assert!(accepts("pub use tor_socks5_runtime as x;").is_err());
        assert!(accepts("pub use tor_socks5_runtime;").is_err());
        assert!(accepts("pub use tor_socks5_runtime::*;").is_err());
        assert!(accepts("pub use tor_socks5_runtime::{conn_health::{*}};").is_err());
    }

    #[test]
    fn parses_self_nested_groups_comments_and_string_literals() {
        let source = r###"
            // pub use tor_socks5_runtime::conn_health;
            /* outer /* nested pub use tor_socks5_runtime::*; */ comment */
            pub mod runtime {
                const EXAMPLE: &str = r#"pub use tor_socks5_runtime::*;"#;
                pub use tor_socks5_runtime::conn_health::{self, ConnHealthCounters as C};
            }
        "###;
        assert!(
            check_facade(source, RUNTIME_LIB).is_err(),
            "`self` must resolve to the whole module"
        );

        assert!(accepts(
            "pub use self::local_api; pub use tor_socks5_runtime::conn_health::ConnStage;"
        )
        .is_ok());
        assert!(accepts("pub use tor_socks5_runtime::conn_health::ConnHealthCounters;").is_ok());
    }

    #[test]
    fn ignores_comment_and_literal_examples_when_no_runtime_export_exists() {
        let source = r###"
            pub mod runtime {
                // pub use ::tor_socks5_runtime::conn_health;
                const EXAMPLE: &str = r#"pub use tor_socks5_runtime::*;"#;
                const CHAR: char = 'x';
            }
        "###;
        assert!(check_facade(source, RUNTIME_LIB).is_ok());
    }

    #[test]
    fn rejects_unterminated_raw_literals_instead_of_ignoring_the_tail() {
        let source = "pub mod runtime { const EXAMPLE: &str = r#\"unterminated";
        assert!(check_facade(source, RUNTIME_LIB).is_err());
    }

    #[test]
    fn fails_closed_for_unsupported_use_tree_syntax() {
        assert!(
            accepts("pub use tor_socks5_runtime::conn_health::{ConnHealthCounters as};").is_err()
        );
        assert!(accepts("pub use tor_socks5_runtime::conn_health::{ConnHealthCounters};").is_ok());
    }
}
