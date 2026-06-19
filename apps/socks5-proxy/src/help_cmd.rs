//! `tor-socks5 help [--all] [topic]` — print the bundled documentation.
//!
//! The repo's Markdown manuals are embedded into the binary at compile
//! time with `include_str!`, so the same docs that live under `docs/` are
//! the single source of truth *and* are always available offline straight
//! from the CLI.

/// `(topic, one-line summary, embedded Markdown)`, in reading order.
const TOPICS: &[(&str, &str, &str)] = &[
    (
        "overview",
        "What tor-socks5 is and how to start",
        include_str!("../../../README.md"),
    ),
    (
        "bridges",
        "Bridges, transports, health, candidate pool, sources",
        include_str!("../../../docs/bridges.md"),
    ),
    (
        "webtunnel",
        "The webtunnel pluggable transport",
        include_str!("../../../docs/webtunnel.md"),
    ),
    (
        "auth",
        "User accounts, passwords, and .onion gating",
        include_str!("../../../docs/auth.md"),
    ),
    (
        "upstream",
        "Egress through an upstream SOCKS5 proxy",
        include_str!("../../../docs/upstream.md"),
    ),
    (
        "logging",
        "Log sinks, levels, non-blocking writer",
        include_str!("../../../docs/logging.md"),
    ),
    (
        "service",
        "Install/start/stop as an OS service",
        include_str!("../../../docs/service.md"),
    ),
    (
        "architecture",
        "Workspace layout and data flow",
        include_str!("../../../docs/architecture.md"),
    ),
];

/// Run the `help` subcommand.
pub(crate) fn run(all: bool, topic: Option<String>) {
    if all {
        for (i, (name, _, body)) in TOPICS.iter().enumerate() {
            if i > 0 {
                println!();
            }
            print_topic(name, body);
        }
        return;
    }
    match topic {
        Some(t) => match TOPICS
            .iter()
            .find(|(name, _, _)| name.eq_ignore_ascii_case(t.trim()))
        {
            Some((name, _, body)) => print_topic(name, body),
            None => {
                eprintln!("unknown help topic {t:?}.\n");
                print_index();
            }
        },
        None => print_index(),
    }
}

fn print_topic(name: &str, body: &str) {
    let rule = "=".repeat(72);
    println!("{rule}\n  {name}\n{rule}\n");
    println!("{}", body.trim_end());
}

fn print_index() {
    println!("tor-socks5 — bundled documentation\n");
    println!("Topics:");
    let width = TOPICS.iter().map(|(n, _, _)| n.len()).max().unwrap_or(0);
    for (name, summary, _) in TOPICS {
        println!("  {name:<width$}  {summary}");
    }
    println!("\nUsage:");
    println!("  tor-socks5 help <topic>   print one topic");
    println!("  tor-socks5 help --all     print every topic, end to end");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_are_nonempty_and_unique() {
        assert!(!TOPICS.is_empty());
        let mut names: Vec<&str> = TOPICS.iter().map(|(n, _, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "topic names must be unique");
        for (name, summary, body) in TOPICS {
            assert!(!name.is_empty());
            assert!(!summary.is_empty());
            assert!(!body.trim().is_empty(), "topic {name} has empty docs");
        }
    }

    #[test]
    fn bridges_topic_covers_the_new_features() {
        let (_, _, body) = TOPICS
            .iter()
            .find(|(n, _, _)| *n == "bridges")
            .expect("bridges topic present");
        for needle in [
            "candidate pool",
            "headers",
            "cookies",
            "stability",
            "webtunnel",
        ] {
            assert!(
                body.to_lowercase().contains(needle),
                "bridges doc should mention {needle:?}"
            );
        }
    }
}
