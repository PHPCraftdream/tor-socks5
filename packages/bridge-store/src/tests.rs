use super::*;

fn tmp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-bridge-store-test-{}-{}",
        std::process::id(),
        seq
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bridge(line: &str) -> BridgeLine {
    line.parse().expect("test bridge line parses")
}

const OBFS4_A: &str =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";
const OBFS4_A_NEW_PARAMS: &str =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=YYY iat-mode=0";
const OBFS4_B: &str =
    "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0";
const OBFS4_C: &str =
    "obfs4 9.9.9.9:443 1111111111111111111111111111111111111111 cert=YYY iat-mode=0";

const HOUR: Duration = Duration::from_secs(3600);
const MAX_FAILS: u32 = 24;

fn empty() -> BridgeStore {
    BridgeStore {
        path: PathBuf::from("mem.log"),
        entries: BTreeMap::new(),
    }
}

// -- Circuit-layer observation tests -------------------------------------

const HALF_HOUR: Duration = Duration::from_secs(30 * 60);
const MAX_CIRCUIT_FAILS: u32 = 5;

#[path = "tests/carrier_identity.rs"]
mod carrier_identity;

#[path = "tests/circuit.rs"]
mod circuit;
#[path = "tests/persistence.rs"]
mod persistence;
#[path = "tests/probe_health.rs"]
mod probe_health;
#[path = "tests/ranking.rs"]
mod ranking;
#[path = "tests/source_attribution.rs"]
mod source_attribution;
