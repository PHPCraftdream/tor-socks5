use std::error::Error;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use tor_socks5::auth::{AuthState, Registry};
use tor_socks5::config::{migrate_config, Config};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config_path = required(&mut args, "CONFIG_PATH")?;
    let users_path = required(&mut args, "USERS_PATH")?;
    if args.next().is_some() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "unexpected argument").into());
    }

    // Migration is idempotent; when needed it backs up this explicitly supplied config.
    let migration = migrate_config(&config_path)?;
    let config = Config::load_with_override(Some(&config_path))?.into_config();
    let registry = Registry::new(users_path);
    let users = registry.load()?;
    let auth = AuthState::build(&users)?;

    println!("migration={migration:?}");
    println!(
        "users={} auth_required={} listeners={}",
        users.users.len(),
        auth.require_auth(),
        config.listen.len()
    );
    Ok(())
}

fn required(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> io::Result<PathBuf> {
    args.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("usage: accounts_config CONFIG_PATH USERS_PATH (missing {name})"),
        )
    })
}
