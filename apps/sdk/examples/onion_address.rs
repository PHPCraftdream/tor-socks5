use std::error::Error;
use std::io::{self, ErrorKind};
use std::time::Duration;

use tor_socks5::onion::address::{generate, parse_onion_address};
use tor_socks5::onion::vanity::{search, SearchOptions, SearchOutcome, VanityTarget};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(mode) if mode == "--vanity" => {
            let prefix = args.next().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "usage: onion_address --vanity PREFIX",
                )
            })?;
            if args.next().is_some() {
                return Err(io::Error::new(ErrorKind::InvalidInput, "unexpected argument").into());
            }

            let target = VanityTarget::new(&prefix)?;
            let options = SearchOptions {
                threads: 1,
                time_limit: Some(Duration::from_secs(2)),
                ..SearchOptions::default()
            };
            match search(&target, &options)? {
                SearchOutcome::Found(keypair) => {
                    println!("{}", keypair.address());
                }
                SearchOutcome::TimedOut { attempts } => {
                    println!("no match within the 2-second search budget ({attempts} attempts)");
                }
                SearchOutcome::Panicked { attempts } => {
                    println!("a search worker panicked ({attempts} attempts)");
                }
                SearchOutcome::Cancelled { attempts } => {
                    println!("search cancelled ({attempts} attempts)");
                }
            }
        }
        Some(address) => {
            if args.next().is_some() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "usage: onion_address [ADDRESS | --vanity PREFIX]",
                )
                .into());
            }
            let public_key = parse_onion_address(&address)?;
            println!(
                "valid v3 onion address ({}-byte public key)",
                public_key.len()
            );
        }
        None => {
            let keypair = generate();
            let address = keypair.address().to_owned();
            let parsed = parse_onion_address(&address)?;
            if parsed != *keypair.pubkey() {
                return Err(io::Error::other("generated address did not round-trip").into());
            }
            println!("{address}");
        }
    }
    Ok(())
}
