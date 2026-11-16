use std::error::Error;
use std::ffi::OsString;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use tor_socks5::onion::keys::{
    create_service, export_identity, import_identity, list_services, remove_service, show_service,
    NewIdentity,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config_path = PathBuf::from(required_os(&mut args, "CONFIG_PATH")?);
    let keystore_dir = PathBuf::from(required_os(&mut args, "KEYSTORE_DIR")?);
    let command = required_text(&mut args, "COMMAND")?;

    match command.as_str() {
        "create" => {
            let nickname = required_text(&mut args, "NICKNAME")?;
            let force = optional_force(&mut args)?;
            let recorded = create_service(
                &config_path,
                &keystore_dir,
                &nickname,
                None,
                force,
                NewIdentity::Random,
            )?;
            println!("created {nickname}: {}", recorded.address);
        }
        "list" => {
            ensure_finished(args)?;
            for service in list_services(&config_path)? {
                println!(
                    "{} enabled={} address={}",
                    service.nickname,
                    service.enabled,
                    service.address.as_deref().unwrap_or("<not generated>")
                );
            }
        }
        "show" => {
            let nickname = required_text(&mut args, "NICKNAME")?;
            ensure_finished(args)?;
            let service = show_service(&config_path, &nickname)?;
            println!(
                "{} enabled={} address={}",
                service.nickname,
                service.enabled,
                service.address.as_deref().unwrap_or("<not generated>")
            );
        }
        "export" => {
            let nickname = required_text(&mut args, "NICKNAME")?;
            let output = PathBuf::from(required_os(&mut args, "OUTPUT_KEY_FILE")?);
            let force = optional_force(&mut args)?;
            export_identity(&config_path, &nickname, &output, force)?;
            println!("exported {nickname} identity to {}", output.display());
        }
        "import" => {
            let nickname = required_text(&mut args, "NICKNAME")?;
            let input = PathBuf::from(required_os(&mut args, "INPUT_KEY_FILE")?);
            let force = optional_force(&mut args)?;
            let recorded =
                import_identity(&config_path, &keystore_dir, &nickname, &input, None, force)?;
            println!("imported {nickname}: {}", recorded.address);
        }
        "remove" => {
            let nickname = required_text(&mut args, "NICKNAME")?;
            if required_text(&mut args, "CONFIRMATION")? != "--yes" {
                return Err(
                    invalid_input("remove requires the explicit --yes confirmation").into(),
                );
            }
            ensure_finished(args)?;
            remove_service(&config_path, &keystore_dir, &nickname)?;
            println!("removed {nickname}");
        }
        _ => {
            return Err(invalid_input(
                "usage: onion_keys CONFIG_PATH KEYSTORE_DIR <create|list|show|export|import|remove> ...",
            )
            .into());
        }
    }
    Ok(())
}

fn required_os(args: &mut impl Iterator<Item = OsString>, name: &str) -> io::Result<OsString> {
    args.next()
        .ok_or_else(|| invalid_input(&format!("missing {name}")))
}

fn required_text(args: &mut impl Iterator<Item = OsString>, name: &str) -> io::Result<String> {
    required_os(args, name)?
        .into_string()
        .map_err(|_| invalid_input(&format!("{name} must be valid Unicode")))
}

fn optional_force(args: &mut impl Iterator<Item = OsString>) -> io::Result<bool> {
    match args.next() {
        None => Ok(false),
        Some(flag) if flag == "--force" => {
            ensure_finished(args)?;
            Ok(true)
        }
        Some(_) => Err(invalid_input("only the optional --force flag is accepted")),
    }
}

fn ensure_finished(mut args: impl Iterator<Item = OsString>) -> io::Result<()> {
    if args.next().is_some() {
        return Err(invalid_input("unexpected argument"));
    }
    Ok(())
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.to_owned())
}
