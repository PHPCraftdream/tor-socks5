use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=TOR_SOCKS5_NOTICES");
    println!("cargo:rerun-if-env-changed=TOR_SOCKS5_SOURCE_INFO");

    let notices = env::var_os("TOR_SOCKS5_NOTICES");
    let source = env::var_os("TOR_SOCKS5_SOURCE_INFO");
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    match (notices, source) {
        (None, None) => {
            fs::write(
                out.join("notices.txt"),
                "Development build: not a verified release.\ntor-socks5 is licensed under MIT OR Apache-2.0.\nThis is not a complete third-party notices bundle.\n",
            )?;
            fs::write(
                out.join("source-info.txt"),
                "Development build: not a verified release.\ntor-socks5 is licensed under MIT OR Apache-2.0.\nSource: https://github.com/PHPCraftdream/tor-socks5\nThis is not complete source access information for a release.\n",
            )?;
        }
        (Some(notices), Some(source)) if !notices.is_empty() && !source.is_empty() => {
            copy_utf8(Path::new(&notices), &out.join("notices.txt"))?;
            copy_utf8(Path::new(&source), &out.join("source-info.txt"))?;
        }
        _ => {
            return Err(
                "TOR_SOCKS5_NOTICES and TOR_SOCKS5_SOURCE_INFO must both be nonempty paths or both be unset".into(),
            )
        }
    }
    Ok(())
}

fn copy_utf8(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let source = if source.is_absolute() {
        source.to_path_buf()
    } else {
        env::current_dir()?.join(source)
    };
    // Директивы Cargo не поддерживают перевод строки в пути.
    let path = source.to_str().ok_or("notice input path is not UTF-8")?;
    if path.contains(['\n', '\r']) {
        return Err("notice input path contains a newline".into());
    }
    println!("cargo:rerun-if-changed={path}");
    for ancestor in source.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err("notice input path contains a symlink".into());
        }
    }
    let source = fs::canonicalize(source)?;
    let path = source.to_str().ok_or("notice input path is not UTF-8")?;
    if path.contains(['\n', '\r']) {
        return Err("notice input path contains a newline".into());
    }
    println!("cargo:rerun-if-changed={path}");
    if !fs::metadata(&source)?.is_file() {
        return Err("notice input is not a regular file".into());
    }
    let bytes = fs::read(&source)?;
    if bytes.is_empty() {
        return Err("notice input file is empty".into());
    }
    std::str::from_utf8(&bytes)?;
    fs::write(destination, bytes)?;
    Ok(())
}
