//! The identity of a configured onion service at launch.
//!
//! The onion services file (`<stem>.onion.ktav`) is the source of truth: the
//! `key` of a service is its identity and `address` the address that key
//! gives. Arti reads the identity from its keystore, so a launch makes the
//! keystore hold exactly the key of the file. A service without a key gets
//! one (the keystore's, if an older `onion new` left one there, else a fresh
//! one) and the file is completed with the key and the address, so after the
//! first start everything about the service is in the file.

use std::path::Path;

use anyhow::{bail, Context, Result};
use proxy_config::{Config, IdentityKey, OnionServiceEntry};

use super::store;

/// Make the keystore hold the identity that `entry` names, creating and
/// recording it when the file has none, and return the service's address.
///
/// Refuses (`Err`, nothing changed in the keystore) when the file states an
/// address that its key does not give, or an address without any key to
/// check it against. `config_path` is where the onion services file belongs
/// to; without it (built-in defaults) there is no file to complete.
pub(crate) fn ensure(config_path: Option<&Path>, entry: &OnionServiceEntry) -> Result<String> {
    let nick = store::nickname(&entry.nickname)?;
    let dir = store::keystore_dir(config_path);
    let keymgr = store::open(&dir)?;

    let (keypair, key_text) = match &entry.key {
        Some(key) => {
            let bytes = store::decode_key(key.as_str())?;
            let keypair = store::parse_identity_file(&bytes, &nick)
                .context("the key in the onion services file is not a valid identity key")?;
            (keypair, None)
        }
        None => {
            let bytes = match store::identity_file(&dir, &nick) {
                Some(file) => {
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?
                }
                None => {
                    if let Some(address) = &entry.address {
                        bail!(
                            "service {:?} states the address {address} but has no key: \
                             add its key to the onion services file, or remove the address \
                             to get a new one",
                            entry.nickname
                        );
                    }
                    store::generate(&keymgr, &nick, false)?;
                    let file =
                        store::identity_file(&dir, &nick).context("the generated identity file")?;
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?
                }
            };
            let keypair = store::parse_identity_file(&bytes, &nick)
                .context("the identity key in the keystore is not valid")?;
            (keypair, Some(store::encode_key(&bytes)))
        }
    };

    let address = store::address_of(&keypair);
    if let Some(stated) = &entry.address {
        if *stated != address {
            bail!(
                "service {:?}: the onion services file states the address {stated}, \
                 but its key gives {address}",
                entry.nickname
            );
        }
    }
    // The keystore is the copy arti reads: bring it to the file's key.
    if store::address(&keymgr, &nick)?.as_deref() != Some(address.as_str()) {
        store::insert(&keymgr, keypair, &nick, true)?;
    }
    if key_text.is_some() || entry.address.is_none() {
        record(config_path, &entry.nickname, key_text, &address)?;
    }
    Ok(address)
}

/// Complete the file's entry of `nickname`: its `address`, and its `key` when
/// one was just created.
fn record(
    config_path: Option<&Path>,
    nickname: &str,
    key_text: Option<String>,
    address: &str,
) -> Result<()> {
    let Some(config_path) = config_path else {
        return Ok(());
    };
    let key = key_text
        .map(IdentityKey::new)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    Config::update_onion_services(config_path, |services| {
        let Some(entry) = services.iter_mut().find(|entry| entry.nickname == nickname) else {
            bail!("service {nickname:?} is no longer in the onion services file");
        };
        entry.address = Some(address.to_owned());
        if key.is_some() {
            entry.key = key;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use proxy_config::OnionServicePort;
    use tor_hscrypto::pk::HsIdKeypair;
    use tor_llcrypto::pk::ed25519::ExpandedKeypair;

    use super::*;

    fn temp_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("tor-socks5.ktav");
        (dir, config)
    }

    fn entry(nickname: &str) -> OnionServiceEntry {
        OnionServiceEntry {
            nickname: nickname.to_owned(),
            enabled: true,
            address: None,
            key: None,
            circuit_hops: 4,
            ports: vec![OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".to_owned(),
            }],
        }
    }

    /// A fresh identity as the file stores it: (key text, address).
    fn fresh_identity(nickname: &str) -> (String, String) {
        let generated = super::super::address::generate();
        let expanded = ExpandedKeypair::from_secret_key_bytes(generated.to_expanded_bytes())
            .expect("expanded keypair");
        let keypair = HsIdKeypair::from(expanded);
        let nick = store::nickname(nickname).expect("nickname");
        let bytes = store::identity_file_bytes(keypair, &nick).expect("key file bytes");
        (store::encode_key(&bytes), generated.address().to_owned())
    }

    fn stored(config: &Path) -> Vec<OnionServiceEntry> {
        Config::read_onion_services(config).expect("read the file")
    }

    fn keystore_address(config: &Path, nickname: &str) -> Option<String> {
        let keymgr = store::open(&store::keystore_dir(Some(config))).expect("keystore");
        store::address(&keymgr, &store::nickname(nickname).expect("nickname")).expect("address")
    }

    #[test]
    fn a_key_in_the_file_reaches_the_keystore_and_the_address_is_recorded() {
        let (_tmp, config) = temp_config();
        let (key, address) = fresh_identity("web");
        let mut service = entry("web");
        service.key = Some(IdentityKey::new(key.clone()).expect("key text"));
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let got = ensure(Some(&config), &service).expect("ensure");

        assert_eq!(got, address);
        assert_eq!(
            keystore_address(&config, "web").as_deref(),
            Some(address.as_str())
        );
        let file = stored(&config);
        assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
        assert_eq!(
            file[0].key.as_ref().map(IdentityKey::as_str),
            Some(key.as_str())
        );
    }

    #[test]
    fn a_stated_address_that_the_key_does_not_give_is_refused() {
        let (_tmp, config) = temp_config();
        let (key, _address) = fresh_identity("web");
        let (_other_key, other_address) = fresh_identity("web");
        let mut service = entry("web");
        service.key = Some(IdentityKey::new(key).expect("key text"));
        service.address = Some(other_address);
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let error = ensure(Some(&config), &service).expect_err("refused");
        assert!(error.to_string().contains("its key gives"), "{error:#}");
        assert_eq!(keystore_address(&config, "web"), None, "keystore untouched");
    }

    #[test]
    fn a_service_without_a_key_gets_one_and_the_file_is_completed() {
        let (_tmp, config) = temp_config();
        let service = entry("web");
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let address = ensure(Some(&config), &service).expect("ensure");

        let file = stored(&config);
        assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
        let key = file[0].key.as_ref().expect("the key is recorded");
        // The recorded key is the identity the keystore holds.
        let nick = store::nickname("web").expect("nickname");
        let bytes = store::decode_key(key.as_str()).expect("base64");
        let keypair = store::parse_identity_file(&bytes, &nick).expect("key file");
        assert_eq!(store::address_of(&keypair), address);
        assert_eq!(keystore_address(&config, "web"), Some(address));
    }

    #[test]
    fn a_second_launch_keeps_the_same_identity() {
        let (_tmp, config) = temp_config();
        Config::write_onion_services(&config, &[entry("web")]).expect("write");
        let first = ensure(Some(&config), &entry("web")).expect("first");
        let recorded = stored(&config).remove(0);
        let second = ensure(Some(&config), &recorded).expect("second");
        assert_eq!(first, second);
        assert_eq!(
            stored(&config)[0],
            recorded,
            "nothing to complete the second time"
        );
    }

    #[test]
    fn a_key_left_in_the_keystore_by_an_older_version_is_adopted() {
        let (_tmp, config) = temp_config();
        let nick = store::nickname("web").expect("nickname");
        let dir = store::keystore_dir(Some(&config));
        let keymgr = store::open(&dir).expect("keystore");
        store::generate(&keymgr, &nick, false).expect("generate");
        let existing = store::address(&keymgr, &nick)
            .expect("address")
            .expect("present");
        drop(keymgr);
        Config::write_onion_services(&config, &[entry("web")]).expect("write");

        let address = ensure(Some(&config), &entry("web")).expect("ensure");

        assert_eq!(address, existing, "the address does not change");
        assert!(
            stored(&config)[0].key.is_some(),
            "and the key moves into the file"
        );
    }

    #[test]
    fn an_address_without_any_key_is_refused_and_nothing_is_generated() {
        let (_tmp, config) = temp_config();
        let mut service = entry("web");
        service.address = Some(fresh_identity("web").1);
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let error = ensure(Some(&config), &service).expect_err("refused");
        assert!(error.to_string().contains("has no key"), "{error:#}");
        assert_eq!(keystore_address(&config, "web"), None);
    }

    #[test]
    fn a_key_that_is_not_an_identity_key_is_refused() {
        let (_tmp, config) = temp_config();
        let mut service = entry("web");
        service.key = Some(IdentityKey::new(store::encode_key(b"not a key")).expect("key text"));
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");
        let error = ensure(Some(&config), &service).expect_err("refused");
        assert!(
            format!("{error:#}").contains("not a valid identity key"),
            "{error:#}"
        );
    }
}
