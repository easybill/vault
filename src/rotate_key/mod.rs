use std::fs;
use anyhow::{anyhow, Context, Error};
use create_keys;
use crypto::Crypto;
use key::key_map::{KeyMap, KeyMapConfig, Subscription};
use key::Pem;
use ui::question::Question;

pub fn rotate_keys(keymap_config: &KeyMapConfig, private_key_file: Option<String>) -> Result<(), Error> {

    if !Question::confirm("do you want to rotate your private key?") {
        return Ok(());
    }

    let keymap = KeyMap::from_path(keymap_config)?;

    let pem = keymap.get_private_pems().first().unwrap(); // todo, based on filename

    let username_current = pem.get_name();
    let username_rotated = &format!("{}_to_rotate", username_current);

    create_keys(&format!("{}_to_rotate", username_current))?;

    let keymap = KeyMap::from_path(keymap_config)?;

    allow_access_to_all_keys(&keymap, &username_rotated)?;


    Ok(())

}

fn allow_access_to_all_keys(keymap: &KeyMap, username_rotated: &str) -> Result<(), Error> {
    let secret_directory_path = "./.vault/secrets/";

    let secret_directory_path_readdir = fs::read_dir(&secret_directory_path).context(anyhow!(
        "could not read subscription path. directory is missing? {}",
        &secret_directory_path
    ))?;

    for path in secret_directory_path_readdir {
        let path = path.context("could not read directory")?;

        if !path.path().is_dir() {
            continue;
        }

        let path_file_name = path.file_name();
        let secret_name = path_file_name.to_string_lossy().to_string();

        let subscription = Subscription::new(
            username_rotated.to_string(),
            secret_name.clone(),
            false,
        );

        match keymap.fulfill_subscription(&subscription) {
            Ok(k) => {},
            Err(e) => {
                let crypt_file_path = format!("./.vault/secrets/{}/{}.crypt", secret_name, username_rotated);
                if fs::metadata(&crypt_file_path)?.is_file() {
                    return Err(anyhow!("could not read secret {}", crypt_file_path));
                }
            }
        }

    }

    Ok(())
}

fn rename_private_keys(pem : &Pem) -> Result<(), ::anyhow::Error> {
    if pem.get_name().contains("_to_rotate_") {
        return Ok(());
    }

    let pem_file = format!("./vault/private_keys/{}.pem", pem.get_name());
    let pem_pub_file = format!("./vault/private_keys/{}.pem.pub", pem.get_name());

    if fs::metadata(&pem_file)?.is_file() {
        return Err(anyhow!("could not find pem file {}", pem_file));
    }

    if fs::metadata(&pem_pub_file)?.is_file() {
        return Err(anyhow!("could not find pem.pub file {}", pem_pub_file));
    }

    Ok(())
}