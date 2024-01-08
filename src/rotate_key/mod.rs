use std::fs;
use std::fs::{remove_dir, remove_dir_all, remove_file};
use std::time::SystemTime;
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
    delete_user(username_current)?;


    Ok(())

}


fn delete_user(username: &str) -> Result<(), Error> {

    // delete all secrets

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

        let crypt_file_path = format!("./.vault/secrets/{}/{}.crypt", secret_name, username);

        if !fs::metadata(&crypt_file_path).is_ok() {
            continue;
        }

        fs::remove_file(&crypt_file_path).context(anyhow!(
            "could not remove file {}",
            &secret_directory_path
        ))?;
    }

    // delete key folder
    let keys_directory = format!("./.vault/keys/{}", username);

    match fs::metadata(&keys_directory) {
        Ok(s) => {
            if !s.is_dir() {
                return Err(anyhow!("key folder is no folder {}", &keys_directory));
            }


            let dir = fs::read_dir(&keys_directory).context(format!(
                "could not read subscription path. directory is missing? {}",
                &secret_directory_path
            ))?;

            for dir_entry in dir {
                let dir_entry = dir_entry?;
                if !dir_entry.path().is_file() {
                    continue;
                }

                remove_file(dir_entry.path()).context(format!("could not remove path {}", dir_entry.path().to_string_lossy()))?
            }

            remove_dir(&keys_directory).context(format!("could not remove path {}", &keys_directory))?

        },
        Err(_) => {

        }
    }

    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => unreachable!(),
    };

    let _ = fs::rename(format!("./.vault/private_keys/{}.pem", username), format!("./.vault/private_keys/{}_backup_{}.pem", username, timestamp));
    let _ = fs::rename(format!("./.vault/private_keys/{}.pub.pem", username), format!("./.vault/private_keys/{}_backup_{}.pub.pem", username, timestamp));

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