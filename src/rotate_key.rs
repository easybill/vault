use std::fs::{self, remove_dir, remove_file};
use std::time::SystemTime;

use anyhow::{Context, anyhow, bail};

use crate::Result;
use crate::format::FormatVersion;
use crate::key::key_map::{KeyMap, KeyMapConfig, Subscription};
use crate::ui::question::Question;

fn private_key_path(username: &str, version: FormatVersion) -> String {
    match version {
        FormatVersion::V1 => format!("./.vault/private_keys/{username}.pem"),
        FormatVersion::V2 => format!("./.vault/private_keys/{username}.v2.pem"),
    }
}

fn public_key_path(username: &str, version: FormatVersion) -> String {
    match version {
        FormatVersion::V1 => format!("./.vault/private_keys/{username}.pub.pem"),
        FormatVersion::V2 => format!("./.vault/private_keys/{username}.v2.pub.pem"),
    }
}

fn user_public_key_path(
    directory_username: &str,
    key_username: &str,
    version: FormatVersion,
) -> String {
    match version {
        FormatVersion::V1 => format!("./.vault/keys/{directory_username}/{key_username}.pub.pem"),
        FormatVersion::V2 => {
            format!("./.vault/keys/{directory_username}/{key_username}.v2.pub.pem")
        }
    }
}

pub fn rotate_keys(key_map_config: &KeyMapConfig, version: FormatVersion) -> Result<()> {
    let key_map = KeyMap::from_path(key_map_config)?;

    let pems = key_map
        .private_pems()
        .iter()
        .filter(|x| {
            !x.name().contains("_backup_") && x.is_v2() == matches!(version, FormatVersion::V2)
        })
        .collect::<Vec<_>>();
    let pem = pems.first().ok_or_else(|| {
        anyhow!(
            "could not find a {} private key to rotate",
            if matches!(version, FormatVersion::V2) {
                "v2"
            } else {
                "v1"
            }
        )
    })?;

    if !Question::confirm(&format!(
        "do you want to rotate your private key {:?}?",
        pem.name()
    )) {
        return Ok(());
    }

    let username_current = pem.name();
    let username_rotated = &format!("{username_current}_to_rotate");

    println!("1. generate new key");
    crate::format::create_keys(&format!("{username_current}_to_rotate"), version)
        .context("create_keys")?;

    let keymap = KeyMap::from_path(key_map_config)?;

    println!("2. allow access to all keys");
    allow_access_to_all_keys(&keymap, username_rotated, version)
        .context("allow_access_to_all_keys")?;
    validate_rotation_paths(username_current, username_rotated, version)
        .context("validate_rotation_paths")?;
    println!("2. delete the old key");
    delete_user(username_current, version).context("delete_user")?;
    println!("3. rename user");
    rename_user(username_rotated, username_current, version).context("rename_user")?;
    println!("the key has been rotated, the old key is still there and has a backup suffix.");

    Ok(())
}

fn validate_rotation_paths(
    username_current: &str,
    username_rotated: &str,
    version: FormatVersion,
) -> Result<()> {
    for path in [
        private_key_path(username_rotated, version),
        public_key_path(username_rotated, version),
        user_public_key_path(username_rotated, username_rotated, version),
    ] {
        fs::metadata(&path).with_context(|| format!("rotation expected path {path} to exist"))?;
    }
    let rotated_directory = format!("./.vault/keys/{username_rotated}");
    let metadata = fs::metadata(&rotated_directory)
        .with_context(|| format!("rotation expected path {rotated_directory} to exist"))?;
    if !metadata.is_dir() {
        bail!("rotation expected directory {rotated_directory}");
    }

    let secret_directory_path = "./.vault/secrets/";
    let secret_directory_path_readdir = fs::read_dir(secret_directory_path).with_context(|| {
        format!("could not read subscription path. directory is missing? {secret_directory_path}")
    })?;

    for path in secret_directory_path_readdir {
        let path = path.context("could not read directory")?;
        if !path.path().is_dir() {
            continue;
        }

        let secret_name = path.file_name().to_string_lossy().to_string();
        let rotated_crypt_file_path =
            format!("./.vault/secrets/{secret_name}/{username_rotated}.crypt");
        let current_crypt_file_path =
            format!("./.vault/secrets/{secret_name}/{username_current}.crypt");

        if fs::metadata(&current_crypt_file_path).is_ok()
            && fs::metadata(&rotated_crypt_file_path).is_err()
        {
            bail!("rotation expected re-encrypted secret at {rotated_crypt_file_path}");
        }
    }

    Ok(())
}

fn rename_user(username_from: &str, username_to: &str, version: FormatVersion) -> Result<()> {
    struct Rename {
        from: String,
        to: String,
    }

    let mut renames = vec![];

    renames.push(Rename {
        from: private_key_path(username_from, version),
        to: private_key_path(username_to, version),
    });

    renames.push(Rename {
        from: public_key_path(username_from, version),
        to: public_key_path(username_to, version),
    });

    renames.push(Rename {
        from: format!("./.vault/keys/{username_from}"),
        to: format!("./.vault/keys/{username_to}"),
    });

    renames.push(Rename {
        from: user_public_key_path(username_to, username_from, version),
        to: user_public_key_path(username_to, username_to, version),
    });

    let secret_directory_path = "./.vault/secrets/";

    let secret_directory_path_readdir = fs::read_dir(secret_directory_path).context(format!(
        "could not read subscription path. directory is missing? {secret_directory_path}"
    ))?;

    for path in secret_directory_path_readdir {
        let path = path.context("could not read directory")?;

        if !path.path().is_dir() {
            continue;
        }

        let path_file_name = path.file_name();
        let secret_name = path_file_name.to_string_lossy().to_string();

        let crypt_file_path = format!("./.vault/secrets/{secret_name}/{username_from}.crypt");

        if fs::metadata(&crypt_file_path).is_err() {
            continue;
        }

        renames.push(Rename {
            from: crypt_file_path,
            to: format!("./.vault/secrets/{secret_name}/{username_to}.crypt"),
        });
    }

    for rename in renames {
        if fs::metadata(&rename.to).is_ok() {
            return Err(anyhow!(
                "could not copy from {from} to {to}, file/dir already exists",
                from = &rename.from,
                to = &rename.to
            ));
        }

        fs::rename(&rename.from, &rename.to).map_err(|error| {
            anyhow!(
                "could not copy from {from} to {to}, error: {error}",
                from = &rename.from,
                to = &rename.to,
            )
        })?;
    }

    Ok(())
}

fn delete_user(username: &str, version: FormatVersion) -> Result<()> {
    // delete all secrets

    let secret_directory_path = "./.vault/secrets/";

    let secret_directory_path_readdir = fs::read_dir(secret_directory_path).with_context(|| {
        format!("could not read subscription path. directory is missing? {secret_directory_path}")
    })?;

    for path in secret_directory_path_readdir {
        let path = path.context("could not read directory")?;

        if !path.path().is_dir() {
            continue;
        }

        let path_file_name = path.file_name();
        let secret_name = path_file_name.to_string_lossy().to_string();

        let crypt_file_path = format!("./.vault/secrets/{secret_name}/{username}.crypt");

        if fs::metadata(&crypt_file_path).is_err() {
            continue;
        }

        remove_file(&crypt_file_path)
            .with_context(|| format!("could not remove file {secret_directory_path}"))?;
    }

    // delete key folder
    let keys_directory = format!("./.vault/keys/{username}");

    if let Ok(metadata) = fs::metadata(&keys_directory) {
        if !metadata.is_dir() {
            bail!("key folder is no folder {keys_directory}");
        }

        let dir = fs::read_dir(&keys_directory).with_context(|| {
            format!(
                "could not read subscription path. directory is missing? {secret_directory_path}"
            )
        })?;

        for dir_entry in dir {
            let dir_entry = dir_entry?;
            if !dir_entry.path().is_file() {
                continue;
            }

            remove_file(dir_entry.path()).with_context(|| {
                format!(
                    "could not remove path {}",
                    dir_entry.path().to_string_lossy()
                )
            })?
        }

        remove_dir(&keys_directory)
            .with_context(|| format!("could not remove path {keys_directory}"))?
    }

    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => bail!("SystemTime before UNIX_EPOCH"),
    };

    let _ = fs::rename(
        private_key_path(username, version),
        private_key_path(&format!("{username}_backup_{timestamp}"), version),
    );
    let _ = fs::rename(
        public_key_path(username, version),
        public_key_path(&format!("{username}_backup_{timestamp}"), version),
    );

    Ok(())
}

fn allow_access_to_all_keys(
    keymap: &KeyMap,
    username_rotated: &str,
    version: FormatVersion,
) -> Result<()> {
    let secret_directory_path = "./.vault/secrets/";

    let secret_directory_path_readdir = fs::read_dir(secret_directory_path).with_context(|| {
        format!("could not read subscription path. directory is missing? {secret_directory_path}")
    })?;

    for path in secret_directory_path_readdir {
        let path = path.context("could not read directory")?;

        if !path.path().is_dir() {
            continue;
        }

        let path_file_name = path.file_name();
        let secret_name = path_file_name.to_string_lossy().to_string();

        let subscription =
            Subscription::new(username_rotated.to_string(), secret_name.clone(), false);

        match keymap.fulfill_subscription(&subscription, version) {
            Ok(_k) => {}
            Err(_e) => {
                let crypt_file_path =
                    format!("./.vault/secrets/{secret_name}/{username_rotated}.crypt");
                if fs::metadata(&crypt_file_path).is_ok() {
                    bail!("could not read secret {}", crypt_file_path);
                }
            }
        }
    }

    Ok(())
}
