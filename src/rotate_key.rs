use std::fs::{self, remove_dir, remove_file};
use std::time::SystemTime;

use anyhow::{Context, anyhow, bail, ensure};

use crate::Result;
use crate::key::key_map::{KeyMap, Subscription};
use crate::policy::{Policy, Rename};
use crate::ui::question::Question;

/// Rotates the first active key ([`KeyMap::active_pems`], keys of the newest policy first) into a
/// new key of its own policy. With a `migrate_to` policy, the first active key of an older policy
/// in loading order is rotated into a new key of `migrate_to` instead.
pub fn rotate_keys(migrate_to: Option<&'static dyn Policy>) -> Result<()> {
    let key_map = KeyMap::from_path()?;

    let mut active_pems = key_map.active_pems();

    let (pem, target_policy) = match migrate_to {
        None => {
            let pem = active_pems
                .next()
                .context("could not rotate, there is no active private key")?;
            (pem, pem.policy())
        }
        Some(target_policy) => {
            let pem = active_pems
                .find(|pem| pem.policy().file_version() < target_policy.file_version())
                .with_context(|| {
                    format!(
                        "could not migrate, there is no active private key older than V{}",
                        target_policy.file_version()
                    )
                })?;
            (pem, target_policy)
        }
    };

    let source_policy = pem.policy();
    ensure_no_downgrade(
        pem.name(),
        source_policy.file_version(),
        key_map.registered_file_version(pem.name()),
        target_policy,
    )?;

    if !Question::confirm(&format!(
        "do you want to rotate your private key {:?}?",
        pem.name()
    )) {
        return Ok(());
    }

    let username_current = pem.name();
    let username_rotated = &format!("{username_current}_to_rotate");

    println!("1. generate new key");
    target_policy
        .create_replacement_key(username_rotated, pem)
        .context("create_keys")?;

    let keymap = KeyMap::from_path()?;

    println!("2. allow access to all keys");
    allow_access_to_all_keys(&keymap, username_rotated).context("allow_access_to_all_keys")?;
    println!("2. delete the old key");
    delete_user(source_policy, username_current).context("delete_user")?;
    println!("3. rename user");
    rename_user(target_policy, username_rotated, username_current).context("rename_user")?;
    println!("the key has been rotated, the old key is still there and has a backup suffix.");

    Ok(())
}

/// A key is never rotated into a policy whose files have a lower version than the rotated key
/// (`source_version`) or than a key the repository registers under its name
/// (`registered_version`).
fn ensure_no_downgrade(
    name: &str,
    source_version: u16,
    registered_version: Option<u16>,
    target: &dyn Policy,
) -> Result<()> {
    let newest_version = registered_version.map_or(source_version, |registered_version| {
        registered_version.max(source_version)
    });

    ensure!(
        target.file_version() >= newest_version,
        "could not rotate the key {name:?} into a V{} key, it already has a V{newest_version} key",
        target.file_version()
    );

    Ok(())
}

fn rename_user(target_policy: &dyn Policy, username_from: &str, username_to: &str) -> Result<()> {
    let mut renames = target_policy.key_renames(username_from, username_to)?;

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
                from = rename.from,
                to = rename.to
            ));
        }

        fs::rename(&rename.from, &rename.to).map_err(|error| {
            anyhow!(
                "could not copy from {from} to {to}, error: {error}",
                from = rename.from,
                to = rename.to,
            )
        })?;
    }

    Ok(())
}

fn delete_user(source_policy: &dyn Policy, username: &str) -> Result<()> {
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

    source_policy
        .backup_private_key(username, timestamp)
        .context("could not back up the private key")
}

fn allow_access_to_all_keys(keymap: &KeyMap, username_rotated: &str) -> Result<()> {
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

        match keymap.fulfill_subscription(&subscription) {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::policy::{Version1, Version2};

    #[test]
    fn test_no_downgrade() {
        for (source_version, registered_version, target) in [
            (1, None, &Version1 as &dyn Policy),
            (1, Some(1), &Version1),
            (1, None, &Version2),
            (1, Some(1), &Version2),
            (1, Some(2), &Version2),
            (2, Some(2), &Version2),
        ] {
            assert!(
                ensure_no_downgrade("key", source_version, registered_version, target).is_ok(),
                "{source_version} {registered_version:?} {target:?}"
            );
        }

        // A V1 key whose user is registered with a V2 key, and a V2 key.
        for (source_version, registered_version) in [(1, Some(2)), (2, Some(2)), (2, None)] {
            assert_eq!(
                ensure_no_downgrade("key", source_version, registered_version, &Version1)
                    .unwrap_err()
                    .to_string(),
                "could not rotate the key \"key\" into a V1 key, it already has a V2 key",
                "{source_version} {registered_version:?}"
            );
        }
    }
}
