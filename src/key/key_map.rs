use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use globset::Glob;
use serde_derive::Deserialize;
use toml;

use crate::Result;
use crate::crypto::{Crypto, UnencryptedVaultFile};
use crate::key::{Pem, PrivateKey, PublicKey};
use crate::proto::VaultFile;

#[derive(Debug)]
pub struct KeyMap {
    pems: Vec<Pem>,
    entries: Vec<KeyMapEntry>,
}

#[derive(Debug)]
pub struct KeyMapEntry {
    user: String,
    keys: Vec<PublicKey>,
    subscriptions: HashMap<String, Subscription>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigToml {
    subscriptions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    username: String,
    name: String,
    is_satisfied: bool,
    // file for subscription exists, but no subscription is required
    // is_orphan: bool // TODO
}

pub struct KeyMapConfig {
    pub path_private_key: String,
}

impl Subscription {
    pub fn new(username: String, name: String, is_satisfied: bool) -> Self {
        Self {
            username,
            name,
            is_satisfied,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_satisfied(&self) -> bool {
        self.is_satisfied
    }
}

impl KeyMap {
    pub fn build_keys_from_path(root_path: &Path) -> Result<Vec<PublicKey>> {
        let mut buffer = vec![];

        let paths = fs::read_dir(root_path).context("could not read user path")?;

        for raw_path in paths {
            let path = raw_path.context("could not parse path")?.path();

            if !path.display().to_string().ends_with(".pub.pem") {
                continue;
            }

            buffer.push(
                PublicKey::load_from_file(&path.display().to_string())
                    .with_context(|| format!("could not load public key {}", path.display()))?,
            );
        }

        Ok(buffer)
    }

    pub fn subscriptions(config: &ConfigToml) -> Result<Vec<String>> {
        // read the content of ./.vault/secrets/ to find secrets that are matching a glob pattern.
        let available_secrets = {
            let mut buffer = vec![];
            let secrets_dir_entries =
                fs::read_dir("./.vault/secrets/").context("could not read ./.vault/secrets/")?;
            for secrets_dir_entry in secrets_dir_entries {
                let entry = secrets_dir_entry
                    .context("could not get directory item in ./.vault/secrets/")?;

                if !entry
                    .file_type()
                    .context("could not read filetype of secret")?
                    .is_dir()
                {
                    continue;
                }

                let path_as_string = entry.path().display().to_string();

                if path_as_string.ends_with(".crypt") {
                    continue;
                }

                let filename = match entry.file_name().to_str() {
                    None => {
                        bail!("invalid filename encoding in entry in ./.vault/secrets/");
                    }
                    Some(s) => s.to_string(),
                };

                buffer.push(filename);
            }

            buffer
        };

        let mut buffer = HashSet::new();
        for raw_subscription in &config.subscriptions {
            if !raw_subscription.contains("*") {
                buffer.insert(raw_subscription.to_string());
            }

            // looks like we're dealing with a glob pattern ...

            let glob_matcher = Glob::new(raw_subscription)
                .with_context(|| format!("error when compiling glob pattern {raw_subscription}"))?
                .compile_matcher();
            for available_secret in available_secrets.iter() {
                if !glob_matcher.is_match(available_secret) {
                    continue;
                }

                buffer.insert(available_secret.to_string());
            }
        }

        Ok(buffer.into_iter().collect::<Vec<_>>())
    }

    pub fn build_subscriptions(
        username: &str,
        config: &ConfigToml,
    ) -> Result<HashMap<String, Subscription>> {
        let mut buffer = HashMap::new();

        for raw_subscription in
            Self::subscriptions(config).context("could not get subscriptions")?
        {
            let secret_path = format!("./.vault/secrets/{}/{}.crypt", &raw_subscription, username);

            let file_exists = match fs::metadata(&secret_path) {
                Err(_) => false,
                Ok(metadata) => metadata.is_file(),
            };

            buffer.insert(
                raw_subscription.to_string(),
                Subscription {
                    username: username.to_string(),
                    name: raw_subscription.clone(),
                    is_satisfied: file_exists,
                },
            );
        }

        // TODO: later we not only have to read the subscriptions from the config,
        // but also have to look them up in the file system.

        Ok(buffer)
    }

    pub fn build_private_pems(config: &KeyMapConfig) -> Result<Vec<Pem>> {
        let mut buffer = vec![];

        let mut lookup_paths = vec![];

        lookup_paths.push(fs::read_dir(&config.path_private_key).with_context(|| {
            format!(
                "private key directory {} is not readable",
                &config.path_private_key
            )
        })?);

        if let Some(home_dir) = dirs::home_dir() {
            if let Ok(home_path) = fs::read_dir(home_dir.join(".vault/private_keys")) {
                lookup_paths.push(home_path);
            }
        }

        for paths in lookup_paths {
            for path in paths {
                let path_as_string = path
                    .context("could not parse path")?
                    .path()
                    .display()
                    .to_string();

                if path_as_string.ends_with(".md") || path_as_string.ends_with(".DS_Store") {
                    continue;
                }

                if path_as_string.ends_with(".pub.pem") {
                    continue;
                }

                if !path_as_string.ends_with(".pem") && !path_as_string.ends_with(".pem.pgp") {
                    // by default the directory is empty. its annoying when you get this error every time.

                    if path_as_string.ends_with(".gitkeep") {
                        continue;
                    }

                    if path_as_string.ends_with(".bak") {
                        continue;
                    }

                    eprintln!("info: unexpected file {path_as_string}");
                    continue;
                }

                // path is a private key, now lets try to find the pub key:

                let public_key_path = format!(
                    "{}.pub.pem",
                    &path_as_string.trim_end_matches(".pgp")
                        [..path_as_string.trim_end_matches(".pgp").len() - 4]
                );

                let file_exists = match fs::metadata(&public_key_path) {
                    Err(_) => false,
                    Ok(metadata) => metadata.is_file(),
                };

                if !file_exists {
                    bail!(
                        "could not find a corresponding public key at {public_key_path:?} for private key at {path_as_string:?}",
                    );
                }

                buffer.push(Pem::new(
                    PrivateKey::load_from_file(&path_as_string)
                        .with_context(|| format!("could not add private key: {path_as_string}"))?,
                    PublicKey::load_from_file(&public_key_path)
                        .with_context(|| format!("could not add public key: {path_as_string}"))?,
                ));
            }
        }

        Ok(buffer)
    }

    pub fn from_path(config: &KeyMapConfig) -> Result<KeyMap> {
        let mut buffer = vec![];

        let paths = fs::read_dir("./.vault/keys")
            .map_err(|error| anyhow!("could not read ./vault/keys, {error}"))?;

        for path in paths {
            let user_path = match path {
                Err(error) => bail!("could not decode user path {error}"),
                Ok(dir_entry) => {
                    let path = dir_entry.path();

                    if !path.is_dir() {
                        continue;
                    }

                    path
                }
            };

            let user = match user_path.file_name() {
                Some(s) => s.to_string_lossy().to_string(),
                None => {
                    continue;
                }
            };

            let config_file_path = user_path.join("config.toml");
            let raw_config = {
                let mut f = File::open(&config_file_path).map_err(|error| {
                    anyhow!(
                        "could not open config file {}, {}",
                        config_file_path.display(),
                        error
                    )
                })?;

                let mut content = String::new();
                f.read_to_string(&mut content).map_err(|error| {
                    anyhow!(
                        "could not read config file {}, {}",
                        config_file_path.display(),
                        error
                    )
                })?;

                content
            };

            let decoded_config_file: ConfigToml = toml::from_str(&raw_config).map_err(|_| {
                anyhow!("could not parse toml file {}", &config_file_path.display())
            })?;

            buffer.push(KeyMapEntry {
                user: user.clone(),
                subscriptions: Self::build_subscriptions(&user, &decoded_config_file)
                    .context("could not fetch subscriptions")?,
                keys: Self::build_keys_from_path(&user_path)?,
            });
        }

        Ok(KeyMap {
            pems: Self::build_private_pems(config)?,
            entries: buffer,
        })
    }

    pub fn decrypt_subscription(
        &self,
        subscription: &Subscription,
    ) -> Result<UnencryptedVaultFile> {
        self.decrypt(subscription.name())
    }

    pub fn decrypt_subscription_string(
        &self,
        subscription: &Subscription,
    ) -> Result<UnencryptedVaultFile> {
        self.decrypt(subscription.name())
    }

    pub fn decrypt_to_string(&self, subscription_key: &str) -> Result<String> {
        let unencrypted = self
            .decrypt(subscription_key)
            .with_context(|| format!("could not decrypt {subscription_key}"))?;

        String::from_utf8(unencrypted.content().to_vec()).context("Invalid Utf8")
    }

    pub fn decrypt(&self, subscription_key: &str) -> Result<UnencryptedVaultFile> {
        let possible_files: Vec<String> = {
            let mut buffer = vec![];

            let secret_path = format!("./.vault/secrets/{}", subscription_key);

            let paths = fs::read_dir(&secret_path).with_context(|| {
                format!("could not read subscription path. directory is missing? {secret_path}")
            })?;

            for path in paths {
                let path_as_string = path
                    .context("could not parse path")?
                    .path()
                    .display()
                    .to_string();

                if path_as_string.ends_with(".DS_Store") {
                    continue;
                }

                if !path_as_string.ends_with(".crypt") {
                    eprintln!("warning: found a invalid file {path_as_string} in secrets.");
                    continue;
                }

                buffer.push(path_as_string);
            }

            buffer
        };

        for pem in &self.pems {
            for file in &possible_files {
                let vault_file = {
                    let f =
                        File::open(file).with_context(|| format!("could not read file {file}"))?;

                    VaultFile::open(f).context("could not create vault file.")?
                };

                match Crypto::decrypt(pem, &vault_file) {
                    Ok(unencrypted_vault_file) => return Ok(unencrypted_vault_file),
                    Err(_) => {
                        continue;
                    }
                }
            }
        }

        Err(anyhow!("could not find key"))
    }

    pub fn could_fulfill_subscription(&self, subscription: &Subscription) -> bool {
        // TODO: on the one hand we have to make sure that we can decrypt it,
        // on the other hand that we have the other person's pub key,
        // for now we're bluntly assuming that we do.
        self.decrypt_subscription(subscription).is_ok()
    }

    pub fn fulfill_subscription(&self, subscription: &Subscription) -> Result<()> {
        let unencrypted_vault_file = self
            .decrypt_subscription(subscription)
            .with_context(|| format!("could not decrypt subscription {}", subscription.name()))?;

        let public_keys_for_user: &Vec<PublicKey> = {
            let mut keys = None;

            for entry in &self.entries {
                if entry.user != subscription.username() {
                    continue;
                }

                keys = Some(&entry.keys);
                break;
            }

            keys
        }
        .ok_or_else(|| anyhow!("could not find keys for user"))?;

        if public_keys_for_user.is_empty() {
            bail!("could not find key for user");
        }

        for public_key in public_keys_for_user.iter() {
            let new_filename = format!(
                "./.vault/secrets/{}/{}.crypt",
                subscription.name(),
                public_key.name()
            );

            println!("creating file {}", &new_filename);

            // create new vault file:

            let encrypted_file_content = Crypto::encrypt(public_key, &unencrypted_vault_file)
                .with_context(|| {
                    format!("could not encrypt data using key {}", public_key.name())
                })?;

            let vault_file = VaultFile::from_encrypted_file_content(&encrypted_file_content);

            let mut f = File::create(&new_filename)
                .with_context(|| format!("could not create new encrypted file {new_filename}"))?;

            vault_file
                .write(&mut f)
                .context("could not write to file")?;
        }

        Ok(())
    }

    pub fn private_pems(&self) -> &Vec<Pem> {
        &self.pems
    }

    pub fn open_subscriptions(&self) -> Vec<Subscription> {
        let mut buffer = vec![];

        for key_map_entry in &self.entries {
            for subscription in key_map_entry.subscriptions.values() {
                if subscription.is_satisfied {
                    continue;
                }

                buffer.push(subscription.clone())
            }
        }

        buffer
    }

    pub fn add_new_secret(&self, filepath: &str) -> Result<()> {
        let pem = self.private_pems().first().with_context(|| {
            format!("could not fine private key for you, no idea how to encrypt {filepath}")
        })?;

        let file_content = {
            let mut f =
                File::open(filepath).with_context(|| format!("could not open {filepath}"))?;

            let mut content = vec![];
            f.read_to_end(&mut content).context("could not read file")?;

            content
        };

        let unencrypted_file = UnencryptedVaultFile::new(file_content);

        let encrypted_file_content = Crypto::encrypt(pem.public_key(), &unencrypted_file)
            .with_context(|| format!("could not encrypt {filepath} with key {}", pem.name()))?;

        fs::remove_file(filepath).with_context(|| format!("could not remove file {filepath}"))?;

        fs::create_dir(filepath)
            .with_context(|| format!("could not create new directory {filepath}"))?;

        let new_filename = format!("{}/{}.crypt", filepath, pem.name());

        let vault_file = VaultFile::from_encrypted_file_content(&encrypted_file_content);

        let mut f = File::create(&new_filename)
            .with_context(|| format!("could not create new encrypted file {new_filename}"))?;

        vault_file
            .write(&mut f)
            .with_context(|| format!("could not write to file {new_filename}"))?;

        Ok(())
    }
}
