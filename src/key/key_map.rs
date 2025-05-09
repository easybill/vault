use crate::Result;
use crate::crypto::Crypto;
use crate::crypto::UncryptedVaultFile;
use crate::key::Pem;
use crate::key::PrivateKey;
use crate::key::PublicKey;
use crate::proto::VaultFile;
use anyhow::{Context, anyhow, bail};
use globset::Glob;
use serde_derive::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use toml;

#[derive(Debug)]
pub struct KeyMap {
    pems: Vec<Pem>,
    entries: Vec<KeyMapEntry>,
    debug_enable_fetch_raw_secrets_from_env: Option<String>,
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
    is_stisfied: bool,
    // file for subscription exists, but no subscription is required
    // is_orphan: bool // TODO
}

pub struct KeyMapConfig {
    pub path_private_key: String,
    pub debug_enable_fetch_raw_secrets_from_env: Option<String>,
}

impl Subscription {
    pub fn new(username: String, name: String, is_stisfied: bool) -> Self {
        Self {
            username,
            name,
            is_stisfied,
        }
    }
    pub fn get_username(&self) -> &str {
        &self.username
    }
    pub fn get_name(&self) -> &str {
        &self.name
    }
    pub fn is_stisfied(&self) -> bool {
        self.is_stisfied
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

    pub fn get_subsciptions(config: &ConfigToml) -> Result<Vec<String>> {
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

            // we've a glob pattern...
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
            Self::get_subsciptions(config).context("could not get subscriptions")?
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
                    is_stisfied: file_exists,
                },
            );
        }

        // todo, später muss ich die subscriptions nicht nur aus der config lesen, sondern zusätzlich im dateisystem nachsehen.

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
                    // by default the directory is empty. its annoying when you get this error everytime.
                    if path_as_string.ends_with(".gitkeep") {
                        continue;
                    }

                    if path_as_string.ends_with(".bak") {
                        continue;
                    }

                    eprintln!("info: unexpected file {path_as_string}");
                    continue;
                }

                // path is a private key, no lets try to find the pub key.

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
                        "private key given at: {path_as_string} but public key is not found at: {public_key_path}",
                    );
                }

                buffer.push(Pem::new(
                    PrivateKey::load_from_file(&path_as_string).with_context(|| {
                        format!("failed, to add key, private key: {path_as_string}")
                    })?,
                    PublicKey::load_from_file(&public_key_path).with_context(|| {
                        format!("failed, to add key, private key: {path_as_string}")
                    })?,
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
            debug_enable_fetch_raw_secrets_from_env: config
                .debug_enable_fetch_raw_secrets_from_env
                .clone(),
        })
    }

    pub fn decrypt_subscription(&self, subscription: &Subscription) -> Result<UncryptedVaultFile> {
        self.decrypt(subscription.get_name())
    }

    pub fn decrypt_subscription_string(
        &self,
        subscription: &Subscription,
    ) -> Result<UncryptedVaultFile> {
        self.decrypt(subscription.get_name())
    }

    pub fn decrypt_to_string(&self, subscription_key: &str) -> Result<String> {
        let decrypted = self
            .decrypt(subscription_key)
            .with_context(|| format!("could not decrypt {subscription_key}"))?;

        String::from_utf8(decrypted.get_content().to_vec()).context("Invalid Utf8")
    }

    pub fn decrypt_debug_enable_fetch_raw_secrets_from_env(
        &self,
        subscription_key: &str,
    ) -> Result<UncryptedVaultFile> {
        let decrypt_user = self
            .debug_enable_fetch_raw_secrets_from_env
            .as_ref()
            .expect("decrypt user must be given");

        let secret_path = format!(
            "./.vault/secrets/{}/{}.crypt",
            subscription_key, decrypt_user
        );

        let crypt_file = fs::metadata(&secret_path)
            .map_err(|_| anyhow!("could not find key - crypt file {secret_path} does not exist"))?;

        if !crypt_file.is_file() {
            bail!("could not find key - crypt file {secret_path} is not a file");
        }

        let env_var = format!("VAULT_DEBUG_SECRET_{}", subscription_key);
        let secret = std::env::var(&env_var).map_err(|error| {
            anyhow!("could not find key - could not read env var {env_var}, error: {error}")
        })?;

        Ok(UncryptedVaultFile::new(secret.into_bytes()))
    }

    pub fn decrypt(&self, subscription_key: &str) -> Result<UncryptedVaultFile> {
        if self.debug_enable_fetch_raw_secrets_from_env.is_some() {
            return self.decrypt_debug_enable_fetch_raw_secrets_from_env(subscription_key);
        }

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
                    Ok(uncrypted_vault_file) => return Ok(uncrypted_vault_file),
                    Err(_) => {
                        continue;
                    }
                }
            }
        }

        Err(anyhow!("could not find key"))
    }

    pub fn could_fulfill_subscription(&self, subscription: &Subscription) -> bool {
        // auf der einen seite müssen wir sicherstellen, dass wir es decrypten können, todo auf der anderen, dass wir den pub key des anderen haben, davon gehe ich erstmal stumpf aus
        self.decrypt_subscription(subscription).is_ok()
    }

    pub fn fulfill_subscription(&self, subscription: &Subscription) -> Result<()> {
        let uncrypted_vault_file = self.decrypt_subscription(subscription).with_context(|| {
            format!(
                "could not decrypt subscription {}.",
                subscription.get_name()
            )
        })?;

        let public_keys_for_user: &Vec<PublicKey> = {
            let mut keys = None;

            for entry in &self.entries {
                if entry.user != subscription.get_username() {
                    continue;
                }

                keys = Some(&entry.keys);
                break;
            }

            keys
        }
        .ok_or_else(|| anyhow!("could not find keys for user"))?;

        if public_keys_for_user.is_empty() {
            bail!("could not found key for user");
        }

        for public_key in public_keys_for_user.iter() {
            let new_filename = format!(
                "./.vault/secrets/{}/{}.crypt",
                subscription.get_name(),
                public_key.get_name()
            );

            println!("create file {}", &new_filename);

            // neue vaultfile erstellen ....

            let crypted_file_content = Crypto::encrypt(public_key, &uncrypted_vault_file)
                .with_context(|| {
                    format!("could not crypt data using key {}", public_key.get_name())
                })?;

            let vault_file = VaultFile::from_crypted_file_content(&crypted_file_content);

            let mut f = File::create(&new_filename)
                .with_context(|| format!("could not create new crypted file {new_filename}"))?;

            vault_file
                .write(&mut f)
                .context("could not write to file")?;
        }

        Ok(())
    }

    pub fn get_private_pems(&self) -> &Vec<Pem> {
        &self.pems
    }

    pub fn get_open_subscriptions(&self) -> Vec<Subscription> {
        let mut buffer = vec![];

        for key_map_entry in &self.entries {
            for subscription in key_map_entry.subscriptions.values() {
                if subscription.is_stisfied {
                    continue;
                }

                buffer.push(subscription.clone())
            }
        }

        buffer
    }

    pub fn add_new_secet(&self, filepath: &str) -> Result<()> {
        let pem = self
            .get_private_pems()
            .first()
            .with_context(|| format!("you've no private key, no idea how to crypt {filepath}"))?;

        let file_content = {
            let mut f =
                File::open(filepath).with_context(|| format!("could not open {filepath}"))?;

            let mut content = vec![];
            f.read_to_end(&mut content).context("could not read file")?;

            content
        };

        let uncrypted_file = UncryptedVaultFile::new(file_content);

        let crypted_file_content = Crypto::encrypt(pem.get_public_key(), &uncrypted_file)
            .with_context(|| {
                format!(
                    "encryption of {} failed with key {}",
                    &filepath,
                    pem.get_name()
                )
            })?;

        fs::remove_file(filepath).with_context(|| format!("could not remove file {filepath}"))?;

        fs::create_dir(filepath)
            .with_context(|| format!("could not create new directory {filepath}"))?;

        let new_filename = format!("{}/{}.crypt", filepath, pem.get_name());

        let vault_file = VaultFile::from_crypted_file_content(&crypted_file_content);

        let mut f = File::create(&new_filename)
            .with_context(|| format!("could not create new crypted file {new_filename}"))?;

        vault_file
            .write(&mut f)
            .with_context(|| format!("could not write to file {new_filename}"))?;

        Ok(())
    }
}
