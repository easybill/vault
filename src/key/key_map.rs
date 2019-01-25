use crypto::Crypto;
use crypto::UncryptedVaultFile;
use failure::ResultExt;
use key::Pem;
use key::PrivateKey;
use key::PublicKey;
use proto::VaultFile;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use toml;

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
    is_stisfied: bool,
    // file for subscription exists, but no subscription is required
    // is_orphan: bool todo
}

pub struct KeyMapConfig {
    pub path_private_key: String,
}

impl Subscription {
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
    pub fn build_keys_from_path(root_path: &Path) -> Result<Vec<PublicKey>, ::failure::Error> {
        let mut buffer = vec![];

        let paths = fs::read_dir(root_path).context("could not read user path")?;

        for raw_path in paths {
            let path = raw_path.context("could not parse path")?.path();

            if !path.display().to_string().ends_with(".pub.pem") {
                continue;
            }

            buffer.push(
                PublicKey::load_from_file(&path.display().to_string()).context(format_err!(
                    "could not load public key {}",
                    &path.display().to_string()
                ))?,
            );
        }

        Ok(buffer)
    }

    pub fn build_subscriptions(
        username: &str,
        config: &ConfigToml,
    ) -> HashMap<String, Subscription> {
        let mut buffer = HashMap::new();

        for raw_subscription in &config.subscriptions {
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

        buffer
    }

    pub fn build_private_pems(config: &KeyMapConfig) -> Result<Vec<Pem>, ::failure::Error> {
        let mut buffer = vec![];

        let mut lookup_paths = vec![];

        lookup_paths.push(fs::read_dir(&config.path_private_key).context(format_err!(
            "private key directory {} is not readable",
            &config.path_private_key
        ))?);

        if let Ok(home_path) = fs::read_dir("~/.vault/private_keys") {
            lookup_paths.push(home_path)
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

                if !path_as_string.ends_with(".pem") {
                    eprintln!("info: unexpected file {}", &path_as_string);
                    continue;
                }

                // path is a private key, no lets try to find the pub key.

                let public_key_path =
                    format!("{}.pub.pem", &path_as_string[..path_as_string.len() - 4]);

                let file_exists = match fs::metadata(&public_key_path) {
                    Err(_) => false,
                    Ok(metadata) => metadata.is_file(),
                };

                if !file_exists {
                    return Err(format_err!(
                        "private key given at: {} but public key is not found at: {}",
                        &path_as_string,
                        &public_key_path
                    ));
                }

                buffer.push(Pem::new(
                    PrivateKey::load_from_file(&path_as_string).context(format_err!(
                        "failed, to add key, private key: {}",
                        &path_as_string
                    ))?,
                    PublicKey::load_from_file(&public_key_path).context(format_err!(
                        "failed, to add key, private key: {}",
                        &path_as_string
                    ))?,
                ));
            }
        }

        Ok(buffer)
    }

    pub fn from_path(config: &KeyMapConfig) -> Result<KeyMap, ::failure::Error> {
        let mut buffer = vec![];

        let paths = fs::read_dir("./.vault/keys")
            .map_err(|e| format_err!("could not read ./vault/keys, {}", e))?;

        for path in paths {
            let user_path = match path {
                Err(e) => return Err(format_err!("could not decode user path {}", e)),
                Ok(k) => {
                    let path = k.path();

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
                let mut f = File::open(&config_file_path).map_err(|e| {
                    format_err!(
                        "could not open config file {}, {}",
                        config_file_path.display(),
                        e
                    )
                })?;

                let mut content = String::new();
                f.read_to_string(&mut content).map_err(|e| {
                    format_err!(
                        "could not read config file {}, {}",
                        config_file_path.display(),
                        e
                    )
                })?;

                content
            };

            let decoded_config_file: ConfigToml = toml::from_str(&raw_config).map_err(|_| {
                format_err!("could not parse toml file {}", &config_file_path.display())
            })?;

            buffer.push(KeyMapEntry {
                user: user.clone(),
                subscriptions: Self::build_subscriptions(&user, &decoded_config_file),
                keys: Self::build_keys_from_path(&user_path)?,
            });
        }

        Ok(KeyMap {
            pems: Self::build_private_pems(&config)?,
            entries: buffer,
        })
    }

    pub fn decrypt_subscription(
        &self,
        subscription: &Subscription,
    ) -> Result<UncryptedVaultFile, ::failure::Error> {
        self.decrypt(subscription.get_name())
    }

    pub fn decrypt_subscription_string(
        &self,
        subscription: &Subscription,
    ) -> Result<UncryptedVaultFile, ::failure::Error> {
        self.decrypt(subscription.get_name())
    }

    pub fn decrypt_to_string(&self, subscription_key: &str) -> Result<String, ::failure::Error> {
        let decrypted = self
            .decrypt(&subscription_key)
            .context(format_err!("could not decrypt {}", subscription_key))?;

        Ok(String::from_utf8(decrypted.get_content().to_vec())
            .context(format_err!("Invalid Utf8"))?)
    }
    pub fn decrypt(&self, subscription_key: &str) -> Result<UncryptedVaultFile, ::failure::Error> {
        let possible_files: Vec<String> = {
            let mut buffer = vec![];

            let secret_path = format!("./.vault/secrets/{}", subscription_key);

            let paths = fs::read_dir(&secret_path).context(format_err!(
                "could not read subscription path. directory is missing? {}",
                &secret_path
            ))?;

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
                    eprintln!(
                        "warning: found a invalid file {} in secrets.",
                        &path_as_string
                    );
                    continue;
                }

                buffer.push(path_as_string);
            }

            buffer
        };

        for pem in &self.pems {
            for file in &possible_files {
                let vault_file = {
                    let mut f =
                        File::open(file).context(format_err!("could not read file {}", file))?;

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

        Err(format_err!("could not find key"))
    }

    pub fn could_fulfill_subscription(&self, subscription: &Subscription) -> bool {
        // auf der einen seite müssen wir sicherstellen, dass wir es decrypten können, todo auf der anderen, dass wir den pub key des anderen haben, davon gehe ich erstmal stumpf aus
        self.decrypt_subscription(subscription).is_ok()
    }

    pub fn fulfill_subscription(
        &self,
        subscription: &Subscription,
    ) -> Result<(), ::failure::Error> {
        let uncrypted_vault_file = self
            .decrypt_subscription(subscription)
            .context(format_err!(
                "could not decrypt subscription {}.",
                subscription.get_name()
            ))?;

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
        .ok_or_else(|| format_err!("could not find keys for user"))?;

        if public_keys_for_user.is_empty() {
            panic!("could not found key for user");
        }

        for public_key in public_keys_for_user.iter() {
            let new_filename = format!(
                "./.vault/secrets/{}/{}.crypt",
                subscription.get_name(),
                public_key.get_name()
            );

            println!("create file {}", &new_filename);

            // neue vaultfile erstellen ....

            let crypted_file_content = Crypto::encrypt(&public_key, &uncrypted_vault_file)
                .context(format_err!(
                    "could not crypt data using key {}",
                    public_key.get_name()
                ))?;

            let vault_file = VaultFile::from_crypted_file_content(&crypted_file_content);

            let mut f = File::create(&new_filename).context(format_err!(
                "could not create new crypted file {}",
                &new_filename
            ))?;

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

    pub fn add_new_secet(&self, filepath: &str) -> Result<(), ::failure::Error> {
        let pem = self.get_private_pems().first().ok_or_else(|| {
            format_err!("you've no private key, no idea how to crypt {}", filepath)
        })?;

        let file_content = {
            let mut f = File::open(filepath).context(format_err!("could not open {}", filepath))?;

            let mut content = vec![];
            f.read_to_end(&mut content)
                .context(format_err!("could not read file"))?;

            content
        };

        let uncrypted_file = UncryptedVaultFile::new(file_content);

        let crypted_file_content =
            Crypto::encrypt(pem.get_public_key(), &uncrypted_file).context(format_err!(
                "encryption of {} failed with key {}",
                &filepath,
                pem.get_name()
            ))?;

        fs::remove_file(filepath).context(format_err!("could not remove file {}", filepath))?;

        fs::create_dir(filepath)
            .context(format_err!("could not create new directory {}", filepath))?;

        let new_filename = format!("{}/{}.crypt", filepath, pem.get_name());

        let vault_file = VaultFile::from_crypted_file_content(&crypted_file_content);

        let mut f = File::create(&new_filename).context(format_err!(
            "could not create new crypted file {}",
            &new_filename
        ))?;

        vault_file
            .write(&mut f)
            .context(format_err!("could not write to file {}", &new_filename))?;

        Ok(())
    }
}
