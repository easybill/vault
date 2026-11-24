use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use openssl::rand::{rand_bytes, rand_priv_bytes};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, decrypt, encrypt};

use crate::Result;
use crate::key::{Pem, PrivateKey, PublicKey, read_key_file};
use crate::policy::{Policy, Rename};
use crate::proto::{UnencryptedVaultFile, VaultFile};

const KEY_SIZE: usize = 256 / 8;
const IV_SIZE: usize = 128 / 8;

const PUBLIC_KEY_EXTENSION: &str = ".pub.pem";

/// RSA keys wrapping an AES-256-CBC content key.
#[derive(Debug)]
pub struct Version1;

impl Policy for Version1 {
    fn file_version(&self) -> u16 {
        1
    }

    fn load_private_keys(&self) -> Result<Vec<Pem>> {
        let path_private_key = Self::private_key_dir();

        let mut buffer = vec![];

        let mut lookup_paths = vec![];

        lookup_paths.push(fs::read_dir(&path_private_key).with_context(|| {
            format!("private key directory {path_private_key} is not readable")
        })?);

        if let Some(home_dir) = dirs::home_dir()
            && let Ok(home_path) = fs::read_dir(home_dir.join(".vault/private_keys"))
        {
            lookup_paths.push(home_path);
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

                if path_as_string.ends_with(PUBLIC_KEY_EXTENSION) {
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

                let path_as_string_trimmed = path_as_string
                    .trim_end_matches(".pgp")
                    .trim_end_matches(".pem");

                let public_key_path = format!("{path_as_string_trimmed}{PUBLIC_KEY_EXTENSION}");

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
                    Self::load_private_key(&path_as_string)
                        .with_context(|| format!("could not add private key: {path_as_string}"))?,
                    Self::load_public_key(&public_key_path)
                        .with_context(|| format!("could not add public key: {path_as_string}"))?,
                ));
            }
        }

        Ok(buffer)
    }

    fn load_public_keys(&self, user_dir: &Path) -> Result<Vec<PublicKey>> {
        let mut buffer = vec![];

        let paths = fs::read_dir(user_dir).context("could not read user path")?;

        for raw_path in paths {
            let path = raw_path.context("could not parse path")?.path();

            if !path.display().to_string().ends_with(PUBLIC_KEY_EXTENSION) {
                continue;
            }

            buffer.push(
                Self::load_public_key(&path.display().to_string()).with_context(|| {
                    format!("could not load public key {path}", path = path.display())
                })?,
            );
        }

        Ok(buffer)
    }

    fn create_key(&self, username: &str) -> Result<Pem> {
        let private_key_path = format!("./.vault/private_keys/{username}.pem");
        let public_key_path = format!("./.vault/private_keys/{username}{PUBLIC_KEY_EXTENSION}");
        let private_key_public_path =
            format!("./.vault/keys/{username}/{username}{PUBLIC_KEY_EXTENSION}");
        let toml_config_path = format!("./.vault/keys/{username}/config.toml");

        println!("generating keys ...");

        for path in [
            &public_key_path,
            &private_key_path,
            &private_key_public_path,
        ]
        .iter()
        {
            if fs::metadata(path).is_ok() {
                bail!("could not create the key, the file {path} already exists");
            }
        }

        // create directory
        let public_directory = format!("./.vault/keys/{username}");

        fs::create_dir(&public_directory)
            .with_context(|| format!("could not create directory {public_directory}"))?;

        // create config.toml
        {
            let mut f = File::create(&toml_config_path)
                .with_context(|| format!("could not create {toml_config_path}"))?;

            f.write_all(b"subscriptions = []")
                .with_context(|| format!("could not write to {toml_config_path}"))?;
        }

        let key = Rsa::generate(8096).context("could not generate rsa code")?;

        {
            let k0pkey = key
                .public_key_to_pem()
                .with_context(|| format!("could not run public_key_to_pem {username}"))?;

            let public_key =
                Rsa::public_key_from_pem(&k0pkey).context("could not decode public key")?;

            let mut f = File::create(&public_key_path)
                .with_context(|| format!("could not create .pem.pub, {public_key_path}"))?;
            f.write_all(&public_key.public_key_to_pem().unwrap())
                .with_context(|| format!("could not write to {public_key_path}"))?;

            let mut f = File::create(&private_key_public_path)
                .with_context(|| format!("could not create .pem.pub, {private_key_public_path}"))?;
            f.write_all(&public_key.public_key_to_pem().unwrap())
                .with_context(|| format!("could not write to {private_key_public_path}"))?;
        }

        {
            let privkey_pem = key.private_key_to_pem().with_context(|| {
                format!("could not translate private key to pem {private_key_path}")
            })?;

            let mut f = File::create(&private_key_path)
                .with_context(|| format!("could not create {private_key_path}"))?;

            f.write_all(&privkey_pem)
                .with_context(|| format!("could not write to {private_key_path}"))?
        }

        Ok(Pem::new(
            Self::load_private_key(&private_key_path)
                .with_context(|| format!("failed, to add key, private key: {private_key_path}"))?,
            Self::load_public_key(&public_key_path)
                .with_context(|| format!("failed, to add key, public key: {public_key_path}"))?,
        ))
    }

    fn encrypt(
        &self,
        public_key: &PublicKey,
        plaintext: &UnencryptedVaultFile,
    ) -> Result<VaultFile> {
        // at first, we need an AES key, we store the AES key using RSA
        let mut aes_key = [0; KEY_SIZE];
        rand_priv_bytes(&mut aes_key)
            .context("could not create random bytes to encrypt vault_file.")?;

        let mut iv = vec![0; IV_SIZE];
        rand_bytes(&mut iv).context("could not create random bytes for iv.")?;

        let key = Self::key_encrypt(public_key, &aes_key)
            .context("could not encrypt the AES key using the public RSA key")?;

        let cipher = Cipher::aes_256_cbc();

        let mut content = encrypt(cipher, &aes_key, Some(&iv), plaintext.content())
            .context("could not encrypt using content")?;

        let mut content_with_iv = iv;

        content_with_iv.append(&mut content);

        Ok(VaultFile::new(self.file_version(), key, content_with_iv))
    }

    fn decrypt(&self, pem: &Pem, file: &VaultFile) -> Result<UnencryptedVaultFile> {
        // at first, we need to extract the AES key using the private RSA key.
        let aes_key = Self::key_decrypt(pem.private_key(), file.keyfile_content())
            .context("could not decrypt AES key using the private RSA key")?;

        let cipher = Cipher::aes_256_cbc();

        ensure!(
            file.secret_content().len() >= IV_SIZE,
            "encrypted size is to small, could not read enough for IV"
        );

        let (iv, content) = file.secret_content().split_at(IV_SIZE);

        let content = decrypt(cipher, aes_key.as_slice(), Some(iv), content)
            .context("could not encrypt using content")?;

        Ok(UnencryptedVaultFile::new(content))
    }

    fn is_rotatable(&self, pem: &Pem) -> bool {
        !pem.name().contains("_backup_")
    }

    fn backup_private_key(&self, username: &str, timestamp: u64) {
        let _ = fs::rename(
            format!("./.vault/private_keys/{username}.pem"),
            format!("./.vault/private_keys/{username}_backup_{timestamp}.pem"),
        );
        let _ = fs::rename(
            format!("./.vault/private_keys/{username}{PUBLIC_KEY_EXTENSION}"),
            format!("./.vault/private_keys/{username}_backup_{timestamp}{PUBLIC_KEY_EXTENSION}"),
        );
    }

    fn key_renames(&self, from: &str, to: &str) -> Vec<Rename> {
        vec![
            Rename {
                from: format!("./.vault/private_keys/{from}.pem"),
                to: format!("./.vault/private_keys/{to}.pem"),
            },
            Rename {
                from: format!("./.vault/private_keys/{from}{PUBLIC_KEY_EXTENSION}"),
                to: format!("./.vault/private_keys/{to}{PUBLIC_KEY_EXTENSION}"),
            },
            Rename {
                from: format!("./.vault/keys/{from}"),
                to: format!("./.vault/keys/{to}"),
            },
            Rename {
                from: format!("./.vault/keys/{to}/{from}{PUBLIC_KEY_EXTENSION}"),
                to: format!("./.vault/keys/{to}/{to}{PUBLIC_KEY_EXTENSION}"),
            },
        ]
    }
}

impl Version1 {
    /// The configured private key directory, `VAULT_PRIVATE_KEY_PATH` or `./.vault/private_keys`.
    fn private_key_dir() -> String {
        std::env::vars()
            .find(|(key, _)| key == "VAULT_PRIVATE_KEY_PATH")
            .map(|(_, value)| value)
            .unwrap_or_else(|| "./.vault/private_keys".to_string())
    }

    /// The last component of a `/` separated path.
    fn file_name(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }

    /// Loads a public key from `<name>.pub.pem`.
    fn load_public_key(path: &str) -> Result<PublicKey> {
        let data = read_key_file(path)?;

        let Some(name) = Self::file_name(path).strip_suffix(PUBLIC_KEY_EXTENSION) else {
            bail!("public key '{path}' does not end with {PUBLIC_KEY_EXTENSION}");
        };

        Ok(PublicKey::new(data, name.to_string(), &Version1))
    }

    /// Loads a private key from `<name>.pem` or the gpg encrypted `<name>.pem.pgp`.
    fn load_private_key(path: &str) -> Result<PrivateKey> {
        let data = read_key_file(path)?;

        let filename = Self::file_name(path);

        if !filename.trim_end_matches(".pgp").ends_with(".pem") {
            bail!("private key '{path}' does not end with .pem");
        }

        let name = filename
            .trim_end_matches(".pgp")
            .trim_end_matches(".pem")
            .to_string();

        Ok(PrivateKey::new(data, name))
    }

    fn key_encrypt(public_key: &PublicKey, key: &[u8; KEY_SIZE]) -> Result<Vec<u8>> {
        let rsa = Rsa::public_key_from_pem(public_key.data())
            .with_context(|| format!("invalid public key {}", public_key.name()))?;

        // Since this is a low level function, we can only encrypt data that is less than the
        // size of a signature minus the identifier marker of the padding (11 for PKCS1).
        assert!(KEY_SIZE < (rsa.size() as usize - 11));

        let mut encrypted_data: Vec<u8> = vec![0; rsa.size() as usize];

        let size = rsa
            .public_encrypt(key, encrypted_data.as_mut_slice(), Padding::PKCS1)
            .context("could not encrypt secret")?;

        // The size of the created signature is pre-determined. Data that is written into it
        // will always be padded to the full signature size.
        assert_eq!(size, encrypted_data.len());

        Ok(encrypted_data)
    }

    fn key_decrypt(private_key: &PrivateKey, encrypted_key: &[u8]) -> Result<Vec<u8>> {
        let rsa = Rsa::private_key_from_pem(private_key.data())
            .with_context(|| format!("invalid private key {}", private_key.name()))?;

        // The maximal encrypted data can only be the size of the signature minus the identifier
        // marker of the padding (11 for PKCS1). The OpenSSL Rust crate currently doesn't properly
        // check the size based on the padding and always checks as if no padding is used.
        let mut unencrypted_data = vec![0; rsa.size() as usize];

        let size = rsa
            .private_decrypt(
                encrypted_key,
                unencrypted_data.as_mut_slice(),
                Padding::PKCS1,
            )
            .context("could not decrypt secret")?;

        // Older versions of vault seem to have created files, which produced keys that are bigger
        // than the expected KEY_SIZE. For compatibility reasons, we have to allow keys that
        // are bigger than KEY_SIZE. The OpenSSL documentation says that keys are of fixed size,
        // but it seems we rely on an undocumented/undefined behavior.
        let unencrypted_key = unencrypted_data[..size].to_vec();

        Ok(unencrypted_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn generate_pem() -> Pem {
        let rsa = Rsa::generate(1024).unwrap();

        let private_key =
            PrivateKey::new(rsa.private_key_to_pem().unwrap(), "private key".to_string());

        let public_key = PublicKey::new(
            rsa.public_key_to_pem().unwrap(),
            "public key".to_string(),
            &Version1,
        );

        Pem::new(private_key, public_key)
    }

    #[test]
    fn test_key_round_trip() {
        let pem = generate_pem();
        let private_key = pem.private_key();
        let public_key = pem.public_key();

        let mut aes_key = [0; KEY_SIZE];
        rand_priv_bytes(&mut aes_key).unwrap();

        let encrypted_data = Version1::key_encrypt(public_key, &aes_key).unwrap();
        let unencrypted_data = Version1::key_decrypt(private_key, &encrypted_data).unwrap();

        assert_eq!(aes_key.as_slice(), unencrypted_data.as_slice());
    }
}
