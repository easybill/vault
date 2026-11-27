use std::cmp::Reverse;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Generate, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{Context, anyhow, bail, ensure};
use pem_rfc7468::LineEnding;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;
use x_wing::{
    CIPHERTEXT_SIZE, Ciphertext, DECAPSULATION_KEY_SIZE, Decapsulate, DecapsulationKey,
    Decapsulator, ENCAPSULATION_KEY_SIZE, Encapsulate, EncapsulationKey, KeyExport, SharedKey,
};

use crate::Result;
use crate::key::{Pem, PrivateKey, PublicKey, read_key_file};
use crate::policy::{Policy, Rename};
use crate::proto::{UnencryptedVaultFile, VaultFile};

const PRIVATE_KEY_LABEL: &str = "XWING PRIVATE KEY";
const PUBLIC_KEY_LABEL: &str = "XWING PUBLIC KEY";

const PRIVATE_KEY_EXTENSION: &str = ".pem";
const PGP_PRIVATE_KEY_EXTENSION: &str = ".pem.pgp";
const PUBLIC_KEY_EXTENSION: &str = ".pem.pub";
/// Every file of a key pair, the private key files first.
const KEY_EXTENSIONS: [&str; 3] = [
    PRIVATE_KEY_EXTENSION,
    PGP_PRIVATE_KEY_EXTENSION,
    PUBLIC_KEY_EXTENSION,
];

/// Added to the repository ID for the new key while a V2 key is rotated.
const ROTATE_SUFFIX: &str = "_to_rotate";

const REPOSITORY_ID_PATH: &str = "./.vault/repository_id";

/// Domain separation for deriving the AES key from the X-Wing shared key.
const CONTENT_KEY_LABEL: &[u8] = b"vault v2 aes-256-gcm";
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

/// X-Wing (ML-KEM-768 + X25519) wrapping an AES-256-GCM content key.
///
/// Private keys live outside the repository in the key directory ([`Version2::key_dir`]),
/// named after the repository ID: `<ID>.pem` with `<ID>.pem.pub` for the current key and
/// `<ID>_backup_<unix seconds>.pem` with `.pem.pub` for older ones. A private key can also be
/// stored gpg encrypted as `.pem.pgp` instead of `.pem`. While a V2 key is rotated, the new key
/// is `<ID>_to_rotate.pem` with `.pem.pub` and is not loaded. Nothing in the key directory is
/// overwritten or deleted. A local key belongs to the user whose registered public key
/// `.vault/keys/<user>/*.pem.pub` holds the same key.
#[derive(Debug)]
pub struct Version2;

impl Policy for Version2 {
    fn file_version(&self) -> u16 {
        2
    }

    fn load_private_keys(&self) -> Result<Vec<Pem>> {
        let Some(repository_id) = read_repository_id()? else {
            return Ok(vec![]);
        };

        let Some(key_dir) = Self::key_dir() else {
            return Ok(vec![]);
        };

        let entries = match fs::read_dir(&key_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("V2 key directory {} is not readable", key_dir.display())
                });
            }
        };

        let mut private_keys = vec![];

        for entry in entries {
            let file_name = entry.context("could not parse path")?.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };

            let Some(stem) = file_name
                .strip_suffix(PGP_PRIVATE_KEY_EXTENSION)
                .or_else(|| file_name.strip_suffix(PRIVATE_KEY_EXTENSION))
            else {
                continue;
            };

            let backup_timestamp = if stem == repository_id {
                None
            } else if let Some(timestamp) = stem
                .strip_prefix(&repository_id)
                .and_then(|rest| rest.strip_prefix("_backup_"))
                .filter(|timestamp| timestamp.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|timestamp| timestamp.parse::<u64>().ok())
            {
                Some(timestamp)
            } else {
                continue;
            };

            private_keys.push((backup_timestamp, file_name.to_string(), stem.to_string()));
        }

        // The current key first, then the backups, newest first.
        private_keys.sort_by_key(|(backup_timestamp, file_name, _)| {
            (
                backup_timestamp.is_some(),
                Reverse(*backup_timestamp),
                file_name.clone(),
            )
        });

        let mut registered_keys = None;
        let mut buffer = vec![];

        for (_, file_name, stem) in private_keys {
            let private_key_path = key_dir.join(&file_name).display().to_string();
            let public_key_path = key_dir
                .join(format!("{stem}{PUBLIC_KEY_EXTENSION}"))
                .display()
                .to_string();

            let file_exists = match fs::metadata(&public_key_path) {
                Err(_) => false,
                Ok(metadata) => metadata.is_file(),
            };

            if !file_exists {
                bail!(
                    "could not find a corresponding public key at {public_key_path:?} for private key at {private_key_path:?}",
                );
            }

            let private_pem = read_key_file(&private_key_path)
                .with_context(|| format!("could not add private key: {private_key_path}"))?;
            let public_pem = read_key_file(&public_key_path)
                .with_context(|| format!("could not add public key: {public_key_path}"))?;

            let public_key_bytes = decode_private_key(&private_pem)
                .with_context(|| format!("could not add private key: {private_key_path}"))?
                .encapsulation_key()
                .to_bytes();

            let local_public_key_bytes =
                decode_pem(&public_pem, PUBLIC_KEY_LABEL, ENCAPSULATION_KEY_SIZE)
                    .with_context(|| format!("could not add public key: {public_key_path}"))?;

            ensure!(
                local_public_key_bytes == public_key_bytes.as_slice(),
                "the public key {public_key_path} does not belong to the private key \
                 {private_key_path}"
            );

            if registered_keys.is_none() {
                registered_keys = Some(registered_public_keys()?);
            }

            let user = registered_keys
                .iter()
                .flatten()
                .find(|(_, key)| key.as_slice() == public_key_bytes.as_slice())
                .map(|(user, _)| user.clone());

            let active = user.is_some();
            let name = user.unwrap_or(stem);

            buffer.push(Pem::new(
                PrivateKey::new(private_pem, name.clone()),
                PublicKey::new(public_pem, name, &Version2),
                active,
            ));
        }

        Ok(buffer)
    }

    fn load_public_keys(&self, user_dir: &Path) -> Result<Vec<PublicKey>> {
        let mut buffer = vec![];

        let paths = fs::read_dir(user_dir).context("could not read user path")?;

        for raw_path in paths {
            let path = raw_path.context("could not parse path")?.path();
            let path_as_string = path.display().to_string();

            let Some(name) = path
                .file_name()
                .and_then(|file_name| file_name.to_str())
                .and_then(|file_name| file_name.strip_suffix(PUBLIC_KEY_EXTENSION))
            else {
                continue;
            };

            let data = read_key_file(&path_as_string)
                .with_context(|| format!("could not load public key {path_as_string}"))?;

            buffer.push(PublicKey::new(data, name.to_string(), &Version2));
        }

        Ok(buffer)
    }

    fn create_key(&self, username: &str) -> Result<Pem> {
        println!("generating keys ...");

        let key_dir = Self::existing_key_dir()?;
        let repository_id = read_repository_id()?;

        if let Some(repository_id) = &repository_id {
            ensure_no_key_files(&key_dir, repository_id)?;
        }

        create_key_pair(&key_dir, repository_id, "", username, b"subscriptions = []")
    }

    fn encrypt(
        &self,
        public_key: &PublicKey,
        plaintext: &UnencryptedVaultFile,
    ) -> Result<VaultFile> {
        let encapsulation_key = decode_public_key(public_key.data())
            .with_context(|| format!("invalid public key {}", public_key.name()))?;

        let (kem_ciphertext, shared_key) = encapsulation_key.encapsulate();
        let nonce = Nonce::<Aes256Gcm>::generate();

        let content_len = NONCE_SIZE + plaintext.content().len() + TAG_SIZE;
        let header = VaultFile::header_for(self.file_version(), kem_ciphertext.len(), content_len);

        let ciphertext = content_cipher(&shared_key)
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.content(),
                    aad: &header,
                },
            )
            .map_err(|_| anyhow!("could not encrypt the content"))?;

        let mut content = nonce.to_vec();
        content.extend(ciphertext);

        Ok(VaultFile::new(
            self.file_version(),
            kem_ciphertext.to_vec(),
            content,
        ))
    }

    fn decrypt(&self, pem: &Pem, file: &VaultFile) -> Result<UnencryptedVaultFile> {
        let kem_ciphertext = Ciphertext::try_from(file.keyfile_content()).map_err(|_| {
            anyhow!(
                "the X-Wing ciphertext must have {CIPHERTEXT_SIZE} bytes, found {}",
                file.keyfile_content().len()
            )
        })?;

        ensure!(
            file.secret_content().len() >= NONCE_SIZE + TAG_SIZE,
            "encrypted size is too small, could not read nonce and tag"
        );

        let decapsulation_key = decode_private_key(pem.private_key().data())
            .with_context(|| format!("invalid private key {}", pem.name()))?;
        let shared_key = decapsulation_key.decapsulate(&kem_ciphertext);

        let (nonce, ciphertext) = file.secret_content().split_at(NONCE_SIZE);
        let nonce = Nonce::<Aes256Gcm>::try_from(nonce).context("invalid nonce")?;

        let content = content_cipher(&shared_key)
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &file.header(),
                },
            )
            .map_err(|_| anyhow!("could not decrypt the content"))?;

        Ok(UnencryptedVaultFile::new(content))
    }

    /// Replacing a V2 key writes `<ID>_to_rotate.pem` with `.pem.pub`, replacing a key of an older
    /// policy writes the current key `<ID>.pem` with `.pem.pub` and creates the repository ID if
    /// it is missing. Either fails before writing anything if a leftover `<ID>_to_rotate` file or
    /// one of the files to write exists. The new user gets the `config.toml` of the replaced user.
    fn create_replacement_key(&self, username: &str, replaced: &Pem) -> Result<Pem> {
        println!("generating keys ...");

        let key_dir = Self::existing_key_dir()?;
        let repository_id = read_repository_id()?;
        let same_policy = replaced.policy().file_version() == self.file_version();

        if let Some(repository_id) = &repository_id {
            for extension in KEY_EXTENSIONS {
                let path = key_dir.join(format!("{repository_id}{ROTATE_SUFFIX}{extension}"));
                if exists(&path) {
                    bail!(
                        "could not rotate the key, the file {} is left over from an interrupted \
                         rotation, remove it once the repository is restored with git",
                        path.display()
                    );
                }
            }

            if !same_policy {
                ensure_no_key_files(&key_dir, repository_id)?;
            }
        }

        let config_path = format!("./.vault/keys/{}/config.toml", replaced.name());
        let config = match fs::read(&config_path) {
            Ok(config) => config,
            Err(error) if error.kind() == ErrorKind::NotFound => b"subscriptions = []".to_vec(),
            Err(error) => {
                return Err(error).with_context(|| format!("could not read {config_path}"));
            }
        };

        let stem_suffix = if same_policy { ROTATE_SUFFIX } else { "" };

        create_key_pair(&key_dir, repository_id, stem_suffix, username, &config)
    }

    /// Renames every file of the current key (`<ID>.pem`, `<ID>.pem.pgp`, `<ID>.pem.pub`), no
    /// matter which user it belongs to, to `<ID>_backup_<timestamp>`. If a file of that backup
    /// name exists, the timestamp is increased until none does.
    fn backup_private_key(&self, _username: &str, timestamp: u64) -> Result<()> {
        let key_dir = Self::existing_key_dir()?;
        let repository_id = read_repository_id()?
            .with_context(|| format!("could not find the repository ID {REPOSITORY_ID_PATH}"))?;

        let current_extensions: Vec<&str> = KEY_EXTENSIONS
            .into_iter()
            .filter(|extension| exists(&key_dir.join(format!("{repository_id}{extension}"))))
            .collect();

        let mut timestamp = timestamp;
        while KEY_EXTENSIONS.into_iter().any(|extension| {
            exists(&key_dir.join(format!("{repository_id}_backup_{timestamp}{extension}")))
        }) {
            timestamp += 1;
        }

        for extension in current_extensions {
            let from = key_dir.join(format!("{repository_id}{extension}"));
            let to = key_dir.join(format!("{repository_id}_backup_{timestamp}{extension}"));

            fs::rename(&from, &to).with_context(|| {
                format!("could not rename {} to {}", from.display(), to.display())
            })?;
        }

        Ok(())
    }

    /// `<ID>_to_rotate.pem.pub` and `.pem` become the current key if they exist, then the user
    /// directory and the public key in it are renamed. The public key comes first, a public key
    /// without its private key is never loaded.
    fn key_renames(&self, from: &str, to: &str) -> Result<Vec<Rename>> {
        let key_dir = Self::existing_key_dir()?;
        let repository_id = read_repository_id()?
            .with_context(|| format!("could not find the repository ID {REPOSITORY_ID_PATH}"))?;

        let mut renames = vec![];

        for extension in [PUBLIC_KEY_EXTENSION, PRIVATE_KEY_EXTENSION] {
            let rotated = key_dir.join(format!("{repository_id}{ROTATE_SUFFIX}{extension}"));

            if exists(&rotated) {
                renames.push(Rename {
                    from: rotated.display().to_string(),
                    to: key_dir
                        .join(format!("{repository_id}{extension}"))
                        .display()
                        .to_string(),
                });
            }
        }

        renames.push(Rename {
            from: format!("./.vault/keys/{from}"),
            to: format!("./.vault/keys/{to}"),
        });
        renames.push(Rename {
            from: format!("./.vault/keys/{to}/{from}{PUBLIC_KEY_EXTENSION}"),
            to: format!("./.vault/keys/{to}/{to}{PUBLIC_KEY_EXTENSION}"),
        });

        Ok(renames)
    }
}

impl Version2 {
    /// The key directory: `VAULT_V2_KEY_PATH` unless it is empty, else `~/.vault/v2`. `None`
    /// without either.
    fn key_dir() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("VAULT_V2_KEY_PATH")
            && !path.is_empty()
        {
            return Some(PathBuf::from(path));
        }

        dirs::home_dir().map(|home_dir| home_dir.join(".vault/v2"))
    }

    /// The key directory for writing keys, an error without one.
    fn existing_key_dir() -> Result<PathBuf> {
        Self::key_dir().context(
            "could not find the home directory for the V2 key directory ~/.vault/v2, \
             set VAULT_V2_KEY_PATH",
        )
    }
}

/// Whether a file, directory or symlink exists at `path`.
fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Fails if a key file `<stem>.pem`, `<stem>.pem.pgp` or `<stem>.pem.pub` exists in `key_dir`.
fn ensure_no_key_files(key_dir: &Path, stem: &str) -> Result<()> {
    for extension in KEY_EXTENSIONS {
        let path = key_dir.join(format!("{stem}{extension}"));
        if exists(&path) {
            bail!(
                "could not create the key, the file {} already exists",
                path.display()
            );
        }
    }

    Ok(())
}

/// Generates a key pair, writes it as `<ID><stem_suffix>.pem` with `.pem.pub` and registers it as
/// `.vault/keys/<username>/` with `config`. Creates the repository ID if `repository_id` is
/// `None`. Fails before writing anything if the user directory exists.
fn create_key_pair(
    key_dir: &Path,
    repository_id: Option<String>,
    stem_suffix: &str,
    username: &str,
    config: &[u8],
) -> Result<Pem> {
    let user_dir = format!("./.vault/keys/{username}");

    if exists(Path::new(&user_dir)) {
        bail!("could not create the key, the user directory {user_dir} already exists");
    }

    let repository_id = match repository_id {
        Some(repository_id) => repository_id,
        None => create_repository_id()?,
    };
    let stem = format!("{repository_id}{stem_suffix}");

    let decapsulation_key = DecapsulationKey::generate();
    let private_pem = encode_private_key(&decapsulation_key)?;
    let public_pem = encode_public_key(decapsulation_key.encapsulation_key())?;

    // The public key comes first, a public key without its private key is never loaded.
    create_key_dir(key_dir)?;
    create_file(
        &key_dir.join(format!("{stem}{PUBLIC_KEY_EXTENSION}")),
        public_pem.as_bytes(),
        false,
    )?;
    create_file(
        &key_dir.join(format!("{stem}{PRIVATE_KEY_EXTENSION}")),
        private_pem.as_bytes(),
        true,
    )?;

    fs::create_dir(&user_dir).with_context(|| format!("could not create directory {user_dir}"))?;
    create_file(Path::new(&format!("{user_dir}/config.toml")), config, false)?;
    create_file(
        Path::new(&format!("{user_dir}/{username}{PUBLIC_KEY_EXTENSION}")),
        public_pem.as_bytes(),
        false,
    )?;

    Ok(Pem::new(
        PrivateKey::new(private_pem.into_bytes(), username.to_string()),
        PublicKey::new(public_pem.into_bytes(), username.to_string(), &Version2),
        true,
    ))
}

/// The repository ID from `.vault/repository_id` in its canonical form, `None` if the file is
/// missing.
fn read_repository_id() -> Result<Option<String>> {
    let content = match fs::read_to_string(REPOSITORY_ID_PATH) {
        Ok(content) => content,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {REPOSITORY_ID_PATH}"));
        }
    };

    let repository_id = Uuid::try_parse(content.trim())
        .with_context(|| format!("invalid repository ID in {REPOSITORY_ID_PATH}"))?;

    Ok(Some(repository_id.hyphenated().to_string()))
}

/// Writes a new UUIDv7 to `.vault/repository_id`, which must not exist yet.
fn create_repository_id() -> Result<String> {
    let repository_id = Uuid::now_v7().hyphenated().to_string();

    create_file(
        Path::new(REPOSITORY_ID_PATH),
        format!("{repository_id}\n").as_bytes(),
        false,
    )?;

    Ok(repository_id)
}

/// The public keys registered in `.vault/keys/*/*.pem.pub` that can be decoded, with their
/// user, sorted by path.
fn registered_public_keys() -> Result<Vec<(String, Vec<u8>)>> {
    let mut paths = vec![];

    for user_entry in fs::read_dir("./.vault/keys").context("could not read ./.vault/keys")? {
        let user_path = user_entry.context("could not parse path")?.path();

        if !user_path.is_dir() {
            continue;
        }

        let Some(user) = user_path
            .file_name()
            .map(|file_name| file_name.to_string_lossy().to_string())
        else {
            continue;
        };

        for key_entry in fs::read_dir(&user_path)
            .with_context(|| format!("could not read {}", user_path.display()))?
        {
            let key_path = key_entry.context("could not parse path")?.path();

            if key_path
                .display()
                .to_string()
                .ends_with(PUBLIC_KEY_EXTENSION)
            {
                paths.push((key_path, user.clone()));
            }
        }
    }

    paths.sort();

    Ok(paths
        .into_iter()
        .filter_map(|(path, user)| {
            let data = fs::read(path).ok()?;
            let key = decode_pem(&data, PUBLIC_KEY_LABEL, ENCAPSULATION_KEY_SIZE).ok()?;
            Some((user, key))
        })
        .collect())
}

/// Creates the key directory (mode 0700 on unix) if it does not exist.
fn create_key_dir(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    builder
        .create(path)
        .with_context(|| format!("could not create directory {}", path.display()))
}

/// Writes a file that must not exist yet. A `private` file gets mode 0600 on unix.
fn create_file(path: &Path, content: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    let _ = private;

    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;

    file.write_all(content)
        .with_context(|| format!("could not write to {}", path.display()))
}

/// The AES-256-GCM cipher keyed with `SHA3-256(CONTENT_KEY_LABEL || shared_key)`.
fn content_cipher(shared_key: &SharedKey) -> Aes256Gcm {
    let key = Sha3_256::new()
        .chain_update(CONTENT_KEY_LABEL)
        .chain_update(shared_key)
        .finalize();

    Aes256Gcm::new(&key)
}

/// The content of a PEM block with the given label and content length.
fn decode_pem(data: &[u8], label: &str, len: usize) -> Result<Vec<u8>> {
    let (actual_label, content) = pem_rfc7468::decode_vec(data).context("invalid PEM")?;

    ensure!(
        actual_label == label,
        "expected a PEM block with the label {label}, found {actual_label}"
    );
    ensure!(
        content.len() == len,
        "expected {len} bytes in the PEM block {label}, found {}",
        content.len()
    );

    Ok(content)
}

fn encode_private_key(key: &DecapsulationKey) -> Result<String> {
    pem_rfc7468::encode_string(PRIVATE_KEY_LABEL, LineEnding::LF, key.as_bytes())
        .context("could not encode the private key")
}

fn encode_public_key(key: &EncapsulationKey) -> Result<String> {
    pem_rfc7468::encode_string(PUBLIC_KEY_LABEL, LineEnding::LF, &key.to_bytes())
        .context("could not encode the public key")
}

fn decode_private_key(data: &[u8]) -> Result<DecapsulationKey> {
    let content = decode_pem(data, PRIVATE_KEY_LABEL, DECAPSULATION_KEY_SIZE)?;

    let mut seed = [0; DECAPSULATION_KEY_SIZE];
    seed.copy_from_slice(&content);

    Ok(DecapsulationKey::from(seed))
}

fn decode_public_key(data: &[u8]) -> Result<EncapsulationKey> {
    let content = decode_pem(data, PUBLIC_KEY_LABEL, ENCAPSULATION_KEY_SIZE)?;

    EncapsulationKey::try_from(content.as_slice()).context("invalid X-Wing public key")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proto::VAULT_HEADER_SIZE;

    fn generate_pem() -> Pem {
        let decapsulation_key = DecapsulationKey::generate();
        let private_pem = encode_private_key(&decapsulation_key).unwrap();
        let public_pem = encode_public_key(decapsulation_key.encapsulation_key()).unwrap();

        Pem::new(
            PrivateKey::new(private_pem.into_bytes(), "private key".to_string()),
            PublicKey::new(public_pem.into_bytes(), "public key".to_string(), &Version2),
            true,
        )
    }

    fn encrypt_to_bytes(pem: &Pem, plaintext: &[u8]) -> Vec<u8> {
        let file = Version2
            .encrypt(
                pem.public_key(),
                &UnencryptedVaultFile::new(plaintext.to_vec()),
            )
            .unwrap();
        let mut bytes = vec![];
        file.write(&mut bytes).unwrap();
        bytes
    }

    fn decrypt_bytes(pem: &Pem, bytes: &[u8]) -> Result<Vec<u8>> {
        let file = VaultFile::open(bytes)?;
        Ok(Version2.decrypt(pem, &file)?.content().to_vec())
    }

    #[test]
    fn test_round_trip() {
        let pem = generate_pem();

        for plaintext in [&b""[..], b"x", b"hello world", &[0xAB; 100_000]] {
            let bytes = encrypt_to_bytes(&pem, plaintext);

            assert_eq!(
                bytes.len(),
                VAULT_HEADER_SIZE + CIPHERTEXT_SIZE + NONCE_SIZE + plaintext.len() + TAG_SIZE
            );
            assert_eq!(&bytes[2..4], &2u16.to_be_bytes());
            assert_eq!(decrypt_bytes(&pem, &bytes).unwrap(), plaintext);
        }
    }

    #[test]
    fn test_every_tampered_region_fails() {
        let pem = generate_pem();
        let bytes = encrypt_to_bytes(&pem, b"hello world");
        assert_eq!(decrypt_bytes(&pem, &bytes).unwrap(), b"hello world");

        let nonce_start = VAULT_HEADER_SIZE + CIPHERTEXT_SIZE;
        let ciphertext_start = nonce_start + NONCE_SIZE;

        let flip = |index: usize| {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            tampered
        };

        // Version 1 is a valid version, so only the authentication of the header rejects it.
        let mut version_1 = bytes.clone();
        version_1[2..4].copy_from_slice(&1u16.to_be_bytes());

        // A shorter content length still parses, the last byte of the tag is then left unread.
        let mut shorter_content = bytes.clone();
        let content_len = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        shorter_content[12..20].copy_from_slice(&(content_len - 1).to_be_bytes());

        for (region, tampered) in [
            ("header version", version_1),
            ("header content length", shorter_content),
            ("KEM ciphertext start", flip(VAULT_HEADER_SIZE)),
            ("KEM ciphertext end", flip(nonce_start - 1)),
            ("nonce", flip(nonce_start)),
            ("ciphertext", flip(ciphertext_start)),
            ("tag", flip(bytes.len() - 1)),
        ] {
            assert!(decrypt_bytes(&pem, &tampered).is_err(), "{region}");
        }
    }

    #[test]
    fn test_wrong_lengths_fail() {
        let pem = generate_pem();
        let file = Version2
            .encrypt(
                pem.public_key(),
                &UnencryptedVaultFile::new(b"hello world".to_vec()),
            )
            .unwrap();

        let short_kem = VaultFile::new(
            2,
            file.keyfile_content()[..CIPHERTEXT_SIZE - 1].to_vec(),
            file.secret_content().to_vec(),
        );
        assert!(Version2.decrypt(&pem, &short_kem).is_err());

        let short_content = VaultFile::new(
            2,
            file.keyfile_content().to_vec(),
            file.secret_content()[..NONCE_SIZE + TAG_SIZE - 1].to_vec(),
        );
        assert!(Version2.decrypt(&pem, &short_content).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let pem = generate_pem();
        let other = generate_pem();
        let bytes = encrypt_to_bytes(&pem, b"hello world");

        assert!(decrypt_bytes(&other, &bytes).is_err());
    }

    #[test]
    fn test_key_pem_round_trip() {
        let decapsulation_key = DecapsulationKey::generate();
        let encapsulation_key = decapsulation_key.encapsulation_key();

        let private_pem = encode_private_key(&decapsulation_key).unwrap();
        let public_pem = encode_public_key(encapsulation_key).unwrap();

        assert!(private_pem.starts_with("-----BEGIN XWING PRIVATE KEY-----\n"));
        assert!(private_pem.ends_with("-----END XWING PRIVATE KEY-----\n"));
        assert!(public_pem.starts_with("-----BEGIN XWING PUBLIC KEY-----\n"));
        assert!(public_pem.ends_with("-----END XWING PUBLIC KEY-----\n"));
        assert!(!private_pem.contains('\r') && !public_pem.contains('\r'));

        assert_eq!(
            decode_private_key(private_pem.as_bytes())
                .unwrap()
                .as_bytes(),
            decapsulation_key.as_bytes()
        );
        assert_eq!(
            &decode_public_key(public_pem.as_bytes()).unwrap(),
            encapsulation_key
        );

        // Each key is only accepted with its own label and length.
        assert!(decode_private_key(public_pem.as_bytes()).is_err());
        assert!(decode_public_key(private_pem.as_bytes()).is_err());
        let short =
            pem_rfc7468::encode_string(PRIVATE_KEY_LABEL, LineEnding::LF, &[0; 31]).unwrap();
        assert!(decode_private_key(short.as_bytes()).is_err());
    }
}
