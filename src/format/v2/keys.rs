use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Error, bail};
use ml_kem::kem::{Decapsulator, KeyExport};
use ml_kem::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};

use crate::Result;
use crate::key::{Pem, PrivateKey, PublicKey};

/// Raw file loader with optional GPG decryption for `.pgp` suffixed files.
struct Key;

impl Key {
    fn load_from_file_v2(path: &str) -> Result<Vec<u8>, Error> {
        if path.ends_with(".pgp") {
            return Self::load_from_file_pgp(path)
                .with_context(|| format!("could not decode key at {path}"));
        }

        let mut f = File::open(path).with_context(|| format!("could not open file at {path}"))?;
        let mut content: Vec<u8> = vec![];
        f.read_to_end(&mut content)
            .with_context(|| format!("could not read file at {path}"))?;

        Ok(content)
    }

    fn load_from_file_pgp(path: &str) -> Result<Vec<u8>, Error> {
        let mut child = Command::new("gpg")
            .arg("--decrypt")
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg(path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("could not call gpg")?;

        let mut output_stdout = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            stdout.read_to_string(&mut output_stdout)?;
        }
        let mut output_stderr = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            stderr.read_to_string(&mut output_stderr)?;
        }

        let status = child.wait()?;
        if !status.success() {
            bail!("could not run `gpg --decrypt {path}`, {output_stdout}, {output_stderr}");
        }

        Ok(output_stdout.into_bytes())
    }
}

/// Load a v2 public key from a `.v2.pub.pem` file (SPKI PEM format, `BEGIN PUBLIC KEY`).
pub fn load_public_key_v2(path: &str) -> Result<PublicKey, Error> {
    const FILE_EXTENSION: &str = ".v2.pub.pem";

    let content = Key::load_from_file_v2(path)?;
    let pem_str = std::str::from_utf8(&content).context("public key is not valid UTF-8")?;
    EncapsulationKey::<MlKem1024>::from_public_key_pem(pem_str)
        .map_err(|e| anyhow::anyhow!("could not parse ML-KEM-1024 public key: {e}"))?;

    let name = {
        let mut pieces = path.rsplit('/');
        let mut filename: String = match pieces.next() {
            Some(p) => p.into(),
            None => path.into(),
        };

        if !filename.ends_with(FILE_EXTENSION) {
            bail!("v2 public key '{path}' does not end with {FILE_EXTENSION}");
        }

        filename.truncate(filename.len() - FILE_EXTENSION.len());
        filename
    };

    Ok(PublicKey {
        data: content,
        name,
        is_v2: true,
    })
}

/// Load a v2 private key from a `.v2.pem` file (PKCS#8 PEM format, `BEGIN PRIVATE KEY`).
pub fn load_private_key_v2(path: &str) -> Result<PrivateKey, Error> {
    let content = Key::load_from_file_v2(path)?;
    let pem_str = std::str::from_utf8(&content).context("private key is not valid UTF-8")?;
    DecapsulationKey::<MlKem1024>::from_pkcs8_pem(pem_str)
        .map_err(|e| anyhow::anyhow!("could not parse ML-KEM-1024 private key: {e}"))?;

    let name = {
        let mut pieces = path.rsplit('/');
        let filename: String = match pieces.next() {
            Some(p) => p.into(),
            None => path.into(),
        };

        if !filename.trim_end_matches(".pgp").ends_with(".v2.pem") {
            bail!("v2 private key '{path}' does not end with .v2.pem");
        }

        filename
            .trim_end_matches(".pgp")
            .trim_end_matches(".v2.pem")
            .to_string()
    };

    Ok(PrivateKey {
        data: content,
        name,
    })
}

/// Scan a directory for v2 public keys (`.v2.pub.pem` files).
pub fn build_keys_from_path_v2(root_path: &Path) -> Result<Vec<PublicKey>> {
    let mut buffer = vec![];

    let paths = fs::read_dir(root_path).context("could not read user path")?;

    for raw_path in paths {
        let path = raw_path.context("could not parse path")?.path();
        let path_str = path.display().to_string();

        if !path_str.ends_with(".v2.pub.pem") {
            continue;
        }

        buffer.push(load_public_key_v2(&path_str).with_context(|| {
            format!("could not load v2 public key {path}", path = path.display())
        })?);
    }

    Ok(buffer)
}

/// Load all v2 private key PEM pairs from the configured paths.
pub fn build_private_pems_v2(path_private_key: &str) -> Result<Vec<Pem>> {
    let mut buffer = vec![];

    let mut lookup_paths = vec![];

    lookup_paths
        .push(fs::read_dir(path_private_key).with_context(|| {
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

            if path_as_string.ends_with(".v2.pub.pem")
                || path_as_string.ends_with("_backup_.v2.pub.pem")
            {
                continue;
            }

            if path_as_string.contains("_backup_") {
                continue;
            }

            if !path_as_string.ends_with(".v2.pem") && !path_as_string.ends_with(".v2.pem.pgp") {
                if path_as_string.ends_with(".gitkeep") || path_as_string.ends_with(".bak") {
                    continue;
                }

                eprintln!("info: unexpected file {path_as_string}");
                continue;
            }

            let path_as_string_trimmed = path_as_string
                .trim_end_matches(".pgp")
                .trim_end_matches(".v2.pem");
            let public_key_path = format!("{path_as_string_trimmed}.v2.pub.pem");

            let file_exists = match fs::metadata(&public_key_path) {
                Err(_) => false,
                Ok(metadata) => metadata.is_file(),
            };

            if !file_exists {
                bail!(
                    "could not find a corresponding v2 public key at {public_key_path:?} for private key at {path_as_string:?}",
                );
            }

            buffer.push(Pem::new(
                load_private_key_v2(&path_as_string)
                    .with_context(|| format!("could not add v2 private key: {path_as_string}"))?,
                load_public_key_v2(&public_key_path)
                    .with_context(|| format!("could not add v2 public key: {path_as_string}"))?,
            ));
        }
    }

    Ok(buffer)
}

pub fn validate_pem_v2(pem: &Pem) -> Result<()> {
    let private_key_pem =
        std::str::from_utf8(pem.private_key().data()).context("private key is not valid UTF-8")?;
    let public_key_pem =
        std::str::from_utf8(pem.public_key().data()).context("public key is not valid UTF-8")?;

    let private_key = DecapsulationKey::<MlKem1024>::from_pkcs8_pem(private_key_pem)
        .map_err(|e| anyhow::anyhow!("could not parse ML-KEM-1024 private key: {e}"))?;
    let public_key = EncapsulationKey::<MlKem1024>::from_public_key_pem(public_key_pem)
        .map_err(|e| anyhow::anyhow!("could not parse ML-KEM-1024 public key: {e}"))?;

    let derived_public_key = Decapsulator::encapsulation_key(&private_key);
    let derived_public_key_bytes = derived_public_key.to_bytes();
    let public_key_bytes = public_key.to_bytes();

    if derived_public_key_bytes != public_key_bytes {
        bail!(
            "private key {} does not match public key {}",
            pem.private_key().name(),
            pem.public_key().name()
        );
    }

    Ok(())
}
