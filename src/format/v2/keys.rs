use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Error, bail};

use crate::Result;
use crate::key::{Pem, PrivateKey, PublicKey};

/// Load a v2 public key from a `.v2.pub.pem` file (SPKI PEM format, `BEGIN PUBLIC KEY`).
pub fn load_public_key_v2(path: &str) -> Result<PublicKey, Error> {
    const FILE_EXTENSION: &str = ".v2.pub.pem";

    let mut f = File::open(path).with_context(|| format!("could not open file at {path}"))?;
    let mut content: Vec<u8> = vec![];
    f.read_to_end(&mut content)
        .with_context(|| format!("could not read file at {path}"))?;

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
    const FILE_EXTENSION: &str = ".v2.pem";

    let mut f = File::open(path).with_context(|| format!("could not open file at {path}"))?;
    let mut content: Vec<u8> = vec![];
    f.read_to_end(&mut content)
        .with_context(|| format!("could not read file at {path}"))?;

    let name = {
        let mut pieces = path.rsplit('/');
        let filename: String = match pieces.next() {
            Some(p) => p.into(),
            None => path.into(),
        };

        if !filename.ends_with(FILE_EXTENSION) {
            bail!("v2 private key '{path}' does not end with {FILE_EXTENSION}");
        }

        filename.trim_end_matches(FILE_EXTENSION).to_string()
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

            // Only match .v2.pem files (not .v2.pub.pem)
            if !path_as_string.ends_with(".v2.pem") {
                continue;
            }

            let path_as_string_trimmed = path_as_string.trim_end_matches(".v2.pem");
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
