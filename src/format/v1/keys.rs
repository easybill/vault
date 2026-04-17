use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Error, bail};
use openssl::rsa::Rsa;

use crate::Result;
use crate::key::{Pem, PrivateKey, PublicKey};

/// Raw file loader with optional GPG decryption for `.pgp` suffixed files.
struct Key;

impl Key {
    fn load_from_file_v1(path: &str) -> Result<Vec<u8>, Error> {
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

/// Load a v1 public key from a `.pub.pem` file (SPKI/X.509 PEM format).
pub fn load_public_key_v1(path: &str) -> Result<PublicKey, Error> {
    const FILE_EXTENSION: &str = ".pub.pem";

    let data = Key::load_from_file_v1(path)?;
    Rsa::public_key_from_pem(&data).with_context(|| format!("invalid public key {path}"))?;

    Ok(PublicKey {
        data,
        name: {
            let mut pieces = path.rsplit('/');
            let mut filename: String = match pieces.next() {
                Some(p) => p.into(),
                None => path.into(),
            };

            if !filename.ends_with(FILE_EXTENSION) {
                bail!("public key '{path}' does not end with {FILE_EXTENSION}");
            }

            filename.truncate(filename.len() - FILE_EXTENSION.len());

            filename
        },
        is_v2: false,
    })
}

/// Load a v1 private key from a `.pem` or `.pem.pgp` file (PKCS#1 PEM format).
pub fn load_private_key_v1(path: &str) -> Result<PrivateKey, Error> {
    let data = Key::load_from_file_v1(path)?;
    Rsa::private_key_from_pem(&data).with_context(|| format!("invalid private key {path}"))?;

    Ok(PrivateKey {
        data,
        name: {
            let mut pieces = path.rsplit('/');
            let filename: String = match pieces.next() {
                Some(p) => p.into(),
                None => path.into(),
            };

            if !filename.trim_end_matches(".pgp").ends_with(".pem") {
                bail!("private key '{path}' does not end with .pem");
            }

            filename
                .trim_end_matches(".pgp")
                .trim_end_matches(".pem")
                .to_string()
        },
    })
}

/// Scan a directory for v1 public keys (`.pub.pem` files, excluding `.v2.pub.pem`).
pub fn build_keys_from_path_v1(root_path: &Path) -> Result<Vec<PublicKey>> {
    let mut buffer = vec![];

    let paths = fs::read_dir(root_path).context("could not read user path")?;

    for raw_path in paths {
        let path = raw_path.context("could not parse path")?.path();
        let path_str = path.display().to_string();

        if !path_str.ends_with(".pub.pem") || path_str.ends_with(".v2.pub.pem") {
            continue;
        }

        buffer.push(
            load_public_key_v1(&path.display().to_string()).with_context(|| {
                format!("could not load public key {path}", path = path.display())
            })?,
        );
    }

    Ok(buffer)
}

/// Load all v1 private key PEM pairs from the configured paths.
///
/// Looks in `path_private_key` and `~/.vault/private_keys/`. For each `.pem`
/// or `.pem.pgp` file found, expects a matching `.pub.pem` alongside it.
pub fn build_private_pems_v1(path_private_key: &str) -> Result<Vec<Pem>> {
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

            if path_as_string.ends_with(".pub.pem") {
                continue;
            }

            // Skip v2 key files
            if path_as_string.ends_with(".v2.pem") || path_as_string.ends_with(".v2.pem.pgp") {
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

            let public_key_path = format!("{path_as_string_trimmed}.pub.pem",);

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
                load_private_key_v1(&path_as_string)
                    .with_context(|| format!("could not add private key: {path_as_string}"))?,
                load_public_key_v1(&public_key_path)
                    .with_context(|| format!("could not add public key: {path_as_string}"))?,
            ));
        }
    }

    Ok(buffer)
}

pub fn validate_pem_v1(pem: &Pem) -> Result<()> {
    let private_key = Rsa::private_key_from_pem(pem.private_key().data())
        .with_context(|| format!("invalid private key {}", pem.private_key().name()))?;
    let public_key = Rsa::public_key_from_pem(pem.public_key().data())
        .with_context(|| format!("invalid public key {}", pem.public_key().name()))?;

    let expected_public_der = private_key
        .public_key_to_der()
        .context("could not derive public key from private key")?;
    let actual_public_der = public_key
        .public_key_to_der()
        .context("could not encode public key")?;

    if expected_public_der != actual_public_der {
        bail!(
            "private key {} does not match public key {}",
            pem.private_key().name(),
            pem.public_key().name()
        );
    }

    Ok(())
}
