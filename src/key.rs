use std::fs::File;
use std::io::Read;
use std::process::Command;

use anyhow::{Context, Error, bail};

use crate::policy::Policy;

pub mod key_map;

#[derive(Debug)]
pub struct PublicKey {
    data: Vec<u8>,
    name: String,
    policy: &'static dyn Policy,
}

#[derive(Debug)]
pub struct PrivateKey {
    data: Vec<u8>,
    name: String,
}

#[derive(Debug)]
pub struct Pem {
    public_key: PublicKey,
    private_key: PrivateKey,
    active: bool,
}

impl Pem {
    /// A local key pair. Only an `active` key encrypts new secrets and can be rotated, every key
    /// decrypts.
    pub fn new(private_key: PrivateKey, public_key: PublicKey, active: bool) -> Self {
        Pem {
            private_key,
            public_key,
            active,
        }
    }

    pub fn name(&self) -> &str {
        self.private_key.name()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn policy(&self) -> &'static dyn Policy {
        self.public_key.policy()
    }
}

/// Reads the content of a key file. Files ending in `.pgp` are decrypted with `gpg`.
pub fn read_key_file(path: &str) -> Result<Vec<u8>, Error> {
    if path.ends_with(".pgp") {
        return read_key_file_pgp(path).with_context(|| format!("could not decode key at {path}"));
    }

    let mut f = File::open(path).with_context(|| format!("could not open file at {path}"))?;
    let mut content: Vec<u8> = vec![];

    f.read_to_end(&mut content)
        .with_context(|| format!("could not read file at {path}"))?;

    Ok(content)
}

fn read_key_file_pgp(path: &str) -> Result<Vec<u8>, Error> {
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

impl PublicKey {
    pub fn new(data: Vec<u8>, name: String, policy: &'static dyn Policy) -> Self {
        PublicKey { data, name, policy }
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn policy(&self) -> &'static dyn Policy {
        self.policy
    }
}

impl PrivateKey {
    pub fn new(data: Vec<u8>, name: String) -> Self {
        PrivateKey { data, name }
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}
