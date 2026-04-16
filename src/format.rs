use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, bail};
use byteorder::{BigEndian, ByteOrder};

use crate::Result;
use crate::key::{Pem, PublicKey};

pub mod v1;

pub const VAULT_MAGIC_BYTE: u16 = 4242;

#[derive(Clone)]
pub struct UnencryptedVaultFile {
    content: Vec<u8>,
}

impl UnencryptedVaultFile {
    pub fn new(content: Vec<u8>) -> Self {
        UnencryptedVaultFile { content }
    }

    pub fn content(&self) -> &[u8] {
        self.content.as_slice()
    }
}

/// Reads the common header (magic byte + version), then dispatches to the
/// appropriate version module for decryption.
pub fn decrypt(pem: &Pem, mut reader: impl Read) -> Result<UnencryptedVaultFile> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .context("could not read vault file header")?;

    let magic = BigEndian::read_u16(&header[0..2]);
    if magic != VAULT_MAGIC_BYTE {
        bail!("invalid file, magic byte is wrong");
    }

    let version = BigEndian::read_u16(&header[2..4]);
    match version {
        1 => v1::decrypt(pem, reader),
        _ => bail!("unsupported vault file version {version}"),
    }
}

/// Encrypts content and writes the vault file using the current default format version.
pub fn encrypt(
    public_key: &PublicKey,
    unencrypted: &UnencryptedVaultFile,
    writer: impl Write,
) -> Result<()> {
    v1::encrypt(public_key, unencrypted, writer)
}

/// Creates a new keypair using the current default format version.
pub fn create_keys(username: &str) -> Result<Pem> {
    v1::keygen::create_keys(username)
}

/// Scan a directory for public keys using the current default format version.
pub fn build_keys_from_path(root_path: &Path) -> Result<Vec<PublicKey>> {
    v1::keys::build_keys_from_path_v1(root_path)
}

/// Load all private key PEM pairs from the configured path using the current default format version.
pub fn build_private_pems(path_private_key: &str) -> Result<Vec<Pem>> {
    v1::keys::build_private_pems_v1(path_private_key)
}
