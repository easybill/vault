use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, bail};
use byteorder::{BigEndian, ByteOrder};

use crate::Result;
use crate::key::{Pem, PublicKey};

pub mod v1;
pub mod v2;

pub const VAULT_MAGIC_BYTE: u16 = 4242;

#[derive(Clone, Copy, Default)]
pub enum FormatVersion {
    #[default]
    V1,
    V2,
}

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
        2 => v2::decrypt(pem, reader),
        _ => bail!("unsupported vault file version {version}"),
    }
}

/// Encrypts content and writes the vault file using the specified format version.
pub fn encrypt(
    public_key: &PublicKey,
    unencrypted: &UnencryptedVaultFile,
    writer: impl Write,
    version: FormatVersion,
) -> Result<()> {
    match version {
        FormatVersion::V1 => v1::encrypt(public_key, unencrypted, writer),
        FormatVersion::V2 => v2::encrypt(public_key, unencrypted, writer),
    }
}

/// Creates a new keypair using the specified format version.
pub fn create_keys(username: &str, version: FormatVersion) -> Result<Pem> {
    match version {
        FormatVersion::V1 => v1::keygen::create_keys(username),
        FormatVersion::V2 => v2::keygen::create_keys(username),
    }
}

/// Scan a directory for public keys. Tries both v1 and v2 loaders to support
/// mixed key environments during migration.
pub fn build_keys_from_path(root_path: &Path) -> Result<Vec<PublicKey>> {
    let mut keys = Vec::new();

    if let Ok(v1_keys) = v1::keys::build_keys_from_path_v1(root_path) {
        keys.extend(v1_keys);
    }
    if let Ok(v2_keys) = v2::keys::build_keys_from_path_v2(root_path) {
        keys.extend(v2_keys);
    }

    if keys.is_empty() {
        // Fall back to returning the v1 error for diagnostics.
        v1::keys::build_keys_from_path_v1(root_path)?;
    }

    Ok(keys)
}

/// Load all private key PEM pairs from the configured path. Tries both v1 and v2
/// loaders to support mixed key environments during migration.
pub fn build_private_pems(path_private_key: &str) -> Result<Vec<Pem>> {
    let mut pems = Vec::new();

    if let Ok(v1_pems) = v1::keys::build_private_pems_v1(path_private_key) {
        pems.extend(v1_pems);
    }
    if let Ok(v2_pems) = v2::keys::build_private_pems_v2(path_private_key) {
        pems.extend(v2_pems);
    }

    if pems.is_empty() {
        // Fall back to returning the v1 error for diagnostics.
        v1::keys::build_private_pems_v1(path_private_key)?;
    }

    Ok(pems)
}
