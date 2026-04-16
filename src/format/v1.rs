use std::io::{Read, Write};

use anyhow::Context;

use crate::Result;
use crate::format::UnencryptedVaultFile;
use crate::key::{Pem, PublicKey};

pub(crate) mod crypto;
pub mod keygen;
pub mod keys;
pub(crate) mod proto;

pub fn decrypt(pem: &Pem, reader: impl Read) -> Result<UnencryptedVaultFile> {
    let vault_file =
        proto::VaultFile::open_body(reader).context("could not read v1 vault file")?;
    crypto::Crypto::decrypt(pem, &vault_file).context("could not decrypt v1 vault file")
}

pub fn encrypt(
    public_key: &PublicKey,
    unencrypted: &UnencryptedVaultFile,
    writer: impl Write,
) -> Result<()> {
    let encrypted = crypto::Crypto::encrypt(public_key, unencrypted)
        .context("could not encrypt v1 vault file")?;
    let vault_file = proto::VaultFile::from_encrypted_file_content(&encrypted);
    vault_file
        .write(writer)
        .context("could not write v1 vault file")
}
