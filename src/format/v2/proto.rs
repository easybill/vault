use std::borrow::Cow;
use std::io::{Read, Write};

use anyhow::{Context, bail};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use crate::Result;
use crate::format::VAULT_MAGIC_BYTE;

use super::crypto::EncryptedFileContent;

const VAULT_BODY_HEADER_SIZE: usize = 8 + 8;

#[derive(Debug)]
pub struct VaultFile<'a> {
    kem_ciphertext: Cow<'a, [u8]>,
    gcm_ciphertext: Cow<'a, [u8]>,
}

impl<'a> VaultFile<'a> {
    pub fn kem_ciphertext(&self) -> &[u8] {
        self.kem_ciphertext.as_ref()
    }

    pub fn gcm_ciphertext(&self) -> &[u8] {
        self.gcm_ciphertext.as_ref()
    }

    pub fn from_encrypted_file_content(file_content: &'a EncryptedFileContent) -> Self {
        VaultFile {
            kem_ciphertext: Cow::Borrowed(file_content.kem_ciphertext()),
            gcm_ciphertext: Cow::Borrowed(file_content.gcm_ciphertext()),
        }
    }

    /// Read the v2 body from a reader. Assumes the common header (magic byte + version)
    /// has already been consumed by the dispatch layer.
    pub fn open_body(mut content: impl Read) -> Result<Self> {
        let mut header_buffer = vec![0; VAULT_BODY_HEADER_SIZE];

        content
            .read_exact(&mut header_buffer)
            .context("could not read v2 header")?;

        let kem_ciphertext_size = BigEndian::read_u64(&header_buffer[0..8]) as usize;
        let gcm_ciphertext_size = BigEndian::read_u64(&header_buffer[8..16]) as usize;

        if kem_ciphertext_size > 50_000 || gcm_ciphertext_size > 1_000_000_000 {
            bail!("v2 vault file sizes are not supported");
        }

        let mut kem_ciphertext = vec![0; kem_ciphertext_size];
        content
            .read_exact(&mut kem_ciphertext)
            .context("could not read KEM ciphertext")?;

        let mut gcm_ciphertext = vec![0; gcm_ciphertext_size];
        content
            .read_exact(&mut gcm_ciphertext)
            .context("could not read GCM ciphertext")?;

        Ok(VaultFile {
            kem_ciphertext: Cow::Owned(kem_ciphertext),
            gcm_ciphertext: Cow::Owned(gcm_ciphertext),
        })
    }

    pub fn write(&self, mut to: impl Write) -> Result<()> {
        to.write_u16::<BigEndian>(VAULT_MAGIC_BYTE)
            .context("could not write magic byte")?;
        to.write_u16::<BigEndian>(2)
            .context("could not write version")?;
        to.write_u64::<BigEndian>(self.kem_ciphertext.len() as u64)
            .context("could not write KEM ciphertext size")?;
        to.write_u64::<BigEndian>(self.gcm_ciphertext.len() as u64)
            .context("could not write GCM ciphertext size")?;
        to.write_all(self.kem_ciphertext.as_ref())
            .context("could not write KEM ciphertext")?;
        to.write_all(self.gcm_ciphertext.as_ref())
            .context("could not write GCM ciphertext")?;

        Ok(())
    }
}
