use std::borrow::Cow;
use std::io::{Read, Write};

use anyhow::{Context, bail};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use super::crypto::EncryptedFileContent;
use crate::Result;
use crate::format::VAULT_MAGIC_BYTE;

const VAULT_BODY_HEADER_SIZE: usize = 8 + 8;

#[derive(Debug)]
pub struct VaultFile<'a> {
    keyfile_content: Cow<'a, [u8]>,
    secret_content: Cow<'a, [u8]>,
}

impl<'a> VaultFile<'a> {
    pub fn keyfile_content(&self) -> &[u8] {
        self.keyfile_content.as_ref()
    }

    pub fn secret_content(&self) -> &[u8] {
        self.secret_content.as_ref()
    }

    pub fn from_encrypted_file_content(file_content: &'a EncryptedFileContent) -> Self {
        VaultFile {
            keyfile_content: Cow::Borrowed(file_content.encrypted_key()),
            secret_content: Cow::Borrowed(file_content.encrypted_content()),
        }
    }

    /// Read the v1 body from a reader. Assumes the common header (magic byte + version)
    /// has already been consumed by the dispatch layer.
    pub fn open_body(mut content: impl Read) -> Result<Self> {
        let mut header_buffer = vec![0; VAULT_BODY_HEADER_SIZE];

        content
            .read_exact(&mut header_buffer)
            .context("could not read header")?;

        let keyfile_size = BigEndian::read_u64(&header_buffer[0..8]) as usize;
        let secret_bytes_size = BigEndian::read_u64(&header_buffer[8..16]) as usize;

        if keyfile_size > 50_000 || secret_bytes_size > 1_000_000_000 {
            // ensure nobody kills us with a wrong vault file :)
            bail!("key size is not supported");
        }

        let mut keyfile_content = vec![0; keyfile_size];
        content
            .read_exact(&mut keyfile_content)
            .context("could not read key file contents")?;

        let mut secret_content = vec![0; secret_bytes_size];
        content
            .read_exact(&mut secret_content)
            .context("could not read secret contents")?;

        Ok(VaultFile {
            keyfile_content: Cow::Owned(keyfile_content),
            secret_content: Cow::Owned(secret_content),
        })
    }

    pub fn write(&self, mut to: impl Write) -> Result<()> {
        to.write_u16::<BigEndian>(VAULT_MAGIC_BYTE)
            .context("could not write magic byte")?;
        to.write_u16::<BigEndian>(1)
            .context("could not write version")?;
        to.write_u64::<BigEndian>(self.keyfile_content.len() as u64)
            .context("could not write keyfile")?;
        to.write_u64::<BigEndian>(self.secret_content.len() as u64)
            .context("could not write secret")?;
        to.write_all(&self.keyfile_content)
            .context("could not write keyfile content")?;
        to.write_all(&self.secret_content)
            .context("could not write secret content")?;

        Ok(())
    }
}
