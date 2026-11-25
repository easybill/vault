use std::io::{Read, Write};

use anyhow::{Context, bail};
use byteorder::{BigEndian, ByteOrder};

use crate::Result;
use crate::policy;

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

#[derive(Debug)]
pub struct VaultFile {
    version: u16,
    keyfile_content: Vec<u8>,
    secret_content: Vec<u8>,
}

const VAULT_MAGIC_BYTE: u16 = 4242;

/// Size of the header in front of every `.crypt` file: magic, version, key and content length.
pub const VAULT_HEADER_SIZE: usize = 2 + 2 + 8 + 8;

impl VaultFile {
    pub fn new(version: u16, keyfile_content: Vec<u8>, secret_content: Vec<u8>) -> Self {
        VaultFile {
            version,
            keyfile_content,
            secret_content,
        }
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn keyfile_content(&self) -> &[u8] {
        self.keyfile_content.as_slice()
    }

    pub fn secret_content(&self) -> &[u8] {
        self.secret_content.as_slice()
    }

    /// The header of this file, byte for byte as [`VaultFile::write`] writes it.
    pub fn header(&self) -> [u8; VAULT_HEADER_SIZE] {
        Self::header_for(
            self.version,
            self.keyfile_content.len(),
            self.secret_content.len(),
        )
    }

    /// The header of a file with the given version and content lengths.
    pub fn header_for(
        version: u16,
        keyfile_len: usize,
        secret_len: usize,
    ) -> [u8; VAULT_HEADER_SIZE] {
        let mut header = [0; VAULT_HEADER_SIZE];
        BigEndian::write_u16(&mut header[0..2], VAULT_MAGIC_BYTE);
        BigEndian::write_u16(&mut header[2..4], version);
        BigEndian::write_u64(&mut header[4..12], keyfile_len as u64);
        BigEndian::write_u64(&mut header[12..20], secret_len as u64);
        header
    }

    pub fn open(mut content: impl Read) -> Result<Self> {
        let mut header_buffer = vec![0; VAULT_HEADER_SIZE];

        content
            .read_exact(&mut header_buffer)
            .context("could not read header")?;

        let magic_byte = BigEndian::read_u16(&header_buffer[0..2]);

        if magic_byte != VAULT_MAGIC_BYTE {
            bail!("invalid file, magic byte is wrong");
        }

        let version = BigEndian::read_u16(&header_buffer[2..4]);

        if policy::by_file_version(version).is_none() {
            bail!("only version is supported, found {version}");
        }

        let keyfile_size = BigEndian::read_u64(&header_buffer[4..12]) as usize;
        let secret_bytes_size = BigEndian::read_u64(&header_buffer[12..20]) as usize;

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
            version,
            keyfile_content,
            secret_content,
        })
    }

    pub fn write(&self, mut to: impl Write) -> Result<()> {
        to.write_all(&self.header())
            .context("could not write header")?;
        to.write_all(&self.keyfile_content)
            .context("could not write keyfile content")?;
        to.write_all(&self.secret_content)
            .context("could not write secret content")?;

        Ok(())
    }
}
