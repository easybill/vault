use std::io::{Read, Write};

use anyhow::{Context, bail};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

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

const VAULT_HEADER_SIZE: usize = 2 + 2 + 8 + 8;

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
        to.write_u16::<BigEndian>(VAULT_MAGIC_BYTE)
            .context("could not write magic byte")?;
        to.write_u16::<BigEndian>(self.version)
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
