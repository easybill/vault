use byteorder::ByteOrder;
use byteorder::{BigEndian, WriteBytesExt};
use crypto::CryptedFileContent;
use failure::Error;
use failure::ResultExt;
use std::io::Read;
use std::io::Write;

#[derive(Debug)]
pub struct VaultHeader {
    version: u16,
    keyfile_size: usize,
    secret_bytes_size: usize,
}

#[derive(Debug)]
pub struct VaultFile {
    header: VaultHeader,
    keyfile_content: Vec<u8>,
    secret_content: Vec<u8>,
}

const VAULT_MAGIC_BYTE: u16 = 4242;

const VAULT_HEADER_SIZE: usize = { 2 + 2 + 8 + 8 };

impl VaultFile {
    pub fn get_keyfile_content(&self) -> &Vec<u8> {
        &self.keyfile_content
    }

    pub fn get_secret_content(&self) -> &Vec<u8> {
        &self.secret_content
    }

    pub fn from_crypted_file_content(file_content: &CryptedFileContent) -> Self {
        VaultFile {
            header: VaultHeader {
                version: 1,
                keyfile_size: file_content.get_crypted_password().len(),
                secret_bytes_size: file_content.get_content().len(),
            },
            keyfile_content: file_content.get_crypted_password().to_vec(), // todo, avoid copy
            secret_content: file_content.get_content().to_vec(),           // todo, avoid copy
        }
    }

    pub fn open(mut content: impl Read) -> Result<Self, Error> {
        let mut header_buffer = vec![0; VAULT_HEADER_SIZE];

        content
            .read_exact(&mut header_buffer)
            .context("could not read header")?;

        let magic_byte: u16 = BigEndian::read_u16(&header_buffer[0..2]);

        if magic_byte != VAULT_MAGIC_BYTE {
            return Err(format_err!("invalid file, magic byte is wrong."));
        }

        let version: u16 = BigEndian::read_u16(&header_buffer[2..4]);

        if version != 1 {
            return Err(format_err!("version is not supported."));
        }

        let keyfile_size = BigEndian::read_u64(&header_buffer[4..12]) as usize;
        let secret_bytes_size = BigEndian::read_u64(&header_buffer[12..20]) as usize;

        if keyfile_size > 50_000 || secret_bytes_size > 1_000_000_000 {
            // ensure nobody kills us with a wrong vault file :)
            return Err(format_err!("keysize is not supported."));
        }

        let mut keyfile_content = vec![0; keyfile_size];
        content
            .read_exact(&mut keyfile_content)
            .context("read keyfile content")?;

        let mut secret_content = vec![0; secret_bytes_size];
        content
            .read_exact(&mut secret_content)
            .context("read secret content")?;

        Ok(VaultFile {
            header: VaultHeader {
                version,
                keyfile_size,
                secret_bytes_size,
            },
            keyfile_content,
            secret_content,
        })
    }

    pub fn write(&self, mut to: impl Write) -> Result<(), Error> {
        to.write_u16::<BigEndian>(VAULT_MAGIC_BYTE)
            .context(format_err!("could not write magic byte"))?;
        to.write_u16::<BigEndian>(1)
            .context(format_err!("could not write version"))?;
        to.write_u64::<BigEndian>(self.keyfile_content.len() as u64)
            .context(format_err!("could not write keyfile"))?;
        to.write_u64::<BigEndian>(self.secret_content.len() as u64)
            .context(format_err!("could not write secret"))?;
        to.write_all(&self.keyfile_content)
            .context(format_err!("could not write keyfile content"))?;
        to.write_all(&self.secret_content)
            .context(format_err!("could not write secret content"))?;

        Ok(())
    }
}
