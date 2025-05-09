use crate::Result;
use crate::key::Pem;
use crate::key::PublicKey;
use crate::proto::VaultFile;
use anyhow::{Context, anyhow, bail};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, decrypt, encrypt};

#[derive(Clone)]
pub struct CryptedFileContent {
    crypted_password: Vec<u8>,
    content: Vec<u8>,
}

impl CryptedFileContent {
    pub fn get_crypted_password(&self) -> &Vec<u8> {
        &self.crypted_password
    }

    pub fn get_content(&self) -> &Vec<u8> {
        &self.content
    }
}

#[derive(Clone)]
pub struct UncryptedVaultFile {
    content: Vec<u8>,
}

impl UncryptedVaultFile {
    pub fn new(content: Vec<u8>) -> Self {
        UncryptedVaultFile { content }
    }

    pub fn get_content(&self) -> &Vec<u8> {
        &self.content
    }
}

pub struct Crypto;

impl Crypto {
    pub fn encrypt(
        public_key: &PublicKey,
        uncrypted_vault_file: &UncryptedVaultFile,
    ) -> Result<CryptedFileContent> {
        // at first we need a password, we store the password in the "key"
        let mut password = [0; 256 / 8];
        rand_bytes(&mut password)
            .context("could not create random bytes to encrypt vault_file.")?;

        let mut iv = vec![0; 128 / 8];
        rand_bytes(&mut iv).context("could not create random bytes for iv.")?;

        let key = Crypto::key_encrypt(public_key, &password)
            .context("could not encrypt using public_key")?;

        let cipher = Cipher::aes_256_cbc();

        let mut content = encrypt(
            cipher,
            &password,
            Some(&iv),
            uncrypted_vault_file.get_content(),
        )
        .context("could not encrypt using content")?;

        let mut content_with_iv = iv;

        content_with_iv.append(&mut content);

        Ok(CryptedFileContent {
            crypted_password: key,
            content: content_with_iv,
        })
    }

    pub fn decrypt(pem: &Pem, crypted_vault_file: &VaultFile) -> Result<UncryptedVaultFile> {
        // at first we need to extract the password using the private key.
        let password: Vec<u8> = Self::key_decrypt(pem, crypted_vault_file.get_keyfile_content())
            .context("could not decrypt password using private key")?;

        let cipher = Cipher::aes_256_cbc();

        if crypted_vault_file.get_secret_content().len() < 128 / 8 {
            bail!("crypted size is to small, couldnt read enought for IV");
        }

        let iv = &crypted_vault_file.get_secret_content()[0..128 / 8];

        let content = &crypted_vault_file.get_secret_content()[128 / 8..];

        let content = decrypt(cipher, &password, Some(iv), content)
            .context("could not encrypt using content")?;

        Ok(UncryptedVaultFile { content })
    }

    pub fn key_encrypt(public_key: &PublicKey, data: &[u8]) -> Result<Vec<u8>> {
        let rsa = openssl::rsa::Rsa::public_key_from_pem(public_key.get_data())
            .with_context(|| format!("invalid public key {}", &public_key.get_name()))?;

        //let rsa = Rsa::public_key_from_pem(&self.public_key).map_err(|_| { "invalid public key".to_string() })?;
        let mut encrypted_data: Vec<u8> = vec![0; rsa.size() as usize];

        // look at http://php.net/manual/de/function.openssl-public-encrypt.php
        let _ = rsa
            .public_encrypt(data, encrypted_data.as_mut_slice(), Padding::PKCS1)
            .context("could not encrypt")?;

        Ok(encrypted_data)
    }

    pub fn key_decrypt(pem: &Pem, data: &[u8]) -> Result<Vec<u8>> {
        let rsa = Rsa::private_key_from_pem(pem.get_private_key().get_data())
            .context("invalid private key")?;

        let mut decrypted_data: Vec<u8> = vec![0; rsa.size() as usize];

        let size = rsa
            .private_decrypt(data, decrypted_data.as_mut_slice(), Padding::PKCS1)
            .context("could not decrypt")?;

        Ok(decrypted_data[..size].to_vec())
    }
}
