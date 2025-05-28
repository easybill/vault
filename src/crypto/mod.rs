use crate::Result;
use crate::key::PublicKey;
use crate::key::{Pem, PrivateKey};
use crate::proto::VaultFile;
use anyhow::{Context, ensure};
use openssl::rand::{rand_bytes, rand_priv_bytes};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, decrypt, encrypt};

const KEY_SIZE: usize = 256 / 8;
const IV_SIZE: usize = 128 / 8;

#[derive(Clone)]
pub struct CryptedFileContent {
    crypted_password: Vec<u8>,
    content: Vec<u8>,
}

impl CryptedFileContent {
    pub fn get_crypted_password(&self) -> &[u8] {
        self.crypted_password.as_slice()
    }

    pub fn get_content(&self) -> &[u8] {
        self.content.as_slice()
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

    pub fn get_content(&self) -> &[u8] {
        self.content.as_slice()
    }
}

pub struct Crypto;

impl Crypto {
    pub fn encrypt(
        public_key: &PublicKey,
        uncrypted_vault_file: &UncryptedVaultFile,
    ) -> Result<CryptedFileContent> {
        // at first, we need a password, we store the password in the "key"
        let mut password = [0; KEY_SIZE];
        rand_priv_bytes(&mut password)
            .context("could not create random bytes to encrypt vault_file.")?;

        let mut iv = vec![0; IV_SIZE];
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
        // at first, we need to extract the password using the private key.
        let password = Self::key_decrypt(
            pem.get_private_key(),
            crypted_vault_file.get_keyfile_content(),
        )
        .context("could not decrypt password using private key")?;

        let cipher = Cipher::aes_256_cbc();

        ensure!(
            crypted_vault_file.get_secret_content().len() >= IV_SIZE,
            "crypted size is to small, couldnt read enought for IV"
        );

        let (iv, content) = crypted_vault_file.get_secret_content().split_at(IV_SIZE);

        let content = decrypt(cipher, password.as_slice(), Some(iv), content)
            .context("could not encrypt using content")?;

        Ok(UncryptedVaultFile { content })
    }

    pub fn key_encrypt(public_key: &PublicKey, key: &[u8; KEY_SIZE]) -> Result<Vec<u8>> {
        let rsa = openssl::rsa::Rsa::public_key_from_pem(public_key.get_data())
            .with_context(|| format!("invalid public key {}", &public_key.get_name()))?;

        // Since this is a low level function, we can only encrypt data that is less than the
        // size of a signature minus the identifier marker of the padding (11 for PKCS1).
        assert!(KEY_SIZE < (rsa.size() as usize - 11));

        let mut encrypted_data: Vec<u8> = vec![0; rsa.size() as usize];

        let size = rsa
            .public_encrypt(key, encrypted_data.as_mut_slice(), Padding::PKCS1)
            .context("could not encrypt")?;

        // The size of the created signature is pre-determined. Data that is written into it
        // will always be padded to the full signature size.
        assert_eq!(size, encrypted_data.len());

        Ok(encrypted_data)
    }

    pub fn key_decrypt(private_key: &PrivateKey, encrypted_key: &[u8]) -> Result<[u8; KEY_SIZE]> {
        let rsa = Rsa::private_key_from_pem(private_key.get_data())
            .with_context(|| format!("invalid private key {}", &private_key.get_name()))?;

        // The maximal encrypted data can only be the size of the signature minus the identifier
        // marker of the padding (11 for PKCS1). The OpenSSL Rust crate currently doesn't properly
        // check the size based on the padding and always checks as if no padding is used.
        let mut decrypted_data = vec![0; rsa.size() as usize];

        let size = rsa
            .private_decrypt(encrypted_key, decrypted_data.as_mut_slice(), Padding::PKCS1)
            .context("could not decrypt")?;

        assert!(size >= KEY_SIZE);

        let mut key = [0; KEY_SIZE];

        key.copy_from_slice(&decrypted_data[..KEY_SIZE]);

        Ok(key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{Pem, PrivateKey, PublicKey};

    fn generate_pem() -> Pem {
        let rsa = openssl::rsa::Rsa::generate(1024).unwrap();

        let private_key = PrivateKey {
            data: rsa.private_key_to_pem().unwrap(),
            name: "private key".to_string(),
        };

        let public_key = PublicKey {
            data: rsa.public_key_to_pem().unwrap(),
            name: "public key".to_string(),
        };

        Pem::new(private_key, public_key)
    }

    #[test]
    fn test_key_round_trip() {
        let pem = generate_pem();
        let private_key = pem.get_private_key();
        let public_key = pem.get_public_key();

        let mut aes_key = [0; KEY_SIZE];
        rand_priv_bytes(&mut aes_key).unwrap();

        let encrypted_data = Crypto::key_encrypt(public_key, &aes_key).unwrap();
        let decrypted_data = Crypto::key_decrypt(private_key, &encrypted_data).unwrap();

        assert_eq!(aes_key.as_slice(), decrypted_data.as_slice());
    }
}
