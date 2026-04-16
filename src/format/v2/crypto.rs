use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Context;
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
use rand::rand_core::UnwrapErr;
use sha3::Sha3_256;

use crate::Result;
use crate::format::UnencryptedVaultFile;
use crate::key::{Pem, PublicKey};

use super::proto::VaultFile;

const HKDF_INFO: &[u8] = b"vault-v2-aes256gcm";

/// AES-256 key (32 bytes) + AES-GCM nonce (12 bytes).
const KEY_MATERIAL_SIZE: usize = 32 + 12;

#[derive(Clone)]
pub struct EncryptedFileContent {
    kem_ciphertext: Vec<u8>,
    gcm_ciphertext: Vec<u8>,
}

impl EncryptedFileContent {
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    pub fn gcm_ciphertext(&self) -> &[u8] {
        &self.gcm_ciphertext
    }
}

fn derive_key_material(shared_secret: &[u8]) -> Result<([u8; 32], [u8; 12])> {
    let hkdf = Hkdf::<Sha3_256>::new(None, shared_secret);
    let mut key_material = [0u8; KEY_MATERIAL_SIZE];
    hkdf.expand(HKDF_INFO, &mut key_material)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let mut aes_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    aes_key.copy_from_slice(&key_material[..32]);
    nonce.copy_from_slice(&key_material[32..]);

    Ok((aes_key, nonce))
}

pub struct Crypto;

impl Crypto {
    pub fn encrypt(
        public_key: &PublicKey,
        unencrypted: &UnencryptedVaultFile,
    ) -> Result<EncryptedFileContent> {
        let pem_str =
            std::str::from_utf8(public_key.data()).context("public key is not valid UTF-8")?;

        let ek = EncapsulationKey::<MlKem1024>::from_public_key_pem(pem_str)
            .map_err(|e| anyhow::anyhow!("could not parse ML-KEM-1024 public key: {e}"))?;

        let mut sys_rng = UnwrapErr(rand::rngs::SysRng);
        let (ciphertext, shared_secret) =
            ml_kem::kem::Encapsulate::encapsulate_with_rng(&ek, &mut sys_rng);

        let shared_secret_bytes: &[u8] = shared_secret.as_ref();
        let (aes_key, nonce_bytes) = derive_key_material(shared_secret_bytes)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let gcm_ciphertext = cipher
            .encrypt(nonce, unencrypted.content())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))?;

        let ct_bytes: &[u8] = ciphertext.as_ref();
        Ok(EncryptedFileContent {
            kem_ciphertext: ct_bytes.to_vec(),
            gcm_ciphertext,
        })
    }

    pub fn decrypt(pem: &Pem, vault_file: &VaultFile) -> Result<UnencryptedVaultFile> {
        let pem_str = std::str::from_utf8(pem.private_key().data())
            .context("private key is not valid UTF-8")?;

        let dk = DecapsulationKey::<MlKem1024>::from_pkcs8_pem(pem_str)
            .map_err(|e| anyhow::anyhow!("could not parse ML-KEM-1024 private key: {e}"))?;

        let ct_bytes = vault_file.kem_ciphertext();
        let ciphertext: ml_kem::Ciphertext<MlKem1024> = ct_bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "invalid ML-KEM-1024 ciphertext length: expected 1568, got {}",
                ct_bytes.len()
            )
        })?;

        let shared_secret = dk.decapsulate(&ciphertext);

        let shared_secret_bytes: &[u8] = shared_secret.as_ref();
        let (aes_key, nonce_bytes) = derive_key_material(shared_secret_bytes)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, vault_file.gcm_ciphertext())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM decryption failed: {e}"))?;

        Ok(UnencryptedVaultFile::new(plaintext))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{Pem, PrivateKey, PublicKey};
    use der::pem::LineEnding;
    use ml_kem::kem::Generate;
    use ml_kem::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ml_kem::{DecapsulationKey, MlKem1024};

    fn generate_pem() -> Pem {
        let mut sys_rng = rand::rngs::SysRng;
        let dk = DecapsulationKey::<MlKem1024>::try_generate_from_rng(&mut sys_rng)
            .expect("failed to create decryption key");
        let ek = ml_kem::kem::Decapsulator::encapsulation_key(&dk);

        let private_pem = dk
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to encode private key");
        let public_pem = ek
            .to_public_key_pem(LineEnding::LF)
            .expect("failed to encode public key");

        let private_key = PrivateKey {
            data: private_pem.as_bytes().to_vec(),
            name: "test-private".to_string(),
        };
        let public_key = PublicKey {
            data: public_pem.as_bytes().to_vec(),
            name: "test-public".to_string(),
            is_v2: true,
        };

        Pem::new(private_key, public_key)
    }

    #[test]
    fn test_v2_round_trip() {
        let pem = generate_pem();
        let plaintext = b"hello post-quantum world";
        let unencrypted = UnencryptedVaultFile::new(plaintext.to_vec());

        let encrypted = Crypto::encrypt(pem.public_key(), &unencrypted).unwrap();

        let vault_file = super::super::proto::VaultFile::from_encrypted_file_content(&encrypted);

        let decrypted = Crypto::decrypt(&pem, &vault_file).unwrap();
        assert_eq!(decrypted.content(), plaintext);
    }

    #[test]
    fn test_v2_empty_content() {
        let pem = generate_pem();
        let unencrypted = UnencryptedVaultFile::new(vec![]);

        let encrypted = Crypto::encrypt(pem.public_key(), &unencrypted).unwrap();
        let vault_file = super::super::proto::VaultFile::from_encrypted_file_content(&encrypted);

        let decrypted = Crypto::decrypt(&pem, &vault_file).unwrap();
        assert_eq!(decrypted.content(), &[] as &[u8]);
    }
}
