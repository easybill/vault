//! Test utilities for vault integration tests.
//!
//! Provides a `TestVault` builder that creates isolated test environments with
//! dynamically generated key material and encrypted secrets.

#![allow(dead_code)] // Not all test files use all helpers

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use assert_cmd::Command;
use byteorder::{BigEndian, WriteBytesExt};
use der::pem::LineEnding;
use hkdf::Hkdf;
use ml_kem::kem::{Encapsulate, Generate};
use ml_kem::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
use openssl::rand::{rand_bytes, rand_priv_bytes};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, encrypt};
use rand::rand_core::UnwrapErr;
use sha3::Sha3_256;
use tempfile::TempDir;

const KEY_SIZE: usize = 256 / 8; // 32 bytes for AES-256
const IV_SIZE: usize = 128 / 8; // 16 bytes for AES-256-CBC
const VAULT_MAGIC_BYTE: u16 = 4242;
const HKDF_INFO: &[u8] = b"vault-v2-aes256gcm";
const KEY_MATERIAL_SIZE: usize = 32 + 12;

#[derive(Clone, Copy, Default)]
pub enum TestVaultFormat {
    #[default]
    V1,
    V2,
    Mixed,
}

/// A test vault environment with isolated directory and generated fixtures.
pub struct TestVault {
    temp_dir: TempDir,
    username: String,
}

impl TestVault {
    /// Create a new TestVault builder.
    pub fn builder() -> TestVaultBuilder {
        TestVaultBuilder::default()
    }

    /// Get the path to the vault directory.
    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Create a Command configured to run vault in this test directory.
    #[allow(deprecated)] // cargo_bin works fine for standard cargo layouts
    pub fn command(&self) -> Command {
        let mut cmd = Command::cargo_bin("vault").unwrap();
        cmd.current_dir(self.path()).env("VAULT_FORCE_YES", "1");
        cmd
    }

    /// Get the username used for this vault.
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// Builder for creating test vault environments.
#[derive(Default)]
pub struct TestVaultBuilder {
    username: Option<String>,
    secrets: Vec<(String, Vec<u8>)>,
    format: TestVaultFormat,
}

impl TestVaultBuilder {
    /// Add a secret with the given name and plaintext content.
    pub fn with_secret(mut self, name: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.secrets.push((name.into(), content.into()));
        self
    }

    pub fn with_v2(mut self) -> Self {
        self.format = TestVaultFormat::V2;
        self
    }

    pub fn with_mixed_formats(mut self) -> Self {
        self.format = TestVaultFormat::Mixed;
        self
    }

    /// Build the TestVault with all fixtures generated.
    pub fn build(self) -> TestVault {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let username = self.username.unwrap_or_else(|| "testuser".to_string());

        create_base_vault_structure(temp_dir.path(), &username);

        let mut v1_public_key_pem = None;
        let mut v2_public_key_pem = None;

        match self.format {
            TestVaultFormat::V1 => {
                v1_public_key_pem = Some(create_v1_keys(temp_dir.path(), &username));
            }
            TestVaultFormat::V2 => {
                v2_public_key_pem = Some(create_v2_keys(temp_dir.path(), &username));
            }
            TestVaultFormat::Mixed => {
                v1_public_key_pem = Some(create_v1_keys(temp_dir.path(), &username));
                v2_public_key_pem = Some(create_v2_keys(temp_dir.path(), &username));
            }
        }

        for (name, content) in &self.secrets {
            match self.format {
                TestVaultFormat::V1 | TestVaultFormat::Mixed => create_encrypted_secret_v1(
                    temp_dir.path(),
                    &username,
                    name,
                    content,
                    v1_public_key_pem
                        .as_deref()
                        .expect("v1 public key should exist for v1 fixtures"),
                ),
                TestVaultFormat::V2 => create_encrypted_secret_v2(
                    temp_dir.path(),
                    &username,
                    name,
                    content,
                    v2_public_key_pem
                        .as_deref()
                        .expect("v2 public key should exist for v2 fixtures"),
                ),
            }
        }

        TestVault { temp_dir, username }
    }
}

fn create_base_vault_structure(base_path: &Path, username: &str) {
    let vault_dir = base_path.join(".vault");

    fs::create_dir_all(vault_dir.join("private_keys")).expect("Failed to create private_keys dir");
    fs::create_dir_all(vault_dir.join("keys").join(username)).expect("Failed to create keys dir");
    fs::create_dir_all(vault_dir.join("secrets")).expect("Failed to create secrets dir");

    let config_path = vault_dir.join("keys").join(username).join("config.toml");
    if !config_path.exists() {
        File::create(&config_path)
            .expect("Failed to create config.toml")
            .write_all(b"subscriptions = []")
            .expect("Failed to write config.toml");
    }
}

fn create_v1_keys(base_path: &Path, username: &str) -> Vec<u8> {
    let vault_dir = base_path.join(".vault");

    let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
    let private_pem = rsa
        .private_key_to_pem()
        .expect("Failed to export private key");
    let public_pem = rsa
        .public_key_to_pem()
        .expect("Failed to export public key");

    let private_key_path = vault_dir
        .join("private_keys")
        .join(format!("{username}.pem"));
    File::create(&private_key_path)
        .expect("Failed to create private key file")
        .write_all(&private_pem)
        .expect("Failed to write private key");

    let public_key_private_path = vault_dir
        .join("private_keys")
        .join(format!("{username}.pub.pem"));
    File::create(&public_key_private_path)
        .expect("Failed to create public key file (private_keys)")
        .write_all(&public_pem)
        .expect("Failed to write public key");

    let public_key_path = vault_dir
        .join("keys")
        .join(username)
        .join(format!("{username}.pub.pem"));
    File::create(&public_key_path)
        .expect("Failed to create public key file")
        .write_all(&public_pem)
        .expect("Failed to write public key");

    public_pem
}

fn create_v2_keys(base_path: &Path, username: &str) -> Vec<u8> {
    let vault_dir = base_path.join(".vault");

    let mut sys_rng = rand::rngs::SysRng;
    let dk = DecapsulationKey::<MlKem1024>::try_generate_from_rng(&mut sys_rng)
        .expect("Failed to generate ML-KEM private key");
    let ek = ml_kem::kem::Decapsulator::encapsulation_key(&dk);

    let private_pem = dk
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to export ML-KEM private key");
    let public_pem = ek
        .to_public_key_pem(LineEnding::LF)
        .expect("Failed to export ML-KEM public key");

    let private_key_path = vault_dir
        .join("private_keys")
        .join(format!("{username}.v2.pem"));
    File::create(&private_key_path)
        .expect("Failed to create V2 private key file")
        .write_all(private_pem.as_bytes())
        .expect("Failed to write V2 private key");

    let public_key_private_path = vault_dir
        .join("private_keys")
        .join(format!("{username}.v2.pub.pem"));
    File::create(&public_key_private_path)
        .expect("Failed to create V2 public key file (private_keys)")
        .write_all(public_pem.as_bytes())
        .expect("Failed to write V2 public key");

    let public_key_path = vault_dir
        .join("keys")
        .join(username)
        .join(format!("{username}.v2.pub.pem"));
    File::create(&public_key_path)
        .expect("Failed to create V2 public key file")
        .write_all(public_pem.as_bytes())
        .expect("Failed to write V2 public key");

    public_pem.as_bytes().to_vec()
}

fn derive_v2_key_material(shared_secret: &[u8]) -> ([u8; 32], [u8; 12]) {
    let hkdf = Hkdf::<Sha3_256>::new(None, shared_secret);
    let mut key_material = [0u8; KEY_MATERIAL_SIZE];
    hkdf.expand(HKDF_INFO, &mut key_material)
        .expect("Failed to derive V2 key material");

    let mut aes_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    aes_key.copy_from_slice(&key_material[..32]);
    nonce.copy_from_slice(&key_material[32..]);

    (aes_key, nonce)
}

/// Encrypt content and write as a .crypt file in the v1 vault file format.
fn create_encrypted_secret_v1(
    base_path: &Path,
    username: &str,
    secret_name: &str,
    content: &[u8],
    public_key_pem: &[u8],
) {
    let vault_dir = base_path.join(".vault");

    // Parse the public key
    let rsa = Rsa::public_key_from_pem(public_key_pem)
        .expect("Failed to parse public key for encryption");

    // Generate AES key and IV
    let mut aes_key = [0u8; KEY_SIZE];
    rand_priv_bytes(&mut aes_key).expect("Failed to generate AES key");

    let mut iv = vec![0u8; IV_SIZE];
    rand_bytes(&mut iv).expect("Failed to generate IV");

    // Encrypt AES key with RSA public key
    let mut encrypted_aes_key = vec![0u8; rsa.size() as usize];
    let encrypted_key_len = rsa
        .public_encrypt(&aes_key, &mut encrypted_aes_key, Padding::PKCS1)
        .expect("Failed to encrypt AES key");
    assert_eq!(encrypted_key_len, encrypted_aes_key.len());

    // Encrypt content with AES-256-CBC
    let cipher = Cipher::aes_256_cbc();
    let encrypted_content =
        encrypt(cipher, &aes_key, Some(&iv), content).expect("Failed to encrypt content");

    // Prepend IV to encrypted content
    let mut content_with_iv = iv;
    content_with_iv.extend(encrypted_content);

    // Create secret directory and write vault file
    let secret_dir = vault_dir.join("secrets").join(secret_name);
    fs::create_dir_all(&secret_dir).expect("Failed to create secret directory");

    let crypt_file_path = secret_dir.join(format!("{username}.crypt"));
    let mut file = File::create(&crypt_file_path).expect("Failed to create crypt file");

    // Write vault file format (from src/proto.rs):
    // [magic_byte: u16][version: u16][key_size: u64][content_size: u64][encrypted_key][iv+encrypted_content]
    file.write_u16::<BigEndian>(VAULT_MAGIC_BYTE)
        .expect("Failed to write magic byte");
    file.write_u16::<BigEndian>(1)
        .expect("Failed to write version");
    file.write_u64::<BigEndian>(encrypted_aes_key.len() as u64)
        .expect("Failed to write key size");
    file.write_u64::<BigEndian>(content_with_iv.len() as u64)
        .expect("Failed to write content size");
    file.write_all(&encrypted_aes_key)
        .expect("Failed to write encrypted key");
    file.write_all(&content_with_iv)
        .expect("Failed to write encrypted content");
}

/// Encrypt content and write as a .crypt file in the v2 vault file format.
fn create_encrypted_secret_v2(
    base_path: &Path,
    username: &str,
    secret_name: &str,
    content: &[u8],
    public_key_pem: &[u8],
) {
    let vault_dir = base_path.join(".vault");

    let public_key_pem = std::str::from_utf8(public_key_pem).expect("public key should be UTF-8");
    let ek = EncapsulationKey::<MlKem1024>::from_public_key_pem(public_key_pem)
        .expect("Failed to parse ML-KEM public key");

    let mut sys_rng = UnwrapErr(rand::rngs::SysRng);
    let (ciphertext, shared_secret) = Encapsulate::encapsulate_with_rng(&ek, &mut sys_rng);
    let ciphertext_bytes: &[u8] = ciphertext.as_ref();
    let (aes_key, nonce_bytes) = derive_v2_key_material(shared_secret.as_ref());

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let gcm_ciphertext = cipher
        .encrypt(nonce, content)
        .expect("Failed to encrypt V2 content");

    let secret_dir = vault_dir.join("secrets").join(secret_name);
    fs::create_dir_all(&secret_dir).expect("Failed to create secret directory");

    let crypt_file_path = secret_dir.join(format!("{username}.crypt"));
    let mut file = File::create(&crypt_file_path).expect("Failed to create crypt file");

    file.write_u16::<BigEndian>(VAULT_MAGIC_BYTE)
        .expect("Failed to write magic byte");
    file.write_u16::<BigEndian>(2)
        .expect("Failed to write version");
    file.write_u64::<BigEndian>(ciphertext_bytes.len() as u64)
        .expect("Failed to write KEM ciphertext size");
    file.write_u64::<BigEndian>(gcm_ciphertext.len() as u64)
        .expect("Failed to write GCM ciphertext size");
    file.write_all(ciphertext_bytes)
        .expect("Failed to write KEM ciphertext");
    file.write_all(&gcm_ciphertext)
        .expect("Failed to write GCM ciphertext");
}

/// Helper to remove backup files created during key rotation.
pub fn clean_backup_files(vault_path: &Path) {
    let private_keys_dir = vault_path.join(".vault/private_keys");
    if let Ok(entries) = fs::read_dir(&private_keys_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.to_string_lossy().contains("_backup_") {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

pub fn create_fake_gpg_dir() -> TempDir {
    let fake_gpg_dir = TempDir::new().expect("Failed to create fake GPG directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(fake_gpg_dir.path(), fs::Permissions::from_mode(0o700))
            .expect("Failed to lock down fake GPG directory permissions");
    }
    let gpg_path = fake_gpg_dir.path().join("gpg");
    fs::write(
        &gpg_path,
        "#!/bin/sh\nfor last_arg do :; done\ncat \"$last_arg\"\n",
    )
    .expect("Failed to write fake gpg binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&gpg_path, fs::Permissions::from_mode(0o755))
            .expect("Failed to mark fake gpg binary executable");
    }

    fake_gpg_dir
}

pub fn wrap_v2_private_key_with_gpg(vault_path: &Path, username: &str) {
    let private_key_path = vault_path
        .join(".vault/private_keys")
        .join(format!("{username}.v2.pem"));
    let encrypted_private_key_path = vault_path
        .join(".vault/private_keys")
        .join(format!("{username}.v2.pem.pgp"));

    fs::rename(&private_key_path, &encrypted_private_key_path)
        .expect("Failed to move V2 private key to .pgp path");
}
