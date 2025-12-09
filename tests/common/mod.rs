//! Test utilities for vault integration tests.
//!
//! Provides a `TestVault` builder that creates isolated test environments with
//! dynamically generated RSA keys and encrypted secrets.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use assert_cmd::Command;
use byteorder::{BigEndian, WriteBytesExt};
use openssl::rand::{rand_bytes, rand_priv_bytes};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, encrypt};
use tempfile::TempDir;

const KEY_SIZE: usize = 256 / 8; // 32 bytes for AES-256
const IV_SIZE: usize = 128 / 8; // 16 bytes for AES-256-CBC
const VAULT_MAGIC_BYTE: u16 = 4242;

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
}

impl TestVaultBuilder {
    /// Add a secret with the given name and plaintext content.
    pub fn with_secret(mut self, name: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        self.secrets.push((name.into(), content.into()));
        self
    }

    /// Build the TestVault with all fixtures generated.
    pub fn build(self) -> TestVault {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let username = self.username.unwrap_or_else(|| "testuser".to_string());

        // Create .vault directory structure
        let public_key_pem = create_vault_structure(temp_dir.path(), &username);

        // Create encrypted secrets
        for (name, content) in &self.secrets {
            create_encrypted_secret(
                temp_dir.path(),
                &username,
                name,
                content,
                &public_key_pem,
            );
        }

        TestVault { temp_dir, username }
    }
}

/// Create the .vault directory structure with keys for the given user.
/// Returns the public key PEM data for encrypting secrets.
fn create_vault_structure(base_path: &Path, username: &str) -> Vec<u8> {
    let vault_dir = base_path.join(".vault");

    // Create directories
    fs::create_dir_all(vault_dir.join("private_keys")).expect("Failed to create private_keys dir");
    fs::create_dir_all(vault_dir.join("keys").join(username)).expect("Failed to create keys dir");
    fs::create_dir_all(vault_dir.join("secrets")).expect("Failed to create secrets dir");

    // Generate RSA-2048 keypair (smaller than production 8096 for faster tests)
    let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
    let private_pem = rsa
        .private_key_to_pem()
        .expect("Failed to export private key");
    let public_pem = rsa.public_key_to_pem().expect("Failed to export public key");

    // Write private key
    let private_key_path = vault_dir
        .join("private_keys")
        .join(format!("{username}.pem"));
    File::create(&private_key_path)
        .expect("Failed to create private key file")
        .write_all(&private_pem)
        .expect("Failed to write private key");

    // Write public key in private_keys directory
    let public_key_private_path = vault_dir
        .join("private_keys")
        .join(format!("{username}.pub.pem"));
    File::create(&public_key_private_path)
        .expect("Failed to create public key file (private_keys)")
        .write_all(&public_pem)
        .expect("Failed to write public key");

    // Write public key in keys/{username}/ directory
    let public_key_path = vault_dir
        .join("keys")
        .join(username)
        .join(format!("{username}.pub.pem"));
    File::create(&public_key_path)
        .expect("Failed to create public key file")
        .write_all(&public_pem)
        .expect("Failed to write public key");

    // Write config.toml
    let config_path = vault_dir.join("keys").join(username).join("config.toml");
    File::create(&config_path)
        .expect("Failed to create config.toml")
        .write_all(b"subscriptions = []")
        .expect("Failed to write config.toml");

    public_pem
}

/// Encrypt content and write as a .crypt file in the vault file format.
fn create_encrypted_secret(
    base_path: &Path,
    username: &str,
    secret_name: &str,
    content: &[u8],
    public_key_pem: &[u8],
) {
    let vault_dir = base_path.join(".vault");

    // Parse the public key
    let rsa =
        Rsa::public_key_from_pem(public_key_pem).expect("Failed to parse public key for encryption");

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
