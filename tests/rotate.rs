//! Tests for the `vault rotate` command.

use std::fs;

use self::common::{TestVault, clean_backup_files};

mod common;

#[test]
fn preserves_access() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "MY_CONTENT")
        .build();

    // Rotate keys
    vault.command().args(["rotate"]).assert().success();

    // Clean backup files (they can interfere with key loading)
    clean_backup_files(vault.path());

    // Verify secret still accessible
    vault
        .command()
        .args(["get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("MY_CONTENT");
}

#[test]
fn reads_old_encrypted_files() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "MY_CONTENT")
        .build();

    // Save original encrypted file
    let crypt_path = vault.path().join(format!(
        ".vault/secrets/MY_SECRET/{}.crypt",
        vault.username()
    ));
    let original_crypt = fs::read(&crypt_path).unwrap();

    // Rotate keys
    vault.command().args(["rotate"]).assert().success();

    // Restore old encrypted file (simulating old file encrypted with old key)
    fs::remove_dir_all(vault.path().join(".vault/secrets")).unwrap();
    fs::create_dir_all(vault.path().join(".vault/secrets/MY_SECRET")).unwrap();
    fs::write(&crypt_path, &original_crypt).unwrap();

    // Should still decrypt using backup key
    vault
        .command()
        .args(["get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("MY_CONTENT");
}

#[test]
fn without_secrets_succeeds() {
    let vault = TestVault::builder().build();

    vault.command().args(["rotate"]).assert().success();

    // Verify new key was created and old key was backed up
    let private_keys_dir = vault.path().join(".vault/private_keys");
    let entries: Vec<_> = fs::read_dir(&private_keys_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    // Should have at least: new .pem, new .pub.pem, backup .pem
    assert!(entries.len() >= 3);

    // Verify a backup file was created
    let has_backup = entries
        .iter()
        .any(|e| e.file_name().to_string_lossy().contains("_backup_"));
    assert!(has_backup, "Expected backup file to be created");
}

#[test]
fn with_multiple_secrets() {
    let vault = TestVault::builder()
        .with_secret("SECRET_A", "CONTENT_A")
        .with_secret("SECRET_B", "CONTENT_B")
        .build();

    vault.command().args(["rotate"]).assert().success();

    clean_backup_files(vault.path());

    // Verify all secrets are still accessible
    vault
        .command()
        .args(["get", "SECRET_A"])
        .assert()
        .success()
        .stdout("CONTENT_A");

    vault
        .command()
        .args(["get", "SECRET_B"])
        .assert()
        .success()
        .stdout("CONTENT_B");
}
