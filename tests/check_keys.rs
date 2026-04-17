//! Tests for the `vault check-keys` command.

use std::fs;

use predicates::prelude::*;

use self::common::{TestVault, create_fake_gpg_dir, wrap_v2_private_key_with_gpg};

mod common;

#[test]
fn succeeds_with_valid_keys() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["check-keys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keys are fine"));
}

#[test]
fn fails_without_private_keys() {
    let vault = TestVault::builder().build();

    // Remove the private keys directory contents
    let private_keys_dir = vault.path().join(".vault/private_keys");
    for entry in fs::read_dir(&private_keys_dir).unwrap() {
        let entry = entry.unwrap();
        fs::remove_file(entry.path()).unwrap();
    }

    vault
        .command()
        .args(["check-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no private key"));
}

#[test]
fn succeeds_with_valid_v2_keys() {
    let vault = TestVault::builder().with_v2().build();

    vault
        .command()
        .args(["check-keys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keys are fine"));
}

#[test]
fn fails_with_invalid_v2_keys_even_if_v1_keys_are_valid() {
    let vault = TestVault::builder().with_mixed_formats().build();

    fs::remove_file(vault.path().join(".vault/private_keys/testuser.v2.pub.pem")).unwrap();

    vault
        .command()
        .args(["check-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not find a corresponding v2 public key",
        ));
}

#[test]
fn succeeds_with_gpg_wrapped_v2_private_key() {
    let vault = TestVault::builder().with_v2().build();
    let fake_gpg_dir = create_fake_gpg_dir();

    wrap_v2_private_key_with_gpg(vault.path(), "testuser");

    vault
        .command()
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_gpg_dir.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args(["check-keys"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keys are fine"));
}

#[test]
fn ignores_v2_backup_private_keys_during_loading() {
    let vault = TestVault::builder().with_v2().build();

    fs::rename(
        vault.path().join(".vault/private_keys/testuser.v2.pem"),
        vault
            .path()
            .join(".vault/private_keys/testuser_backup_123.v2.pem"),
    )
    .unwrap();
    fs::rename(
        vault.path().join(".vault/private_keys/testuser.v2.pub.pem"),
        vault
            .path()
            .join(".vault/private_keys/testuser_backup_123.v2.pub.pem"),
    )
    .unwrap();

    vault
        .command()
        .args(["check-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no private key"));
}
