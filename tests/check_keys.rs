//! Tests for the `vault check-keys` command.

use std::fs;

use predicates::prelude::*;

use self::common::TestVault;

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
