//! Tests for the `vault create-openssl-key` command.

use predicates::prelude::*;

use self::common::TestVault;

mod common;

#[test]
fn creates_key_files() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["create-openssl-key", "newuser"])
        .assert()
        .success();

    // Verify the key files were created
    assert!(
        vault
            .path()
            .join(".vault/private_keys/newuser.pem")
            .exists()
    );
    assert!(
        vault
            .path()
            .join(".vault/private_keys/newuser.pub.pem")
            .exists()
    );
    assert!(
        vault
            .path()
            .join(".vault/keys/newuser/newuser.pub.pem")
            .exists()
    );
    assert!(
        vault
            .path()
            .join(".vault/keys/newuser/config.toml")
            .exists()
    );
}

#[test]
fn fails_if_user_exists() {
    let vault = TestVault::builder().build();

    // testuser already exists from the builder
    vault
        .command()
        .args(["create-openssl-key", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}
