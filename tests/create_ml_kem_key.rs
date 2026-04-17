//! Tests for the `vault create-ml-kem-key` command.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use predicates::prelude::*;

use self::common::TestVault;

mod common;

#[test]
fn creates_v2_key_files() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["create-ml-kem-key", "newuser"])
        .assert()
        .success();

    assert!(
        vault
            .path()
            .join(".vault/private_keys/newuser.v2.pem")
            .exists()
    );
    assert!(
        vault
            .path()
            .join(".vault/private_keys/newuser.v2.pub.pem")
            .exists()
    );
    assert!(
        vault
            .path()
            .join(".vault/keys/newuser/newuser.v2.pub.pem")
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
fn fails_if_v2_user_exists() {
    let vault = TestVault::builder().with_v2().build();

    vault
        .command()
        .args(["create-ml-kem-key", "testuser"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[cfg(unix)]
#[test]
fn creates_v2_private_key_with_owner_only_permissions() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["create-ml-kem-key", "newuser"])
        .assert()
        .success();

    let metadata = std::fs::metadata(vault.path().join(".vault/private_keys/newuser.v2.pem"))
        .expect("expected V2 private key metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}
