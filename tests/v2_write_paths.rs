//! Tests for V2 write-path behavior and failure handling.

use std::fs;

use predicates::prelude::*;

use self::common::TestVault;

mod common;

#[test]
fn auto_selects_v2_for_new_secrets_when_only_v2_keys_exist() {
    let vault = TestVault::builder().with_v2().build();

    fs::write(
        vault.path().join(".vault/secrets/MY_SECRET"),
        "MY_SECRET_CONTENT",
    )
    .unwrap();

    vault.command().assert().success();

    let crypt_path = vault
        .path()
        .join(".vault/secrets/MY_SECRET")
        .join(format!("{}.crypt", vault.username()));
    assert!(crypt_path.exists());

    vault
        .command()
        .args(["get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("MY_SECRET_CONTENT");
}

#[test]
fn invalid_v2_public_key_keeps_plaintext_secret_untouched() {
    let vault = TestVault::builder().with_v2().build();

    fs::write(
        vault.path().join(".vault/private_keys/testuser.v2.pub.pem"),
        "not-a-valid-public-key",
    )
    .unwrap();
    fs::write(
        vault.path().join(".vault/secrets/MY_SECRET"),
        "MY_SECRET_CONTENT",
    )
    .unwrap();

    vault
        .command()
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not parse ML-KEM-1024 public key",
        ));

    let plaintext_path = vault.path().join(".vault/secrets/MY_SECRET");
    assert!(plaintext_path.is_file());
    assert_eq!(
        fs::read_to_string(&plaintext_path).unwrap(),
        "MY_SECRET_CONTENT"
    );
}
