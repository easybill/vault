//! `vault get` on the command line: raw output, how the secret name is used and how the
//! configuration of every user is read before a secret is decrypted.

use std::fs;
use std::process::Output;

use crate::common::{TestVault, assert_failure, assert_success, run};
use crate::support::GOLDEN;

fn get(vault: &TestVault, secret: &str) -> Output {
    run(vault.command().args(["get", secret]))
}

#[test]
fn stdout_is_the_raw_secret() {
    let vault = TestVault::from_fixture(GOLDEN);
    let cases: &[(&str, &[u8])] = &[
        ("SIMPLE", b"hello world"),
        ("EMPTY", b""),
        (
            "UNICODE_MULTILINE",
            "Grüße, Welt!\n🔐 Schlüssel 🗝️\r\nlast line\n".as_bytes(),
        ),
        ("BINARY", &(0..=255).collect::<Vec<u8>>()),
    ];

    // No newline is added and bytes that are not UTF-8 (NUL, 0xFF, ...) are written as is.
    for (secret, stdout) in cases {
        assert_success(&get(&vault, secret), stdout, "", secret);
    }
}

#[test]
fn secret_name_is_used_as_a_path() {
    let vault = TestVault::from_fixture(GOLDEN);

    // The name is not validated, `./.vault/secrets/<name>` is read as given.
    for secret in ["../secrets/SIMPLE", "./SIMPLE", "SIMPLE/"] {
        assert_success(&get(&vault, secret), b"hello world", "", secret);
    }
}

#[test]
fn plaintext_secret_that_was_not_added_is_not_readable() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::write(vault.path().join(".vault/secrets/NEW"), "plaintext").unwrap();

    // The secret exists, but the error talks about the subscription path.
    assert_failure(
        &get(&vault, "NEW"),
        "Vault error: could not read subscription path. directory is missing? \
         ./.vault/secrets/NEW\n\nCaused by:\n    Not a directory (os error 20)\n",
        "get NEW",
    );
}

#[test]
fn invalid_config_of_another_user_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    let config = vault.path().join(".vault/keys/bob/config.toml");
    fs::write(&config, "subscriptions = [").unwrap();

    // Every user's config is read before anything else, so bob's broken config stops
    // alice from reading her own secret.
    let error = "Vault error: could not parse toml file ./.vault/keys/bob/config.toml\n";
    assert_failure(&get(&vault, "SIMPLE"), error, "get SIMPLE");
    assert_failure(&run(vault.command().arg("check-keys")), error, "check-keys");
}

#[test]
fn missing_config_of_another_user_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::remove_file(vault.path().join(".vault/keys/bob/config.toml")).unwrap();

    // Bob's missing config stops alice from reading her own secret.
    assert_failure(
        &get(&vault, "SIMPLE"),
        "Vault error: could not open config file ./.vault/keys/bob/config.toml, \
         No such file or directory (os error 2)\n",
        "get SIMPLE",
    );
}

#[test]
fn invalid_glob_of_another_user_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::write(
        vault.path().join(".vault/keys/bob/config.toml"),
        r#"subscriptions = ["[a"]"#,
    )
    .unwrap();
    let cause = globset::Glob::new("[a").unwrap_err();
    let error = format!(
        "Vault error: could not fetch subscriptions\n\nCaused by:\n    \
         0: could not get subscriptions\n    \
         1: error when compiling glob pattern [a\n    \
         2: {cause}\n"
    );

    // Bob's broken glob stops alice from reading her own secret.
    assert_failure(&get(&vault, "SIMPLE"), &error, "get SIMPLE");
    assert_failure(
        &run(vault.command().arg("check-keys")),
        &error,
        "check-keys",
    );
}

#[test]
fn files_in_the_keys_dir_and_users_without_public_key_are_fine() {
    let vault = TestVault::from_fixture(GOLDEN);
    let keys = vault.path().join(".vault/keys");
    fs::write(keys.join("README.md"), "not a user").unwrap();
    fs::create_dir(keys.join("carol")).unwrap();
    fs::write(keys.join("carol/config.toml"), "subscriptions = []").unwrap();

    assert_success(&get(&vault, "SIMPLE"), b"hello world", "", "SIMPLE");
}
