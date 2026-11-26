//! `vault create-openssl-key <user>`: a new 8096-bit key pair in `.vault/private_keys/` and the
//! user dir `.vault/keys/<user>/` with the public key and an empty subscription list.
//!
//! Generating the key takes seconds, so only one test generates one.

use std::fs;
use std::process::Output;

use openssl::rsa::Rsa;

use crate::common::{TestVault, assert_only_changed, assert_output, assert_success, run, snapshot};
use crate::support::{GOLDEN, assert_crypt_file};

const GENERATING: &[u8] = b"generating keys ...\n";

fn create_key(vault: &TestVault, user: &str) -> Output {
    run(vault.command().args(["create-openssl-key", user]))
}

/// Asserts a failed run that printed only the first progress line.
fn assert_create_failure(output: &Output, stderr: &str, context: &str) {
    assert_output(output, 1, GENERATING, stderr, context);
}

/// Asserts that `pem` is a PEM block with the given label and nothing else.
fn assert_pem(pem: &[u8], label: &str, context: &str) {
    let pem = std::str::from_utf8(pem).expect("PEM is text");
    assert!(
        pem.starts_with(&format!("-----BEGIN {label}-----\n")),
        "{context}: {pem}"
    );
    assert!(
        pem.ends_with(&format!("-----END {label}-----\n")),
        "{context}: {pem}"
    );
    assert_eq!(pem.matches("-----BEGIN").count(), 1, "{context}: {pem}");
}

#[test]
fn creates_a_key_pair_and_the_user_dir() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    assert_success(&create_key(&vault, "carol"), GENERATING, "", "create carol");

    let private_keys = vault.path().join(".vault/private_keys");
    let user_dir = vault.path().join(".vault/keys/carol");
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/private_keys/carol.pem",
            ".vault/private_keys/carol.pub.pem",
            ".vault/keys/carol",
            ".vault/keys/carol/carol.pub.pem",
            ".vault/keys/carol/config.toml",
        ],
    );
    assert_eq!(
        fs::read(user_dir.join("config.toml")).unwrap(),
        b"subscriptions = []"
    );

    let private_pem = fs::read(private_keys.join("carol.pem")).unwrap();
    let public_pem = fs::read(private_keys.join("carol.pub.pem")).unwrap();
    assert_pem(&private_pem, "RSA PRIVATE KEY", "private key");
    assert_pem(&public_pem, "PUBLIC KEY", "public key");
    assert_eq!(
        fs::read(user_dir.join("carol.pub.pem")).unwrap(),
        public_pem,
        "both public keys are equal"
    );

    let rsa = Rsa::private_key_from_pem(&private_pem).unwrap();
    assert!(rsa.check_key().unwrap(), "valid key");
    assert_eq!(rsa.n().num_bits(), 8096, "modulus size");
    assert_eq!(
        rsa.public_key_to_pem().unwrap(),
        public_pem,
        "the public key belongs to the private key"
    );

    // Keep carol's key pair outside the default key dir, so that only alice's key is loaded.
    let carol_keys = vault.path().join("carol_keys");
    fs::create_dir(&carol_keys).unwrap();
    for file in ["carol.pem", "carol.pub.pem"] {
        fs::rename(private_keys.join(file), carol_keys.join(file)).unwrap();
    }

    // alice fulfills a subscription of carol with the new public key.
    fs::write(
        user_dir.join("config.toml"),
        r#"subscriptions = ["SIMPLE"]"#,
    )
    .unwrap();
    assert_success(
        &run(&mut vault.command()),
        b"\ncreate key map.\n\nloaded keys:\n- alice\n\n\
          open subscriptions you've the required right to fulfill (1):\n  \
          - user: carol, name: SIMPLE\n\n\
          creating file ./.vault/secrets/SIMPLE/carol.crypt\n\nall fine\n\n",
        "",
        "alice fulfills carol's subscription",
    );
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "carol"),
        &private_pem,
        b"hello world",
    );

    // carol adds a new secret with the new private key.
    fs::write(vault.secret_dir("NEW"), "carol's secret").unwrap();
    let as_carol = || {
        let mut cmd = vault.command();
        cmd.env("VAULT_PRIVATE_KEY_PATH", "carol_keys");
        cmd
    };
    assert_success(
        &run(&mut as_carol()),
        b"\ncreate key map.\n\n\nnew secrets (1):\n  - ./.vault/secrets/NEW\n\n\
          loaded keys:\n- carol\n\nall fine\n\n",
        "",
        "carol adds a secret",
    );
    assert_crypt_file(
        &vault.crypt_path("NEW", "carol"),
        &private_pem,
        b"carol's secret",
    );
    for (secret, content) in [("SIMPLE", &b"hello world"[..]), ("NEW", b"carol's secret")] {
        assert_success(&run(as_carol().args(["get", secret])), content, "", secret);
    }
}

#[test]
fn existing_key_file_is_not_overwritten() {
    // The files are checked in this order, the first existing one is reported.
    for (index, existing) in [
        "./.vault/private_keys/dave.pub.pem",
        "./.vault/private_keys/dave.pem",
        "./.vault/keys/dave/dave.pub.pem",
    ]
    .into_iter()
    .enumerate()
    {
        let vault = TestVault::from_fixture(GOLDEN);
        let path = vault.path().join(existing);
        if index == 2 {
            fs::create_dir(path.parent().unwrap()).unwrap();
            fs::write(path.with_file_name("config.toml"), "subscriptions = []").unwrap();
        }
        fs::write(&path, "existing").unwrap();
        let before = snapshot(&vault.path());
        let mut cmd = vault.command();
        if index == 1 {
            // A private key without its public key in the loaded key dir fails before, so the
            // keys are loaded from another dir.
            cmd.env("VAULT_PRIVATE_KEY_PATH", "bob_private_keys");
        }

        assert_create_failure(
            &run(cmd.args(["create-openssl-key", "dave"])),
            &format!("Vault error: could not create the key, the file {existing} already exists\n"),
            existing,
        );
        assert_eq!(
            snapshot(&vault.path()),
            before,
            "{existing}: nothing may change"
        );
    }
}

#[test]
fn existing_user_is_not_overwritten() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    assert_create_failure(
        &create_key(&vault, "alice"),
        "Vault error: could not create the key, the file ./.vault/private_keys/alice.pub.pem \
         already exists\n",
        "alice",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

#[test]
fn existing_user_dir_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    let user_dir = vault.path().join(".vault/keys/dave");
    fs::create_dir(&user_dir).unwrap();

    // Every command reads every user dir first, so a user dir without config.toml
    // stops even the command that would create it.
    assert_output(
        &create_key(&vault, "dave"),
        1,
        b"",
        "Vault error: could not open config file ./.vault/keys/dave/config.toml, \
         No such file or directory (os error 2)\n",
        "without config.toml",
    );

    fs::write(user_dir.join("config.toml"), "subscriptions = []").unwrap();
    let before = snapshot(&vault.path());
    assert_create_failure(
        &create_key(&vault, "dave"),
        "Vault error: could not create directory ./.vault/keys/dave\n\n\
         Caused by:\n    File exists (os error 17)\n",
        "with config.toml",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

#[test]
fn user_name_is_used_as_a_path() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    // The user name is not validated.
    assert_create_failure(
        &create_key(&vault, "team/dave"),
        "Vault error: could not create directory ./.vault/keys/team/dave\n\n\
         Caused by:\n    No such file or directory (os error 2)\n",
        "team/dave",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}
