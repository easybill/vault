//! New secrets and subscriptions with V2 keys: every file is written in the format of its
//! recipient's key, so V1 and V2 users share secrets in one repository.

use std::fs;
use std::process::Output;

use assert_cmd::Command;

use crate::common::{TestVault, assert_only_changed, assert_success, run, snapshot};
use crate::support::{GOLDEN, assert_crypt_file};
use crate::support_v2::{
    GOLDEN_V2, as_v2_user, assert_v2_crypt_file, golden_v2_file, no_v1_keys, v2_private_key,
};

fn get(mut cmd: Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

fn set_subscriptions(vault: &TestVault, user: &str, subscriptions: &str) {
    fs::write(
        vault
            .path()
            .join(".vault/keys")
            .join(user)
            .join("config.toml"),
        format!("subscriptions = {subscriptions}"),
    )
    .unwrap();
}

/// The stdout of a default run that fulfilled the subscriptions `(user, secret)`.
fn fulfilled(loaded_key: &str, subscriptions: &[(&str, &str)]) -> Vec<u8> {
    let mut stdout = format!(
        "\ncreate key map.\n\nloaded keys:\n- {loaded_key}\n\n\
         open subscriptions you've the required right to fulfill ({}):\n",
        subscriptions.len()
    );
    for (user, secret) in subscriptions {
        stdout.push_str(&format!("  - user: {user}, name: {secret}\n"));
    }
    stdout.push('\n');
    for (user, secret) in subscriptions {
        stdout.push_str(&format!(
            "creating file ./.vault/secrets/{secret}/{user}.crypt\n"
        ));
    }
    stdout.push_str("\nall fine\n\n");
    stdout.into_bytes()
}

fn alice_private_key() -> Vec<u8> {
    golden_v2_file(".vault/private_keys/alice.pem")
}

#[test]
fn new_secrets_are_encrypted_for_the_v2_key() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let cases: &[(&str, &[u8])] = &[("NEW_EMPTY", b""), ("NEW_TEXT", b"new secret\n")];
    for (name, content) in cases {
        fs::write(vault.secret_dir(name), content).unwrap();
    }
    let before = snapshot(&vault.path());

    assert_success(
        &run(&mut as_v2_user(&vault, "carol")),
        b"\ncreate key map.\n\n\nnew secrets (2):\n  - ./.vault/secrets/NEW_EMPTY\n  \
          - ./.vault/secrets/NEW_TEXT\n\nloaded keys:\n- carol\n\nall fine\n\n",
        "",
        "default run",
    );

    for (name, content) in cases {
        assert_v2_crypt_file(
            &vault.crypt_path(name, "carol"),
            &v2_private_key("carol"),
            content,
        );
        assert_success(&get(as_v2_user(&vault, "carol"), name), content, "", name);
    }
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/secrets/NEW_EMPTY",
            ".vault/secrets/NEW_EMPTY/carol.crypt",
            ".vault/secrets/NEW_TEXT",
            ".vault/secrets/NEW_TEXT/carol.crypt",
        ],
    );
}

#[test]
fn v1_key_fulfills_a_subscription_of_a_v2_user() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    set_subscriptions(&vault, "carol", r#"["GLOB_A"]"#);
    let before = snapshot(&vault.path());

    assert_success(
        &run(&mut vault.command()),
        &fulfilled("alice", &[("carol", "GLOB_A")]),
        "",
        "alice",
    );
    assert_v2_crypt_file(
        &vault.crypt_path("GLOB_A", "carol"),
        &v2_private_key("carol"),
        b"glob a",
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/GLOB_A/carol.crypt"],
    );
    assert_success(
        &get(as_v2_user(&vault, "carol"), "GLOB_A"),
        b"glob a",
        "",
        "carol",
    );
}

#[test]
fn v2_key_fulfills_subscriptions_of_v1_and_v2_users() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    set_subscriptions(&vault, "alice", r#"["SHARED", "SIMPLE"]"#);
    set_subscriptions(&vault, "dave", r#"["SHARED", "GLOB_*", "BINARY"]"#);
    let before = snapshot(&vault.path());

    assert_success(
        &run(&mut as_v2_user(&vault, "carol")),
        &fulfilled("carol", &[("alice", "SIMPLE"), ("dave", "BINARY")]),
        "",
        "carol",
    );
    // alice's file is version 1, dave's version 2.
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "alice"),
        &alice_private_key(),
        b"hello world",
    );
    assert_v2_crypt_file(
        &vault.crypt_path("BINARY", "dave"),
        &v2_private_key("dave"),
        &vault.expected("BINARY"),
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/secrets/SIMPLE/alice.crypt",
            ".vault/secrets/BINARY/dave.crypt",
        ],
    );
    assert_success(&get(vault.command(), "SIMPLE"), b"hello world", "", "alice");
    assert_success(
        &get(as_v2_user(&vault, "dave"), "BINARY"),
        &vault.expected("BINARY"),
        "",
        "dave",
    );
}

#[test]
fn new_v2_user_in_a_v1_repository_gets_its_subscription() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_success(
        &run(vault.command().args(["create-key", "carol"])),
        b"generating keys ...\n",
        "",
        "create-key",
    );
    set_subscriptions(&vault, "carol", r#"["SIMPLE"]"#);

    assert_success(
        &run(&mut vault.command()),
        b"\ncreate key map.\n\nloaded keys:\n- alice\n- carol\n\n\
          open subscriptions you've the required right to fulfill (1):\n  \
          - user: carol, name: SIMPLE\n\n\
          creating file ./.vault/secrets/SIMPLE/carol.crypt\n\nall fine\n\n",
        "",
        "alice fulfills carol's subscription",
    );

    let id = fs::read_to_string(vault.path().join(".vault/repository_id")).unwrap();
    let private_key = fs::read(
        vault
            .home()
            .join(format!(".vault/v2/{}.pem", id.trim_end())),
    )
    .unwrap();
    assert_v2_crypt_file(
        &vault.crypt_path("SIMPLE", "carol"),
        &private_key,
        b"hello world",
    );

    let mut as_carol = vault.command();
    as_carol.env("VAULT_PRIVATE_KEY_PATH", no_v1_keys(&vault));
    assert_success(&get(as_carol, "SIMPLE"), b"hello world", "", "carol");
}
