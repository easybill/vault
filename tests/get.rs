//! Tests for the `vault get` command.

use predicates::prelude::*;

use self::common::TestVault;

mod common;

#[test]
fn secret_decryption() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "MY_SECRET_CONTENT")
        .build();

    vault
        .command()
        .args(["get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("MY_SECRET_CONTENT");
}

#[test]
fn nonexistent_secret_fails() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["get", "NONEXISTENT"])
        .assert()
        .failure();
}

#[test]
fn requires_key_argument() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["get"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

// MARK: Special Content

#[test]
fn secret_with_newlines() {
    let vault = TestVault::builder()
        .with_secret("MULTILINE", "line1\nline2\nline3")
        .build();

    vault
        .command()
        .args(["get", "MULTILINE"])
        .assert()
        .success()
        .stdout("line1\nline2\nline3");
}

#[test]
fn secret_with_special_characters() {
    let vault = TestVault::builder()
        .with_secret("SPECIAL", r#"{"key": "value", "special": "!@#$%^&*()"}"#)
        .build();

    vault
        .command()
        .args(["get", "SPECIAL"])
        .assert()
        .success()
        .stdout(r#"{"key": "value", "special": "!@#$%^&*()"}"#);
}

#[test]
fn secret_with_unicode() {
    let vault = TestVault::builder()
        .with_secret("UNICODE", "Hello, Welt! Emoji: 🔐🗝️")
        .build();

    vault
        .command()
        .args(["get", "UNICODE"])
        .assert()
        .success()
        .stdout("Hello, Welt! Emoji: 🔐🗝️");
}

#[test]
fn secret_with_empty_content() {
    let vault = TestVault::builder().with_secret("EMPTY", "").build();

    vault
        .command()
        .args(["get", "EMPTY"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn secret_with_binary_content() {
    // Binary content with null bytes and non-UTF8 sequences
    let binary_content: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0xAB, 0xCD];

    let vault = TestVault::builder()
        .with_secret("BINARY", binary_content.clone())
        .build();

    let output = vault
        .command()
        .args(["get", "BINARY"])
        .output()
        .expect("Failed to execute");

    assert!(output.status.success());
    assert_eq!(output.stdout, binary_content);
}
