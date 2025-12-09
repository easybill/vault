//! Tests for the `vault template` command.

use std::fs;

use self::common::TestVault;

mod common;

#[test]
fn rendering() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "SECRET_VALUE")
        .build();

    // Create template file dynamically
    let template = "prefix {vault{MY_SECRET}vault} suffix";
    fs::write(vault.path().join("test.vault"), template).unwrap();

    vault
        .command()
        .args(["template", "test.vault"])
        .assert()
        .success()
        .stdout("prefix SECRET_VALUE suffix");
}

#[test]
fn whitespace_in_placeholder() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "SECRET_VALUE")
        .build();

    // Template with whitespace around key name
    let template = "{vault{ MY_SECRET }vault}";
    fs::write(vault.path().join("test.vault"), template).unwrap();

    vault
        .command()
        .args(["template", "test.vault"])
        .assert()
        .success()
        .stdout("SECRET_VALUE");
}

#[test]
fn preserves_escaped_braces() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "SECRET_VALUE")
        .build();

    // Template with escaped braces: {{text}} should remain as {{text}}
    let template = "some othe{{r cont}}ent {vault{MY_SECRET}vault}";
    fs::write(vault.path().join("test.vault"), template).unwrap();

    vault
        .command()
        .args(["template", "test.vault"])
        .assert()
        .success()
        .stdout("some othe{{r cont}}ent SECRET_VALUE");
}

#[test]
fn missing_secret_fails() {
    let vault = TestVault::builder().build();
    fs::write(vault.path().join("bad.vault"), "{vault{MISSING}vault}").unwrap();

    vault
        .command()
        .args(["template", "bad.vault"])
        .assert()
        .failure();
}

#[test]
fn nonexistent_file_fails() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["template", "nonexistent.vault"])
        .assert()
        .failure();
}

#[test]
fn multiple_secrets() {
    let vault = TestVault::builder()
        .with_secret("SECRET_A", "VALUE_A")
        .with_secret("SECRET_B", "VALUE_B")
        .build();

    // Note: Multiple placeholders must be on separate lines due to greedy regex matching
    let template = "{vault{SECRET_A}vault}\n{vault{SECRET_B}vault}";
    fs::write(vault.path().join("test.vault"), template).unwrap();

    vault
        .command()
        .args(["template", "test.vault"])
        .assert()
        .success()
        .stdout("VALUE_A\nVALUE_B");
}

#[test]
fn no_placeholders() {
    let vault = TestVault::builder().build();

    let template = "just plain text with no secrets";
    fs::write(vault.path().join("test.vault"), template).unwrap();

    vault
        .command()
        .args(["template", "test.vault"])
        .assert()
        .success()
        .stdout("just plain text with no secrets");
}
