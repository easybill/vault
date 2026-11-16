//! Tests for CLI flags and general vault behavior.
use std::fs;
use std::time::Duration;

use predicates::prelude::*;

use self::common::TestVault;

mod common;

// MARK: Version Flag

#[test]
fn version_flag_shows_version() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"[Vv]ault \d+\.\d+\.\d+").unwrap());
}

// MARK: Expect Version Flag

#[test]
fn version_succeeds_with_matching_version() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "CONTENT")
        .build();

    // Use a version requirement that should match current version
    vault
        .command()
        .args(["--expect_version", ">=1.0.0", "get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("CONTENT");
}

#[test]
fn version_fails_with_impossible_version() {
    let vault = TestVault::builder().build();

    // Use a version requirement that can't possibly match
    vault
        .command()
        .args(["--expect_version", ">=999.0.0", "check-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("coworker"));
}

#[test]
fn version_fails_with_invalid_semver() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["--expect_version", "not-a-version", "check-keys"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not parse version"));
}

// MARK: Filesystem

#[test]
fn fails_without_vault_directory() {
    let temp_dir = tempfile::TempDir::new().unwrap();

    // Create a command without a .vault directory
    #[allow(deprecated)] // cargo_bin works fine for standard cargo layouts
    let mut cmd = assert_cmd::Command::cargo_bin("vault").unwrap();
    cmd.current_dir(temp_dir.path())
        .env("VAULT_FORCE_YES", "1")
        .args(["check-keys"])
        .assert()
        .failure();
}

#[test]
fn batch_each_adds_only_accepted_secrets() {
    let vault = TestVault::builder().build();
    fs::write(vault.path().join(".vault/secrets/A"), "a").unwrap();
    fs::write(vault.path().join(".vault/secrets/B"), "b").unwrap();

    vault
        .command()
        .env_remove("VAULT_FORCE_YES")
        .write_stdin("c\ny\nn\n") // case by case → yes to A, no to B (paths are sorted)
        .timeout(Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicate::str::contains("new secrets (2):"))
        .stderr(predicate::str::contains("unexpected char").not());

    let secrets = vault.path().join(".vault/secrets");

    // A was encrypted: the plaintext file is replaced by a directory with <user>.crypt
    assert!(secrets.join("A").is_dir());
    assert!(
        secrets
            .join("A")
            .join(format!("{}.crypt", vault.username()))
            .is_file()
    );

    // B was declined: still a plaintext file
    assert!(secrets.join("B").is_file());
    assert_eq!(fs::read_to_string(secrets.join("B")).unwrap(), "b");

    // A decrypts back to its original content
    vault
        .command()
        .args(["get", "A"])
        .assert()
        .success()
        .stdout("a");
}

#[test]
fn batch_adds_all_secrets() {
    let vault = TestVault::builder().build();
    fs::write(vault.path().join(".vault/secrets/A"), "a").unwrap();
    fs::write(vault.path().join(".vault/secrets/B"), "b").unwrap();

    vault
        .command()
        .env_remove("VAULT_FORCE_YES")
        .write_stdin("y\n") // yes to all
        .timeout(Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicate::str::contains("new secrets (2):"))
        .stderr(predicate::str::contains("unexpected char").not());

    let secrets = vault.path().join(".vault/secrets");

    // A was encrypted: the plaintext file is replaced by a directory with <user>.crypt
    assert!(secrets.join("A").is_dir());
    assert!(
        secrets
            .join("A")
            .join(format!("{}.crypt", vault.username()))
            .is_file()
    );

    // B was encrypted: the plaintext file is replaced by a directory with <user>.crypt
    assert!(secrets.join("B").is_dir());
    assert!(
        secrets
            .join("B")
            .join(format!("{}.crypt", vault.username()))
            .is_file()
    );

    // A decrypts back to its original content
    vault
        .command()
        .args(["get", "A"])
        .assert()
        .success()
        .stdout("a");

    // B decrypts back to its original content
    vault
        .command()
        .args(["get", "B"])
        .assert()
        .success()
        .stdout("b");
}
