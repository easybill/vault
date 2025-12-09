//! Tests for CLI flags and general vault behavior.

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
