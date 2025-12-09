mod common;

use std::fs;

use predicates::prelude::*;

use common::{TestVault, clean_backup_files};

// ============ Secret Decryption Tests ============

#[test]
fn test_secret_decryption() {
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
fn test_template_rendering() {
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
fn test_template_with_whitespace_in_placeholder() {
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
fn test_template_preserves_escaped_braces() {
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

// ============ Multi-Key Tests ============

#[test]
fn test_get_multi_secrets() {
    let vault = TestVault::builder()
        .with_secret("SECRET_A", "CONTENT_A")
        .with_secret("SECRET_B", "CONTENT_B")
        .build();

    let input = r#"{"secrets":[{"secret":"SECRET_A"},{"secret":"SECRET_B"}],"templates":[]}"#;

    vault
        .command()
        .args(["get_multi", input])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""value":"CONTENT_A""#))
        .stdout(predicate::str::contains(r#""value":"CONTENT_B""#));
}

#[test]
fn test_get_multi_templates() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "SECRET_VALUE")
        .build();

    let input = r#"{"secrets":[],"templates":[{"template":"{vault{ MY_SECRET }vault}TEST"}]}"#;

    vault
        .command()
        .args(["get_multi", input])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""value":"SECRET_VALUETEST""#));
}

#[test]
fn test_get_multi_secrets_and_templates() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "SECRET_VALUE")
        .build();

    let input = r#"{"secrets":[{"secret":"MY_SECRET"}],"templates":[{"template":"{vault{ MY_SECRET }vault}TEST"}]}"#;

    vault
        .command()
        .args(["get_multi", input])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""name":"MY_SECRET""#))
        .stdout(predicate::str::contains(r#""value":"SECRET_VALUE""#))
        .stdout(predicate::str::contains(r#""value":"SECRET_VALUETEST""#));
}

// ============ Key Rotation Tests ============

#[test]
fn test_key_rotation_preserves_access() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "MY_CONTENT")
        .build();

    // Rotate keys
    vault.command().args(["rotate"]).assert().success();

    // Clean backup files (they can interfere with key loading)
    clean_backup_files(vault.path());

    // Verify secret still accessible
    vault
        .command()
        .args(["get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("MY_CONTENT");
}

#[test]
fn test_rotation_reads_old_encrypted_files() {
    let vault = TestVault::builder()
        .with_secret("MY_SECRET", "MY_CONTENT")
        .build();

    // Save original encrypted file
    let crypt_path = vault
        .path()
        .join(format!(".vault/secrets/MY_SECRET/{}.crypt", vault.username()));
    let original_crypt = fs::read(&crypt_path).unwrap();

    // Rotate keys
    vault.command().args(["rotate"]).assert().success();

    // Restore old encrypted file (simulating old file encrypted with old key)
    fs::remove_dir_all(vault.path().join(".vault/secrets")).unwrap();
    fs::create_dir_all(vault.path().join(".vault/secrets/MY_SECRET")).unwrap();
    fs::write(&crypt_path, &original_crypt).unwrap();

    // Should still decrypt using backup key
    vault
        .command()
        .args(["get", "MY_SECRET"])
        .assert()
        .success()
        .stdout("MY_CONTENT");
}

// ============ Error Case Tests ============

#[test]
fn test_get_nonexistent_secret_fails() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["get", "NONEXISTENT"])
        .assert()
        .failure();
}

#[test]
fn test_template_missing_secret_fails() {
    let vault = TestVault::builder().build();
    fs::write(vault.path().join("bad.vault"), "{vault{MISSING}vault}").unwrap();

    vault
        .command()
        .args(["template", "bad.vault"])
        .assert()
        .failure();
}
