//! Tests for the `vault get_multi` command.

use predicates::prelude::*;

mod common;

use self::common::TestVault;

#[test]
fn secrets() {
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
fn templates() {
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
fn secrets_and_templates() {
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

#[test]
fn fails_with_invalid_json() {
    let vault = TestVault::builder().build();

    vault
        .command()
        .args(["get_multi", "not valid json"])
        .assert()
        .failure();
}

#[test]
fn fails_with_missing_secret() {
    let vault = TestVault::builder().build();

    let input = r#"{"secrets":[{"secret":"NONEXISTENT"}],"templates":[]}"#;

    vault
        .command()
        .args(["get_multi", input])
        .assert()
        .failure();
}

#[test]
fn empty_request_succeeds() {
    let vault = TestVault::builder().build();

    let input = r#"{"secrets":[],"templates":[]}"#;

    vault
        .command()
        .args(["get_multi", input])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""secrets":{}"#))
        .stdout(predicate::str::contains(r#""templates":{}"#));
}
