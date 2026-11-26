//! `vault get_multi <json>`: decrypts several secrets and templates at once and prints them as
//! JSON.
//!
//! The output objects are hash maps, so their key order varies between runs. Successful output
//! is therefore parsed and compared as a whole [`Value`].

use std::process::Output;

use serde_derive::Deserialize;
use serde_json::{Value, json};

use crate::common::{TestVault, assert_failure, assert_success, run};
use crate::support::GOLDEN;

fn get_multi(vault: &TestVault, input: &str) -> Output {
    run(vault.command().args(["get_multi", input]))
}

/// Asserts a successful run with empty stderr and `expected` as JSON on stdout.
fn assert_json(output: &Output, expected: &Value, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{context}: failed: {stderr}");
    assert_eq!(stderr, "", "{context}: stderr");
    let actual: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{context}: stdout is not JSON: {error}"));
    assert_eq!(&actual, expected, "{context}");
}

/// Asserts the error list of `get_multi`: exit code 1, no stdout and the given lines on stderr.
fn assert_errors(output: &Output, errors: &[String], context: &str) {
    let mut stderr = String::from("could not decrypt some keys.\n");
    for error in errors {
        stderr.push_str(&format!("\t{error}\n"));
    }
    assert_failure(output, &stderr, context);
}

/// The error line for a secret that cannot be decrypted. Only the outermost error is shown,
/// without its cause.
fn decrypt_error(secret: &str) -> String {
    format!(
        "could not decrypt key {secret}, error: could not read subscription path. directory is \
         missing? ./.vault/secrets/{secret}"
    )
}

/// The error line for BINARY, which is not UTF-8.
fn binary_error(vault: &TestVault) -> String {
    let cause = String::from_utf8(vault.expected("BINARY")).unwrap_err();
    // The message says "could decode" without a "not".
    format!("could decode key BINARY. maybe it's not valid utf8?, error: {cause}")
}

/// The error line for a template with a secret that cannot be read.
fn template_error(template: &str, key: &str) -> String {
    // The message says "could decode" without a "not".
    format!(
        "could decode template {template}. error: template requires the key \"{key}\", but \
         it's not possible to decrypt the key"
    )
}

/// The input shape of `get_multi`, to compute the error messages of serde_json.
#[allow(dead_code)]
#[derive(Deserialize)]
struct Input {
    secrets: Option<Vec<SecretInput>>,
    templates: Option<Vec<TemplateInput>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct SecretInput {
    secret: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TemplateInput {
    template: String,
}

/// `{"<field>s":[{"<field>":<value>}, ...]}`
fn input(field: &str, values: &[&str]) -> String {
    let entries: Vec<Value> = values.iter().map(|value| json!({ field: value })).collect();
    json!({ format!("{field}s"): entries }).to_string()
}

/// `{"secrets":[{"secret":<name>}, ...]}`
fn secrets_input(secrets: &[&str]) -> String {
    input("secret", secrets)
}

/// `{"templates":[{"template":<template>}, ...]}`
fn templates_input(templates: &[&str]) -> String {
    input("template", templates)
}

fn secret_entry(vault: &TestVault, secret: &str) -> Value {
    let value = String::from_utf8(vault.expected(secret)).unwrap();
    json!({ "name": secret, "value": value })
}

#[test]
fn empty_request_returns_empty_objects() {
    let vault = TestVault::from_fixture(GOLDEN);

    // Both fields are optional. With no entries the output is deterministic.
    for input in [
        "{}",
        r#"{"secrets":[],"templates":[]}"#,
        r#"{"secrets":null,"templates":null}"#,
    ] {
        assert_success(
            &get_multi(&vault, input),
            br#"{"secrets":{},"templates":{}}"#,
            "",
            input,
        );
    }
}

#[test]
fn secrets_and_templates() {
    let vault = TestVault::from_fixture(GOLDEN);
    let input = json!({
        "secrets": [
            { "secret": "SIMPLE" },
            { "secret": "EMPTY" },
            { "secret": "UNICODE_MULTILINE" },
            { "secret": "GLOB_A" },
        ],
        "templates": [
            { "template": "{vault{ SIMPLE }vault}TEST" },
            { "template": "a={vault{SIMPLE}vault}\nb={vault{GLOB_A}vault}" },
            { "template": "plain text" },
            { "template": "<{vault{UNICODE_MULTILINE}vault}>" },
        ],
    })
    .to_string();

    let unicode = String::from_utf8(vault.expected("UNICODE_MULTILINE")).unwrap();
    let two_lines = "a={vault{SIMPLE}vault}\nb={vault{GLOB_A}vault}";
    let template = |name: &str, value: &str| json!({ "name": name, "value": value });
    assert_json(
        &get_multi(&vault, &input),
        &json!({
            "secrets": {
                "SIMPLE": secret_entry(&vault, "SIMPLE"),
                "EMPTY": secret_entry(&vault, "EMPTY"),
                "UNICODE_MULTILINE": secret_entry(&vault, "UNICODE_MULTILINE"),
                "GLOB_A": secret_entry(&vault, "GLOB_A"),
            },
            "templates": {
                "{vault{ SIMPLE }vault}TEST":
                    template("{vault{ SIMPLE }vault}TEST", "hello worldTEST"),
                two_lines: template(two_lines, "a=hello world\nb=glob a"),
                "plain text": template("plain text", "plain text"),
                "<{vault{UNICODE_MULTILINE}vault}>":
                    template("<{vault{UNICODE_MULTILINE}vault}>", &format!("<{unicode}>")),
            },
        }),
        "secrets_and_templates",
    );
}

#[test]
fn only_secrets() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_json(
        &get_multi(&vault, &secrets_input(&["SIMPLE", "SHARED"])),
        &json!({
            "secrets": {
                "SIMPLE": secret_entry(&vault, "SIMPLE"),
                "SHARED": secret_entry(&vault, "SHARED"),
            },
            "templates": {},
        }),
        "only_secrets",
    );
}

#[test]
fn only_templates() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_json(
        &get_multi(&vault, &templates_input(&["x{vault{SHARED}vault}x"])),
        &json!({
            "secrets": {},
            "templates": {
                "x{vault{SHARED}vault}x":
                    { "name": "x{vault{SHARED}vault}x", "value": "xshared contentx" },
            },
        }),
        "only_templates",
    );
}

#[test]
fn duplicate_entries_are_merged() {
    let vault = TestVault::from_fixture(GOLDEN);
    let input = json!({
        "secrets": [{ "secret": "SIMPLE" }, { "secret": "SIMPLE" }],
        "templates": [
            { "template": "{vault{SIMPLE}vault}" },
            { "template": "{vault{SIMPLE}vault}" },
        ],
    })
    .to_string();

    assert_json(
        &get_multi(&vault, &input),
        &json!({
            "secrets": { "SIMPLE": secret_entry(&vault, "SIMPLE") },
            "templates": {
                "{vault{SIMPLE}vault}":
                    { "name": "{vault{SIMPLE}vault}", "value": "hello world" },
            },
        }),
        "duplicate_entries_are_merged",
    );
}

#[test]
fn unknown_fields_are_ignored() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_json(
        &get_multi(
            &vault,
            r#"{"secrets":[{"secret":"SIMPLE","other":1}],"version":2}"#,
        ),
        &json!({
            "secrets": { "SIMPLE": secret_entry(&vault, "SIMPLE") },
            "templates": {},
        }),
        "unknown_fields_are_ignored",
    );
}

// MARK: Errors

#[test]
fn missing_secret_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_errors(
        &get_multi(&vault, &secrets_input(&["MISSING"])),
        &[decrypt_error("MISSING")],
        "MISSING",
    );
}

#[test]
fn secret_without_a_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_errors(
        &get_multi(&vault, &secrets_input(&["BOB_ONLY"])),
        &["could not decrypt key BOB_ONLY, error: could not find key".to_string()],
        "BOB_ONLY",
    );
}

#[test]
fn secret_that_is_not_utf8_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_errors(
        &get_multi(&vault, &secrets_input(&["BINARY"])),
        &[binary_error(&vault)],
        "BINARY",
    );
}

#[test]
fn template_errors_fail() {
    let vault = TestVault::from_fixture(GOLDEN);
    let cases = [
        ("{vault{MISSING}vault}", "MISSING"),
        ("{vault{BINARY}vault}", "BINARY"),
        // Two placeholders on one line are captured as one key.
        (
            "{vault{SIMPLE}vault} {vault{GLOB_A}vault}",
            "SIMPLE}vault} {vault{GLOB_A",
        ),
    ];

    for (template, key) in cases {
        assert_errors(
            &get_multi(&vault, &templates_input(&[template])),
            &[template_error(template, key)],
            template,
        );
    }
}

#[test]
fn errors_are_listed_secrets_first_in_input_order() {
    let vault = TestVault::from_fixture(GOLDEN);
    let input = json!({
        "templates": [
            { "template": "{vault{MISSING_T}vault}" },
            { "template": "{vault{SIMPLE}vault}" },
        ],
        "secrets": [
            { "secret": "MISSING_B" },
            { "secret": "SIMPLE" },
            { "secret": "BINARY" },
            { "secret": "MISSING_A" },
        ],
    })
    .to_string();

    // The successful entries are not printed either.
    assert_errors(
        &get_multi(&vault, &input),
        &[
            decrypt_error("MISSING_B"),
            binary_error(&vault),
            decrypt_error("MISSING_A"),
            template_error("{vault{MISSING_T}vault}", "MISSING_T"),
        ],
        &input,
    );
}

#[test]
fn invalid_input_fails() {
    let vault = TestVault::from_fixture(GOLDEN);

    for input in [
        "not valid json",
        r#"{"secrets":[{"name":"SIMPLE"}]}"#,
        r#"{"secrets":{}}"#,
        r#"{"templates":[{"template":1}]}"#,
    ] {
        let cause = serde_json::from_str::<Input>(input).err().unwrap();
        assert_failure(
            &get_multi(&vault, input),
            &format!("Vault error: could not deserialize input\n\nCaused by:\n    {cause}\n"),
            input,
        );
    }
}
