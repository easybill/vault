//! `vault template <file>`: replaces every `{vault{ NAME }vault}` with the secret `NAME`.

use std::collections::BTreeSet;
use std::fs;
use std::process::Output;

use crate::common::{TestVault, assert_failure, assert_success, run};
use crate::support::{ALICE_SECRETS, BOB_SECRETS, GOLDEN};

const TEMPLATE: &str = "app.tpl";

/// Writes `template` to `app.tpl` in the working directory and renders it.
fn render(vault: &TestVault, template: impl AsRef<[u8]>) -> Output {
    fs::write(vault.path().join(TEMPLATE), template).unwrap();
    run(vault.command().args(["template", TEMPLATE]))
}

fn assert_renders(vault: &TestVault, template: &str, stdout: &[u8]) {
    assert_success(&render(vault, template), stdout, "", template);
}

/// The error for a placeholder whose secret cannot be read.
fn requires_key_error(key: &str, causes: &[&str]) -> String {
    let mut error = format!(
        "Vault error: template requires the key \"{key}\", but it's not possible to decrypt \
         the key\n\nCaused by:\n"
    );
    for (index, cause) in causes.iter().enumerate() {
        error.push_str(&format!("    {index}: {cause}\n"));
    }
    error
}

#[test]
fn renders_secrets_into_the_text() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_renders(
        &vault,
        "prefix {vault{SIMPLE}vault} suffix",
        b"prefix hello world suffix",
    );

    // An absolute path works as well.
    let path = vault.path().join(TEMPLATE);
    assert_success(
        &run(vault.command().arg("template").arg(&path)),
        b"prefix hello world suffix",
        "",
        "absolute path",
    );
}

#[test]
fn whitespace_around_the_key_is_trimmed() {
    let vault = TestVault::from_fixture(GOLDEN);
    for template in ["{vault{ SIMPLE }vault}", "{vault{\tSIMPLE  }vault}"] {
        assert_renders(&vault, template, b"hello world");
    }
}

#[test]
fn escaped_braces_are_untouched() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_renders(
        &vault,
        "some othe{{r cont}}ent {{SIMPLE}} {vault{SIMPLE}vault}",
        b"some othe{{r cont}}ent {{SIMPLE}} hello world",
    );
}

#[test]
fn text_without_placeholders_passes_through() {
    let vault = TestVault::from_fixture(GOLDEN);
    for template in [
        "",
        "just plain text with no secrets",
        "line one\r\nline two\n\n",
        "{vault{}vault}",
        "{vault{SIMPLE}vault",
        "{vault SIMPLE vault}",
        // A placeholder does not span lines.
        "{vault{SIMPLE\n}vault}",
    ] {
        assert_renders(&vault, template, template.as_bytes());
    }
}

#[test]
fn placeholders_on_separate_lines_are_all_replaced() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_renders(
        &vault,
        "a={vault{SIMPLE}vault}\nb={vault{ GLOB_A }vault}\nc={vault{SIMPLE}vault}\n",
        b"a=hello world\nb=glob a\nc=hello world\n",
    );
}

#[test]
fn two_placeholders_on_one_line_fail() {
    let vault = TestVault::from_fixture(GOLDEN);
    let key = "SIMPLE}vault} and {vault{GLOB_A";

    // The greedy pattern captures everything between the first `{vault{` and the
    // last `}vault}` of a line as one key.
    assert_failure(
        &render(&vault, "{vault{SIMPLE}vault} and {vault{GLOB_A}vault}"),
        &requires_key_error(
            key,
            &[
                &format!("could not decrypt {key}"),
                &format!(
                    "could not read subscription path. directory is missing? ./.vault/secrets/{key}"
                ),
                "No such file or directory (os error 2)",
            ],
        ),
        "two_placeholders_on_one_line_fail",
    );
}

#[test]
fn empty_secret_is_inserted_as_nothing() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_renders(&vault, "[{vault{EMPTY}vault}]", b"[]");
}

#[test]
fn multiline_utf8_secret_is_inserted_verbatim() {
    let vault = TestVault::from_fixture(GOLDEN);
    let mut expected = b"<".to_vec();
    expected.extend(vault.expected("UNICODE_MULTILINE"));
    expected.extend(b">\n");

    assert_renders(&vault, "<{vault{UNICODE_MULTILINE}vault}>\n", &expected);
}

#[test]
fn missing_secret_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_failure(
        &render(&vault, "a\n{vault{MISSING}vault}\n"),
        &requires_key_error(
            "MISSING",
            &[
                "could not decrypt MISSING",
                "could not read subscription path. directory is missing? ./.vault/secrets/MISSING",
                "No such file or directory (os error 2)",
            ],
        ),
        "missing_secret_fails",
    );
}

#[test]
fn secret_without_a_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_failure(
        &render(&vault, "{vault{BOB_ONLY}vault}"),
        &requires_key_error(
            "BOB_ONLY",
            &["could not decrypt BOB_ONLY", "could not find key"],
        ),
        "secret_without_a_key_fails",
    );
}

#[test]
fn secret_that_is_not_utf8_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    let cause = std::str::from_utf8(&vault.expected("BINARY"))
        .unwrap_err()
        .to_string();
    assert_failure(
        &render(&vault, "{vault{BINARY}vault}"),
        &requires_key_error("BINARY", &["Invalid Utf8", &cause]),
        "secret_that_is_not_utf8_fails",
    );
}

#[test]
fn missing_template_file_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_failure(
        &run(vault.command().args(["template", "missing.tpl"])),
        "Vault error: could not open template missing.tpl.\n\nCaused by:\n    \
         No such file or directory (os error 2)\n",
        "missing_template_file_fails",
    );
}

#[test]
fn template_that_is_not_utf8_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    let template = [b'a', 0xFF, b'b'];
    let cause = std::io::Read::read_to_string(&mut &template[..], &mut String::new()).unwrap_err();
    assert_failure(
        &render(&vault, template),
        &format!(
            "Vault error: could not read content of template app.tpl\n\nCaused by:\n    {cause}\n"
        ),
        "template_that_is_not_utf8_fails",
    );
}

#[test]
fn blank_key_reads_the_secrets_dir() {
    let vault = TestVault::from_fixture(GOLDEN);
    let output = render(&vault, "{vault{ }vault}");

    // The trimmed key is empty, so vault tries `./.vault/secrets/` itself and warns
    // about every secret directory in it (in directory order).
    let error = requires_key_error("", &["could not decrypt ", "could not find key"]);
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    let warnings = stderr
        .strip_suffix(&error)
        .unwrap_or_else(|| panic!("unexpected stderr: {stderr}"));
    let expected_warnings: BTreeSet<String> = ALICE_SECRETS
        .iter()
        .chain(BOB_SECRETS)
        .map(|secret| {
            format!("warning: found a invalid file ./.vault/secrets/{secret} in secrets.")
        })
        .collect();
    assert_eq!(
        warnings.lines().map(String::from).collect::<BTreeSet<_>>(),
        expected_warnings
    );
    assert_eq!(warnings.lines().count(), expected_warnings.len());
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}
