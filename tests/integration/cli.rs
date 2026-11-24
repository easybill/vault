//! Command line handling that does not depend on secrets: `--version`, `--expect_version`, usage
//! errors, the error format and the checks of the `.vault` directory, including the wizard
//! that creates it.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Output;

use crate::common::{TestVault, assert_failure, assert_output, assert_success, run, snapshot};
use crate::support::GOLDEN;

const WIZARD: &str =
    "seems that vault isn't \"installed\" here.\nmay you're just in the wrong directory?\n";
const WIZARD_PROMPT: &str = "do you want to create an empty ./.vault directory? (y/n)\n";
const NO_PRIVATE_KEY: &str = "Vault error: there is no private key\n";
const COWORKER: &str = "Vault error: probably a coworker wants to prevent this vault version \
     from being used. maybe there was a bug in vault or a feature is being used that is only \
     available in this version. please install the latest version from \
     https://github.com/easybill/vault/releases.\n";

/// The stdout of a default run that has no keys and nothing to do.
const NOTHING_TO_DO: &[u8] = b"\ncreate key map.\n\nloaded keys:\n\nall fine\n\n";

/// The snapshot of a working directory that holds only the empty basic directories.
fn basic_dirs() -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    [
        ".vault",
        ".vault/keys",
        ".vault/private_keys",
        ".vault/secrets",
    ]
    .into_iter()
    .map(|dir| (PathBuf::from(dir), None))
    .collect()
}

/// Asserts a clap usage error: exit code 2, no stdout and an error on stderr that contains
/// `parts`. The wording around them belongs to clap and is not pinned.
fn assert_usage_error(output: &Output, parts: &[&str], context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{context}: exit code, stderr: {stderr}"
    );
    assert!(output.stdout.is_empty(), "{context}: stdout must be empty");
    assert!(stderr.starts_with("error: "), "{context}: stderr: {stderr}");
    for part in parts {
        assert!(
            stderr.contains(part),
            "{context}: {part:?} missing in stderr: {stderr}"
        );
    }
}

/// The major version of this vault.
fn major_version() -> u64 {
    env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap()
}

// MARK: Version

#[test]
fn version_flag_prints_the_version() {
    // No `.vault` directory needed, the flag is handled before anything else.
    let vault = TestVault::empty();
    let version = format!("Vault {}\n", env!("CARGO_PKG_VERSION"));

    for flag in ["--version", "-V"] {
        assert_success(
            &run(vault.command().arg(flag)),
            version.as_bytes(),
            "",
            flag,
        );
    }
    assert!(snapshot(&vault.path()).is_empty());
}

#[test]
fn matching_expect_version_runs_the_command() {
    let vault = TestVault::from_fixture(GOLDEN);
    let exact = format!("={}", env!("CARGO_PKG_VERSION"));
    let major = major_version().to_string();

    for requirement in [">=1.0.0", major.as_str(), "*", exact.as_str()] {
        assert_success(
            &run(vault
                .command()
                .args(["--expect_version", requirement, "get", "SIMPLE"])),
            b"hello world",
            "",
            requirement,
        );
    }
}

#[test]
fn mismatching_expect_version_fails() {
    let vault = TestVault::from_fixture(GOLDEN);

    let next_major = (major_version() + 1).to_string();

    for requirement in [">=999.0.0", "<1.0.0", next_major.as_str()] {
        assert_failure(
            &run(vault
                .command()
                .args(["--expect_version", requirement, "get", "SIMPLE"])),
            COWORKER,
            requirement,
        );
    }
}

#[test]
fn expect_version_is_checked_before_the_vault_dir() {
    let vault = TestVault::empty();

    assert_failure(
        &run(vault
            .command()
            .args(["--expect_version", ">=999.0.0", "check-keys"])),
        COWORKER,
        "check-keys",
    );
    assert!(snapshot(&vault.path()).is_empty(), "no wizard ran");
}

#[test]
fn unparsable_expect_version_fails_with_its_cause() {
    let vault = TestVault::from_fixture(GOLDEN);
    let cause = semver::VersionReq::parse("not-a-version").unwrap_err();

    assert_failure(
        &run(vault
            .command()
            .args(["--expect_version", "not-a-version", "get", "SIMPLE"])),
        &format!(
            "Vault error: could not parse version requirement, expected something like \
             >=1.2.3, <1.8.0\n\nCaused by:\n    {cause}\n"
        ),
        "not-a-version",
    );
}

// MARK: Usage errors

#[test]
fn usage_errors_exit_with_code_2() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    let cases: &[(&[&str], &[&str])] = &[
        (&["get"], &["<key>", "Usage: vault get <key>"]),
        (&["get_multi"], &["<json>", "Usage: vault get_multi <json>"]),
        (
            &["template"],
            &["<filename>", "Usage: vault template <filename>"],
        ),
        (
            &["create-openssl-key"],
            &["<username>", "Usage: vault create-openssl-key <username>"],
        ),
        (
            &["get", "SIMPLE", "extra"],
            &["'extra'", "Usage: vault get <key>"],
        ),
        (
            &["unknown"],
            &["'unknown'", "Usage: vault [OPTIONS] [COMMAND]"],
        ),
    ];

    for (args, parts) in cases {
        assert_usage_error(&run(vault.command().args(*args)), parts, &args.join(" "));
    }
    assert_eq!(snapshot(&vault.path()), before);
}

#[test]
fn usage_errors_do_not_need_a_vault_dir() {
    let vault = TestVault::empty();

    assert_usage_error(
        &run(vault.command().arg("get")),
        &["<key>", "Usage: vault get <key>"],
        "get",
    );
    assert!(snapshot(&vault.path()).is_empty(), "no wizard ran");
}

// MARK: The `.vault` directory

#[test]
fn wizard_with_force_yes_creates_the_basic_dirs() {
    let vault = TestVault::empty();

    // The default run continues with the new, empty directories.
    assert_success(&run(&mut vault.command()), NOTHING_TO_DO, WIZARD, "vault");
    assert_eq!(snapshot(&vault.path()), basic_dirs());
}

#[test]
fn wizard_before_check_keys_fails_without_keys() {
    let vault = TestVault::empty();

    assert_failure(
        &run(vault.command().arg("check-keys")),
        &format!("{WIZARD}{NO_PRIVATE_KEY}"),
        "check-keys",
    );
    assert_eq!(snapshot(&vault.path()), basic_dirs());
}

#[test]
fn wizard_answered_yes_creates_the_basic_dirs() {
    let vault = TestVault::empty();

    assert_output(
        &run(vault.answering("x\ny\n").arg("check-keys")),
        1,
        WIZARD_PROMPT.repeat(2).as_bytes(),
        &format!("{WIZARD}unexpected char \"x\" - reask.\n{NO_PRIVATE_KEY}"),
        "check-keys",
    );
    assert_eq!(snapshot(&vault.path()), basic_dirs());
}

#[test]
fn wizard_answered_no_creates_nothing() {
    let vault = TestVault::empty();

    // The run goes on without the directory, and the message lacks the dot of
    // `./.vault/keys`.
    assert_output(
        &run(&mut vault.answering("n\n")),
        1,
        WIZARD_PROMPT.as_bytes(),
        &format!(
            "{WIZARD}Vault error: could not read ./vault/keys, No such file or directory \
             (os error 2)\n"
        ),
        "vault",
    );
    assert!(snapshot(&vault.path()).is_empty());
}

#[test]
fn vault_file_instead_of_dir_fails_in_the_wizard() {
    let vault = TestVault::empty();
    fs::write(vault.path().join(".vault"), "not a directory").unwrap();

    assert_failure(
        &run(vault.command().arg("check-keys")),
        &format!(
            "{WIZARD}Vault error: could not create directory .vault/keys, Not a directory \
             (os error 20)\n"
        ),
        "check-keys",
    );
}

#[test]
fn only_the_current_dir_is_searched() {
    let vault = TestVault::from_fixture(GOLDEN);
    let sub_dir = vault.path().join("sub");
    fs::create_dir(&sub_dir).unwrap();

    assert_output(
        &run(vault
            .answering("n\n")
            .current_dir(&sub_dir)
            .args(["get", "SIMPLE"])),
        1,
        WIZARD_PROMPT.as_bytes(),
        &format!(
            "{WIZARD}Vault error: could not read ./vault/keys, No such file or directory \
             (os error 2)\n"
        ),
        "get SIMPLE in a subdirectory",
    );
    assert!(snapshot(&sub_dir).is_empty());
}

#[test]
fn missing_basic_dir_fails() {
    for dir in ["keys", "private_keys", "secrets"] {
        let vault = TestVault::from_fixture(GOLDEN);
        fs::remove_dir_all(vault.path().join(".vault").join(dir)).unwrap();
        // vault reports its current directory, which has symlinks resolved (e.g. /private/var
        // instead of /var on macOS).
        let cwd = fs::canonicalize(vault.path()).unwrap();

        assert_failure(
            &run(vault.command().args(["get", "SIMPLE"])),
            &format!(
                "Vault error: issues with the filesystem, e.g. a basic directory could be \
                 missing\ndirectory {cwd}/.vault/{dir} must exist, but is not present\n",
                cwd = cwd.display()
            ),
            dir,
        );
    }
}

#[test]
fn only_the_first_missing_basic_dir_is_reported() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::remove_dir_all(vault.path().join(".vault/private_keys")).unwrap();
    fs::remove_dir_all(vault.path().join(".vault/secrets")).unwrap();
    let cwd = fs::canonicalize(vault.path()).unwrap();

    assert_failure(
        &run(vault.command().arg("check-keys")),
        &format!(
            "Vault error: issues with the filesystem, e.g. a basic directory could be \
             missing\ndirectory {cwd}/.vault/private_keys must exist, but is not present\n",
            cwd = cwd.display()
        ),
        "check-keys",
    );
}
