//! Private key discovery: the configured key directory, `$HOME/.vault/private_keys`, key names,
//! files that are not keys, `check-keys` and keys stored as `.pem.pgp`.
//!
//! The default `vault` run is the only command that prints the names of the loaded keys. The
//! golden fixture has no open subscriptions and no new secrets, so such a run changes nothing,
//! which [`default_run`] asserts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;

use crate::common::{TestVault, assert_failure, assert_no_panic, assert_success, run, snapshot};
use crate::support::GOLDEN;

/// `.vault/private_keys` in the working directory.
fn private_keys(vault: &TestVault) -> PathBuf {
    vault.path().join(".vault/private_keys")
}

/// `$HOME/.vault/private_keys`, created on first use.
fn home_private_keys(vault: &TestVault) -> PathBuf {
    let dir = vault.home().join(".vault/private_keys");
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Copies alice's key pair from the default key directory into `dir`.
fn copy_alice_keys(vault: &TestVault, dir: &Path) {
    for file in ["alice.pem", "alice.pub.pem"] {
        fs::copy(private_keys(vault).join(file), dir.join(file)).unwrap();
    }
}

/// Removes alice's key pair from the default key directory.
fn remove_alice_keys(vault: &TestVault) {
    for file in ["alice.pem", "alice.pub.pem"] {
        fs::remove_file(private_keys(vault).join(file)).unwrap();
    }
}

/// A command that loads bob's keys through `VAULT_PRIVATE_KEY_PATH`, given relative to the
/// working directory.
fn as_bob(vault: &TestVault) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", "bob_private_keys");
    cmd
}

/// Runs the default `vault` command (no subcommand) and asserts that it changed no file.
fn default_run(vault: &TestVault, mut cmd: Command) -> Output {
    let before = snapshot(&vault.path());
    let output = run(&mut cmd);
    assert_eq!(
        snapshot(&vault.path()),
        before,
        "a default run with nothing to do must not change files"
    );
    output
}

/// The stdout of a default run that has nothing to do, listing the loaded keys.
fn nothing_to_do(keys: &[&str]) -> Vec<u8> {
    let mut stdout = String::from("\ncreate key map.\n\nloaded keys:\n");
    for key in keys {
        stdout.push_str(&format!("- {key}\n"));
    }
    stdout.push_str("\nall fine\n\n");
    stdout.into_bytes()
}

fn check_keys(mut cmd: Command) -> Output {
    run(cmd.arg("check-keys"))
}

fn get(mut cmd: Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

const KEYS_ARE_FINE: &[u8] = b"keys are fine\n";
const NO_PRIVATE_KEY: &str = "Vault error: there is no private key\n";
const COULD_NOT_FIND_KEY: &str = "Vault error: could not find key\n";

/// The error for a private key whose `.pub.pem` is missing.
fn missing_public_key_error(public_key: &str, private_key: &str) -> String {
    format!(
        "Vault error: could not find a corresponding public key at {public_key:?} for private \
         key at {private_key:?}\n"
    )
}

// MARK: Key directories

#[test]
fn default_key_dir_is_used() {
    let vault = TestVault::from_fixture(GOLDEN);

    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "",
        "check-keys",
    );
    assert_success(
        &default_run(&vault, vault.command()),
        &nothing_to_do(&["alice"]),
        "",
        "default run",
    );
}

#[test]
fn key_path_env_replaces_the_default_dir() {
    let vault = TestVault::from_fixture(GOLDEN);

    assert_success(
        &get(as_bob(&vault), "BOB_ONLY"),
        &vault.expected("BOB_ONLY"),
        "",
        "BOB_ONLY",
    );
    assert_failure(
        &get(as_bob(&vault), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "get SIMPLE",
    );
    assert_success(
        &default_run(&vault, as_bob(&vault)),
        &nothing_to_do(&["bob"]),
        "",
        "default run",
    );
}

#[test]
fn home_keys_are_loaded_after_the_configured_dir() {
    let vault = TestVault::from_fixture(GOLDEN);
    copy_alice_keys(&vault, &home_private_keys(&vault));

    assert_success(
        &default_run(&vault, as_bob(&vault)),
        &nothing_to_do(&["bob", "alice"]),
        "",
        "default run",
    );
    assert_success(
        &get(as_bob(&vault), "BOB_ONLY"),
        &vault.expected("BOB_ONLY"),
        "",
        "BOB_ONLY",
    );
    assert_success(&get(as_bob(&vault), "SIMPLE"), b"hello world", "", "SIMPLE");
}

#[test]
fn home_keys_alone_are_enough() {
    let vault = TestVault::from_fixture(GOLDEN);
    copy_alice_keys(&vault, &home_private_keys(&vault));
    remove_alice_keys(&vault);

    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "",
        "check-keys",
    );
    assert_success(
        &get(vault.command(), "SIMPLE"),
        b"hello world",
        "",
        "SIMPLE",
    );
}

#[test]
fn same_key_in_both_dirs_is_loaded_twice() {
    let vault = TestVault::from_fixture(GOLDEN);
    copy_alice_keys(&vault, &home_private_keys(&vault));

    // Keys are not deduplicated.
    assert_success(
        &default_run(&vault, vault.command()),
        &nothing_to_do(&["alice", "alice"]),
        "",
        "default run",
    );
}

#[test]
fn missing_home_key_dir_is_ignored() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert!(!vault.home().join(".vault").exists());
    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "",
        "no home key dir",
    );

    fs::create_dir(vault.home().join(".vault")).unwrap();
    fs::write(vault.home().join(".vault/private_keys"), "not a directory").unwrap();
    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "",
        "home key dir is a file",
    );
}

#[test]
fn missing_configured_key_dir_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    // The keys in $HOME do not make up for it.
    copy_alice_keys(&vault, &home_private_keys(&vault));

    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", "missing_keys");
    assert_failure(
        &get(cmd, "SIMPLE"),
        "Vault error: private key directory missing_keys is not readable\n\nCaused by:\n    \
         No such file or directory (os error 2)\n",
        "get SIMPLE",
    );

    fs::write(vault.path().join("keys_file"), "not a directory").unwrap();
    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", "keys_file");
    assert_failure(
        &check_keys(cmd),
        "Vault error: private key directory keys_file is not readable\n\nCaused by:\n    \
         Not a directory (os error 20)\n",
        "check-keys",
    );
}

#[cfg(unix)]
#[test]
fn unreadable_key_dir_fails() {
    use std::os::unix::fs::PermissionsExt;

    let vault = TestVault::from_fixture(GOLDEN);
    let dir = private_keys(&vault);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read_dir(&dir).is_ok();

    // Nothing in between may panic, so the permissions are always restored.
    let output = (!readable).then(|| vault.command().arg("check-keys").output());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    let Some(output) = output else {
        // Permissions do not apply to root.
        eprintln!(
            "skipped: {} is still readable without permissions",
            dir.display()
        );
        return;
    };
    let output = output.expect("could not run vault");
    assert_no_panic(&output);
    assert_failure(
        &output,
        "Vault error: private key directory ./.vault/private_keys is not readable\n\n\
         Caused by:\n    Permission denied (os error 13)\n",
        "check-keys",
    );
}

// MARK: Key names

#[test]
fn key_name_comes_from_the_file_name() {
    let vault = TestVault::from_fixture(GOLDEN);
    let dir = private_keys(&vault);
    fs::rename(dir.join("alice.pem"), dir.join("carol.work.pem")).unwrap();
    fs::rename(dir.join("alice.pub.pem"), dir.join("carol.work.pub.pem")).unwrap();

    assert_success(
        &default_run(&vault, vault.command()),
        &nothing_to_do(&["carol.work"]),
        "",
        "default run",
    );
    // Trial decryption does not care about the key name.
    assert_success(
        &get(vault.command(), "SIMPLE"),
        b"hello world",
        "",
        "SIMPLE",
    );
}

#[test]
fn repeated_pem_extensions_are_all_trimmed() {
    let vault = TestVault::from_fixture(GOLDEN);
    let dir = private_keys(&vault);
    fs::rename(dir.join("alice.pem"), dir.join("alice.pem.pem")).unwrap();

    // `alice.pem.pem` is the key `alice` with the public key `alice.pub.pem`.
    assert_success(
        &default_run(&vault, vault.command()),
        &nothing_to_do(&["alice"]),
        "",
        "default run",
    );
}

// MARK: Files that are not private keys

#[test]
fn unexpected_files_are_reported() {
    let vault = TestVault::from_fixture(GOLDEN);
    let dir = private_keys(&vault);

    for name in [
        "notes.txt",
        "README",
        "alice.key",
        "alice.pem.txt",
        "alice.pgp",
    ] {
        fs::write(dir.join(name), "not a key").unwrap();
        assert_success(
            &check_keys(vault.command()),
            KEYS_ARE_FINE,
            &format!("info: unexpected file ./.vault/private_keys/{name}\n"),
            name,
        );
        fs::remove_file(dir.join(name)).unwrap();
    }

    fs::create_dir(dir.join("old_keys")).unwrap();
    // A directory is reported as an unexpected file.
    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "info: unexpected file ./.vault/private_keys/old_keys\n",
        "directory",
    );
}

#[test]
fn unexpected_files_are_reported_with_the_path_of_their_dir() {
    let vault = TestVault::from_fixture(GOLDEN);
    let bob_dir = vault.path().join("bob_private_keys");
    fs::write(bob_dir.join("notes.txt"), "not a key").unwrap();
    let home_dir = home_private_keys(&vault);
    fs::write(home_dir.join("notes.txt"), "not a key").unwrap();

    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", &bob_dir);
    assert_success(
        &check_keys(cmd),
        KEYS_ARE_FINE,
        &format!(
            "info: unexpected file {}\ninfo: unexpected file {}\n",
            bob_dir.join("notes.txt").display(),
            home_dir.join("notes.txt").display(),
        ),
        "check-keys",
    );
}

#[test]
fn markdown_gitkeep_and_backup_files_are_skipped_silently() {
    let vault = TestVault::from_fixture(GOLDEN);
    let dir = private_keys(&vault);
    for name in [
        "README.md",
        "notes.md",
        ".gitkeep",
        "old.bak",
        "alice.pem.bak",
    ] {
        fs::write(dir.join(name), "not a key").unwrap();
    }

    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "",
        "check-keys",
    );
    assert_success(
        &default_run(&vault, vault.command()),
        &nothing_to_do(&["alice"]),
        "",
        "default run",
    );
}

#[test]
fn public_keys_are_not_private_keys() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::remove_file(private_keys(&vault).join("alice.pem")).unwrap();

    assert_failure(&check_keys(vault.command()), NO_PRIVATE_KEY, "check-keys");
    assert_failure(
        &get(vault.command(), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "get SIMPLE",
    );
}

#[test]
fn empty_key_dir_has_no_private_key() {
    let vault = TestVault::from_fixture(GOLDEN);
    remove_alice_keys(&vault);

    assert_failure(&check_keys(vault.command()), NO_PRIVATE_KEY, "check-keys");
    assert_failure(
        &get(vault.command(), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "get SIMPLE",
    );
    // The default run does not need a key when there is nothing to do.
    assert_success(
        &default_run(&vault, vault.command()),
        &nothing_to_do(&[]),
        "",
        "default run",
    );
}

#[test]
fn private_key_without_public_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    let dir = private_keys(&vault);
    fs::copy(dir.join("alice.pem"), dir.join("carol.pem")).unwrap();

    let error = missing_public_key_error(
        "./.vault/private_keys/carol.pub.pem",
        "./.vault/private_keys/carol.pem",
    );
    assert_failure(&check_keys(vault.command()), &error, "check-keys");
    assert_failure(&get(vault.command(), "SIMPLE"), &error, "get SIMPLE");
}

#[test]
fn private_key_without_public_key_in_home_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    let home_dir = home_private_keys(&vault);
    fs::copy(
        private_keys(&vault).join("alice.pem"),
        home_dir.join("carol.pem"),
    )
    .unwrap();

    assert_failure(
        &check_keys(vault.command()),
        &missing_public_key_error(
            &home_dir.join("carol.pub.pem").display().to_string(),
            &home_dir.join("carol.pem").display().to_string(),
        ),
        "check-keys",
    );
}

#[test]
fn invalid_private_key_passes_check_keys() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::write(private_keys(&vault).join("alice.pem"), "not a key").unwrap();

    // `check-keys` only counts the key files, it never parses them.
    assert_success(
        &check_keys(vault.command()),
        KEYS_ARE_FINE,
        "",
        "check-keys",
    );
    assert_failure(
        &get(vault.command(), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "get SIMPLE",
    );
}

// MARK: Keys stored with gpg

#[cfg(unix)]
mod pgp {
    use super::*;
    use crate::support::FakeGpg;

    const PGP_KEY: &str = "./.vault/private_keys/alice.pem.pgp";

    /// Replaces alice's `alice.pem` with `alice.pem.pgp`, which only the fake gpg can read: it
    /// prints the original key, stored outside the working directory.
    fn vault_with_pgp_key() -> (TestVault, FakeGpg) {
        let vault = TestVault::from_fixture(GOLDEN);
        let plain_key = vault.root().join("alice.plain.pem");
        fs::rename(private_keys(&vault).join("alice.pem"), &plain_key).unwrap();
        fs::write(vault.path().join(PGP_KEY), "not really encrypted").unwrap();
        let gpg = FakeGpg::new(&vault.root().join("fake_gpg"), &plain_key, "", 0);
        (vault, gpg)
    }

    fn with_gpg(vault: &TestVault, gpg: &FakeGpg) -> Command {
        let mut cmd = vault.command();
        cmd.env("PATH", gpg.path_env());
        cmd
    }

    fn gpg_call(path: &str) -> String {
        format!("--decrypt\n--pinentry-mode\nloopback\n{path}\n")
    }

    #[test]
    fn pgp_key_is_decrypted_with_gpg() {
        let (vault, gpg) = vault_with_pgp_key();

        assert_success(
            &get(with_gpg(&vault, &gpg), "SIMPLE"),
            b"hello world",
            "",
            "SIMPLE",
        );
        assert_eq!(gpg.calls(), gpg_call(PGP_KEY));

        // The key name drops both extensions.
        assert_success(
            &default_run(&vault, with_gpg(&vault, &gpg)),
            &nothing_to_do(&["alice"]),
            "",
            "default run",
        );
        assert_eq!(gpg.calls(), gpg_call(PGP_KEY).repeat(2));
    }

    #[test]
    fn failing_gpg_aborts_with_its_output() {
        let vault = TestVault::from_fixture(GOLDEN);
        fs::write(vault.path().join(PGP_KEY), "not really encrypted").unwrap();
        let gpg_stdout = vault.root().join("gpg_stdout");
        fs::write(&gpg_stdout, "fake stdout").unwrap();
        let gpg = FakeGpg::new(
            &vault.root().join("fake_gpg"),
            &gpg_stdout,
            "fake stderr",
            2,
        );

        assert_failure(
            &check_keys(with_gpg(&vault, &gpg)),
            &format!(
                "Vault error: could not add private key: {PGP_KEY}\n\nCaused by:\n    \
                 0: could not decode key at {PGP_KEY}\n    \
                 1: could not run `gpg --decrypt {PGP_KEY}`, fake stdout, fake stderr\n"
            ),
            "check-keys",
        );
        assert_eq!(gpg.calls(), gpg_call(PGP_KEY));
    }

    #[test]
    fn missing_gpg_fails() {
        let (vault, _gpg) = vault_with_pgp_key();
        let empty_dir = vault.root().join("empty_path");
        fs::create_dir(&empty_dir).unwrap();

        let mut cmd = vault.command();
        cmd.env("PATH", &empty_dir);
        assert_failure(
            &get(cmd, "SIMPLE"),
            &format!(
                "Vault error: could not add private key: {PGP_KEY}\n\nCaused by:\n    \
                 0: could not decode key at {PGP_KEY}\n    \
                 1: could not call gpg\n    \
                 2: No such file or directory (os error 2)\n"
            ),
            "get SIMPLE",
        );
    }

    #[test]
    fn pgp_key_without_public_key_fails_before_calling_gpg() {
        let (vault, gpg) = vault_with_pgp_key();
        let dir = private_keys(&vault);
        fs::rename(dir.join("alice.pem.pgp"), dir.join("carol.pem.pgp")).unwrap();

        assert_failure(
            &check_keys(with_gpg(&vault, &gpg)),
            &missing_public_key_error(
                "./.vault/private_keys/carol.pub.pem",
                "./.vault/private_keys/carol.pem.pgp",
            ),
            "check-keys",
        );
        assert_eq!(gpg.calls(), "");
    }
}
