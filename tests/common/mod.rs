//! Test utilities for vault integration tests.
//!
//! `TestVault::from_fixture` copies a committed fixture from `tests/fixtures/` into an isolated
//! temporary directory and runs the vault binary against it with an empty `HOME`.
//! `TestVault::empty` does the same with an empty working directory.

#![allow(dead_code)] // Not all test targets use all helpers

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use assert_cmd::Command;
use tempfile::TempDir;

/// Returns the path of a committed fixture, e.g. `fixture_dir("v1/golden")`.
pub fn fixture_dir(fixture: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture)
}

/// Recursively copies the directory `from` into the (not yet existing) directory `to`.
pub fn copy_dir_recursive(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap_or_else(|error| panic!("could not create {}: {error}", to.display()));

    for entry in fs::read_dir(from)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", from.display()))
    {
        let entry = entry.expect("could not read directory entry");
        let file_type = entry.file_type().expect("could not read file type");
        let target = to.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).unwrap_or_else(|error| {
                panic!("could not copy {}: {error}", entry.path().display())
            });
        } else {
            panic!(
                "unexpected file type in fixture: {}",
                entry.path().display()
            );
        }
    }
}

/// Asserts that the vault process did not panic.
pub fn assert_no_panic(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "vault panicked, stderr:\n{stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(101),
        "vault exited with the panic exit code, stderr:\n{stderr}"
    );
}

/// Runs the command and asserts that vault did not panic.
pub fn run(cmd: &mut Command) -> Output {
    let output = cmd.output().expect("could not run vault");
    assert_no_panic(&output);
    output
}

/// Asserts that vault exited with `code` and printed exactly `stdout` and `stderr`.
pub fn assert_output(output: &Output, code: i32, stdout: &[u8], stderr: &str, context: &str) {
    let actual_stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(code),
        "{context}: exit code, stderr: {actual_stderr}"
    );
    assert_eq!(
        output.stdout,
        stdout,
        "{context}: stdout, as text: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(actual_stderr, stderr, "{context}: stderr");
}

/// Asserts a successful run with exactly `stdout` and `stderr`.
pub fn assert_success(output: &Output, stdout: &[u8], stderr: &str, context: &str) {
    assert_output(output, 0, stdout, stderr, context);
}

/// Asserts a failed run: exit code 1, no stdout and exactly `stderr`.
pub fn assert_failure(output: &Output, stderr: &str, context: &str) {
    assert_output(output, 1, b"", stderr, context);
}

/// Every file (with its contents) and directory (`None`) below a directory, by relative path.
pub type Snapshot = BTreeMap<PathBuf, Option<Vec<u8>>>;

/// Every file and directory below `dir` (relative paths), with the contents of the files.
/// Comparing two snapshots shows whether a run changed anything on disk.
pub fn snapshot(dir: &Path) -> Snapshot {
    fn walk(root: &Path, dir: &Path, entries: &mut Snapshot) {
        for entry in fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", dir.display()))
        {
            let path = entry.expect("could not read directory entry").path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if path.is_dir() {
                entries.insert(relative, None);
                walk(root, &path, entries);
            } else {
                entries.insert(relative, Some(fs::read(&path).unwrap()));
            }
        }
    }

    let mut entries = BTreeMap::new();
    walk(dir, dir, &mut entries);
    entries
}

/// Asserts that `after` differs from `before` only in `changed`: each of these relative paths
/// must exist in `after` (new or modified), every other entry must be unchanged.
pub fn assert_only_changed(before: &Snapshot, after: &Snapshot, changed: &[&str]) {
    let mut before = before.clone();
    let mut after = after.clone();
    for path in changed {
        before.remove(Path::new(path));
        assert!(
            after.remove(Path::new(path)).is_some(),
            "{path} must exist after the run"
        );
    }
    let changed_paths = |snapshot: &Snapshot, other: &Snapshot| {
        snapshot
            .iter()
            .filter(|(path, content)| other.get(*path) != Some(*content))
            .map(|(path, _)| path.display().to_string())
            .collect::<Vec<_>>()
    };
    assert!(
        before == after,
        "unexpected changes on disk, only {changed:?} may change. \
         before (differing): {:?}, after (differing): {:?}",
        changed_paths(&before, &after),
        changed_paths(&after, &before),
    );
}

/// How long a vault command that asks questions may run. vault asks again on every unexpected
/// answer, also at the end of stdin, so a missing answer would otherwise keep it running.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// An isolated vault working directory with its own empty `HOME`.
pub struct TestVault {
    temp_dir: TempDir,
}

impl TestVault {
    /// Copies the fixture `tests/fixtures/<fixture>` into a new temporary directory and creates
    /// an empty `home/` next to it.
    pub fn from_fixture(fixture: &str) -> TestVault {
        let temp_dir = TempDir::new().expect("could not create temp directory");
        copy_dir_recursive(&fixture_dir(fixture), &temp_dir.path().join("vault"));
        fs::create_dir(temp_dir.path().join("home")).expect("could not create home directory");
        TestVault { temp_dir }
    }

    /// Creates a new temporary directory with an empty working directory and an empty `home/`.
    pub fn empty() -> TestVault {
        let temp_dir = TempDir::new().expect("could not create temp directory");
        fs::create_dir(temp_dir.path().join("vault")).expect("could not create vault directory");
        fs::create_dir(temp_dir.path().join("home")).expect("could not create home directory");
        TestVault { temp_dir }
    }

    /// The temporary directory that holds the working directory and `HOME`. Tests can put
    /// further files here that vault does not see.
    pub fn root(&self) -> PathBuf {
        self.temp_dir.path().to_path_buf()
    }

    /// The working directory vault runs in.
    pub fn path(&self) -> PathBuf {
        self.temp_dir.path().join("vault")
    }

    /// The `HOME` directory vault sees.
    pub fn home(&self) -> PathBuf {
        self.temp_dir.path().join("home")
    }

    /// A vault command that answers every question with yes (`VAULT_FORCE_YES=1`).
    pub fn command(&self) -> Command {
        let mut cmd = self.base_command();
        cmd.env("VAULT_FORCE_YES", "1");
        cmd
    }

    /// A vault command that asks its questions on stdin, killed after [`ANSWER_TIMEOUT`].
    /// Callers can set a longer timeout with `Command::timeout`.
    pub fn interactive(&self) -> Command {
        let mut cmd = self.base_command();
        cmd.timeout(ANSWER_TIMEOUT);
        cmd
    }

    /// A vault command that reads `answers` as its stdin, killed after [`ANSWER_TIMEOUT`].
    pub fn answering(&self, answers: &str) -> Command {
        let mut cmd = self.interactive();
        cmd.write_stdin(answers);
        cmd
    }

    fn base_command(&self) -> Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("vault");
        cmd.current_dir(self.path())
            .env("HOME", self.home())
            .env("NO_COLOR", "1")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("VAULT_FORCE_YES")
            .env_remove("VAULT_PRIVATE_KEY_PATH")
            .env_remove("VAULT_V2_KEY_PATH")
            .env_remove("RUST_BACKTRACE")
            .env_remove("RUST_LIB_BACKTRACE");
        cmd
    }

    /// `.vault/secrets/<secret>`
    pub fn secret_dir(&self, secret: &str) -> PathBuf {
        self.path().join(".vault/secrets").join(secret)
    }

    /// `.vault/secrets/<secret>/<user>.crypt`
    pub fn crypt_path(&self, secret: &str, user: &str) -> PathBuf {
        self.secret_dir(secret).join(format!("{user}.crypt"))
    }

    /// `expected/<secret>`, the plaintext of a fixture secret.
    pub fn expected_path(&self, secret: &str) -> PathBuf {
        self.path().join("expected").join(secret)
    }

    /// The plaintext of a fixture secret.
    pub fn expected(&self, secret: &str) -> Vec<u8> {
        let path = self.expected_path(secret);
        fs::read(&path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
    }
}
