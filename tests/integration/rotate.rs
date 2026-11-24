//! `vault rotate`: replaces the first loaded private key without `_backup_` in its name with a
//! new one, encrypts every secret that any loaded key can read (also keys from `$HOME` and
//! backups) for the new key and keeps the old key pair as a backup.
//!
//! Every rotation generates an 8096-bit key, which takes seconds, so only a few tests rotate.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;

use crate::common::{Snapshot, TestVault, assert_output, assert_success, run, snapshot};
use crate::support::{
    ALICE_SECRETS, BOB_SECRETS, GOLDEN, alice_private_key, alice_public_key, assert_crypt_file,
    bob_private_key, bob_public_key, golden_file,
};

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get(mut cmd: Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

/// A command that loads the private keys from `dir`, relative to the working directory.
fn with_key_dir(vault: &TestVault, dir: &str) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", dir);
    cmd
}

/// Asserts the stdout of a rotation of `user`'s key that encrypted `secrets` for the new key.
///
/// The files are created in the order of the secrets dir listing, which is not fixed.
fn assert_rotate_output(output: &Output, user: &str, secrets: &[&str]) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let prefix = "1. generate new key\ngenerating keys ...\n2. allow access to all keys\n";
    // Two steps are numbered 2.
    let suffix = "2. delete the old key\n3. rename user\n\
                  the key has been rotated, the old key is still there and has a backup suffix.\n";
    assert_eq!(output.status.code(), Some(0), "exit code, stdout: {stdout}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "", "stderr");
    assert!(
        stdout.starts_with(prefix) && stdout.ends_with(suffix),
        "stdout: {stdout}"
    );

    let created: BTreeSet<&str> = stdout[prefix.len()..stdout.len() - suffix.len()]
        .lines()
        .collect();
    let expected: BTreeSet<String> = secrets
        .iter()
        .map(|secret| format!("creating file ./.vault/secrets/{secret}/{user}_to_rotate.crypt"))
        .collect();
    assert_eq!(
        created,
        expected.iter().map(String::as_str).collect(),
        "stdout: {stdout}"
    );
    assert_eq!(
        stdout.lines().count(),
        6 + secrets.len(),
        "every file is created once, stdout: {stdout}"
    );
}

/// The names in `.vault/private_keys/`.
fn private_key_files(vault: &TestVault) -> BTreeSet<String> {
    fs::read_dir(vault.path().join(".vault/private_keys"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

/// The `<timestamp>` of the single `<user>_backup_<timestamp>.pem` in `.vault/private_keys/`.
fn backup_timestamp(vault: &TestVault, user: &str) -> String {
    let prefix = format!("{user}_backup_");
    let timestamps: Vec<String> = private_key_files(vault)
        .iter()
        .filter_map(|name| name.strip_prefix(&prefix)?.strip_suffix(".pem"))
        .filter(|rest| !rest.ends_with(".pub"))
        .map(str::to_string)
        .collect();
    assert_eq!(timestamps.len(), 1, "one backup: {timestamps:?}");
    let timestamp = timestamps.into_iter().next().unwrap();
    assert!(
        !timestamp.is_empty() && timestamp.bytes().all(|byte| byte.is_ascii_digit()),
        "timestamp: {timestamp}"
    );
    timestamp
}

/// The entries of `snapshot` whose path does not contain one of `parts`.
fn without(snapshot: &Snapshot, parts: &[&str]) -> Snapshot {
    snapshot
        .iter()
        .filter(|(path, _)| {
            let path = path.to_str().unwrap();
            !parts.iter().any(|part| path.contains(part))
        })
        .map(|(path, content)| (path.clone(), content.clone()))
        .collect()
}

/// The secrets that hold a file named `file_name` in `snapshot`.
fn secrets_with(snapshot: &Snapshot, file_name: &str) -> BTreeSet<String> {
    snapshot
        .keys()
        .filter_map(|path| {
            let secret = path.strip_prefix(".vault/secrets").ok()?;
            let mut parts = secret.iter();
            let name = parts.next()?;
            (parts.next()? == file_name && parts.next().is_none())
                .then(|| name.to_str().unwrap().to_string())
        })
        .collect()
}

/// The names of the entries directly in `dir` in `snapshot`.
fn files_in(snapshot: &Snapshot, dir: &str) -> BTreeSet<String> {
    snapshot
        .keys()
        .filter(|path| path.parent() == Some(Path::new(dir)))
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_string())
        .collect()
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_string()).collect()
}

/// Copies alice's key pair into `$HOME/.vault/private_keys`.
fn copy_alice_keys_to_home(vault: &TestVault) {
    let home_keys = vault.home().join(".vault/private_keys");
    fs::create_dir_all(&home_keys).unwrap();
    fs::write(home_keys.join("alice.pem"), alice_private_key()).unwrap();
    fs::write(home_keys.join("alice.pub.pem"), alice_public_key()).unwrap();
}

fn read(vault: &TestVault, relative: &str) -> Vec<u8> {
    let path = vault.path().join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

#[test]
fn rotate_replaces_the_key_and_keeps_a_backup() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    let started = unix_time();
    // No question is printed with `VAULT_FORCE_YES=1`.
    let output = run(vault.command().arg("rotate"));
    let finished = unix_time();
    assert_rotate_output(&output, "alice", ALICE_SECRETS);

    // The old key pair is kept byte for byte as a backup.
    let timestamp = backup_timestamp(&vault, "alice");
    let parsed: u64 = timestamp.parse().unwrap();
    assert!((started..=finished).contains(&parsed), "timestamp {parsed}");
    let backup = format!("alice_backup_{timestamp}");
    assert_eq!(
        private_key_files(&vault),
        BTreeSet::from([
            "alice.pem".to_string(),
            "alice.pub.pem".to_string(),
            format!("{backup}.pem"),
            format!("{backup}.pub.pem"),
        ])
    );
    assert_eq!(
        read(&vault, &format!(".vault/private_keys/{backup}.pem")),
        alice_private_key()
    );
    assert_eq!(
        read(&vault, &format!(".vault/private_keys/{backup}.pub.pem")),
        alice_public_key()
    );

    // The new key pair replaces the old one under the same name.
    let new_private = read(&vault, ".vault/private_keys/alice.pem");
    let new_public = read(&vault, ".vault/private_keys/alice.pub.pem");
    assert_ne!(new_private, alice_private_key());
    assert_ne!(new_public, alice_public_key());
    assert_eq!(read(&vault, ".vault/keys/alice/alice.pub.pem"), new_public);
    // Rotation creates the user dir anew, so config.toml has no subscriptions any more.
    assert_eq!(
        read(&vault, ".vault/keys/alice/config.toml"),
        b"subscriptions = []"
    );

    // Every secret alice could read is encrypted for the new key.
    for secret in ALICE_SECRETS {
        assert_crypt_file(
            &vault.crypt_path(secret, "alice"),
            &new_private,
            &vault.expected(secret),
        );
    }

    // Everything else is unchanged: bob's files, the fixture's `bob_private_keys` and
    // `expected`, and no `alice_to_rotate` file or dir is left.
    let after = snapshot(&vault.path());
    let changed = [
        "alice.crypt",
        ".vault/private_keys/alice",
        ".vault/keys/alice/",
    ];
    assert_eq!(without(&after, &changed), without(&before, &changed));
    assert!(
        after
            .keys()
            .all(|path| !path.to_str().unwrap().contains("_to_rotate")),
        "leftovers: {:?}",
        after.keys().collect::<Vec<_>>()
    );
    assert_eq!(secrets_with(&after, "alice.crypt"), names(ALICE_SECRETS));
    assert_eq!(
        files_in(&after, ".vault/keys/alice"),
        names(&["alice.pub.pem", "config.toml"])
    );

    // The new key alone reads every secret.
    let new_keys = vault.path().join("new_keys");
    fs::create_dir(&new_keys).unwrap();
    fs::write(new_keys.join("alice.pem"), &new_private).unwrap();
    fs::write(new_keys.join("alice.pub.pem"), &new_public).unwrap();
    for secret in ALICE_SECRETS {
        assert_success(
            &get(with_key_dir(&vault, "new_keys"), secret),
            &vault.expected(secret),
            "",
            secret,
        );
    }

    // The backup is loaded as a key of its own. The order follows the key dir listing.
    let output = run(&mut vault.command());
    let stdout = |first: &str, second: &str| {
        format!("\ncreate key map.\n\nloaded keys:\n- {first}\n- {second}\n\nall fine\n\n")
    };
    let expected = if output.stdout == stdout("alice", &backup).as_bytes() {
        stdout("alice", &backup)
    } else {
        stdout(&backup, "alice")
    };
    assert_success(&output, expected.as_bytes(), "", "default run");

    // A file encrypted for the old key is still read through the backup.
    fs::write(
        vault.crypt_path("SIMPLE", "alice"),
        golden_file(".vault/secrets/SIMPLE/alice.crypt"),
    )
    .unwrap();
    assert_success(
        &get(vault.command(), "SIMPLE"),
        b"hello world",
        "",
        "old file",
    );
    assert_output(
        &get(with_key_dir(&vault, "new_keys"), "SIMPLE"),
        1,
        b"",
        "Vault error: could not find key\n",
        "old file with the new key only",
    );
}

#[test]
fn rotate_answered_with_no_changes_nothing() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());
    let question = "do you want to rotate your private key \"alice\"? (y/n)\n";

    assert_output(
        &run(vault.answering("x\nn\n").arg("rotate")),
        0,
        format!("{question}{question}").as_bytes(),
        "unexpected char \"x\" - reask.\n",
        "rotate",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

#[test]
fn rotate_skips_backup_keys() {
    let vault = TestVault::from_fixture(GOLDEN);
    let bob_keys = vault.path().join("bob_private_keys");
    fs::rename(bob_keys.join("bob.pem"), bob_keys.join("bob_backup_1.pem")).unwrap();
    fs::rename(
        bob_keys.join("bob.pub.pem"),
        bob_keys.join("bob_backup_1.pub.pem"),
    )
    .unwrap();
    // The configured key dir is read before `$HOME`, so the backup is the first loaded key.
    copy_alice_keys_to_home(&vault);
    let before = snapshot(&vault.path());

    let mut cmd = vault.answering("n\n");
    cmd.env("VAULT_PRIVATE_KEY_PATH", "bob_private_keys");
    assert_success(
        &run(cmd.arg("rotate")),
        b"do you want to rotate your private key \"alice\"? (y/n)\n",
        "",
        "rotate",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

#[test]
fn rotate_with_key_path_env_writes_to_the_default_key_dir() {
    let vault = TestVault::from_fixture(GOLDEN);
    // alice's keys in `$HOME` are loaded after bob's, so bob's key is rotated, but the new key
    // gets every secret that any loaded key can read.
    copy_alice_keys_to_home(&vault);
    let mut all_secrets = names(ALICE_SECRETS);
    all_secrets.extend(names(BOB_SECRETS));
    let all_secrets: Vec<&str> = all_secrets.iter().map(String::as_str).collect();
    let before = snapshot(&vault.path());

    assert_rotate_output(
        &run(with_key_dir(&vault, "bob_private_keys").arg("rotate")),
        "bob",
        &all_secrets,
    );

    // The new key goes to `./.vault/private_keys`, not to the configured key dir,
    // and the old key there is not backed up and stays as it is.
    assert_eq!(
        private_key_files(&vault),
        names(&["alice.pem", "alice.pub.pem", "bob.pem", "bob.pub.pem"])
    );
    assert_eq!(read(&vault, "bob_private_keys/bob.pem"), bob_private_key());
    assert_eq!(
        read(&vault, "bob_private_keys/bob.pub.pem"),
        bob_public_key()
    );

    let new_private = read(&vault, ".vault/private_keys/bob.pem");
    let new_public = read(&vault, ".vault/private_keys/bob.pub.pem");
    assert_ne!(new_private, bob_private_key());
    assert_eq!(read(&vault, ".vault/keys/bob/bob.pub.pem"), new_public);
    assert_eq!(
        read(&vault, ".vault/keys/bob/config.toml"),
        b"subscriptions = []"
    );
    for secret in &all_secrets {
        assert_crypt_file(
            &vault.crypt_path(secret, "bob"),
            &new_private,
            &vault.expected(secret),
        );
    }

    let after = snapshot(&vault.path());
    let changed = ["bob.crypt", ".vault/private_keys/bob", ".vault/keys/bob/"];
    assert_eq!(without(&after, &changed), without(&before, &changed));
    assert_eq!(secrets_with(&after, "bob.crypt"), names(&all_secrets));
    assert_eq!(
        files_in(&after, ".vault/keys/bob"),
        names(&["bob.pub.pem", "config.toml"])
    );
    assert!(
        after
            .keys()
            .all(|path| !path.to_str().unwrap().contains("_to_rotate")),
        "leftovers"
    );

    // The configured key dir still holds the old key, which reads none of bob's
    // files any more (alice's key in `$HOME` cannot read BOB_ONLY either). The default key dir
    // now holds the new one.
    assert_output(
        &get(with_key_dir(&vault, "bob_private_keys"), "BOB_ONLY"),
        1,
        b"",
        "Vault error: could not find key\n",
        "old key",
    );
    assert_success(
        &get(vault.command(), "BOB_ONLY"),
        &vault.expected("BOB_ONLY"),
        "",
        "new key",
    );
}

#[test]
fn rotate_without_secrets_only_replaces_the_key() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::remove_dir_all(vault.path().join(".vault/secrets")).unwrap();
    fs::create_dir(vault.path().join(".vault/secrets")).unwrap();

    assert_rotate_output(&run(vault.command().arg("rotate")), "alice", &[]);

    let backup = format!("alice_backup_{}", backup_timestamp(&vault, "alice"));
    assert_eq!(
        private_key_files(&vault),
        names(&[
            "alice.pem",
            "alice.pub.pem",
            &format!("{backup}.pem"),
            &format!("{backup}.pub.pem"),
        ])
    );
    assert_eq!(
        read(&vault, &format!(".vault/private_keys/{backup}.pem")),
        alice_private_key()
    );
    assert_ne!(
        read(&vault, ".vault/private_keys/alice.pem"),
        alice_private_key()
    );
    assert_eq!(
        read(&vault, ".vault/keys/alice/alice.pub.pem"),
        read(&vault, ".vault/private_keys/alice.pub.pem")
    );
    assert!(snapshot(&vault.path().join(".vault/secrets")).is_empty());
}
