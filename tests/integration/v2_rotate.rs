//! `vault rotate` with V2 keys and `vault rotate --migrate v2`.
//!
//! A V2 key is rotated into a new V2 key: the new key is written as `<ID>_to_rotate.pem`, every
//! file of the current key `<ID>` is renamed to `<ID>_backup_<timestamp>` and the new key becomes
//! `<ID>`. A migration rotates the first active V1 key into a new current V2 key `<ID>` and keeps
//! the V1 key as a backup like a V1 rotation. When the new key is a V2 key, the user keeps their
//! `config.toml`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;

use crate::common::{
    Snapshot, TestVault, assert_failure, assert_only_changed, assert_output, assert_success, run,
    snapshot,
};
use crate::support::{ALICE_SECRETS, GOLDEN, alice_private_key, alice_public_key, golden_file};
use crate::support_v2::{
    ALICE_V2_SECRETS, CAROL_SECRETS, DAVE_SECRETS, GOLDEN_V2, REPOSITORY_ID, as_v2_user,
    assert_v2_crypt_file, generate_key_pair, golden_v2_file, no_v1_keys, public_key_of,
    reference_encrypt_v2, v2_private_key, v2_public_key,
};

const COULD_NOT_FIND_KEY: &str = "Vault error: could not find key\n";
const BEFORE_KEY_CREATION: &[u8] = b"1. generate new key\ngenerating keys ...\n";

/// The error of a rotation that refuses the file `path` before anything changes.
fn already_exists(path: &str) -> String {
    format!(
        "Vault error: rotate keys\n\nCaused by:\n    0: create_keys\n    \
         1: could not create the key, the file {path} already exists\n"
    )
}

/// The error of a rotation that refuses the leftover `path` before anything changes.
fn left_over(path: &str) -> String {
    format!(
        "Vault error: rotate keys\n\nCaused by:\n    0: create_keys\n    \
         1: could not rotate the key, the file {path} is left over from an interrupted rotation, \
         remove it once the repository is restored with git\n"
    )
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get(mut cmd: Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

/// A command with only the V2 keys of `key_dir` and no V1 key.
fn with_v2_keys(vault: &TestVault, key_dir: &Path) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", key_dir)
        .env("VAULT_PRIVATE_KEY_PATH", no_v1_keys(vault));
    cmd
}

/// Writes a key pair as `<dir>/<stem>.pem` and `<dir>/<stem>.pem.pub`.
fn write_key_pair(dir: &Path, stem: &str, private_pem: &[u8]) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(format!("{stem}.pem")), private_pem).unwrap();
    fs::write(
        dir.join(format!("{stem}.pem.pub")),
        public_key_of(private_pem),
    )
    .unwrap();
}

/// A key directory outside the working directory with the golden V2 key of `user` as current key.
fn key_dir_of(vault: &TestVault, user: &str) -> PathBuf {
    let dir = vault.root().join("keys");
    write_key_pair(&dir, REPOSITORY_ID, &v2_private_key(user));
    dir
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn file_names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_string()).collect()
}

/// The file names of the key pairs `<stem>.pem` and `<stem>.pem.pub` of every stem.
fn key_pair_names(stems: &[&str]) -> BTreeSet<String> {
    stems
        .iter()
        .flat_map(|stem| [format!("{stem}.pem"), format!("{stem}.pem.pub")])
        .collect()
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

/// Asserts the stdout of a rotation of `user`'s key that encrypted `secrets` for the new key.
/// The files are created in the order of the secrets dir listing, which is not fixed.
fn assert_rotate_output(output: &Output, user: &str, secrets: &[&str]) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let prefix = "1. generate new key\ngenerating keys ...\n2. allow access to all keys\n";
    let suffix = "2. delete the old key\n3. rename user\n\
                  the key has been rotated, the old key is still there and has a backup suffix.\n";
    assert_eq!(output.status.code(), Some(0), "exit code, stdout: {stdout}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "", "stderr");
    assert!(
        stdout.starts_with(prefix) && stdout.ends_with(suffix),
        "stdout: {stdout}"
    );

    let created: Vec<&str> = stdout[prefix.len()..stdout.len() - suffix.len()]
        .lines()
        .collect();
    let expected: BTreeSet<String> = secrets
        .iter()
        .map(|secret| format!("creating file ./.vault/secrets/{secret}/{user}_to_rotate.crypt"))
        .collect();
    assert_eq!(created.len(), secrets.len(), "stdout: {stdout}");
    assert_eq!(
        created.into_iter().collect::<BTreeSet<_>>(),
        expected.iter().map(String::as_str).collect(),
        "stdout: {stdout}"
    );
}

/// The timestamps of the backups `<ID>_backup_<timestamp>.pem` or `.pem.pgp` in `dir`, oldest
/// first.
fn backup_timestamps(dir: &Path) -> Vec<u64> {
    backup_timestamps_of(dir, REPOSITORY_ID)
}

/// [`backup_timestamps`] for the repository ID `id`.
fn backup_timestamps_of(dir: &Path, id: &str) -> Vec<u64> {
    let prefix = format!("{id}_backup_");
    let mut timestamps: Vec<u64> = file_names(dir)
        .iter()
        .filter_map(|name| {
            let rest = name.strip_prefix(&prefix)?;
            rest.strip_suffix(".pem")
                .or_else(|| rest.strip_suffix(".pem.pgp"))
        })
        .map(|timestamp| timestamp.parse().unwrap())
        .collect();
    timestamps.sort();
    timestamps
}

/// Asserts that `before` and `after` only differ in paths that contain one of `parts`.
fn assert_unchanged_except(before: &Snapshot, after: &Snapshot, parts: &[&str]) {
    let without = |snapshot: &Snapshot| -> Snapshot {
        snapshot
            .iter()
            .filter(|(path, _)| {
                let path = path.to_str().unwrap();
                !parts.iter().any(|part| path.contains(part))
            })
            .map(|(path, content)| (path.clone(), content.clone()))
            .collect()
    };
    assert!(
        without(before) == without(after),
        "unexpected changes on disk, only paths with {parts:?} may change"
    );
}

/// Asserts that no file or directory below `dir` contains `_to_rotate` in its path.
fn assert_no_leftovers(dir: &Path) {
    let snapshot = snapshot(dir);
    assert!(
        snapshot
            .keys()
            .all(|path| !path.to_str().unwrap().contains("_to_rotate")),
        "leftovers in {}: {:?}",
        dir.display(),
        snapshot.keys().collect::<Vec<_>>()
    );
}

/// The `.crypt` paths of `user` for `secrets`, relative to the working directory.
fn crypt_paths(user: &str, secrets: &[&str]) -> Vec<String> {
    secrets
        .iter()
        .map(|secret| format!(".vault/secrets/{secret}/{user}.crypt"))
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// MARK: V2 -> V2

#[test]
fn rotate_v2_key_keeps_a_backup_and_the_subscriptions() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let key_dir = key_dir_of(&vault, "dave");
    let before = snapshot(&vault.path());

    let started = unix_time();
    let output = run(with_v2_keys(&vault, &key_dir).arg("rotate"));
    let finished = unix_time();
    assert_rotate_output(&output, "dave", DAVE_SECRETS);

    // The old key pair is kept byte for byte as a backup.
    let timestamps = backup_timestamps(&key_dir);
    assert_eq!(timestamps.len(), 1, "one backup: {timestamps:?}");
    assert!(
        (started..=finished).contains(&timestamps[0]),
        "timestamp {}",
        timestamps[0]
    );
    let backup = format!("{REPOSITORY_ID}_backup_{}", timestamps[0]);
    assert_eq!(
        file_names(&key_dir),
        key_pair_names(&[REPOSITORY_ID, &backup])
    );
    assert_eq!(
        read(&key_dir.join(format!("{backup}.pem"))),
        v2_private_key("dave")
    );
    assert_eq!(
        read(&key_dir.join(format!("{backup}.pem.pub"))),
        v2_public_key("dave")
    );

    // The new key pair is the current key and is registered for dave, who keeps his
    // subscriptions.
    let new_private = read(&key_dir.join(format!("{REPOSITORY_ID}.pem")));
    let new_public = read(&key_dir.join(format!("{REPOSITORY_ID}.pem.pub")));
    assert_ne!(new_private, v2_private_key("dave"));
    assert_eq!(public_key_of(&new_private).as_bytes(), new_public);
    #[cfg(unix)]
    assert_eq!(
        mode(&key_dir.join(format!("{REPOSITORY_ID}.pem"))),
        0o600,
        "private key"
    );
    assert_eq!(
        read(&vault.path().join(".vault/keys/dave/dave.pem.pub")),
        new_public
    );
    assert_eq!(
        read(&vault.path().join(".vault/keys/dave/config.toml")),
        golden_v2_file(".vault/keys/dave/config.toml")
    );

    // Every secret dave could read is a version 2 file for the new key.
    for secret in DAVE_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "dave"),
            &new_private,
            &vault.expected(secret),
        );
    }

    let mut changed = crypt_paths("dave", DAVE_SECRETS);
    changed.push(".vault/keys/dave/dave.pem.pub".to_string());
    let changed: Vec<&str> = changed.iter().map(String::as_str).collect();
    assert_only_changed(&before, &snapshot(&vault.path()), &changed);

    // The new key alone reads every secret of dave.
    let new_keys = vault.root().join("new_keys");
    write_key_pair(&new_keys, REPOSITORY_ID, &new_private);
    for secret in DAVE_SECRETS {
        assert_success(
            &get(with_v2_keys(&vault, &new_keys), secret),
            &vault.expected(secret),
            "",
            secret,
        );
    }

    // The backup is loaded as an unregistered key and still reads a file for the old key.
    assert_success(
        &run(&mut with_v2_keys(&vault, &key_dir)),
        &nothing_to_do(&["dave", &backup]),
        "",
        "default run",
    );
    fs::write(
        vault.crypt_path("DAVE_ONLY", "dave"),
        golden_v2_file(".vault/secrets/DAVE_ONLY/dave.crypt"),
    )
    .unwrap();
    assert_success(
        &get(with_v2_keys(&vault, &key_dir), "DAVE_ONLY"),
        &vault.expected("DAVE_ONLY"),
        "",
        "old file",
    );
    assert_failure(
        &get(with_v2_keys(&vault, &new_keys), "DAVE_ONLY"),
        COULD_NOT_FIND_KEY,
        "old file with the new key only",
    );
}

#[test]
fn two_rotations_in_a_row_take_the_next_free_backup_names() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let key_dir = key_dir_of(&vault, "carol");

    // A lone public key file is never loaded, but it takes its backup name.
    let now = unix_time();
    let taken: Vec<String> = (now..=now + 3600)
        .map(|timestamp| format!("{REPOSITORY_ID}_backup_{timestamp}.pem.pub"))
        .collect();
    for name in &taken {
        fs::write(key_dir.join(name), "taken").unwrap();
    }

    assert_rotate_output(
        &run(with_v2_keys(&vault, &key_dir).arg("rotate")),
        "carol",
        CAROL_SECRETS,
    );
    let first_private = read(&key_dir.join(format!("{REPOSITORY_ID}.pem")));
    assert_rotate_output(
        &run(with_v2_keys(&vault, &key_dir).arg("rotate")),
        "carol",
        CAROL_SECRETS,
    );
    let second_private = read(&key_dir.join(format!("{REPOSITORY_ID}.pem")));
    assert_ne!(first_private, second_private);

    let first_backup = format!("{REPOSITORY_ID}_backup_{}", now + 3601);
    let second_backup = format!("{REPOSITORY_ID}_backup_{}", now + 3602);
    let mut expected_files = key_pair_names(&[REPOSITORY_ID, &first_backup, &second_backup]);
    expected_files.extend(taken.iter().cloned());
    assert_eq!(file_names(&key_dir), expected_files);
    for name in &taken {
        assert_eq!(read(&key_dir.join(name)), b"taken", "{name}");
    }
    assert_eq!(
        read(&key_dir.join(format!("{first_backup}.pem"))),
        v2_private_key("carol")
    );
    assert_eq!(
        read(&key_dir.join(format!("{second_backup}.pem"))),
        first_private
    );

    for secret in CAROL_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "carol"),
            &second_private,
            &vault.expected(secret),
        );
    }
    assert_eq!(
        read(&vault.path().join(".vault/keys/carol/config.toml")),
        golden_v2_file(".vault/keys/carol/config.toml")
    );
    assert_no_leftovers(&vault.path());
    assert_no_leftovers(&key_dir);

    // The current key first, then the backups, newest first.
    assert_success(
        &run(&mut with_v2_keys(&vault, &key_dir)),
        &nothing_to_do(&["carol", &second_backup, &first_backup]),
        "",
        "default run",
    );
}

#[test]
fn leftover_to_rotate_file_fails_before_anything_changes() {
    for extension in [".pem", ".pem.pgp", ".pem.pub"] {
        let vault = TestVault::from_fixture(GOLDEN_V2);
        let key_dir = key_dir_of(&vault, "carol");
        let leftover = key_dir.join(format!("{REPOSITORY_ID}_to_rotate{extension}"));
        fs::write(&leftover, "leftover").unwrap();
        let before = snapshot(&vault.path());
        let keys_before = snapshot(&key_dir);

        assert_output(
            &run(with_v2_keys(&vault, &key_dir).arg("rotate")),
            1,
            BEFORE_KEY_CREATION,
            &left_over(&leftover.display().to_string()),
            extension,
        );
        assert_eq!(snapshot(&vault.path()), before, "{extension}: repository");
        assert_eq!(snapshot(&key_dir), keys_before, "{extension}: key dir");
    }
}

#[test]
fn rotate_registered_backup_key_keeps_the_unregistered_current_key() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let key_dir = vault.root().join("keys");
    // The current key comes from a rotation on another branch, only the backup is registered.
    let (abandoned_private, abandoned_public) = generate_key_pair();
    write_key_pair(&key_dir, REPOSITORY_ID, &abandoned_private);
    let carol_backup = format!("{REPOSITORY_ID}_backup_1");
    write_key_pair(&key_dir, &carol_backup, &v2_private_key("carol"));
    // A secret of that branch that only the unregistered key reads.
    fs::create_dir(vault.secret_dir("ABANDONED")).unwrap();
    fs::write(
        vault.crypt_path("ABANDONED", "carol"),
        reference_encrypt_v2(&abandoned_public, b"abandoned branch"),
    )
    .unwrap();

    let started = unix_time();
    let output = run(with_v2_keys(&vault, &key_dir).arg("rotate"));
    let finished = unix_time();
    let mut secrets = CAROL_SECRETS.to_vec();
    secrets.push("ABANDONED");
    assert_rotate_output(&output, "carol", &secrets);

    // The unregistered key became a backup, the registered backup is unchanged.
    let timestamps = backup_timestamps(&key_dir);
    assert_eq!(timestamps.len(), 2, "{timestamps:?}");
    assert_eq!(timestamps[0], 1);
    assert!((started..=finished).contains(&timestamps[1]));
    let abandoned_backup = format!("{REPOSITORY_ID}_backup_{}", timestamps[1]);
    assert_eq!(
        file_names(&key_dir),
        key_pair_names(&[REPOSITORY_ID, &carol_backup, &abandoned_backup])
    );
    assert_eq!(
        read(&key_dir.join(format!("{abandoned_backup}.pem"))),
        abandoned_private
    );
    assert_eq!(
        read(&key_dir.join(format!("{abandoned_backup}.pem.pub"))),
        abandoned_public
    );
    assert_eq!(
        read(&key_dir.join(format!("{carol_backup}.pem"))),
        v2_private_key("carol")
    );

    let new_private = read(&key_dir.join(format!("{REPOSITORY_ID}.pem")));
    assert_ne!(new_private, abandoned_private);
    assert_ne!(new_private, v2_private_key("carol"));
    assert_eq!(
        read(&vault.path().join(".vault/keys/carol/carol.pem.pub")),
        read(&key_dir.join(format!("{REPOSITORY_ID}.pem.pub")))
    );
    for secret in CAROL_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "carol"),
            &new_private,
            &vault.expected(secret),
        );
    }
    assert_v2_crypt_file(
        &vault.crypt_path("ABANDONED", "carol"),
        &new_private,
        b"abandoned branch",
    );
    assert_no_leftovers(&vault.path());

    assert_success(
        &run(&mut with_v2_keys(&vault, &key_dir)),
        &nothing_to_do(&["carol", &abandoned_backup, &carol_backup]),
        "",
        "default run",
    );
}

#[cfg(unix)]
#[test]
fn rotate_pgp_key_keeps_the_pgp_file_as_backup() {
    use crate::support::FakeGpg;

    let vault = TestVault::from_fixture(GOLDEN_V2);
    let key_dir = vault.root().join("keys");
    fs::create_dir(&key_dir).unwrap();
    fs::write(
        key_dir.join(format!("{REPOSITORY_ID}.pem.pgp")),
        "not really encrypted",
    )
    .unwrap();
    fs::write(
        key_dir.join(format!("{REPOSITORY_ID}.pem.pub")),
        v2_public_key("carol"),
    )
    .unwrap();
    let plain_key = vault.root().join("plain.pem");
    fs::write(&plain_key, v2_private_key("carol")).unwrap();
    let gpg = FakeGpg::new(&vault.root().join("fake_gpg"), &plain_key, "", 0);
    let with_gpg = || {
        let mut cmd = with_v2_keys(&vault, &key_dir);
        cmd.env("PATH", gpg.path_env());
        cmd
    };

    assert_rotate_output(&run(with_gpg().arg("rotate")), "carol", CAROL_SECRETS);

    // The gpg file and its public key are the backup, the new key is a plain `.pem`.
    let timestamps = backup_timestamps(&key_dir);
    assert_eq!(timestamps.len(), 1, "one backup: {timestamps:?}");
    let backup = format!("{REPOSITORY_ID}_backup_{}", timestamps[0]);
    assert_eq!(
        file_names(&key_dir),
        names(&[
            &format!("{REPOSITORY_ID}.pem"),
            &format!("{REPOSITORY_ID}.pem.pub"),
            &format!("{backup}.pem.pgp"),
            &format!("{backup}.pem.pub"),
        ])
    );
    assert_eq!(
        read(&key_dir.join(format!("{backup}.pem.pgp"))),
        b"not really encrypted"
    );
    assert_eq!(
        read(&key_dir.join(format!("{backup}.pem.pub"))),
        v2_public_key("carol")
    );
    let new_private = read(&key_dir.join(format!("{REPOSITORY_ID}.pem")));
    assert_eq!(
        public_key_of(&new_private).as_bytes(),
        read(&key_dir.join(format!("{REPOSITORY_ID}.pem.pub")))
    );
    for secret in CAROL_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "carol"),
            &new_private,
            &vault.expected(secret),
        );
    }

    // The backup is still decrypted with gpg and reads a file for the old key.
    assert_success(
        &run(&mut with_gpg()),
        &nothing_to_do(&["carol", &backup]),
        "",
        "default run",
    );
    fs::write(
        vault.crypt_path("SIMPLE", "carol"),
        golden_v2_file(".vault/secrets/SIMPLE/carol.crypt"),
    )
    .unwrap();
    assert_success(&get(with_gpg(), "SIMPLE"), b"hello world", "", "old file");
    assert!(
        gpg.calls().contains(&format!(
            "{}\n",
            key_dir.join(format!("{backup}.pem.pgp")).display()
        )),
        "calls: {}",
        gpg.calls()
    );
}

// MARK: V1 -> V2

#[test]
fn migrate_turns_every_secret_into_version_2() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    let started = unix_time();
    let output = run(vault.command().args(["rotate", "--migrate", "v2"]));
    let finished = unix_time();
    assert_rotate_output(&output, "alice", ALICE_SECRETS);

    // The repository ID is created.
    let id_file = fs::read_to_string(vault.path().join(".vault/repository_id")).unwrap();
    let id = id_file.strip_suffix('\n').expect("one trailing newline");
    assert_eq!(id.len(), 36, "{id}");
    assert_eq!(&id[14..15], "7", "UUIDv7: {id}");

    // The new key is the current V2 key in the home key dir.
    let key_dir = vault.home().join(".vault/v2");
    assert_eq!(file_names(&key_dir), key_pair_names(&[id]));
    let new_private = read(&key_dir.join(format!("{id}.pem")));
    let new_public = read(&key_dir.join(format!("{id}.pem.pub")));
    assert_eq!(public_key_of(&new_private).as_bytes(), new_public);
    #[cfg(unix)]
    {
        assert_eq!(mode(&key_dir), 0o700, "key dir");
        assert_eq!(
            mode(&key_dir.join(format!("{id}.pem"))),
            0o600,
            "private key"
        );
    }

    // The V1 key is backed up as in a V1 rotation.
    let private_keys = vault.path().join(".vault/private_keys");
    let backups: Vec<String> = file_names(&private_keys).into_iter().collect();
    assert_eq!(backups.len(), 2, "{backups:?}");
    let backup = backups[0].strip_suffix(".pem").unwrap().to_string();
    let timestamp: u64 = backup
        .strip_prefix("alice_backup_")
        .unwrap()
        .parse()
        .unwrap();
    assert!((started..=finished).contains(&timestamp));
    assert_eq!(backups[1], format!("{backup}.pub.pem"));
    assert_eq!(
        read(&private_keys.join(format!("{backup}.pem"))),
        alice_private_key()
    );
    assert_eq!(
        read(&private_keys.join(format!("{backup}.pub.pem"))),
        alice_public_key()
    );

    // alice is registered with the V2 key and keeps her subscriptions.
    let user_dir = vault.path().join(".vault/keys/alice");
    assert_eq!(
        file_names(&user_dir),
        names(&["alice.pem.pub", "config.toml"])
    );
    assert_eq!(read(&user_dir.join("alice.pem.pub")), new_public);
    assert_eq!(
        read(&user_dir.join("config.toml")),
        golden_file(".vault/keys/alice/config.toml")
    );

    for secret in ALICE_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "alice"),
            &new_private,
            &vault.expected(secret),
        );
    }
    assert_unchanged_except(
        &before,
        &snapshot(&vault.path()),
        &[
            "alice.crypt",
            ".vault/private_keys/alice",
            ".vault/keys/alice",
            ".vault/repository_id",
        ],
    );
    assert_no_leftovers(&vault.path());

    // The V1 backup is loaded first, the V2 key is the active one and encrypts new secrets.
    fs::write(vault.secret_dir("NEW"), "new secret").unwrap();
    assert_success(
        &run(&mut vault.command()),
        format!(
            "\ncreate key map.\n\n\nnew secrets (1):\n  - ./.vault/secrets/NEW\n\n\
             loaded keys:\n- {backup}\n- alice\n\nall fine\n\n"
        )
        .as_bytes(),
        "",
        "default run",
    );
    assert_v2_crypt_file(
        &vault.crypt_path("NEW", "alice"),
        &new_private,
        b"new secret",
    );

    // A file for the old key is still read through the V1 backup.
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
}

#[test]
fn migrate_keeps_the_repository_id() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let key_dir = vault.root().join("alice_keys");
    let before = snapshot(&vault.path());

    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", &key_dir);
    assert_rotate_output(
        &run(cmd.args(["rotate", "--migrate", "v2"])),
        "alice",
        ALICE_V2_SECRETS,
    );

    assert_eq!(file_names(&key_dir), key_pair_names(&[REPOSITORY_ID]));
    let new_private = read(&key_dir.join(format!("{REPOSITORY_ID}.pem")));
    for secret in ALICE_V2_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "alice"),
            &new_private,
            &vault.expected(secret),
        );
    }
    assert_eq!(
        read(&vault.path().join(".vault/keys/alice/config.toml")),
        golden_v2_file(".vault/keys/alice/config.toml")
    );
    // The repository ID, carol and dave are unchanged.
    assert_unchanged_except(
        &before,
        &snapshot(&vault.path()),
        &[
            "alice.crypt",
            ".vault/private_keys/alice",
            ".vault/keys/alice",
        ],
    );

    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", &key_dir);
    assert_success(&get(cmd, "SHARED"), &vault.expected("SHARED"), "", "SHARED");
}

#[test]
fn migrate_refuses_an_existing_v2_key() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let (unregistered, _) = generate_key_pair();
    write_key_pair(
        &vault.path().join("unregistered_keys"),
        REPOSITORY_ID,
        &unregistered,
    );
    let leftover_dir = vault.path().join("leftover_keys");
    fs::create_dir(&leftover_dir).unwrap();
    fs::write(
        leftover_dir.join(format!("{REPOSITORY_ID}_to_rotate.pem.pub")),
        "leftover",
    )
    .unwrap();
    let before = snapshot(&vault.path());

    for (key_dir, error) in [
        (
            "carol_v2_keys",
            already_exists(&format!("carol_v2_keys/{REPOSITORY_ID}.pem")),
        ),
        (
            "unregistered_keys",
            already_exists(&format!("unregistered_keys/{REPOSITORY_ID}.pem")),
        ),
        (
            "leftover_keys",
            left_over(&format!("leftover_keys/{REPOSITORY_ID}_to_rotate.pem.pub")),
        ),
    ] {
        let mut cmd = vault.command();
        cmd.env("VAULT_V2_KEY_PATH", key_dir);
        assert_output(
            &run(cmd.args(["rotate", "--migrate", "v2"])),
            1,
            BEFORE_KEY_CREATION,
            &error,
            key_dir,
        );
        assert_eq!(
            snapshot(&vault.path()),
            before,
            "{key_dir}: nothing may change"
        );
    }
}

#[test]
fn migrate_without_an_active_v1_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let before = snapshot(&vault.path());

    assert_failure(
        &run(as_v2_user(&vault, "carol").args(["rotate", "--migrate", "v2"])),
        "Vault error: rotate keys\n\nCaused by:\n    \
         could not migrate, there is no active private key older than V2\n",
        "rotate --migrate v2",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

#[test]
fn migrate_backs_up_the_v1_key_under_a_free_name() {
    let vault = TestVault::from_fixture(GOLDEN);
    let private_keys = vault.path().join(".vault/private_keys");

    // Lone V1 public keys are not loaded, pairs are loaded as inactive backups. Both take their
    // backup name.
    let now = unix_time();
    let mut taken = vec![];
    for timestamp in now..=now + 3600 {
        taken.push(format!("alice_backup_{timestamp}.pub.pem"));
    }
    for timestamp in now + 3601..=now + 3610 {
        taken.push(format!("alice_backup_{timestamp}.pem"));
        taken.push(format!("alice_backup_{timestamp}.pub.pem"));
    }
    for name in &taken {
        fs::write(private_keys.join(name), "taken").unwrap();
    }

    assert_rotate_output(
        &run(vault.command().args(["rotate", "--migrate", "v2"])),
        "alice",
        ALICE_SECRETS,
    );

    let backup = format!("alice_backup_{}", now + 3611);
    let mut expected_files: BTreeSet<String> = taken.iter().cloned().collect();
    expected_files.insert(format!("{backup}.pem"));
    expected_files.insert(format!("{backup}.pub.pem"));
    assert_eq!(file_names(&private_keys), expected_files);
    for name in &taken {
        assert_eq!(read(&private_keys.join(name)), b"taken", "{name}");
    }
    assert_eq!(
        read(&private_keys.join(format!("{backup}.pem"))),
        alice_private_key()
    );
    assert_eq!(
        read(&private_keys.join(format!("{backup}.pub.pem"))),
        alice_public_key()
    );
}

/// A gpg encrypted V1 key is backed up with its public key, a `.pem.pgp` without its public key
/// would fail every later command.
#[cfg(unix)]
#[test]
fn migrate_backs_up_a_pgp_v1_key() {
    use crate::support::FakeGpg;

    let vault = TestVault::from_fixture(GOLDEN);
    let private_keys = vault.path().join(".vault/private_keys");
    let plain_key = vault.root().join("alice.plain.pem");
    fs::rename(private_keys.join("alice.pem"), &plain_key).unwrap();
    fs::write(private_keys.join("alice.pem.pgp"), "not really encrypted").unwrap();
    let gpg = FakeGpg::new(&vault.root().join("fake_gpg"), &plain_key, "", 0);
    let with_gpg = || {
        let mut cmd = vault.command();
        cmd.env("PATH", gpg.path_env());
        cmd
    };

    assert_rotate_output(
        &run(with_gpg().args(["rotate", "--migrate", "v2"])),
        "alice",
        ALICE_SECRETS,
    );

    let files = file_names(&private_keys);
    let backup = files
        .iter()
        .find_map(|name| name.strip_suffix(".pem.pgp"))
        .expect("a gpg encrypted backup")
        .to_string();
    assert!(backup.starts_with("alice_backup_"), "{backup}");
    assert_eq!(
        files,
        names(&[&format!("{backup}.pem.pgp"), &format!("{backup}.pub.pem")])
    );
    assert_eq!(
        read(&private_keys.join(format!("{backup}.pem.pgp"))),
        b"not really encrypted"
    );
    assert_eq!(
        read(&private_keys.join(format!("{backup}.pub.pem"))),
        alice_public_key()
    );

    // The migrated key reads the secrets, the backup is still loaded with gpg.
    let calls = gpg.calls();
    let output = get(with_gpg(), "SIMPLE");
    assert_success(&output, &vault.expected("SIMPLE"), "", "get SIMPLE");
    assert_eq!(
        gpg.calls(),
        format!(
            "{calls}--decrypt\n--pinentry-mode\nloopback\n./.vault/private_keys/{backup}.pem.pgp\n"
        )
    );
}

// MARK: Superseded V1 keys

/// alice's V1 key outside `./.vault/private_keys` is not backed up by a migration and stays
/// loaded as "alice". The repository registers a V2 key for alice, so the V1 key only decrypts:
/// it neither encrypts new secrets nor is it rotated or migrated again.
fn assert_superseded_v1_key_only_decrypts(
    vault: &TestVault,
    v1_key_dir: &Path,
    command: impl Fn() -> Command,
) {
    let mut migrate = command();
    assert_rotate_output(
        &run(migrate.args(["rotate", "--migrate", "v2"])),
        "alice",
        ALICE_SECRETS,
    );
    let id = fs::read_to_string(vault.path().join(".vault/repository_id")).unwrap();
    let id = id.trim();
    let key_dir = vault.home().join(".vault/v2");
    let migrated_private = read(&key_dir.join(format!("{id}.pem")));
    let v1_keys = || {
        assert_eq!(
            file_names(v1_key_dir),
            names(&["alice.pem", "alice.pub.pem"])
        );
        assert_eq!(read(&v1_key_dir.join("alice.pem")), alice_private_key());
    };
    v1_keys();

    // There is nothing left to migrate.
    let before = snapshot(&vault.root());
    let mut migrate = command();
    assert_failure(
        &run(migrate.args(["rotate", "--migrate", "v2"])),
        "Vault error: rotate keys\n\nCaused by:\n    \
         could not migrate, there is no active private key older than V2\n",
        "second migration",
    );
    assert_eq!(snapshot(&vault.root()), before, "nothing may change");

    // A new secret is encrypted for the V2 key.
    fs::write(vault.secret_dir("NEW"), "new secret").unwrap();
    assert_success(
        &run(&mut command()),
        b"\ncreate key map.\n\n\nnew secrets (1):\n  - ./.vault/secrets/NEW\n\n\
          loaded keys:\n- alice\n- alice\n\nall fine\n\n",
        "",
        "new secret",
    );
    assert_v2_crypt_file(
        &vault.crypt_path("NEW", "alice"),
        &migrated_private,
        b"new secret",
    );

    // A plain rotation rotates the V2 key.
    let mut secrets = ALICE_SECRETS.to_vec();
    secrets.push("NEW");
    assert_rotate_output(&run(command().arg("rotate")), "alice", &secrets);

    let timestamps = backup_timestamps_of(&key_dir, id);
    assert_eq!(timestamps.len(), 1, "one backup: {timestamps:?}");
    let backup = format!("{id}_backup_{}", timestamps[0]);
    assert_eq!(file_names(&key_dir), key_pair_names(&[id, &backup]));
    assert_eq!(
        read(&key_dir.join(format!("{backup}.pem"))),
        migrated_private
    );
    let new_private = read(&key_dir.join(format!("{id}.pem")));
    assert_ne!(new_private, migrated_private);

    let user_dir = vault.path().join(".vault/keys/alice");
    assert_eq!(
        file_names(&user_dir),
        names(&["alice.pem.pub", "config.toml"])
    );
    assert_eq!(
        read(&user_dir.join("alice.pem.pub")),
        read(&key_dir.join(format!("{id}.pem.pub")))
    );
    for secret in ALICE_SECRETS {
        assert_v2_crypt_file(
            &vault.crypt_path(secret, "alice"),
            &new_private,
            &vault.expected(secret),
        );
    }
    assert_v2_crypt_file(
        &vault.crypt_path("NEW", "alice"),
        &new_private,
        b"new secret",
    );
    v1_keys();
}

/// Moves alice's V1 key pair from `./.vault/private_keys` into `dir`.
fn move_alice_v1_keys(vault: &TestVault, dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    for name in ["alice.pem", "alice.pub.pem"] {
        fs::rename(
            vault.path().join(".vault/private_keys").join(name),
            dir.join(name),
        )
        .unwrap();
    }
}

#[test]
fn superseded_v1_key_in_home_only_decrypts() {
    let vault = TestVault::from_fixture(GOLDEN);
    let v1_key_dir = vault.home().join(".vault/private_keys");
    move_alice_v1_keys(&vault, &v1_key_dir);

    assert_superseded_v1_key_only_decrypts(&vault, &v1_key_dir, || vault.command());
}

#[test]
fn superseded_v1_key_in_key_path_only_decrypts() {
    let vault = TestVault::from_fixture(GOLDEN);
    let v1_key_dir = vault.root().join("alice_v1_keys");
    move_alice_v1_keys(&vault, &v1_key_dir);

    assert_superseded_v1_key_only_decrypts(&vault, &v1_key_dir, || {
        let mut cmd = vault.command();
        cmd.env("VAULT_PRIVATE_KEY_PATH", &v1_key_dir);
        cmd
    });
}

// MARK: No downgrade

/// A plain `rotate` of a V2 key stays V2, see `rotate_v2_key_keeps_a_backup_and_the_subscriptions`.
#[test]
fn migrate_accepts_only_v2() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let before = snapshot(&vault.path());

    for version in ["v1", "V2", "2"] {
        let output = run(as_v2_user(&vault, "carol").args(["rotate", "--migrate", version]));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{version}: stderr: {stderr}");
        assert!(output.stdout.is_empty(), "{version}: stdout");
        assert!(
            stderr.starts_with(&format!(
                "error: invalid value '{version}' for '--migrate <VERSION>'\n"
            )) && stderr.contains("[possible values: v2]"),
            "{version}: stderr: {stderr}"
        );
    }
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

// MARK: No key

#[test]
fn rotate_without_an_active_key_fails() {
    let golden = TestVault::from_fixture(GOLDEN);
    let mut no_keys = golden.command();
    no_keys.env("VAULT_PRIVATE_KEY_PATH", no_v1_keys(&golden));

    let unregistered = TestVault::from_fixture(GOLDEN_V2);
    fs::remove_file(unregistered.path().join(".vault/keys/carol/carol.pem.pub")).unwrap();

    for (vault, mut cmd, context) in [
        (&golden, no_keys, "no key"),
        (
            &unregistered,
            as_v2_user(&unregistered, "carol"),
            "unregistered key",
        ),
    ] {
        let before = snapshot(&vault.path());
        assert_failure(
            &run(cmd.arg("rotate")),
            "Vault error: rotate keys\n\nCaused by:\n    \
             could not rotate, there is no active private key\n",
            context,
        );
        assert_eq!(
            snapshot(&vault.path()),
            before,
            "{context}: nothing may change"
        );
    }
}
