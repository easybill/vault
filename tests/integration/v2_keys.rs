//! V2 keys: `vault create-key <user>`, the repository ID, the key directory (`VAULT_V2_KEY_PATH`
//! or `$HOME/.vault/v2`), loading of current and backup keys, keys stored as `.pem.pgp`, which
//! user a local key belongs to and `vault rotate` with a V2 key.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Output;

use assert_cmd::Command;

use crate::common::{
    TestVault, assert_failure, assert_only_changed, assert_output, assert_success, run, snapshot,
};
use crate::support::GOLDEN;
use crate::support_v2::{
    GOLDEN_V2, REPOSITORY_ID, as_v2_user, assert_v2_crypt_file, generate_key_pair, no_v1_keys,
    public_key_of, v2_private_key, v2_public_key,
};

const GENERATING: &[u8] = b"generating keys ...\n";
const NO_PRIVATE_KEY: &str = "Vault error: there is no private key\n";
const COULD_NOT_FIND_KEY: &str = "Vault error: could not find key\n";

/// The stdout of a default run that has nothing to do, listing the loaded keys.
fn nothing_to_do(keys: &[&str]) -> Vec<u8> {
    let mut stdout = String::from("\ncreate key map.\n\nloaded keys:\n");
    for key in keys {
        stdout.push_str(&format!("- {key}\n"));
    }
    stdout.push_str("\nall fine\n\n");
    stdout.into_bytes()
}

/// A command with only the V2 keys of `key_dir` (relative to the working directory or absolute)
/// and no V1 key.
fn with_v2_keys(vault: &TestVault, key_dir: impl AsRef<Path>) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", key_dir.as_ref())
        .env("VAULT_PRIVATE_KEY_PATH", no_v1_keys(vault));
    cmd
}

/// A command with no V1 key and the V2 keys of `$HOME/.vault/v2`.
fn with_home_keys(vault: &TestVault) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", no_v1_keys(vault));
    cmd
}

fn get(mut cmd: Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

fn check_keys(mut cmd: Command) -> Output {
    run(cmd.arg("check-keys"))
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

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Asserts that `id` is a UUIDv7 in its canonical form.
fn assert_uuid_v7(id: &str) {
    assert_eq!(id.len(), 36, "{id}");
    for (index, char) in id.chars().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            assert_eq!(char, '-', "{id}");
        } else {
            assert!(matches!(char, '0'..='9' | 'a'..='f'), "{id}");
        }
    }
    assert_eq!(&id[14..15], "7", "version 7: {id}");
}

// MARK: create-key

#[test]
fn create_key_creates_the_repository_id_the_key_pair_and_the_user_dir() {
    let vault = TestVault::from_fixture(GOLDEN);
    let before = snapshot(&vault.path());

    assert_success(
        &run(vault.command().args(["create-key", "carol"])),
        GENERATING,
        "",
        "create-key carol",
    );

    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/repository_id",
            ".vault/keys/carol",
            ".vault/keys/carol/carol.pem.pub",
            ".vault/keys/carol/config.toml",
        ],
    );
    let id_file = fs::read_to_string(vault.path().join(".vault/repository_id")).unwrap();
    let id = id_file.strip_suffix('\n').expect("one trailing newline");
    assert_uuid_v7(id);

    let key_dir = vault.home().join(".vault/v2");
    assert_eq!(
        file_names(&key_dir),
        names(&[&format!("{id}.pem"), &format!("{id}.pem.pub")])
    );
    let private_pem = fs::read(key_dir.join(format!("{id}.pem"))).unwrap();
    let public_pem = fs::read(key_dir.join(format!("{id}.pem.pub"))).unwrap();
    assert!(private_pem.starts_with(b"-----BEGIN XWING PRIVATE KEY-----\n"));
    assert_eq!(public_key_of(&private_pem).as_bytes(), public_pem);

    let user_dir = vault.path().join(".vault/keys/carol");
    assert_eq!(
        fs::read(user_dir.join("carol.pem.pub")).unwrap(),
        public_pem
    );
    assert_eq!(
        fs::read(user_dir.join("config.toml")).unwrap(),
        b"subscriptions = []"
    );

    #[cfg(unix)]
    {
        assert_eq!(mode(&key_dir), 0o700, "key dir");
        assert_eq!(
            mode(&vault.home().join(".vault")),
            0o700,
            "parent of the key dir"
        );
        assert_eq!(
            mode(&key_dir.join(format!("{id}.pem"))),
            0o600,
            "private key"
        );
    }

    // The new key is loaded after alice's V1 key and belongs to carol.
    assert_success(
        &run(&mut vault.command()),
        &nothing_to_do(&["alice", "carol"]),
        "",
        "default run",
    );
}

#[test]
fn create_key_keeps_the_repository_id() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let key_dir = vault.root().join("erin_keys");
    let before = snapshot(&vault.path());

    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", &key_dir);
    assert_success(
        &run(cmd.args(["create-key", "erin"])),
        GENERATING,
        "",
        "create-key erin",
    );

    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/keys/erin",
            ".vault/keys/erin/erin.pem.pub",
            ".vault/keys/erin/config.toml",
        ],
    );
    assert_eq!(
        file_names(&key_dir),
        names(&[
            &format!("{REPOSITORY_ID}.pem"),
            &format!("{REPOSITORY_ID}.pem.pub")
        ])
    );
    assert!(
        !vault.home().join(".vault").exists(),
        "the home dir is unused"
    );
    #[cfg(unix)]
    assert_eq!(mode(&key_dir), 0o700, "key dir");

    assert_success(
        &run(&mut with_v2_keys(&vault, &key_dir)),
        &nothing_to_do(&["erin"]),
        "",
        "default run",
    );
}

#[test]
fn create_key_refuses_an_existing_key_file() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let lone_public_key = vault.path().join("lone_public_key");
    fs::create_dir(&lone_public_key).unwrap();
    fs::copy(
        vault
            .path()
            .join(format!("carol_v2_keys/{REPOSITORY_ID}.pem.pub")),
        lone_public_key.join(format!("{REPOSITORY_ID}.pem.pub")),
    )
    .unwrap();
    let before = snapshot(&vault.path());

    for (key_dir, existing) in [
        (
            "carol_v2_keys",
            format!("carol_v2_keys/{REPOSITORY_ID}.pem"),
        ),
        (
            "lone_public_key",
            format!("lone_public_key/{REPOSITORY_ID}.pem.pub"),
        ),
    ] {
        let mut cmd = vault.command();
        cmd.env("VAULT_V2_KEY_PATH", key_dir);
        assert_output(
            &run(cmd.args(["create-key", "erin"])),
            1,
            GENERATING,
            &format!("Vault error: could not create the key, the file {existing} already exists\n"),
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
fn create_key_refuses_an_existing_user() {
    for fixture in [GOLDEN, GOLDEN_V2] {
        let vault = TestVault::from_fixture(fixture);
        let key_dir = vault.root().join("new_keys");
        let before = snapshot(&vault.path());

        let mut cmd = vault.command();
        cmd.env("VAULT_V2_KEY_PATH", &key_dir);
        assert_output(
            &run(cmd.args(["create-key", "alice"])),
            1,
            GENERATING,
            "Vault error: could not create the key, the user directory ./.vault/keys/alice \
             already exists\n",
            fixture,
        );
        // Not even the repository ID is created.
        assert_eq!(
            snapshot(&vault.path()),
            before,
            "{fixture}: nothing may change"
        );
        assert!(!key_dir.exists(), "{fixture}: no key dir");
    }
}

#[test]
fn wizard_does_not_create_a_repository_id() {
    let vault = TestVault::empty();
    let output = run(&mut vault.command());
    assert_eq!(output.status.code(), Some(0));
    assert!(vault.path().join(".vault/keys").is_dir());
    assert!(!vault.path().join(".vault/repository_id").exists());
}

// MARK: Key directories

#[test]
fn home_key_dir_is_used() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    write_key_pair(
        &vault.home().join(".vault/v2"),
        REPOSITORY_ID,
        &v2_private_key("carol"),
    );

    assert_success(
        &run(&mut with_home_keys(&vault)),
        &nothing_to_do(&["carol"]),
        "",
        "default run",
    );
    assert_success(
        &get(with_home_keys(&vault), "SIMPLE"),
        b"hello world",
        "",
        "SIMPLE",
    );
}

#[test]
fn key_path_env_replaces_the_home_key_dir() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    write_key_pair(
        &vault.home().join(".vault/v2"),
        REPOSITORY_ID,
        &v2_private_key("carol"),
    );

    assert_success(
        &run(&mut as_v2_user(&vault, "dave")),
        &nothing_to_do(&["dave"]),
        "",
        "default run",
    );
    assert_failure(
        &get(as_v2_user(&vault, "dave"), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "SIMPLE",
    );
}

#[test]
fn empty_key_path_env_uses_the_home_key_dir() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let before = snapshot(&vault.path());

    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", "");
    assert_success(
        &run(cmd.args(["create-key", "erin"])),
        GENERATING,
        "",
        "create-key erin",
    );

    // Nothing is written into the working directory except erin's user dir.
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/keys/erin",
            ".vault/keys/erin/erin.pem.pub",
            ".vault/keys/erin/config.toml",
        ],
    );
    assert_eq!(
        file_names(&vault.home().join(".vault/v2")),
        names(&[
            &format!("{REPOSITORY_ID}.pem"),
            &format!("{REPOSITORY_ID}.pem.pub")
        ])
    );

    let mut cmd = with_home_keys(&vault);
    cmd.env("VAULT_V2_KEY_PATH", "");
    assert_success(&run(&mut cmd), &nothing_to_do(&["erin"]), "", "default run");
}

#[test]
fn missing_key_dir_has_no_keys() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    assert_failure(&check_keys(with_home_keys(&vault)), NO_PRIVATE_KEY, "home");
    assert_failure(
        &check_keys(with_v2_keys(&vault, "missing_keys")),
        NO_PRIVATE_KEY,
        "VAULT_V2_KEY_PATH",
    );
}

#[test]
fn keys_of_other_repositories_and_other_files_are_ignored() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let dir = vault.path().join("carol_v2_keys");
    for name in [
        "01a21196-0000-7000-8000-000000000000.pem".to_string(),
        "notes.txt".to_string(),
        format!("{REPOSITORY_ID}_to_rotate.pem"),
        format!("{REPOSITORY_ID}_backup_.pem"),
        format!("{REPOSITORY_ID}_backup_1x.pem"),
        format!("{REPOSITORY_ID}.pem.bak"),
    ] {
        fs::write(dir.join(name), "not a key").unwrap();
    }

    assert_success(
        &run(&mut as_v2_user(&vault, "carol")),
        &nothing_to_do(&["carol"]),
        "",
        "default run",
    );
}

// MARK: Invalid keys

#[test]
fn private_key_without_public_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::remove_file(
        vault
            .path()
            .join(format!("carol_v2_keys/{REPOSITORY_ID}.pem.pub")),
    )
    .unwrap();

    assert_failure(
        &check_keys(as_v2_user(&vault, "carol")),
        &format!(
            "Vault error: could not find a corresponding public key at \
             \"carol_v2_keys/{REPOSITORY_ID}.pem.pub\" for private key at \
             \"carol_v2_keys/{REPOSITORY_ID}.pem\"\n"
        ),
        "check-keys",
    );
}

#[test]
fn public_key_of_another_private_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::write(
        vault
            .path()
            .join(format!("carol_v2_keys/{REPOSITORY_ID}.pem.pub")),
        v2_public_key("dave"),
    )
    .unwrap();

    assert_failure(
        &check_keys(as_v2_user(&vault, "carol")),
        &format!(
            "Vault error: the public key carol_v2_keys/{REPOSITORY_ID}.pem.pub does not belong \
             to the private key carol_v2_keys/{REPOSITORY_ID}.pem\n"
        ),
        "check-keys",
    );
}

#[test]
fn invalid_private_key_fails_when_loaded() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let path = format!("carol_v2_keys/{REPOSITORY_ID}.pem");
    fs::write(vault.path().join(&path), v2_public_key("carol")).unwrap();

    assert_failure(
        &check_keys(as_v2_user(&vault, "carol")),
        &format!(
            "Vault error: could not add private key: {path}\n\nCaused by:\n    \
             expected a PEM block with the label XWING PRIVATE KEY, found XWING PUBLIC KEY\n"
        ),
        "check-keys",
    );
}

#[test]
fn invalid_registered_public_key_fails_only_when_used() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let user_dir = vault.path().join(".vault/keys/erin");
    fs::create_dir(&user_dir).unwrap();
    fs::write(
        user_dir.join("config.toml"),
        r#"subscriptions = ["SIMPLE"]"#,
    )
    .unwrap();
    fs::write(user_dir.join("erin.pem.pub"), "not a key").unwrap();

    // It never matches a local key and only fails the encryption for erin.
    assert_success(
        &get(as_v2_user(&vault, "carol"), "SIMPLE"),
        b"hello world",
        "",
        "get",
    );
    assert_output(
        &run(&mut as_v2_user(&vault, "carol")),
        1,
        b"\ncreate key map.\n\nloaded keys:\n- carol\n\n\
          open subscriptions you've the required right to fulfill (1):\n  \
          - user: erin, name: SIMPLE\n\n\
          creating file ./.vault/secrets/SIMPLE/erin.crypt\n",
        "Vault error: could not encrypt data using key erin\n\nCaused by:\n    \
         0: invalid public key erin\n    1: invalid PEM\n    \
         2: PEM preamble contains invalid data (NUL byte)\n",
        "default run",
    );
}

// MARK: Repository ID

#[test]
fn invalid_repository_id_fails_every_command() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::write(vault.path().join(".vault/repository_id"), "not-a-uuid\n").unwrap();
    let error = "Vault error: invalid repository ID in ./.vault/repository_id\n\nCaused by:\n    \
         failed to parse a UUID\n";

    // Also for alice, who has no V2 key.
    assert_failure(&check_keys(vault.command()), error, "alice");
    assert_failure(&get(as_v2_user(&vault, "carol"), "SIMPLE"), error, "carol");
}

#[test]
fn repository_id_is_read_in_its_canonical_form() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::write(
        vault.path().join(".vault/repository_id"),
        format!("  {}\r\n\n", REPOSITORY_ID.to_uppercase()),
    )
    .unwrap();

    assert_success(
        &get(as_v2_user(&vault, "carol"), "SIMPLE"),
        b"hello world",
        "",
        "SIMPLE",
    );
}

#[test]
fn missing_repository_id_means_no_v2_keys() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::remove_file(vault.path().join(".vault/repository_id")).unwrap();

    assert_failure(
        &check_keys(as_v2_user(&vault, "carol")),
        NO_PRIVATE_KEY,
        "check-keys",
    );
}

// MARK: Backups and identity

#[test]
fn current_key_comes_first_then_backups_newest_first() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let dir = vault.root().join("keys");
    let (unregistered, _) = generate_key_pair();
    write_key_pair(&dir, REPOSITORY_ID, &unregistered);
    write_key_pair(
        &dir,
        &format!("{REPOSITORY_ID}_backup_20"),
        &v2_private_key("dave"),
    );
    write_key_pair(
        &dir,
        &format!("{REPOSITORY_ID}_backup_100"),
        &v2_private_key("carol"),
    );
    let (unregistered_backup, _) = generate_key_pair();
    write_key_pair(
        &dir,
        &format!("{REPOSITORY_ID}_backup_3"),
        &unregistered_backup,
    );

    // A registered key is named after its user, an unregistered one after its file.
    assert_success(
        &run(&mut with_v2_keys(&vault, &dir)),
        &nothing_to_do(&[
            REPOSITORY_ID,
            "carol",
            "dave",
            &format!("{REPOSITORY_ID}_backup_3"),
        ]),
        "",
        "default run",
    );
    for secret in ["SIMPLE", "DAVE_ONLY"] {
        assert_success(
            &get(with_v2_keys(&vault, &dir), secret),
            &vault.expected(secret),
            "",
            secret,
        );
    }
}

#[test]
fn unregistered_key_only_decrypts() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::remove_file(vault.path().join(".vault/keys/carol/carol.pem.pub")).unwrap();
    fs::write(vault.secret_dir("NEW"), "new secret").unwrap();
    let before = snapshot(&vault.path());

    assert_success(
        &get(as_v2_user(&vault, "carol"), "SIMPLE"),
        b"hello world",
        "",
        "SIMPLE",
    );
    assert_output(
        &run(&mut as_v2_user(&vault, "carol")),
        1,
        b"\ncreate key map.\n\n\nnew secrets (1):\n  - ./.vault/secrets/NEW\n\n",
        "Vault error: could not fine private key for you, no idea how to encrypt \
         ./.vault/secrets/NEW\n",
        "new secret",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");

    fs::remove_file(vault.secret_dir("NEW")).unwrap();
    assert_success(
        &run(&mut as_v2_user(&vault, "carol")),
        &nothing_to_do(&[REPOSITORY_ID]),
        "",
        "default run",
    );
}

#[test]
fn registered_backup_key_encrypts_new_secrets() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let dir = vault.root().join("keys");
    let (unregistered, _) = generate_key_pair();
    write_key_pair(&dir, REPOSITORY_ID, &unregistered);
    write_key_pair(
        &dir,
        &format!("{REPOSITORY_ID}_backup_1"),
        &v2_private_key("carol"),
    );
    fs::write(vault.secret_dir("NEW"), "new secret").unwrap();

    assert_success(
        &run(&mut with_v2_keys(&vault, &dir)),
        format!(
            "\ncreate key map.\n\n\nnew secrets (1):\n  - ./.vault/secrets/NEW\n\n\
             loaded keys:\n- {REPOSITORY_ID}\n- carol\n\nall fine\n\n"
        )
        .as_bytes(),
        "",
        "default run",
    );
    assert_v2_crypt_file(
        &vault.crypt_path("NEW", "carol"),
        &v2_private_key("carol"),
        b"new secret",
    );
}

#[test]
fn key_registered_twice_belongs_to_the_first_user() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let user_dir = vault.path().join(".vault/keys/bob");
    fs::create_dir(&user_dir).unwrap();
    fs::write(user_dir.join("config.toml"), "subscriptions = []").unwrap();
    fs::write(user_dir.join("bob.pem.pub"), v2_public_key("carol")).unwrap();

    assert_success(
        &run(&mut as_v2_user(&vault, "carol")),
        &nothing_to_do(&["bob"]),
        "",
        "default run",
    );
}

// MARK: Keys stored with gpg

#[cfg(unix)]
#[test]
fn pgp_key_is_decrypted_with_gpg() {
    use crate::support::FakeGpg;

    let vault = TestVault::from_fixture(GOLDEN_V2);
    let pgp_key = format!("carol_v2_keys/{REPOSITORY_ID}.pem.pgp");
    let plain_key = vault.root().join("carol.plain.pem");
    fs::rename(
        vault
            .path()
            .join(format!("carol_v2_keys/{REPOSITORY_ID}.pem")),
        &plain_key,
    )
    .unwrap();
    fs::write(vault.path().join(&pgp_key), "not really encrypted").unwrap();
    let gpg = FakeGpg::new(&vault.root().join("fake_gpg"), &plain_key, "", 0);

    let mut cmd = as_v2_user(&vault, "carol");
    cmd.env("PATH", gpg.path_env());
    assert_success(&get(cmd, "SIMPLE"), b"hello world", "", "SIMPLE");
    assert_eq!(
        gpg.calls(),
        format!("--decrypt\n--pinentry-mode\nloopback\n{pgp_key}\n")
    );
}

/// A fake gpg that prints `private_pem`, stored outside the working directory.
#[cfg(unix)]
fn fake_gpg_printing(vault: &TestVault, private_pem: &[u8]) -> crate::support::FakeGpg {
    let plain_key = vault.root().join("plain.pem");
    fs::write(&plain_key, private_pem).unwrap();
    crate::support::FakeGpg::new(&vault.root().join("fake_gpg"), &plain_key, "", 0)
}

#[cfg(unix)]
#[test]
fn pgp_backup_key_is_decrypted_with_gpg() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let dir = vault.root().join("keys");
    write_key_pair(&dir, REPOSITORY_ID, &v2_private_key("carol"));
    let backup = format!("{REPOSITORY_ID}_backup_5");
    fs::write(
        dir.join(format!("{backup}.pem.pgp")),
        "not really encrypted",
    )
    .unwrap();
    fs::write(dir.join(format!("{backup}.pem.pub")), v2_public_key("dave")).unwrap();
    let gpg = fake_gpg_printing(&vault, &v2_private_key("dave"));
    let with_gpg = || {
        let mut cmd = with_v2_keys(&vault, &dir);
        cmd.env("PATH", gpg.path_env());
        cmd
    };

    assert_success(
        &run(&mut with_gpg()),
        &nothing_to_do(&["carol", "dave"]),
        "",
        "default run",
    );
    assert_success(
        &get(with_gpg(), "DAVE_ONLY"),
        &vault.expected("DAVE_ONLY"),
        "",
        "DAVE_ONLY",
    );
    let pgp_key = dir.join(format!("{backup}.pem.pgp"));
    assert_eq!(
        gpg.calls(),
        format!(
            "--decrypt\n--pinentry-mode\nloopback\n{}\n",
            pgp_key.display()
        )
        .repeat(2)
    );
}

#[cfg(unix)]
#[test]
fn create_key_refuses_an_existing_pgp_key() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let dir = vault.path().join("pgp_keys");
    fs::create_dir(&dir).unwrap();
    fs::write(
        dir.join(format!("{REPOSITORY_ID}.pem.pgp")),
        "not really encrypted",
    )
    .unwrap();
    fs::write(
        dir.join(format!("{REPOSITORY_ID}.pem.pub")),
        v2_public_key("carol"),
    )
    .unwrap();
    let gpg = fake_gpg_printing(&vault, &v2_private_key("carol"));
    let before = snapshot(&vault.path());

    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", "pgp_keys")
        .env("PATH", gpg.path_env());
    assert_output(
        &run(cmd.args(["create-key", "erin"])),
        1,
        GENERATING,
        &format!(
            "Vault error: could not create the key, the file pgp_keys/{REPOSITORY_ID}.pem.pgp \
             already exists\n"
        ),
        "create-key",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

// MARK: Rotation

#[test]
fn rotate_refuses_a_v2_key() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    let before = snapshot(&vault.path());

    assert_failure(
        &run(as_v2_user(&vault, "carol").arg("rotate")),
        "Vault error: rotate keys\n\nCaused by:\n    could not rotate the key \"carol\", \
         rotating V2 keys is not supported\n",
        "rotate",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}
