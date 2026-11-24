//! The default `vault` run (no subcommand): plaintext files in `.vault/secrets/` become new
//! secrets, and open subscriptions of other users are fulfilled with the secrets the loaded keys
//! can read. Both steps list their changes and ask once for the whole batch.
//!
//! New secrets are encrypted for the first loaded private key, so every test that adds secrets
//! loads exactly one private key.

use std::fs;
use std::process::Output;

use assert_cmd::Command;

use crate::common::{TestVault, assert_only_changed, assert_output, assert_success, run, snapshot};
use crate::support::{
    GOLDEN, alice_private_key, alice_public_key, assert_crypt_file, bob_private_key,
    bob_public_key, encrypted_key_of, iv_of,
};

const CREATE_KEY_MAP: &str = "\ncreate key map.\n\n";
const ALL_FINE: &str = "\nall fine\n\n";
const MAYBE_LATER: &str = "maybe later\n";

/// The list of new secrets, by file name in `.vault/secrets/`.
fn new_secrets(names: &[&str]) -> String {
    let mut out = format!("\nnew secrets ({}):\n", names.len());
    for name in names {
        out.push_str(&format!("  - ./.vault/secrets/{name}\n"));
    }
    out.push('\n');
    out
}

/// The question asked once for a batch of `count` changes.
fn batch_prompt(count: usize) -> String {
    format!("apply these {count} change(s)? (y)es to all / (n)o to all / (c)ase by case\n")
}

/// The question for one new secret after answering `c`.
fn add_prompt(name: &str) -> String {
    format!("do you want to add the new secret at ./.vault/secrets/{name}? (y/n)\n")
}

fn loaded_keys(keys: &[&str]) -> String {
    let mut out = String::from("loaded keys:\n");
    for key in keys {
        out.push_str(&format!("- {key}\n"));
    }
    out
}

/// The list of open subscriptions that no loaded key can read.
fn unfulfillable(subscriptions: &[(&str, &str)]) -> String {
    let mut out = format!(
        "\nopen subscriptions without a key to fulfill them, ask someone who has access ({}):\n",
        subscriptions.len()
    );
    for (user, name) in subscriptions {
        out.push_str(&format!("  - user: {user}, name: {name}\n"));
    }
    out
}

/// The list of open subscriptions that the loaded keys can fulfill.
fn fulfillable(subscriptions: &[(&str, &str)]) -> String {
    let mut out = format!(
        "\nopen subscriptions you've the required right to fulfill ({}):\n",
        subscriptions.len()
    );
    for (user, name) in subscriptions {
        out.push_str(&format!("  - user: {user}, name: {name}\n"));
    }
    out.push('\n');
    out
}

/// The question for one subscription after answering `c`.
fn give_prompt(user: &str, name: &str) -> String {
    format!("   give {user} access to {name}? (y/n)\n")
}

fn creating(secret: &str, key: &str) -> String {
    format!("creating file ./.vault/secrets/{secret}/{key}.crypt\n")
}

/// The stdout of a run with nothing to do and only alice's key loaded.
fn nothing_to_do() -> String {
    [CREATE_KEY_MAP, &loaded_keys(&["alice"]), ALL_FINE].concat()
}

fn as_bob(vault: &TestVault) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_PRIVATE_KEY_PATH", "bob_private_keys");
    cmd
}

fn get(mut cmd: Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

fn write_secret(vault: &TestVault, name: &str, content: impl AsRef<[u8]>) {
    fs::write(vault.secret_dir(name), content).unwrap();
}

fn set_subscriptions(vault: &TestVault, user: &str, subscriptions: &str) {
    fs::write(
        vault
            .path()
            .join(".vault/keys")
            .join(user)
            .join("config.toml"),
        format!("subscriptions = {subscriptions}"),
    )
    .unwrap();
}

/// Creates the user dir `.vault/keys/<user>` with a config and the given public keys.
fn add_user(vault: &TestVault, user: &str, subscriptions: &str, keys: &[(&str, &[u8])]) {
    fs::create_dir(vault.path().join(".vault/keys").join(user)).unwrap();
    set_subscriptions(vault, user, subscriptions);
    for (name, pem) in keys {
        fs::write(
            vault
                .path()
                .join(".vault/keys")
                .join(user)
                .join(format!("{name}.pub.pem")),
            pem,
        )
        .unwrap();
    }
}

/// The names in a secret dir.
fn listing(vault: &TestVault, secret: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(vault.secret_dir(secret))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Asserts that a second run has nothing left to do.
fn assert_nothing_left(vault: &TestVault) {
    let before = snapshot(&vault.path());
    assert_success(
        &run(&mut vault.command()),
        nothing_to_do().as_bytes(),
        "",
        "second run",
    );
    assert_eq!(snapshot(&vault.path()), before, "second run changed files");
}

// MARK: New secrets

#[test]
fn new_secrets_are_encrypted_for_the_loaded_key() {
    let vault = TestVault::from_fixture(GOLDEN);
    let binary: Vec<u8> = (0..=255).rev().collect();
    let cases: &[(&str, &[u8])] = &[
        ("NEW_TEXT", b"new secret\n"),
        ("NEW_BINARY", &binary),
        ("NEW_EMPTY", b""),
    ];
    for (name, content) in cases {
        write_secret(&vault, name, content);
    }
    let before = snapshot(&vault.path());

    // The list is sorted by path.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &new_secrets(&["NEW_BINARY", "NEW_EMPTY", "NEW_TEXT"]),
            &loaded_keys(&["alice"]),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );

    // The plaintext file is replaced by a directory holding only `<key>.crypt`.
    for (name, content) in cases {
        assert_eq!(listing(&vault, name), ["alice.crypt"], "{name}");
        assert_crypt_file(
            &vault.crypt_path(name, "alice"),
            &alice_private_key(),
            content,
        );
        assert_success(&get(vault.command(), name), content, "", name);
    }
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/secrets/NEW_TEXT",
            ".vault/secrets/NEW_TEXT/alice.crypt",
            ".vault/secrets/NEW_BINARY",
            ".vault/secrets/NEW_BINARY/alice.crypt",
            ".vault/secrets/NEW_EMPTY",
            ".vault/secrets/NEW_EMPTY/alice.crypt",
        ],
    );
    assert_nothing_left(&vault);
}

#[test]
fn hidden_files_are_new_secrets_too() {
    let vault = TestVault::from_fixture(GOLDEN);
    write_secret(&vault, ".gitkeep", "");

    // Every file in `.vault/secrets/` is a new secret, also a hidden placeholder file.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &new_secrets(&[".gitkeep"]),
            &loaded_keys(&["alice"]),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );
    assert_crypt_file(
        &vault.crypt_path(".gitkeep", "alice"),
        &alice_private_key(),
        b"",
    );
}

#[test]
fn new_secret_without_private_key_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    for file in ["alice.pem", "alice.pub.pem"] {
        fs::remove_file(vault.path().join(".vault/private_keys").join(file)).unwrap();
    }
    write_secret(&vault, "NEW", "plaintext");
    let before = snapshot(&vault.path());

    assert_output(
        &run(&mut vault.command()),
        1,
        [CREATE_KEY_MAP, &new_secrets(&["NEW"])].concat().as_bytes(),
        "Vault error: could not fine private key for you, no idea how to encrypt \
         ./.vault/secrets/NEW\n",
        "default run",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

// MARK: Fulfilling subscriptions

#[test]
fn subscription_is_fulfilled_with_the_public_key_of_the_user() {
    let vault = TestVault::from_fixture(GOLDEN);
    set_subscriptions(&vault, "bob", r#"["SHARED", "GLOB_*", "SIMPLE"]"#);
    let before = snapshot(&vault.path());

    // Satisfied subscriptions (SHARED, GLOB_A) are not listed.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "SIMPLE")]),
            &creating("SIMPLE", "bob"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );

    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "bob"),
        &bob_private_key(),
        b"hello world",
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/SIMPLE/bob.crypt"],
    );
    assert_success(&get(as_bob(&vault), "SIMPLE"), b"hello world", "", "bob");
    assert_nothing_left(&vault);
}

#[test]
fn subscription_gets_one_file_per_public_key_of_the_user() {
    let vault = TestVault::from_fixture(GOLDEN);
    // A second key of bob. It is alice's public key, so alice's private key reads its files.
    fs::write(
        vault.path().join(".vault/keys/bob/bob2.pub.pem"),
        alice_public_key(),
    )
    .unwrap();
    set_subscriptions(&vault, "bob", r#"["SHARED", "GLOB_*", "SIMPLE"]"#);
    let before = snapshot(&vault.path());

    let output = run(&mut vault.command());
    // The files are created in the order of the user dir listing, which is not fixed.
    let stdout = |first: &str, second: &str| {
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "SIMPLE")]),
            &creating("SIMPLE", first),
            &creating("SIMPLE", second),
            ALL_FINE,
        ]
        .concat()
    };
    let expected = if output.stdout == stdout("bob", "bob2").as_bytes() {
        stdout("bob", "bob2")
    } else {
        stdout("bob2", "bob")
    };
    assert_success(&output, expected.as_bytes(), "", "default run");

    // Each file is named after its key.
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "bob"),
        &bob_private_key(),
        b"hello world",
    );
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "bob2"),
        &alice_private_key(),
        b"hello world",
    );
    // A subscription counts as satisfied once `<user>.crypt` exists, so the new key
    // gets no files for SHARED and GLOB_A.
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/secrets/SIMPLE/bob.crypt",
            ".vault/secrets/SIMPLE/bob2.crypt",
        ],
    );
    assert_nothing_left(&vault);
}

#[test]
fn subscription_of_a_user_whose_key_has_another_name_stays_open() {
    let vault = TestVault::from_fixture(GOLDEN);
    add_user(
        &vault,
        "carol",
        r#"["SIMPLE"]"#,
        &[("carol_laptop", &bob_public_key())],
    );
    let stdout = [
        CREATE_KEY_MAP,
        &loaded_keys(&["alice"]),
        &fulfillable(&[("carol", "SIMPLE")]),
        &creating("SIMPLE", "carol_laptop"),
        ALL_FINE,
    ]
    .concat();

    assert_success(
        &run(&mut vault.command()),
        stdout.as_bytes(),
        "",
        "first run",
    );
    let first = fs::read(vault.crypt_path("SIMPLE", "carol_laptop")).unwrap();

    // The subscription is satisfied only by `carol.crypt`, so every run encrypts the
    // secret again for `carol_laptop`.
    assert_success(
        &run(&mut vault.command()),
        stdout.as_bytes(),
        "",
        "second run",
    );
    // The file is written again with a fresh IV and AES key.
    let second = fs::read(vault.crypt_path("SIMPLE", "carol_laptop")).unwrap();
    assert_ne!(iv_of(&second), iv_of(&first), "IV");
    assert_ne!(
        encrypted_key_of(&second),
        encrypted_key_of(&first),
        "encrypted key"
    );
    assert_eq!(
        listing(&vault, "SIMPLE"),
        ["alice.crypt", "carol_laptop.crypt"]
    );
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "carol_laptop"),
        &bob_private_key(),
        b"hello world",
    );
}

#[test]
fn user_without_public_key_cannot_be_fulfilled() {
    let vault = TestVault::from_fixture(GOLDEN);
    add_user(&vault, "carol", r#"["SIMPLE"]"#, &[]);
    let before = snapshot(&vault.path());

    assert_output(
        &run(&mut vault.command()),
        1,
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("carol", "SIMPLE")]),
        ]
        .concat()
        .as_bytes(),
        "Vault error: could not find key for user\n",
        "carol only",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");

    // Subscriptions are fulfilled in order, the ones before the failing one are written.
    set_subscriptions(&vault, "bob", r#"["SHARED", "GLOB_*", "SIMPLE"]"#);
    let before = snapshot(&vault.path());
    assert_output(
        &run(&mut vault.command()),
        1,
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "SIMPLE"), ("carol", "SIMPLE")]),
            &creating("SIMPLE", "bob"),
        ]
        .concat()
        .as_bytes(),
        "Vault error: could not find key for user\n",
        "bob and carol",
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/SIMPLE/bob.crypt"],
    );
}

#[test]
fn invalid_file_in_a_secret_dir_warns_on_every_read() {
    let vault = TestVault::from_fixture(GOLDEN);
    set_subscriptions(&vault, "bob", r#"["SHARED", "GLOB_*", "SIMPLE"]"#);
    fs::write(vault.secret_dir("SIMPLE").join("notes.txt"), "not a secret").unwrap();
    let warning = "warning: found a invalid file ./.vault/secrets/SIMPLE/notes.txt in secrets.\n";

    // The secret is decrypted twice: to check the subscription and to fulfill it.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "SIMPLE")]),
            &creating("SIMPLE", "bob"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        &warning.repeat(2),
        "default run",
    );
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "bob"),
        &bob_private_key(),
        b"hello world",
    );
}

// MARK: Glob subscriptions

#[test]
fn glob_subscription_matches_existing_secret_dirs() {
    let vault = TestVault::from_fixture(GOLDEN);
    // bob subscribes to `GLOB_*` and already has GLOB_A.
    for name in ["GLOB_B", "GLOB_C.crypt"] {
        fs::create_dir(vault.secret_dir(name)).unwrap();
        fs::copy(
            vault.crypt_path("SIMPLE", "alice"),
            vault.crypt_path(name, "alice"),
        )
        .unwrap();
    }
    let before = snapshot(&vault.path());

    // Secret dirs whose name ends with `.crypt` never match a glob.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "GLOB_B")]),
            &creating("GLOB_B", "bob"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );
    assert_crypt_file(
        &vault.crypt_path("GLOB_B", "bob"),
        &bob_private_key(),
        b"hello world",
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/GLOB_B/bob.crypt"],
    );
}

#[test]
fn new_secret_is_matched_by_a_glob_in_the_same_run() {
    let vault = TestVault::from_fixture(GOLDEN);
    write_secret(&vault, "GLOB_B", "new glob secret");
    let before = snapshot(&vault.path());

    // The key map is read again after adding new secrets, so bob's `GLOB_*` sees the new
    // secret dir and alice's new file fulfills it right away.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &new_secrets(&["GLOB_B"]),
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "GLOB_B")]),
            &creating("GLOB_B", "bob"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );
    assert_crypt_file(
        &vault.crypt_path("GLOB_B", "alice"),
        &alice_private_key(),
        b"new glob secret",
    );
    assert_crypt_file(
        &vault.crypt_path("GLOB_B", "bob"),
        &bob_private_key(),
        b"new glob secret",
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/secrets/GLOB_B",
            ".vault/secrets/GLOB_B/alice.crypt",
            ".vault/secrets/GLOB_B/bob.crypt",
        ],
    );
    assert_success(
        &get(as_bob(&vault), "GLOB_B"),
        b"new glob secret",
        "",
        "bob",
    );
}

#[test]
fn subscription_without_star_is_a_name_and_a_glob() {
    let vault = TestVault::from_fixture(GOLDEN);
    // `NOPE_*` matches nothing and is not listed: a subscription with `*` is only a glob.
    set_subscriptions(&vault, "bob", r#"["SIMPL?", "NOPE_*"]"#);

    // A subscription without `*` is taken as a secret name and also as a glob, so
    // `SIMPL?` subscribes to the missing secret `SIMPL?` and to SIMPLE.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &unfulfillable(&[("bob", "SIMPL?")]),
            &fulfillable(&[("bob", "SIMPLE")]),
            &creating("SIMPLE", "bob"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "bob"),
        &bob_private_key(),
        b"hello world",
    );
}

// MARK: Subscriptions nobody can fulfill

#[test]
fn subscription_without_access_is_listed() {
    let vault = TestVault::from_fixture(GOLDEN);
    set_subscriptions(&vault, "alice", r#"["SIMPLE", "BOB_ONLY"]"#);
    let before = snapshot(&vault.path());

    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &unfulfillable(&[("alice", "BOB_ONLY")]),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "alice",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");

    // bob can read BOB_ONLY and fulfills alice's subscription.
    assert_success(
        &run(&mut as_bob(&vault)),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["bob"]),
            &fulfillable(&[("alice", "BOB_ONLY")]),
            &creating("BOB_ONLY", "alice"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "bob",
    );
    assert_crypt_file(
        &vault.crypt_path("BOB_ONLY", "alice"),
        &alice_private_key(),
        &vault.expected("BOB_ONLY"),
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/BOB_ONLY/alice.crypt"],
    );
    assert_success(
        &get(vault.command(), "BOB_ONLY"),
        &vault.expected("BOB_ONLY"),
        "",
        "alice",
    );
}

#[test]
fn subscription_to_a_missing_secret_is_listed() {
    let vault = TestVault::from_fixture(GOLDEN);
    set_subscriptions(&vault, "alice", r#"["SIMPLE", "MISSING"]"#);
    let before = snapshot(&vault.path());

    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &unfulfillable(&[("alice", "MISSING")]),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );
    assert_eq!(snapshot(&vault.path()), before, "nothing may change");
}

// MARK: Answers

#[test]
fn yes_to_all_adds_every_new_secret() {
    for answer in ["y", "j", "a", "Y", "J", "A"] {
        let vault = TestVault::from_fixture(GOLDEN);
        write_secret(&vault, "A", "a");
        write_secret(&vault, "B", "b");

        assert_success(
            &run(&mut vault.answering(&format!("{answer}\n"))),
            [
                CREATE_KEY_MAP,
                &new_secrets(&["A", "B"]),
                &batch_prompt(2),
                &loaded_keys(&["alice"]),
                ALL_FINE,
            ]
            .concat()
            .as_bytes(),
            "",
            answer,
        );
        for (name, content) in [("A", b"a"), ("B", b"b")] {
            assert_eq!(listing(&vault, name), ["alice.crypt"], "{answer}: {name}");
            assert_success(&get(vault.command(), name), content, "", name);
        }
    }
}

#[test]
fn no_to_all_changes_nothing() {
    for answers in ["n\nn\n", "N\nN\n"] {
        let vault = TestVault::from_fixture(GOLDEN);
        write_secret(&vault, "A", "a");
        set_subscriptions(&vault, "bob", r#"["SHARED", "GLOB_*", "SIMPLE"]"#);
        let before = snapshot(&vault.path());

        assert_success(
            &run(&mut vault.answering(answers)),
            [
                CREATE_KEY_MAP,
                &new_secrets(&["A"]),
                &batch_prompt(1),
                MAYBE_LATER,
                &loaded_keys(&["alice"]),
                &fulfillable(&[("bob", "SIMPLE")]),
                &batch_prompt(1),
                MAYBE_LATER,
                ALL_FINE,
            ]
            .concat()
            .as_bytes(),
            "",
            answers,
        );
        assert_eq!(
            snapshot(&vault.path()),
            before,
            "{answers:?}: nothing may change"
        );
    }
}

#[test]
fn case_by_case_adds_only_accepted_secrets() {
    let vault = TestVault::from_fixture(GOLDEN);
    write_secret(&vault, "A", "a");
    write_secret(&vault, "B", "b");
    let before = snapshot(&vault.path());

    // The questions follow the sorted paths: yes to A, no to B.
    assert_success(
        &run(&mut vault.answering("c\ny\nn\n")),
        [
            CREATE_KEY_MAP,
            &new_secrets(&["A", "B"]),
            &batch_prompt(2),
            &add_prompt("A"),
            &add_prompt("B"),
            &loaded_keys(&["alice"]),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );

    assert_crypt_file(&vault.crypt_path("A", "alice"), &alice_private_key(), b"a");
    // B stays a plaintext file.
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/A", ".vault/secrets/A/alice.crypt"],
    );
    assert_success(&get(vault.command(), "A"), b"a", "", "A");
}

#[test]
fn unexpected_answers_are_asked_again() {
    let vault = TestVault::from_fixture(GOLDEN);
    write_secret(&vault, "A", "a");
    write_secret(&vault, "B", "b");
    let before = snapshot(&vault.path());

    // Answers are trimmed and lowercased, also in the error. The question for a single item
    // accepts only y, j and n.
    assert_success(
        &run(&mut vault.answering(" X \n\n C \nmaybe\na\nY\nN\n")),
        [
            CREATE_KEY_MAP,
            &new_secrets(&["A", "B"]),
            &batch_prompt(2).repeat(3),
            &add_prompt("A").repeat(3),
            &add_prompt("B"),
            &loaded_keys(&["alice"]),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "unexpected char \"x\" - reask.\n\
         unexpected char \"\" - reask.\n\
         unexpected char \"maybe\" - reask.\n\
         unexpected char \"a\" - reask.\n",
        "default run",
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[".vault/secrets/A", ".vault/secrets/A/alice.crypt"],
    );
}

#[test]
fn new_secrets_and_subscriptions_are_asked_in_one_run() {
    let vault = TestVault::from_fixture(GOLDEN);
    write_secret(&vault, "NEW", "new");
    write_secret(&vault, "GLOB_B", "glob");
    set_subscriptions(&vault, "bob", r#"["SHARED", "GLOB_*", "SIMPLE", "EMPTY"]"#);
    // carol uses bob's public key, so bob's private key reads her files.
    add_user(
        &vault,
        "carol",
        r#"["BINARY"]"#,
        &[("carol", &bob_public_key())],
    );
    let before = snapshot(&vault.path());

    // Subscriptions are sorted by user, then name. Yes to bob's EMPTY and SIMPLE and carol's
    // BINARY, no to bob's GLOB_B. The accepted ones are written after the last answer.
    assert_success(
        &run(&mut vault.answering("y\nc\ny\nn\ny\ny\n")),
        [
            CREATE_KEY_MAP,
            &new_secrets(&["GLOB_B", "NEW"]),
            &batch_prompt(2),
            &loaded_keys(&["alice"]),
            &fulfillable(&[
                ("bob", "EMPTY"),
                ("bob", "GLOB_B"),
                ("bob", "SIMPLE"),
                ("carol", "BINARY"),
            ]),
            &batch_prompt(4),
            &give_prompt("bob", "EMPTY"),
            &give_prompt("bob", "GLOB_B"),
            &give_prompt("bob", "SIMPLE"),
            &give_prompt("carol", "BINARY"),
            &creating("EMPTY", "bob"),
            &creating("SIMPLE", "bob"),
            &creating("BINARY", "carol"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "default run",
    );

    assert_crypt_file(
        &vault.crypt_path("NEW", "alice"),
        &alice_private_key(),
        b"new",
    );
    assert_crypt_file(
        &vault.crypt_path("GLOB_B", "alice"),
        &alice_private_key(),
        b"glob",
    );
    assert_crypt_file(&vault.crypt_path("EMPTY", "bob"), &bob_private_key(), b"");
    assert_crypt_file(
        &vault.crypt_path("SIMPLE", "bob"),
        &bob_private_key(),
        b"hello world",
    );
    assert_crypt_file(
        &vault.crypt_path("BINARY", "carol"),
        &bob_private_key(),
        &vault.expected("BINARY"),
    );
    assert_only_changed(
        &before,
        &snapshot(&vault.path()),
        &[
            ".vault/secrets/NEW",
            ".vault/secrets/NEW/alice.crypt",
            ".vault/secrets/GLOB_B",
            ".vault/secrets/GLOB_B/alice.crypt",
            ".vault/secrets/EMPTY/bob.crypt",
            ".vault/secrets/SIMPLE/bob.crypt",
            ".vault/secrets/BINARY/carol.crypt",
        ],
    );

    // The declined subscription is offered again.
    assert_success(
        &run(&mut vault.command()),
        [
            CREATE_KEY_MAP,
            &loaded_keys(&["alice"]),
            &fulfillable(&[("bob", "GLOB_B")]),
            &creating("GLOB_B", "bob"),
            ALL_FINE,
        ]
        .concat()
        .as_bytes(),
        "",
        "second run",
    );
}
