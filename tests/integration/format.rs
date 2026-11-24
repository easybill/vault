//! The vault file format: decrypting the golden fixtures, the header layout and how vault
//! handles malformed or foreign files.

use std::collections::BTreeSet;
use std::fs;
use std::process::Output;

use crate::common::{TestVault, assert_failure, assert_no_panic, assert_success, fixture_dir};
use crate::support::{
    AES_KEY_SIZE, ALICE_SECRETS, BLOCK_SIZE, BOB_SECRETS, GOLDEN, HEADER_SIZE, IV_SIZE,
    LEGACY_1_0_0, MAGIC, RSA_SIZE, VERSION, aes_encrypt, alice_private_key, alice_public_key,
    bob_private_key, bob_public_key, build_file, golden_file, golden_path, pkcs7_padded_len,
    random_bytes, read_header, reference_decrypt, reference_encrypt, rsa_encrypt,
};

/// Runs `vault get <secret>` with alice's keys.
fn get(vault: &TestVault, secret: &str) -> Output {
    let output = vault.command().args(["get", secret]).output().unwrap();
    assert_no_panic(&output);
    output
}

/// Runs `vault get <secret>` with bob's keys.
fn get_as_bob(vault: &TestVault, secret: &str) -> Output {
    let output = vault
        .command()
        .env(
            "VAULT_PRIVATE_KEY_PATH",
            vault.path().join("bob_private_keys"),
        )
        .args(["get", secret])
        .output()
        .unwrap();
    assert_no_panic(&output);
    output
}

/// Asserts the trial decryption failure, which hides the reason why each file failed.
fn assert_could_not_find_key(output: &Output, context: &str) {
    assert_failure(output, "Vault error: could not find key\n", context);
}

/// The error for a file that `vault get` cannot parse.
fn vault_file_error(cause: &str) -> String {
    format!("Vault error: could not create vault file.\n\nCaused by:\n    {cause}\n")
}

/// The error for a file that ends before the length given in its header.
fn short_read_error(context: &str) -> String {
    vault_file_error(&format!("0: {context}\n    1: failed to fill whole buffer"))
}

/// The `(secret, user)` pairs of every `.crypt` file in the golden fixture.
fn golden_crypt_files() -> BTreeSet<(String, String)> {
    let mut files = BTreeSet::new();
    for secret in fs::read_dir(golden_path(".vault/secrets")).unwrap() {
        let secret = secret.unwrap();
        assert!(secret.file_type().unwrap().is_dir());
        for file in fs::read_dir(secret.path()).unwrap() {
            let name = file.unwrap().file_name().into_string().unwrap();
            let user = name.strip_suffix(".crypt").expect("only .crypt files");
            files.insert((secret.file_name().into_string().unwrap(), user.to_string()));
        }
    }
    files
}

fn private_key_of(user: &str) -> Vec<u8> {
    match user {
        "alice" => alice_private_key(),
        "bob" => bob_private_key(),
        _ => panic!("unknown user {user}"),
    }
}

/// The file names in a directory of the golden fixture.
fn golden_listing(relative: &str) -> BTreeSet<String> {
    fs::read_dir(golden_path(relative))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_string()).collect()
}

#[test]
fn golden_fixture_has_the_expected_files() {
    let mut expected = BTreeSet::new();
    for secret in ALICE_SECRETS {
        expected.insert((secret.to_string(), "alice".to_string()));
    }
    for secret in BOB_SECRETS {
        expected.insert((secret.to_string(), "bob".to_string()));
    }
    assert_eq!(golden_crypt_files(), expected);

    let mut all_secrets = names(ALICE_SECRETS);
    all_secrets.extend(names(BOB_SECRETS));
    assert_eq!(golden_listing("expected"), all_secrets);

    assert_eq!(
        golden_listing(".vault/private_keys"),
        names(&["alice.pem", "alice.pub.pem"])
    );
    assert_eq!(
        golden_listing("bob_private_keys"),
        names(&["bob.pem", "bob.pub.pem"])
    );
    assert_eq!(
        golden_listing(".vault/keys/alice"),
        names(&["alice.pub.pem", "config.toml"])
    );
    assert_eq!(
        golden_listing(".vault/keys/bob"),
        names(&["bob.pub.pem", "config.toml"])
    );
    assert_eq!(
        golden_file(".vault/keys/alice/config.toml"),
        br#"subscriptions = ["SIMPLE"]"#
    );
    assert_eq!(
        golden_file(".vault/keys/bob/config.toml"),
        br#"subscriptions = ["SHARED", "GLOB_*"]"#
    );
    assert_eq!(
        golden_file(".vault/private_keys/alice.pub.pem"),
        alice_public_key()
    );
    assert_eq!(
        golden_file("bob_private_keys/bob.pub.pem"),
        bob_public_key()
    );

    assert_eq!(golden_file("expected/SIMPLE"), b"hello world");
    assert_eq!(golden_file("expected/EMPTY"), b"");
    assert_eq!(
        golden_file("expected/BINARY"),
        (0..=255).collect::<Vec<u8>>()
    );
    assert_eq!(golden_file("expected/LARGE").len(), 64 * 1024);
}

#[test]
fn alice_gets_every_golden_secret() {
    let vault = TestVault::from_fixture(GOLDEN);
    for secret in ALICE_SECRETS {
        assert_success(&get(&vault, secret), &vault.expected(secret), "", secret);
    }
}

#[test]
fn bob_gets_his_golden_secrets() {
    let vault = TestVault::from_fixture(GOLDEN);
    for secret in BOB_SECRETS {
        assert_success(
            &get_as_bob(&vault, secret),
            &vault.expected(secret),
            "",
            secret,
        );
    }
}

#[test]
fn shared_secret_is_readable_by_every_holder() {
    // SHARED holds alice.crypt and bob.crypt, so one of the two runs has to skip the file of
    // the other holder.
    let vault = TestVault::from_fixture(GOLDEN);
    assert_success(&get(&vault, "SHARED"), b"shared content", "", "alice");
    assert_success(&get_as_bob(&vault, "SHARED"), b"shared content", "", "bob");
}

#[test]
fn every_private_key_is_tried() {
    // The configured key directory is read before ~/.vault/private_keys, so bob's key is
    // tried first and fails on SIMPLE before alice's key succeeds.
    let vault = TestVault::from_fixture(GOLDEN);
    let home_keys = vault.home().join(".vault/private_keys");
    fs::create_dir_all(&home_keys).unwrap();
    for file in ["alice.pem", "alice.pub.pem"] {
        fs::copy(
            vault.path().join(".vault/private_keys").join(file),
            home_keys.join(file),
        )
        .unwrap();
    }

    assert_success(&get_as_bob(&vault, "SIMPLE"), b"hello world", "", "SIMPLE");
}

#[test]
fn golden_files_have_the_header_layout() {
    for (secret, user) in golden_crypt_files() {
        let file = golden_file(&format!(".vault/secrets/{secret}/{user}.crypt"));
        let plaintext_len = golden_file(&format!("expected/{secret}")).len();
        let content_len = IV_SIZE + pkcs7_padded_len(plaintext_len);

        let header = read_header(&file);
        assert_eq!(header.magic, MAGIC, "{secret}/{user}");
        assert_eq!(header.version, VERSION, "{secret}/{user}");
        assert_eq!(header.key_len, RSA_SIZE as u64, "{secret}/{user}");
        assert_eq!(header.content_len, content_len as u64, "{secret}/{user}");
        assert_eq!(
            file.len(),
            HEADER_SIZE + RSA_SIZE + content_len,
            "{secret}/{user}"
        );
    }
}

#[test]
fn pkcs7_padding_always_adds_a_block_on_boundaries() {
    assert_eq!(pkcs7_padded_len(0), BLOCK_SIZE);
    assert_eq!(pkcs7_padded_len(15), BLOCK_SIZE);
    assert_eq!(pkcs7_padded_len(16), 2 * BLOCK_SIZE);
    assert_eq!(pkcs7_padded_len(17), 2 * BLOCK_SIZE);
}

#[test]
fn reference_decryptor_agrees_with_golden_files() {
    for (secret, user) in golden_crypt_files() {
        let file = golden_file(&format!(".vault/secrets/{secret}/{user}.crypt"));
        assert_eq!(
            reference_decrypt(&private_key_of(&user), &file),
            golden_file(&format!("expected/{secret}")),
            "{secret}/{user}"
        );
    }
}

#[test]
fn legacy_1_0_0_file_decrypts() {
    let vault = TestVault::from_fixture(LEGACY_1_0_0);
    let secret = "VERSION_1_0_0_SECRET";
    let expected = vault.expected(secret);
    assert_eq!(expected, b"VERSION_1_0_0_SECRET_CONTENT");

    assert_success(&get(&vault, secret), &expected, "", secret);

    let file = fs::read(vault.crypt_path(secret, "testuser")).unwrap();
    let header = read_header(&file);
    assert_eq!(header.magic, MAGIC);
    assert_eq!(header.version, VERSION);
    assert_eq!(header.key_len, RSA_SIZE as u64);
    assert_eq!(
        header.content_len,
        (IV_SIZE + pkcs7_padded_len(expected.len())) as u64
    );

    let private_key =
        fs::read(fixture_dir(LEGACY_1_0_0).join(".vault/private_keys/testuser.pem")).unwrap();
    assert_eq!(reference_decrypt(&private_key, &file), expected);
}

#[test]
fn trial_decryption_ignores_file_names() {
    let vault = TestVault::from_fixture(GOLDEN);
    let original = vault.crypt_path("SIMPLE", "alice");
    fs::copy(&original, vault.secret_dir("SIMPLE").join("other.crypt")).unwrap();
    fs::remove_file(&original).unwrap();

    assert_success(&get(&vault, "SIMPLE"), b"hello world", "", "SIMPLE");
}

#[test]
fn non_crypt_file_in_secret_dir_warns_and_is_skipped() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::write(
        vault.secret_dir("SIMPLE").join("notes.txt"),
        "not a vault file",
    )
    .unwrap();

    assert_success(
        &get(&vault, "SIMPLE"),
        b"hello world",
        "warning: found a invalid file ./.vault/secrets/SIMPLE/notes.txt in secrets.\n",
        "SIMPLE",
    );
}

#[test]
fn missing_secret_dir_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_failure(
        &get(&vault, "MISSING"),
        "Vault error: could not read subscription path. directory is missing? \
         ./.vault/secrets/MISSING\n\nCaused by:\n    No such file or directory (os error 2)\n",
        "missing_secret_dir_fails",
    );
}

#[test]
fn empty_secret_dir_fails() {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::create_dir(vault.secret_dir("EMPTY_DIR")).unwrap();
    assert_could_not_find_key(&get(&vault, "EMPTY_DIR"), "empty_secret_dir_fails");
}

#[test]
fn secret_of_another_user_is_not_found() {
    let vault = TestVault::from_fixture(GOLDEN);
    assert_could_not_find_key(
        &get(&vault, "BOB_ONLY"),
        "secret_of_another_user_is_not_found",
    );
}

// MARK: Crafted files

const CRAFTED: &str = "CRAFTED";

/// Puts `file` as the only file into `.vault/secrets/CRAFTED/` of a golden copy.
fn vault_with_crafted_file(file: &[u8]) -> TestVault {
    let vault = TestVault::from_fixture(GOLDEN);
    fs::create_dir(vault.secret_dir(CRAFTED)).unwrap();
    fs::write(vault.crypt_path(CRAFTED, "alice"), file).unwrap();
    vault
}

/// Runs `vault get CRAFTED` as alice with `file` as the only file of the secret.
fn get_crafted(file: &[u8]) -> Output {
    get(&vault_with_crafted_file(file), CRAFTED)
}

fn valid_file() -> Vec<u8> {
    golden_file(".vault/secrets/SIMPLE/alice.crypt")
}

fn patched(range: std::ops::Range<usize>, bytes: &[u8]) -> Vec<u8> {
    let mut file = valid_file();
    file[range].copy_from_slice(bytes);
    file
}

#[test]
fn crafted_valid_file_decrypts() {
    let aes_key = random_bytes::<AES_KEY_SIZE>();
    let file = reference_encrypt(&alice_public_key(), b"crafted content", &aes_key);
    assert_success(&get_crafted(&file), b"crafted content", "", CRAFTED);
}

#[test]
fn crafted_trailing_bytes_are_ignored() {
    let mut file = valid_file();
    file.extend_from_slice(b"TRAILING");
    // Bytes after the lengths given in the header are never read.
    assert_success(&get_crafted(&file), b"hello world", "", CRAFTED);
}

#[test]
fn crafted_bad_magic_fails() {
    let file = patched(0..2, &4243u16.to_be_bytes());
    assert_failure(
        &get_crafted(&file),
        &vault_file_error("invalid file, magic byte is wrong"),
        "crafted_bad_magic_fails",
    );
}

#[test]
fn crafted_version_2_fails() {
    let file = patched(2..4, &2u16.to_be_bytes());
    // The message lacks the supported version number.
    assert_failure(
        &get_crafted(&file),
        &vault_file_error("only version is supported, found 2"),
        "crafted_version_2_fails",
    );
}

#[test]
fn crafted_key_len_over_limit_fails() {
    let file = patched(4..12, &50_001u64.to_be_bytes());
    assert_failure(
        &get_crafted(&file),
        &vault_file_error("key size is not supported"),
        "crafted_key_len_over_limit_fails",
    );
}

#[test]
fn crafted_key_len_at_limit_is_read() {
    let file = patched(4..12, &50_000u64.to_be_bytes());
    assert_failure(
        &get_crafted(&file),
        &short_read_error("could not read key file contents"),
        "crafted_key_len_at_limit_is_read",
    );
}

#[test]
fn crafted_content_len_over_limit_fails() {
    let file = patched(12..20, &1_000_000_001u64.to_be_bytes());
    // An oversized content length is reported as a key size problem.
    assert_failure(
        &get_crafted(&file),
        &vault_file_error("key size is not supported"),
        "crafted_content_len_over_limit_fails",
    );
}

#[test]
fn crafted_content_len_at_limit_is_read() {
    // vault allocates a zeroed buffer of this size before reading. The allocation is lazy, so
    // the untouched 1 GB is never backed by memory.
    let file = patched(12..20, &1_000_000_000u64.to_be_bytes());
    assert_failure(
        &get_crafted(&file),
        &short_read_error("could not read secret contents"),
        "crafted_content_len_at_limit_is_read",
    );
}

#[test]
fn crafted_truncated_header_fails() {
    let file = valid_file()[..HEADER_SIZE - 1].to_vec();
    assert_failure(
        &get_crafted(&file),
        &short_read_error("could not read header"),
        "crafted_truncated_header_fails",
    );
}

#[test]
fn crafted_truncated_key_fails() {
    let file = valid_file()[..HEADER_SIZE + RSA_SIZE / 2].to_vec();
    assert_failure(
        &get_crafted(&file),
        &short_read_error("could not read key file contents"),
        "crafted_truncated_key_fails",
    );
}

#[test]
fn crafted_truncated_content_fails() {
    let mut file = valid_file();
    file.pop();
    assert_failure(
        &get_crafted(&file),
        &short_read_error("could not read secret contents"),
        "crafted_truncated_content_fails",
    );
}

#[test]
fn crafted_content_shorter_than_iv_is_not_decrypted() {
    let aes_key = random_bytes::<AES_KEY_SIZE>();
    let file = build_file(
        MAGIC,
        VERSION,
        &rsa_encrypt(&alice_public_key(), &aes_key),
        &[0; IV_SIZE - 1],
    );
    // Trial decryption drops the reason ("encrypted size is to small").
    assert_could_not_find_key(
        &get_crafted(&file),
        "crafted_content_shorter_than_iv_is_not_decrypted",
    );
}

#[test]
fn crafted_bad_padding_is_not_decrypted() {
    let aes_key = random_bytes::<AES_KEY_SIZE>();
    let iv = random_bytes::<IV_SIZE>();
    // A last block ending in 0x00 is never valid PKCS#7 padding.
    let mut content = iv.to_vec();
    content.extend(aes_encrypt(&aes_key, &iv, &[0; BLOCK_SIZE], false));
    let file = build_file(
        MAGIC,
        VERSION,
        &rsa_encrypt(&alice_public_key(), &aes_key),
        &content,
    );
    assert_could_not_find_key(&get_crafted(&file), "crafted_bad_padding_is_not_decrypted");
}

#[test]
fn crafted_file_for_another_key_is_not_decrypted() {
    let aes_key = random_bytes::<AES_KEY_SIZE>();
    let file = reference_encrypt(&bob_public_key(), b"for bob", &aes_key);
    let vault = vault_with_crafted_file(&file);

    assert_could_not_find_key(
        &get(&vault, CRAFTED),
        "crafted_file_for_another_key_is_not_decrypted",
    );
    assert_success(&get_as_bob(&vault, CRAFTED), b"for bob", "", CRAFTED);
}

#[test]
fn crafted_aes_key_longer_than_32_bytes_is_not_decrypted() {
    let aes_key = random_bytes::<48>();
    let file = reference_encrypt(&alice_public_key(), b"long key", &aes_key);
    // `key_decrypt` passes keys longer than 32 bytes on for compatibility, but
    // AES-256-CBC rejects them, so the file is never decrypted.
    assert_could_not_find_key(
        &get_crafted(&file),
        "crafted_aes_key_longer_than_32_bytes_is_not_decrypted",
    );
}

#[test]
fn crafted_aes_key_shorter_than_32_bytes_is_not_decrypted() {
    let aes_key = random_bytes::<16>();
    // The content is encrypted with the key zero-extended to 32 bytes, so only rejecting the
    // key length makes the decryption fail.
    let mut extended_key = [0; AES_KEY_SIZE];
    extended_key[..16].copy_from_slice(&aes_key);
    let iv = random_bytes::<IV_SIZE>();
    let mut content = iv.to_vec();
    content.extend(aes_encrypt(&extended_key, &iv, b"short key", true));
    let file = build_file(
        MAGIC,
        VERSION,
        &rsa_encrypt(&alice_public_key(), &aes_key),
        &content,
    );
    assert_could_not_find_key(
        &get_crafted(&file),
        "crafted_aes_key_shorter_than_32_bytes_is_not_decrypted",
    );
}
