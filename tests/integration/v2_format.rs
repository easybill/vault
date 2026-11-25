//! File format version 2: the golden V2 fixture (a repository with the V1 user alice and the V2
//! users carol and dave), its header layout and how vault handles crafted version 2 files.

use std::collections::BTreeSet;
use std::fs;
use std::process::Output;

use crate::common::{TestVault, assert_failure, assert_success, run};
use crate::support::{
    HEADER_SIZE, IV_SIZE, RSA_SIZE, pkcs7_padded_len, read_header, reference_decrypt,
};
use crate::support_v2::{
    ALICE_V2_SECRETS, CAROL_SECRETS, DAVE_SECRETS, GOLDEN_V2, KEM_CIPHERTEXT_SIZE, NONCE_SIZE,
    REPOSITORY_ID, TAG_SIZE, VERSION_2, as_v2_user, golden_v2_file, golden_v2_path, public_key_of,
    reference_decrypt_v2, reference_encrypt_v2, v2_private_key, v2_public_key,
};

const COULD_NOT_FIND_KEY: &str = "Vault error: could not find key\n";

fn get(mut cmd: assert_cmd::Command, secret: &str) -> Output {
    run(cmd.args(["get", secret]))
}

/// The `(secret, user)` pairs of every `.crypt` file in the golden V2 fixture.
fn golden_crypt_files() -> BTreeSet<(String, String)> {
    let mut files = BTreeSet::new();
    for secret in fs::read_dir(golden_v2_path(".vault/secrets")).unwrap() {
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

fn listing(relative: &str) -> BTreeSet<String> {
    fs::read_dir(golden_v2_path(relative))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_string()).collect()
}

fn alice_private_key() -> Vec<u8> {
    golden_v2_file(".vault/private_keys/alice.pem")
}

#[test]
fn golden_v2_fixture_has_the_expected_files() {
    let mut expected = BTreeSet::new();
    for (user, secrets) in [
        ("alice", ALICE_V2_SECRETS),
        ("carol", CAROL_SECRETS),
        ("dave", DAVE_SECRETS),
    ] {
        for secret in secrets {
            expected.insert((secret.to_string(), user.to_string()));
        }
    }
    assert_eq!(golden_crypt_files(), expected);

    let mut all_secrets = names(CAROL_SECRETS);
    all_secrets.extend(names(DAVE_SECRETS));
    all_secrets.extend(names(ALICE_V2_SECRETS));
    assert_eq!(listing("expected"), all_secrets);

    assert_eq!(
        golden_v2_file(".vault/repository_id"),
        format!("{REPOSITORY_ID}\n").into_bytes()
    );
    assert_eq!(listing(".vault/keys"), names(&["alice", "carol", "dave"]));
    assert_eq!(
        listing(".vault/keys/alice"),
        names(&["alice.pub.pem", "config.toml"])
    );
    for user in ["carol", "dave"] {
        assert_eq!(
            listing(&format!(".vault/keys/{user}")),
            names(&[&format!("{user}.pem.pub"), "config.toml"])
        );
        assert_eq!(
            listing(&format!("{user}_v2_keys")),
            names(&[
                &format!("{REPOSITORY_ID}.pem"),
                &format!("{REPOSITORY_ID}.pem.pub")
            ])
        );
    }
    assert_eq!(
        listing(".vault/private_keys"),
        names(&["alice.pem", "alice.pub.pem"])
    );
    assert_eq!(
        golden_v2_file(".vault/keys/alice/config.toml"),
        br#"subscriptions = ["SHARED"]"#
    );
    assert_eq!(
        golden_v2_file(".vault/keys/carol/config.toml"),
        b"subscriptions = []"
    );
    assert_eq!(
        golden_v2_file(".vault/keys/dave/config.toml"),
        br#"subscriptions = ["SHARED", "GLOB_*"]"#
    );

    assert_eq!(golden_v2_file("expected/SIMPLE"), b"hello world");
    assert_eq!(golden_v2_file("expected/EMPTY"), b"");
    assert_eq!(
        golden_v2_file("expected/BINARY"),
        (0..=255).collect::<Vec<u8>>()
    );
    assert_eq!(golden_v2_file("expected/LARGE").len(), 64 * 1024);
}

#[test]
fn golden_v2_public_keys_belong_to_the_private_keys() {
    for user in ["carol", "dave"] {
        let public_key = v2_public_key(user);
        let pem = std::str::from_utf8(&public_key).unwrap();
        assert!(
            pem.starts_with("-----BEGIN XWING PUBLIC KEY-----\n"),
            "{user}"
        );
        assert!(pem.ends_with("-----END XWING PUBLIC KEY-----\n"), "{user}");
        assert_eq!(public_key_of(&v2_private_key(user)).as_bytes(), public_key);
        assert_eq!(
            golden_v2_file(&format!(".vault/keys/{user}/{user}.pem.pub")),
            public_key,
            "{user}: registered public key"
        );

        let private_key = v2_private_key(user);
        let pem = std::str::from_utf8(&private_key).unwrap();
        assert!(
            pem.starts_with("-----BEGIN XWING PRIVATE KEY-----\n"),
            "{user}"
        );
        assert!(pem.ends_with("-----END XWING PRIVATE KEY-----\n"), "{user}");
    }
}

#[test]
fn golden_v2_files_have_the_header_layout() {
    for (secret, user) in golden_crypt_files() {
        let file = golden_v2_file(&format!(".vault/secrets/{secret}/{user}.crypt"));
        let plaintext_len = golden_v2_file(&format!("expected/{secret}")).len();
        let header = read_header(&file);

        // alice's files are version 1, also when vault 2.0.0 wrote them.
        let (version, key_len, content_len) = if user == "alice" {
            (1, RSA_SIZE, IV_SIZE + pkcs7_padded_len(plaintext_len))
        } else {
            (
                VERSION_2,
                KEM_CIPHERTEXT_SIZE,
                NONCE_SIZE + plaintext_len + TAG_SIZE,
            )
        };
        assert_eq!(header.version, version, "{secret}/{user}");
        assert_eq!(header.key_len, key_len as u64, "{secret}/{user}");
        assert_eq!(header.content_len, content_len as u64, "{secret}/{user}");
        assert_eq!(
            file.len(),
            HEADER_SIZE + key_len + content_len,
            "{secret}/{user}"
        );
    }
}

#[test]
fn reference_decryptor_agrees_with_golden_v2_files() {
    for (secret, user) in golden_crypt_files() {
        let file = golden_v2_file(&format!(".vault/secrets/{secret}/{user}.crypt"));
        let plaintext = if user == "alice" {
            reference_decrypt(&alice_private_key(), &file)
        } else {
            reference_decrypt_v2(&v2_private_key(&user), &file)
        };
        assert_eq!(
            plaintext,
            golden_v2_file(&format!("expected/{secret}")),
            "{secret}/{user}"
        );
    }
}

#[test]
fn v2_users_get_their_golden_secrets() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    for (user, secrets) in [("carol", CAROL_SECRETS), ("dave", DAVE_SECRETS)] {
        for secret in secrets {
            assert_success(
                &get(as_v2_user(&vault, user), secret),
                &vault.expected(secret),
                "",
                &format!("{user}: {secret}"),
            );
        }
    }
    assert_failure(
        &get(as_v2_user(&vault, "carol"), "DAVE_ONLY"),
        COULD_NOT_FIND_KEY,
        "carol: DAVE_ONLY",
    );
    assert_failure(
        &get(as_v2_user(&vault, "dave"), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "dave: SIMPLE",
    );
}

#[test]
fn v1_user_gets_its_golden_v2_secrets() {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    for secret in ALICE_V2_SECRETS {
        assert_success(
            &get(vault.command(), secret),
            &vault.expected(secret),
            "",
            secret,
        );
    }
    assert_failure(
        &get(vault.command(), "SIMPLE"),
        COULD_NOT_FIND_KEY,
        "SIMPLE",
    );
}

// MARK: Crafted files

const CRAFTED: &str = "CRAFTED";

/// Runs `vault get CRAFTED` as carol with `file` as the only file of the secret.
fn get_crafted(file: &[u8]) -> Output {
    let vault = TestVault::from_fixture(GOLDEN_V2);
    fs::create_dir(vault.secret_dir(CRAFTED)).unwrap();
    fs::write(vault.crypt_path(CRAFTED, "carol"), file).unwrap();
    get(as_v2_user(&vault, "carol"), CRAFTED)
}

#[test]
fn crafted_v2_file_decrypts() {
    let file = reference_encrypt_v2(&v2_public_key("carol"), b"crafted content");
    assert_success(&get_crafted(&file), b"crafted content", "", CRAFTED);
}

#[test]
fn crafted_v2_file_with_trailing_bytes_decrypts() {
    let mut file = reference_encrypt_v2(&v2_public_key("carol"), b"crafted content");
    file.extend_from_slice(b"TRAILING");
    // Bytes after the lengths given in the header are never read.
    assert_success(&get_crafted(&file), b"crafted content", "", CRAFTED);
}

#[test]
fn crafted_v2_file_for_another_key_is_not_decrypted() {
    let file = reference_encrypt_v2(&v2_public_key("dave"), b"for dave");
    assert_failure(&get_crafted(&file), COULD_NOT_FIND_KEY, CRAFTED);
}

#[test]
fn crafted_tampered_v2_files_are_not_decrypted() {
    let file = reference_encrypt_v2(&v2_public_key("carol"), b"crafted content");
    let nonce_start = HEADER_SIZE + KEM_CIPHERTEXT_SIZE;
    let ciphertext_start = nonce_start + NONCE_SIZE;
    let flip = |index: usize| {
        let mut tampered = file.clone();
        tampered[index] ^= 0x01;
        tampered
    };

    // A shorter content length still parses, the last byte of the tag is then left unread.
    let mut shorter_content = file.clone();
    let content_len = read_header(&file).content_len;
    shorter_content[12..20].copy_from_slice(&(content_len - 1).to_be_bytes());

    // A KEM ciphertext one byte short, with a header that matches it.
    let mut short_kem = file.clone();
    short_kem.remove(HEADER_SIZE);
    short_kem[4..12].copy_from_slice(&(KEM_CIPHERTEXT_SIZE as u64 - 1).to_be_bytes());

    // Content shorter than nonce and tag.
    let mut short_content = file[..nonce_start + NONCE_SIZE + TAG_SIZE - 1].to_vec();
    short_content[12..20].copy_from_slice(&((NONCE_SIZE + TAG_SIZE - 1) as u64).to_be_bytes());

    for (region, tampered) in [
        ("header content length", shorter_content),
        ("KEM ciphertext", flip(HEADER_SIZE)),
        ("KEM ciphertext length", short_kem),
        ("nonce", flip(nonce_start)),
        ("ciphertext", flip(ciphertext_start)),
        ("tag", flip(file.len() - 1)),
        ("content length", short_content),
    ] {
        // Trial decryption drops the reason.
        assert_failure(&get_crafted(&tampered), COULD_NOT_FIND_KEY, region);
    }
}

#[test]
fn crafted_v2_file_with_version_1_is_not_decrypted() {
    let mut file = reference_encrypt_v2(&v2_public_key("carol"), b"crafted content");
    file[2..4].copy_from_slice(&1u16.to_be_bytes());
    // A version 1 file is only tried with V1 keys, and none is loaded.
    assert_failure(&get_crafted(&file), COULD_NOT_FIND_KEY, CRAFTED);
}
