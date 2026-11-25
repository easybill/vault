//! Vault file format version 2 and a reference implementation of its crypto.
//!
//! The reference implementation uses the `x-wing`, `aes-gcm`, `sha3` and `pem-rfc7468` crates
//! directly and never calls vault code, so the tests stay independent of the implementation.
//!
//! File layout (all integers big endian, the version field is 2):
//!
//! ```text
//! u16 magic | u16 version | u64 key_len = 1120 | u64 content_len
//! | X-Wing ciphertext (1120) | nonce (12) | AES-256-GCM ciphertext | tag (16)
//! ```
//!
//! X-Wing encapsulates a shared key for the recipient's public key, the AES-256 key is
//! `SHA3-256("vault v2 aes-256-gcm" || shared key)` and the additional authenticated data is the
//! 20 byte header. Keys are PEM files (`XWING PRIVATE KEY`: the 32 byte seed, `XWING PUBLIC KEY`:
//! the 1216 byte encapsulation key).

#![allow(dead_code)] // Not all test modules use all helpers

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Generate, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use assert_cmd::Command;
use pem_rfc7468::LineEnding;
use sha3::{Digest, Sha3_256};
use x_wing::{
    Ciphertext, Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey,
    KeyExport,
};

use crate::common::{TestVault, fixture_dir};
use crate::support::{HEADER_SIZE, MAGIC, build_file, read_header};

pub const VERSION_2: u16 = 2;
pub const KEM_CIPHERTEXT_SIZE: usize = 1120;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const SEED_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 1216;
pub const CONTENT_KEY_LABEL: &[u8] = b"vault v2 aes-256-gcm";
pub const PRIVATE_KEY_LABEL: &str = "XWING PRIVATE KEY";
pub const PUBLIC_KEY_LABEL: &str = "XWING PUBLIC KEY";

pub const GOLDEN_V2: &str = "v2/golden";

/// The repository ID of the golden V2 fixture.
pub const REPOSITORY_ID: &str = "01a21196-8b34-7567-ac1e-89c8dea136b0";

/// Secrets in the golden V2 fixture that carol (V2) can read.
pub const CAROL_SECRETS: &[&str] = &[
    "BINARY",
    "EMPTY",
    "LARGE",
    "SHARED",
    "SIMPLE",
    "UNICODE_MULTILINE",
];

/// Secrets in the golden V2 fixture that dave (V2) can read.
pub const DAVE_SECRETS: &[&str] = &["DAVE_ONLY", "GLOB_A", "SHARED"];

/// Secrets in the golden V2 fixture that alice (V1) can read.
pub const ALICE_V2_SECRETS: &[&str] = &["GLOB_A", "SHARED"];

/// Path of a file inside the golden V2 fixture.
pub fn golden_v2_path(relative: &str) -> PathBuf {
    fixture_dir(GOLDEN_V2).join(relative)
}

/// Reads a file inside the golden V2 fixture.
pub fn golden_v2_file(relative: &str) -> Vec<u8> {
    let path = golden_v2_path(relative);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// The private key of a V2 user (`carol` or `dave`) in the golden V2 fixture.
pub fn v2_private_key(user: &str) -> Vec<u8> {
    golden_v2_file(&format!("{user}_v2_keys/{REPOSITORY_ID}.pem"))
}

/// The public key of a V2 user (`carol` or `dave`) in the golden V2 fixture.
pub fn v2_public_key(user: &str) -> Vec<u8> {
    golden_v2_file(&format!("{user}_v2_keys/{REPOSITORY_ID}.pem.pub"))
}

/// A vault command that loads only the V2 key of `user` (`carol` or `dave`) from the golden V2
/// fixture: `VAULT_V2_KEY_PATH` is its key directory, `VAULT_PRIVATE_KEY_PATH` an empty
/// directory.
pub fn as_v2_user(vault: &TestVault, user: &str) -> Command {
    let mut cmd = vault.command();
    cmd.env("VAULT_V2_KEY_PATH", format!("{user}_v2_keys"))
        .env("VAULT_PRIVATE_KEY_PATH", no_v1_keys(vault));
    cmd
}

/// An empty directory outside the working directory, for `VAULT_PRIVATE_KEY_PATH`.
pub fn no_v1_keys(vault: &TestVault) -> PathBuf {
    let dir = vault.root().join("no_v1_keys");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The content of a PEM block. Panics unless it has the given label and length.
pub fn decode_pem(pem: &[u8], label: &str, len: usize) -> Vec<u8> {
    let (actual_label, content) = pem_rfc7468::decode_vec(pem).expect("invalid PEM");
    assert_eq!(actual_label, label, "PEM label");
    assert_eq!(content.len(), len, "PEM content length");
    content
}

pub fn decode_private_key(pem: &[u8]) -> DecapsulationKey {
    let seed: [u8; SEED_SIZE] = decode_pem(pem, PRIVATE_KEY_LABEL, SEED_SIZE)
        .try_into()
        .unwrap();
    DecapsulationKey::from(seed)
}

pub fn decode_public_key(pem: &[u8]) -> EncapsulationKey {
    EncapsulationKey::try_from(decode_pem(pem, PUBLIC_KEY_LABEL, PUBLIC_KEY_SIZE).as_slice())
        .expect("invalid X-Wing public key")
}

/// A new key pair as `(private key PEM, public key PEM)`.
pub fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    let key = DecapsulationKey::generate();
    let private_pem = pem_rfc7468::encode_string(PRIVATE_KEY_LABEL, LineEnding::LF, key.as_bytes())
        .unwrap()
        .into_bytes();
    let public_pem = public_key_of(&private_pem).into_bytes();
    (private_pem, public_pem)
}

/// The public key PEM that belongs to a private key PEM.
pub fn public_key_of(private_pem: &[u8]) -> String {
    let key = decode_private_key(private_pem);
    pem_rfc7468::encode_string(
        PUBLIC_KEY_LABEL,
        LineEnding::LF,
        &key.encapsulation_key().to_bytes(),
    )
    .unwrap()
}

fn content_cipher(shared_key: &[u8]) -> Aes256Gcm {
    let mut hasher = Sha3_256::new();
    hasher.update(CONTENT_KEY_LABEL);
    hasher.update(shared_key);
    Aes256Gcm::new_from_slice(&hasher.finalize()).unwrap()
}

/// The 20 byte header of a version 2 file.
pub fn header_v2(content_len: usize) -> Vec<u8> {
    build_file(
        MAGIC,
        VERSION_2,
        &[0; KEM_CIPHERTEXT_SIZE],
        &vec![0; content_len],
    )[..HEADER_SIZE]
        .to_vec()
}

/// Decrypts a version 2 file with the given private key PEM. Panics if anything does not match
/// the file format exactly or the authentication fails.
pub fn reference_decrypt_v2(private_pem: &[u8], file: &[u8]) -> Vec<u8> {
    let header = read_header(file);
    assert_eq!(header.magic, MAGIC, "magic");
    assert_eq!(header.version, VERSION_2, "version");
    assert_eq!(header.key_len, KEM_CIPHERTEXT_SIZE as u64, "key_len");
    assert_eq!(
        file.len(),
        HEADER_SIZE + KEM_CIPHERTEXT_SIZE + header.content_len as usize,
        "file size must match the header"
    );
    assert!(
        header.content_len as usize >= NONCE_SIZE + TAG_SIZE,
        "content too short"
    );

    let kem_end = HEADER_SIZE + KEM_CIPHERTEXT_SIZE;
    let kem_ciphertext = Ciphertext::try_from(&file[HEADER_SIZE..kem_end]).unwrap();
    let shared_key = decode_private_key(private_pem).decapsulate(&kem_ciphertext);
    let nonce = Nonce::<Aes256Gcm>::try_from(&file[kem_end..kem_end + NONCE_SIZE]).unwrap();

    content_cipher(&shared_key)
        .decrypt(
            &nonce,
            Payload {
                msg: &file[kem_end + NONCE_SIZE..],
                aad: &file[..HEADER_SIZE],
            },
        )
        .expect("could not AES-GCM decrypt the content")
}

/// Encrypts `plaintext` into a version 2 file for the given public key PEM.
pub fn reference_encrypt_v2(public_pem: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (kem_ciphertext, shared_key) = decode_public_key(public_pem).encapsulate();
    let nonce = Nonce::<Aes256Gcm>::generate();
    let header = header_v2(NONCE_SIZE + plaintext.len() + TAG_SIZE);

    let mut content = nonce.to_vec();
    content.extend(
        content_cipher(&shared_key)
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .unwrap(),
    );

    build_file(MAGIC, VERSION_2, &kem_ciphertext, &content)
}

/// Asserts that `path` is a `.crypt` file with format version 2 (header layout and size) that
/// the private key PEM decrypts to `plaintext`.
pub fn assert_v2_crypt_file(path: &Path, private_pem: &[u8], plaintext: &[u8]) {
    let file = std::fs::read(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    let content_len = NONCE_SIZE + plaintext.len() + TAG_SIZE;
    let header = read_header(&file);
    let context = path.display();

    assert_eq!(header.magic, MAGIC, "{context}: magic");
    assert_eq!(header.version, VERSION_2, "{context}: version");
    assert_eq!(
        header.key_len, KEM_CIPHERTEXT_SIZE as u64,
        "{context}: key_len"
    );
    assert_eq!(
        header.content_len, content_len as u64,
        "{context}: content_len"
    );
    assert_eq!(
        file.len(),
        HEADER_SIZE + KEM_CIPHERTEXT_SIZE + content_len,
        "{context}: file size"
    );
    assert_eq!(
        reference_decrypt_v2(private_pem, &file),
        plaintext,
        "{context}: plaintext"
    );
}
