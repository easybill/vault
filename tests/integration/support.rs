//! Vault file format constants and a reference implementation of its crypto.
//!
//! The reference implementation uses the `openssl` crate directly and never calls vault code,
//! so the tests stay independent of the implementation.
//!
//! File layout (all integers big endian, the version field is 1):
//!
//! ```text
//! u16 magic | u16 version | u64 key_len | u64 content_len | encrypted AES key | IV + ciphertext
//! ```
//!
//! The AES-256 key is encrypted with RSA PKCS#1 v1.5, the content with AES-256-CBC and PKCS#7
//! padding. The IV is the first 16 bytes of the content block.

#![allow(dead_code)] // Not all test modules use all helpers

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, Mode, decrypt, encrypt};

use crate::common::fixture_dir;

pub const MAGIC: u16 = 4242;
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 20;
pub const IV_SIZE: usize = 16;
pub const AES_KEY_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
/// RSA output size of the 8096-bit keys written by `vault create-openssl-key`.
pub const RSA_SIZE: usize = 1012;

pub const GOLDEN: &str = "v1/golden";
pub const LEGACY_1_0_0: &str = "v1/legacy_1_0_0";

/// Secrets in the golden fixture that alice can read (`.vault/private_keys/alice.pem`).
pub const ALICE_SECRETS: &[&str] = &[
    "BINARY",
    "BLOCK_15",
    "BLOCK_16",
    "BLOCK_17",
    "EMPTY",
    "GLOB_A",
    "LARGE",
    "ONE_BYTE",
    "SHARED",
    "SIMPLE",
    "UNICODE_MULTILINE",
];

/// Secrets in the golden fixture that bob can read (`bob_private_keys/bob.pem`).
pub const BOB_SECRETS: &[&str] = &["BOB_ONLY", "GLOB_A", "SHARED"];

/// Path of a file inside the golden fixture.
pub fn golden_path(relative: &str) -> PathBuf {
    fixture_dir(GOLDEN).join(relative)
}

/// Reads a file inside the golden fixture.
pub fn golden_file(relative: &str) -> Vec<u8> {
    let path = golden_path(relative);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// alice's private key in the golden fixture.
pub fn alice_private_key() -> Vec<u8> {
    golden_file(".vault/private_keys/alice.pem")
}

/// alice's public key in the golden fixture.
pub fn alice_public_key() -> Vec<u8> {
    golden_file(".vault/keys/alice/alice.pub.pem")
}

/// bob's private key in the golden fixture.
pub fn bob_private_key() -> Vec<u8> {
    golden_file("bob_private_keys/bob.pem")
}

/// bob's public key in the golden fixture.
pub fn bob_public_key() -> Vec<u8> {
    golden_file(".vault/keys/bob/bob.pub.pem")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub magic: u16,
    pub version: u16,
    pub key_len: u64,
    pub content_len: u64,
}

/// Reads the 20 byte header of a vault file.
pub fn read_header(file: &[u8]) -> Header {
    assert!(file.len() >= HEADER_SIZE, "file is shorter than the header");
    Header {
        magic: u16::from_be_bytes(file[0..2].try_into().unwrap()),
        version: u16::from_be_bytes(file[2..4].try_into().unwrap()),
        key_len: u64::from_be_bytes(file[4..12].try_into().unwrap()),
        content_len: u64::from_be_bytes(file[12..20].try_into().unwrap()),
    }
}

/// Serializes a vault file from its parts, with header lengths taken from the parts.
pub fn build_file(magic: u16, version: u16, encrypted_key: &[u8], content: &[u8]) -> Vec<u8> {
    let mut file = Vec::with_capacity(HEADER_SIZE + encrypted_key.len() + content.len());
    file.extend_from_slice(&magic.to_be_bytes());
    file.extend_from_slice(&version.to_be_bytes());
    file.extend_from_slice(&(encrypted_key.len() as u64).to_be_bytes());
    file.extend_from_slice(&(content.len() as u64).to_be_bytes());
    file.extend_from_slice(encrypted_key);
    file.extend_from_slice(content);
    file
}

/// Length of the AES-256-CBC ciphertext with PKCS#7 padding (always at least one padding byte).
pub fn pkcs7_padded_len(plaintext_len: usize) -> usize {
    (plaintext_len / BLOCK_SIZE + 1) * BLOCK_SIZE
}

/// Decrypts a vault file with the given private key PEM. Panics if anything does not match the
/// vault file format exactly.
pub fn reference_decrypt(private_pem: &[u8], file: &[u8]) -> Vec<u8> {
    let header = read_header(file);
    assert_eq!(header.magic, MAGIC, "magic");
    assert_eq!(header.version, VERSION, "version");

    let key_end = HEADER_SIZE + header.key_len as usize;
    assert_eq!(
        file.len(),
        key_end + header.content_len as usize,
        "file size must match the header"
    );
    let aes_key = reference_aes_key(private_pem, file);
    let (iv, ciphertext) = file[key_end..].split_at(IV_SIZE);
    decrypt(Cipher::aes_256_cbc(), &aes_key, Some(iv), ciphertext)
        .expect("could not AES decrypt the content")
}

/// The encrypted AES key block of a `.crypt` file, as given by its header.
pub fn encrypted_key_of(file: &[u8]) -> &[u8] {
    let header = read_header(file);
    &file[HEADER_SIZE..HEADER_SIZE + header.key_len as usize]
}

/// The IV of a `.crypt` file: the first bytes of the content block.
pub fn iv_of(file: &[u8]) -> &[u8] {
    let header = read_header(file);
    &file[HEADER_SIZE + header.key_len as usize..][..IV_SIZE]
}

/// The AES key of a `.crypt` file, RSA decrypted with the given private key PEM. Panics unless
/// it has exactly 32 bytes.
pub fn reference_aes_key(private_pem: &[u8], file: &[u8]) -> Vec<u8> {
    let rsa = Rsa::private_key_from_pem(private_pem).expect("invalid private key PEM");
    let mut aes_key = vec![0; rsa.size() as usize];
    let aes_key_len = rsa
        .private_decrypt(encrypted_key_of(file), &mut aes_key, Padding::PKCS1)
        .expect("could not RSA decrypt the AES key");
    assert_eq!(aes_key_len, AES_KEY_SIZE, "AES key size");
    aes_key.truncate(AES_KEY_SIZE);
    aes_key
}

/// Asserts that `path` is a `.crypt` file with format version 1 for an 8096-bit key (header
/// layout and size) that the private key PEM decrypts to `plaintext`, with an IV that is
/// neither zero nor taken from the AES key.
pub fn assert_crypt_file(path: &Path, private_pem: &[u8], plaintext: &[u8]) {
    let file = std::fs::read(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    let content_len = IV_SIZE + pkcs7_padded_len(plaintext.len());
    let header = read_header(&file);
    let context = path.display();

    assert_eq!(header.magic, MAGIC, "{context}: magic");
    assert_eq!(header.version, VERSION, "{context}: version");
    assert_eq!(header.key_len, RSA_SIZE as u64, "{context}: key_len");
    assert_eq!(
        header.content_len, content_len as u64,
        "{context}: content_len"
    );
    assert_eq!(
        file.len(),
        HEADER_SIZE + RSA_SIZE + content_len,
        "{context}: file size"
    );
    assert_eq!(
        reference_decrypt(private_pem, &file),
        plaintext,
        "{context}: plaintext"
    );

    let iv = iv_of(&file);
    assert_ne!(iv, [0; IV_SIZE], "{context}: IV is zero");
    assert_ne!(
        iv,
        &reference_aes_key(private_pem, &file)[..IV_SIZE],
        "{context}: IV is part of the AES key"
    );
}

/// RSA PKCS#1 v1.5 encrypts `data` with the given public key PEM.
pub fn rsa_encrypt(public_pem: &[u8], data: &[u8]) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(public_pem).expect("invalid public key PEM");
    let mut encrypted = vec![0; rsa.size() as usize];
    let len = rsa
        .public_encrypt(data, &mut encrypted, Padding::PKCS1)
        .expect("could not RSA encrypt");
    assert_eq!(len, encrypted.len());
    encrypted
}

/// AES-256-CBC encrypts `data`. Without `pad`, `data` must be a multiple of the block size and
/// is encrypted as is.
pub fn aes_encrypt(aes_key: &[u8; AES_KEY_SIZE], iv: &[u8], data: &[u8], pad: bool) -> Vec<u8> {
    if pad {
        return encrypt(Cipher::aes_256_cbc(), aes_key, Some(iv), data).expect("AES encrypt");
    }

    let mut crypter =
        Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, aes_key, Some(iv)).expect("AES crypter");
    crypter.pad(false);
    let mut out = vec![0; data.len() + BLOCK_SIZE];
    let mut len = crypter.update(data, &mut out).expect("AES update");
    len += crypter.finalize(&mut out[len..]).expect("AES finalize");
    out.truncate(len);
    out
}

/// Random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand_bytes(&mut bytes).expect("random bytes");
    bytes
}

/// Encrypts `plaintext` into a vault file for the given public key PEM.
///
/// The RSA block carries all of `aes_key`, the content is encrypted with its first 32 bytes.
/// Passing a key longer than 32 bytes crafts files with an oversized AES key.
pub fn reference_encrypt(public_pem: &[u8], plaintext: &[u8], aes_key: &[u8]) -> Vec<u8> {
    let content_key: &[u8; AES_KEY_SIZE] = aes_key[..AES_KEY_SIZE]
        .try_into()
        .expect("AES key must have at least 32 bytes");
    let iv = random_bytes::<IV_SIZE>();

    let mut content = iv.to_vec();
    content.extend(aes_encrypt(content_key, &iv, plaintext, true));

    build_file(MAGIC, VERSION, &rsa_encrypt(public_pem, aes_key), &content)
}

/// A fake `gpg` executable for private keys stored as `.pem.pgp`.
///
/// vault decrypts such keys by running `gpg` from `PATH`. The fake appends each of its arguments
/// as one line to [`FakeGpg::calls`], prints the contents of a file on stdout and a fixed text on
/// stderr and exits with a fixed code. With `FAKE_GPG_PROBE` set it only exits successfully.
#[cfg(unix)]
pub struct FakeGpg {
    dir: PathBuf,
}

#[cfg(unix)]
impl FakeGpg {
    /// Creates the directory `dir` holding the executable `gpg`.
    pub fn new(dir: &Path, stdout_file: &Path, stderr: &str, exit_code: i32) -> FakeGpg {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir(dir).unwrap();
        let log = dir.join("calls.log");
        for value in [log.to_str().unwrap(), stdout_file.to_str().unwrap(), stderr] {
            assert!(!value.contains('\''), "cannot quote {value}");
        }

        let script = dir.join("gpg");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 [ -n \"$FAKE_GPG_PROBE\" ] && exit 0\n\
                 printf '%s\\n' \"$@\" >> '{log}'\n\
                 cat '{stdout_file}'\n\
                 printf '%s' '{stderr}' >&2\n\
                 exit {exit_code}\n",
                log = log.display(),
                stdout_file = stdout_file.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_until_executable(&script);

        FakeGpg {
            dir: dir.to_path_buf(),
        }
    }

    /// `PATH` with the fake `gpg` in front of the inherited entries.
    pub fn path_env(&self) -> OsString {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![self.dir.clone()];
        paths.extend(std::env::split_paths(&inherited));
        std::env::join_paths(paths).unwrap()
    }

    /// The arguments of every call so far, one per line.
    pub fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
    }
}

/// Runs the new script until it no longer fails with "text file busy".
///
/// On Linux, a process forked by another test thread while the script was open for writing
/// keeps a writable descriptor until it calls `exec`, and executing the script fails meanwhile.
#[cfg(unix)]
fn wait_until_executable(script: &Path) {
    const TEXT_FILE_BUSY: i32 = 26; // ETXTBSY on Linux and macOS

    // 500 attempts, 10 ms apart: about 5 s.
    for _ in 0..500 {
        match std::process::Command::new(script)
            .env("FAKE_GPG_PROBE", "1")
            .status()
        {
            Ok(status) => {
                assert!(status.success(), "fake gpg probe failed: {status}");
                return;
            }
            Err(error) if error.raw_os_error() == Some(TEXT_FILE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("could not run {}: {error}", script.display()),
        }
    }
    panic!("{} stays busy", script.display());
}
