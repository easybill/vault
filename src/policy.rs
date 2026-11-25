use std::fmt::Debug;
use std::path::Path;

use crate::Result;
use crate::key::{Pem, PublicKey};
use crate::proto::{UnencryptedVaultFile, VaultFile};

mod v1;
mod v2;

pub use v1::Version1;
pub use v2::Version2;

/// A policy defines how keys are stored, named and created, the cryptography used with them and
/// the version of the `.crypt` files it produces. Every key belongs to exactly one policy.
pub trait Policy: Debug + Send + Sync {
    /// Version written to the header of every `.crypt` file this policy encrypts.
    fn file_version(&self) -> u16;

    /// Loads all private keys of this policy that are available to the current user.
    fn load_private_keys(&self) -> Result<Vec<Pem>>;

    /// Loads all public keys of this policy from the key directory of a user.
    fn load_public_keys(&self, user_dir: &Path) -> Result<Vec<PublicKey>>;

    /// Creates a new key pair for `username` and registers the user in the repository (public key
    /// and config).
    fn create_key(&self, username: &str) -> Result<Pem>;

    fn encrypt(
        &self,
        public_key: &PublicKey,
        plaintext: &UnencryptedVaultFile,
    ) -> Result<VaultFile>;

    fn decrypt(&self, pem: &Pem, file: &VaultFile) -> Result<UnencryptedVaultFile>;

    /// Creates the key pair that replaces `replaced` in a rotation and registers it in the
    /// repository as user `username`. `replaced` belongs to this policy or to an older one.
    fn create_replacement_key(&self, username: &str, replaced: &Pem) -> Result<Pem>;

    /// Moves the private key of the rotated user `username` aside under a backup name containing
    /// `timestamp`.
    fn backup_private_key(&self, username: &str, timestamp: u64) -> Result<()>;

    /// The renames, in order, that move the keys created by
    /// [`Policy::create_replacement_key`] for user `from` to user `to`.
    fn key_renames(&self, from: &str, to: &str) -> Result<Vec<Rename>>;
}

/// A file or directory rename.
pub struct Rename {
    pub from: String,
    pub to: String,
}

/// All supported policies.
pub static ALL: &[&dyn Policy] = &[&Version1, &Version2];

/// The policy used for new keys.
pub fn current() -> &'static dyn Policy {
    &Version2
}

pub fn by_file_version(version: u16) -> Option<&'static dyn Policy> {
    ALL.iter()
        .copied()
        .find(|policy| policy.file_version() == version)
}
