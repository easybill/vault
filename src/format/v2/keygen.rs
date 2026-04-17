use std::fs;
use std::fs::File;
use std::io::Write;

use anyhow::{Context, Result, bail};
use der::pem::LineEnding;
use ml_kem::kem::Generate;
use ml_kem::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ml_kem::{DecapsulationKey, MlKem1024};

use crate::key::Pem;

#[cfg(unix)]
fn set_owner_only_permissions(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("could not set owner-only permissions on {path}"))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &str) -> Result<()> {
    Ok(())
}

pub fn create_keys(username: &str) -> Result<Pem> {
    let private_key_path = format!("./.vault/private_keys/{username}.v2.pem");
    let public_key_path = format!("./.vault/private_keys/{username}.v2.pub.pem");
    let private_key_public_path = format!("./.vault/keys/{username}/{username}.v2.pub.pem");
    let toml_config_path = format!("./.vault/keys/{username}/config.toml");

    println!("generating ML-KEM-1024 keys ...");

    for path in [
        &public_key_path,
        &private_key_path,
        &private_key_public_path,
    ]
    .iter()
    {
        if fs::metadata(path).is_ok() {
            bail!("could not create the key, the file {path} already exists");
        }
    }

    // create directory if it doesn't exist (may already exist from v1 key)
    let public_directory = format!("./.vault/keys/{username}");
    if fs::metadata(&public_directory).is_err() {
        fs::create_dir(&public_directory)
            .with_context(|| format!("could not create directory {public_directory}"))?;
    }

    // create config.toml if it doesn't exist (may already exist from v1 key)
    if fs::metadata(&toml_config_path).is_err() {
        let mut f = File::create(&toml_config_path)
            .with_context(|| format!("could not create {toml_config_path}"))?;

        f.write_all(b"subscriptions = []")
            .with_context(|| format!("could not write to {toml_config_path}"))?;
    }

    let mut sys_rng = rand::rngs::SysRng;
    let dk = DecapsulationKey::<MlKem1024>::try_generate_from_rng(&mut sys_rng)?;
    let ek = ml_kem::kem::Decapsulator::encapsulation_key(&dk);

    // Write public key (SPKI PEM: "-----BEGIN PUBLIC KEY-----")
    {
        let public_pem = ek
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("could not encode public key to PEM: {e}"))?;

        let mut f = File::create(&public_key_path)
            .with_context(|| format!("could not create {public_key_path}"))?;
        f.write_all(public_pem.as_bytes())
            .with_context(|| format!("could not write to {public_key_path}"))?;

        let mut f = File::create(&private_key_public_path)
            .with_context(|| format!("could not create {private_key_public_path}"))?;
        f.write_all(public_pem.as_bytes())
            .with_context(|| format!("could not write to {private_key_public_path}"))?;
    }

    // Write private key (PKCS#8 PEM: "-----BEGIN PRIVATE KEY-----")
    {
        let private_pem = dk
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("could not encode private key to PEM: {e}"))?;

        let mut f = File::create(&private_key_path)
            .with_context(|| format!("could not create {private_key_path}"))?;
        f.write_all(private_pem.as_bytes())
            .with_context(|| format!("could not write to {private_key_path}"))?;
        set_owner_only_permissions(&private_key_path)?;
    }

    Ok(Pem::new(
        super::keys::load_private_key_v2(&private_key_path)
            .with_context(|| format!("failed, to add key, private key: {private_key_path}"))?,
        super::keys::load_public_key_v2(&public_key_path)
            .with_context(|| format!("failed, to add key, public key: {public_key_path}"))?,
    ))
}
