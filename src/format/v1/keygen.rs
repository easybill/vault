use std::fs;
use std::fs::File;
use std::io::Write;

use anyhow::{Context, Result, bail};
use openssl::rsa::Rsa;

use crate::key::Pem;

pub fn create_keys(username: &str) -> Result<Pem> {
    let private_key_path = format!("./.vault/private_keys/{username}.pem");
    let public_key_path = format!("./.vault/private_keys/{username}.pub.pem");
    let private_key_public_path = format!("./.vault/keys/{username}/{username}.pub.pem");
    let toml_config_path = format!("./.vault/keys/{username}/config.toml");

    println!("generating keys ...");

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

    // create directory
    let public_directory = format!("./.vault/keys/{username}");

    fs::create_dir(&public_directory)
        .with_context(|| format!("could not create directory {public_directory}"))?;

    // create config.toml
    {
        let mut f = File::create(&toml_config_path)
            .with_context(|| format!("could not create {toml_config_path}"))?;

        f.write_all(b"subscriptions = []")
            .with_context(|| format!("could not write to {toml_config_path}"))?;
    }

    let key = Rsa::generate(8096).context("could not generate rsa code")?;

    {
        let k0pkey = key
            .public_key_to_pem()
            .with_context(|| format!("could not run public_key_to_pem {username}"))?;

        let public_key = openssl::rsa::Rsa::public_key_from_pem(&k0pkey)
            .context("could not decode public key")?;

        let mut f = File::create(&public_key_path)
            .with_context(|| format!("could not create .pem.pub, {public_key_path}"))?;
        f.write_all(&public_key.public_key_to_pem().unwrap())
            .with_context(|| format!("could not write to {public_key_path}"))?;

        let mut f = File::create(&private_key_public_path)
            .with_context(|| format!("could not create .pem.pub, {private_key_public_path}"))?;
        f.write_all(&public_key.public_key_to_pem().unwrap())
            .with_context(|| format!("could not write to {private_key_public_path}"))?;
    }

    {
        let privkey_pem = key.private_key_to_pem().with_context(|| {
            format!("could not translate private key to pem {private_key_path}")
        })?;

        let mut f = File::create(&private_key_path)
            .with_context(|| format!("could not create {private_key_path}"))?;

        f.write_all(&privkey_pem)
            .with_context(|| format!("could not write to {private_key_path}"))?
    }

    Ok(Pem::new(
        super::keys::load_private_key_v1(&private_key_path)
            .with_context(|| format!("failed, to add key, private key: {private_key_path}"))?,
        super::keys::load_public_key_v1(&public_key_path)
            .with_context(|| format!("failed, to add key, public key: {public_key_path}"))?,
    ))
}
