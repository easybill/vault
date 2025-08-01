use std::fs;

use anyhow::{Context, Result, bail};
use clap::Arg;
use openssl::rsa::Rsa;
use self_update::cargo_crate_version;
use semver::{Version, VersionReq};

use crate::commands::get_multi::get_multi;
use crate::filesystem::{Filesystem, FilesystemCheckResult};
use crate::key::key_map::{KeyMap, KeyMapConfig};
use crate::key::{Pem, PrivateKey, PublicKey};
use crate::rotate_key::rotate_keys;
use crate::template::Template;
use crate::ui::question::Question;

mod commands;
mod crypto;
mod filesystem;
mod key;
mod proto;
mod rotate_key;
mod template;
mod ui;

fn main() {
    if let Err(error) = run() {
        eprintln!("Vault error: {error:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let matches = clap::Command::new("Vault")
        .arg(
            Arg::new("yes")
                .short('y')
                .help("always answers questions with yes")
        )
        .arg(
            Arg::new("expect_version")
                .long("expect_version")
                .required(false)
                .help("are you using a feature that only exists in a new vault version and your coworkers are still using an old version? install --min-version to warn your coworkers =)"),
        )
        .version(cargo_crate_version!())
        .subcommand(
            clap::Command::new("get").arg(
                Arg::new("key")
                    .required(true)
                    .help("lists test values"),
            ),
        )
        .subcommand(
            clap::Command::new("get_multi")
                .arg(
                    Arg::new("json")
                        .required(true)
                        .help(r#"something like {"secrets": [{"secret": "foo"}], "templates": [{"template": "{vault{ foo }vault}TEST"}]}"#),
                ),
        )
        .subcommand(
            clap::Command::new("create-openssl-key")
                .about("does testing things")
                .arg(
                    Arg::new("username")
                        .required(true)
                        .help("lists test values"),
                ),
        )
        .subcommand(
            clap::Command::new("update")
                .about("updates vault")
                .arg(
                    Arg::new("current_version")
                        .default_value(cargo_crate_version!())
                        .required(false)
                        .help("lists test values"),
                ),
        )
        .subcommand(
            clap::Command::new("template")
                .about("does testing things")
                .arg(
                    Arg::new("filename")
                        .required(true)
                        .help("lists test values"),
                ),
        )
        .subcommand(
            clap::Command::new("rotate")
                .about("rotated the private key")
        )
        .subcommand(
            clap::Command::new("check-keys")
        )
        .get_matches();

    if let Some(yes) = matches.get_one::<bool>("yes").copied() {
        Question::set_yes(yes);
    }

    if let Some(min_version) = matches.get_one::<String>("expect_version") {
        let version_requirement = VersionReq::parse(min_version).context(
            "could not parse version requirement, expected something like >=1.2.3, <1.8.0",
        )?;
        let version_current = Version::parse(cargo_crate_version!())
            .context("could not parse current version, should not happen")?;

        if !version_requirement.matches(&version_current) {
            bail!(
                "probably a coworker wants to prevent this vault version from being used. maybe there was a bug in vault or a feature is being used that is only available in this version. may you want to run vault update to upgrade to the latest version."
            );
        }
    }

    match Filesystem::check_filesystem() {
        FilesystemCheckResult::IsOk => {}
        FilesystemCheckResult::IsNotInstalled => enter_filesystem_wizard()?,
        FilesystemCheckResult::HasErrors(ref errors) => {
            bail!(
                "issues with the filesystem, e.g. a basic directory could be missing\n{}",
                errors.join("\n")
            );
        }
    };

    let path_private_key = std::env::vars()
        .find(|(key, _)| key == "VAULT_PRIVATE_KEY_PATH")
        .map(|(_, value)| value)
        .unwrap_or_else(|| "./.vault/private_keys".to_string());

    let mut key_map = KeyMap::from_path(&KeyMapConfig {
        path_private_key: path_private_key.clone(),
    })?;

    if let Some(_matches) = matches.subcommand_matches("check-keys") {
        if key_map.get_private_pems().is_empty() {
            bail!("there is no private key");
        }

        println!("keys are fine");
        return Ok(());
    }

    // You can check the value provided by positional arguments, or option arguments
    if let Some(matches) = matches.subcommand_matches("get") {
        let key = matches.get_one::<String>("key").expect("key must exists");

        let unencrypted = key_map.decrypt(key)?;
        use std::io::Write;
        std::io::stdout().write_all(unencrypted.get_content())?;
        return Ok(());
    }

    if let Some(matches) = matches.subcommand_matches("get_multi") {
        return get_multi(
            matches
                .get_one::<String>("json")
                .expect("key json must exists"),
            &key_map,
        );
    }

    if let Some(matches) = matches.subcommand_matches("template") {
        let filename = matches
            .get_one::<String>("filename")
            .expect("filename must exist");

        let template = Template::new(&key_map);
        let value = template.parse_from_file(filename)?;
        print!("{}", value);

        return Ok(());
    }

    if let Some(matches) = matches.subcommand_matches("update") {
        let status = self_update::backends::github::Update::configure()
            .repo_owner("easybill")
            .repo_name("vault")
            .bin_name("vault")
            .show_download_progress(true)
            .current_version(
                matches
                    .get_one::<String>("current_version")
                    .expect("current version has a default"),
            )
            .build()?
            .update()?;
        println!("Update status: `{}`!", status.version());
        return Ok(());
    }

    if let Some(matches) = matches.subcommand_matches("create-openssl-key") {
        let username = matches
            .get_one::<String>("username")
            .expect("username must exist");

        create_keys(username)?;

        return Ok(());
    }

    if let Some(_matches) = matches.subcommand_matches("rotate") {
        rotate_keys(&KeyMapConfig { path_private_key }).context("rotate keys")?;
        return Ok(());
    }

    println!();
    println!("create key map.");
    println!();

    if scan_for_new_secrets(&key_map)? > 0 {
        // refresh the key map
        key_map = KeyMap::from_path(&KeyMapConfig { path_private_key })?;
    }

    // check loaded keys:
    println!("loaded keys:");
    for pem in key_map.get_private_pems() {
        println!("- {}", pem.get_name());
    }

    // check if there are any subscriptions that we can fulfill
    for open_subscription in &key_map.get_open_subscriptions() {
        println!();
        println!("-- Open Subscription");
        println!("--    user: {}", open_subscription.get_username());
        println!("--    name: {}", open_subscription.get_name());

        if !key_map.could_fulfill_subscription(open_subscription) {
            println!(
                "no key found to fulfill the subscription, ask someone who has access to this key"
            );
            continue;
        }

        println!();

        if Question::confirm(
            "   you've the required right to fulfill the subscription, give him access?",
        ) {
            key_map.fulfill_subscription(open_subscription)?;
        } else {
            println!("maybe later");
        }

        println!();
    }

    println!();
    println!("all fine");
    println!();

    Ok(())
}

pub fn enter_filesystem_wizard() -> Result<()> {
    eprintln!("seems that vault isn't \"installed\" here.");
    eprintln!("may you're just in the wrong directory?");

    if Question::confirm("do you want to create an empty ./.vault directory?") {
        Filesystem::create_basic_directory_structure()?
    }

    Ok(())
}

pub fn scan_for_new_secrets(key_map: &KeyMap) -> Result<usize> {
    let mut new_secrets_created = 0;

    let secret_path = "./.vault/secrets/";

    let paths = fs::read_dir(secret_path).with_context(|| {
        format!("could not read subscription path. could the directory be missing? {secret_path}")
    })?;

    for raw_path in paths {
        let path = raw_path.context("could not parse path")?;

        if !path
            .metadata()
            .with_context(|| format!("could not get metadata for file {path:?}"))?
            .is_file()
        {
            continue;
        }

        let path_as_string = path.path().display().to_string();

        if !Question::confirm(&format!(
            "do you want to add the new secret at {}?",
            path_as_string
        )) {
            continue;
        }

        key_map.add_new_secret(&path_as_string)?;

        new_secrets_created += 1;
    }

    Ok(new_secrets_created)
}

pub fn create_keys(username: &str) -> Result<Pem> {
    use std::fs::File;
    use std::io::Write;

    let private_key_path = format!("./.vault/private_keys/{}.pem", username);
    let public_key_path = format!("./.vault/private_keys/{}.pub.pem", username);
    let private_key_public_path = format!("./.vault/keys/{}/{}.pub.pem", username, username);
    let toml_config_path = format!("./.vault/keys/{}/config.toml", username);

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
    let public_directory = format!("./.vault/keys/{}", username);

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
        PrivateKey::load_from_file(&private_key_path)
            .with_context(|| format!("failed, to add key, private key: {private_key_path}"))?,
        PublicKey::load_from_file(&public_key_path)
            .with_context(|| format!("failed, to add key, public key: {public_key_path}"))?,
    ))
}
