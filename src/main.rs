use std::fs;

use anyhow::{Context, Result, bail};
use clap::Arg;
use self_update::cargo_crate_version;
use semver::{Version, VersionReq};

use crate::commands::get_multi::get_multi;
use crate::filesystem::{Filesystem, FilesystemCheckResult};
use crate::format::FormatVersion;
use crate::key::key_map::{KeyMap, KeyMapConfig};
use crate::rotate_key::rotate_keys;
use crate::template::Template;
use crate::ui::question::Question;

mod commands;
mod filesystem;
mod format;
mod key;
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
            Arg::new("v2")
                .long("v2")
                .num_args(0)
                .help("use v2 post-quantum format (ML-KEM-1024 + AES-256-GCM) for key generation and encryption")
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
            clap::Command::new("create-ml-kem-key")
                .about("creates a new ML-KEM-1024 post-quantum keypair")
                .arg(
                    Arg::new("username")
                        .required(true)
                        .help("username for the new keypair"),
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

    let explicit_v2 = matches.get_flag("v2");

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
        if key_map.private_pems().is_empty() {
            bail!("there is no private key");
        }

        format::validate_private_pems(key_map.private_pems())?;
        println!("keys are fine");
        return Ok(());
    }

    let resolved_format_version =
        format::resolve_write_version(key_map.private_pems(), explicit_v2)?;

    // You can check the value provided by positional arguments, or option arguments
    if let Some(matches) = matches.subcommand_matches("get") {
        let key = matches.get_one::<String>("key").expect("key must exists");

        let unencrypted = key_map.decrypt(key)?;
        use std::io::Write;
        std::io::stdout().write_all(unencrypted.content())?;
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
        print!("{value}");

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

        format::create_keys(username, FormatVersion::V1)?;

        return Ok(());
    }

    if let Some(matches) = matches.subcommand_matches("create-ml-kem-key") {
        let username = matches
            .get_one::<String>("username")
            .expect("username must exist");

        format::create_keys(username, FormatVersion::V2)?;

        return Ok(());
    }

    if let Some(_matches) = matches.subcommand_matches("rotate") {
        rotate_keys(&KeyMapConfig { path_private_key }, resolved_format_version)
            .context("rotate keys")?;
        return Ok(());
    }

    println!();
    println!("create key map.");
    println!();

    if scan_for_new_secrets(&key_map, resolved_format_version)? > 0 {
        // refresh the key map
        key_map = KeyMap::from_path(&KeyMapConfig { path_private_key })?;
    }

    // check loaded keys:
    println!("loaded keys:");
    for pem in key_map.private_pems() {
        println!("- {}", pem.name());
    }

    // check if there are any subscriptions that we can fulfill
    for open_subscription in &key_map.open_subscriptions() {
        println!();
        println!("-- Open Subscription");
        println!("--    user: {}", open_subscription.username());
        println!("--    name: {}", open_subscription.name());

        if !key_map
            .could_fulfill_subscription_with_version(open_subscription, resolved_format_version)
        {
            println!(
                "no key found to fulfill the subscription, ask someone who has access to this key"
            );
            continue;
        }

        println!();

        if Question::confirm(
            "   you've the required right to fulfill the subscription, give him access?",
        ) {
            key_map.fulfill_subscription(open_subscription, resolved_format_version)?;
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

pub fn scan_for_new_secrets(key_map: &KeyMap, version: FormatVersion) -> Result<usize> {
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
            "do you want to add the new secret at {path_as_string}?"
        )) {
            continue;
        }

        key_map.add_new_secret(&path_as_string, version)?;

        new_secrets_created += 1;
    }

    Ok(new_secrets_created)
}
