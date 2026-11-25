use std::fs;

use anyhow::{Context, Result, bail};
use clap::Arg;
use semver::{Version, VersionReq};

use crate::commands::get_multi::get_multi;
use crate::filesystem::{Filesystem, FilesystemCheckResult};
use crate::key::key_map::KeyMap;
use crate::policy::{Policy, Version1};
use crate::rotate_key::rotate_keys;
use crate::template::Template;
use crate::ui::question::Question;

mod commands;
mod filesystem;
mod key;
mod policy;
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
        .version(env!("CARGO_PKG_VERSION"))
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
            clap::Command::new("create-key")
                .about("creates a new X-Wing key and registers the user")
                .arg(
                    Arg::new("username")
                        .required(true)
                        .help("name of the new user"),
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
        let version_current = Version::parse(env!("CARGO_PKG_VERSION"))
            .context("could not parse current version, should not happen")?;

        if !version_requirement.matches(&version_current) {
            bail!(
                "probably a coworker wants to prevent this vault version from being used. maybe there was a bug in vault or a feature is being used that is only available in this version. please install the latest version from https://github.com/easybill/vault/releases."
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

    let mut key_map = KeyMap::from_path()?;

    if let Some(_matches) = matches.subcommand_matches("check-keys") {
        if key_map.private_pems().is_empty() {
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

    if let Some(matches) = matches.subcommand_matches("create-key") {
        let username = matches
            .get_one::<String>("username")
            .expect("username must exist");

        policy::current().create_key(username)?;

        return Ok(());
    }

    if let Some(matches) = matches.subcommand_matches("create-openssl-key") {
        let username = matches
            .get_one::<String>("username")
            .expect("username must exist");

        Version1.create_key(username)?;

        return Ok(());
    }

    if let Some(_matches) = matches.subcommand_matches("rotate") {
        rotate_keys().context("rotate keys")?;
        return Ok(());
    }

    println!();
    println!("create key map.");
    println!();

    if scan_for_new_secrets(&key_map)? > 0 {
        // refresh the key map
        key_map = KeyMap::from_path()?;
    }

    // check loaded keys:
    println!("loaded keys:");
    for pem in key_map.private_pems() {
        println!("- {}", pem.name());
    }

    // check if there are any subscriptions that we can fulfill
    let mut fulfillable = Vec::new();
    let mut unfulfillable = Vec::new();
    for open_subscription in key_map.open_subscriptions() {
        if key_map.could_fulfill_subscription(&open_subscription) {
            fulfillable.push(open_subscription);
        } else {
            unfulfillable.push(open_subscription);
        }
    }

    if !unfulfillable.is_empty() {
        println!();
        println!(
            "open subscriptions without a key to fulfill them, ask someone who has access ({}):",
            unfulfillable.len()
        );
        for subscription in &unfulfillable {
            println!(
                "  - user: {}, name: {}",
                subscription.username(),
                subscription.name()
            );
        }
    }

    fulfillable.sort_by(|a, b| (a.username(), a.name()).cmp(&(b.username(), b.name())));
    let accepted = Question::select(
        "open subscriptions you've the required right to fulfill",
        fulfillable,
        |s| format!("user: {}, name: {}", s.username(), s.name()),
        |s| format!("   give {} access to {}?", s.username(), s.name()),
    );
    for subscription in &accepted {
        key_map.fulfill_subscription(subscription)?;
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

    let mut new_secret_paths = Vec::new();

    for raw_path in paths {
        let path = raw_path.context("could not parse path")?;

        if !path
            .metadata()
            .with_context(|| format!("could not get metadata for file {path:?}"))?
            .is_file()
        {
            continue;
        }

        new_secret_paths.push(path.path().display().to_string());
    }

    new_secret_paths.sort();
    let accepted = Question::select(
        "new secrets",
        new_secret_paths,
        |path| path.clone(),
        |path| format!("do you want to add the new secret at {path}?"),
    );

    for path in &accepted {
        key_map.add_new_secret(path)?;
        new_secrets_created += 1;
    }

    Ok(new_secrets_created)
}
