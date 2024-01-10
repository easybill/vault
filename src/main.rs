use anyhow::{anyhow, format_err, Context, Error};

use clap::{Arg};

use crate::filesystem::Filesystem;
use crate::filesystem::FilesystemCheckResult;
use crate::key::key_map::KeyMap;
use crate::key::key_map::KeyMapConfig;
use openssl::rsa::Rsa;
use std::fs;

use self_update::cargo_crate_version;
use crate::key::{Pem, PrivateKey, PublicKey};
use crate::rotate_key::rotate_keys;
use crate::template::Template;
use crate::ui::question::Question;

mod crypto;
mod filesystem;
mod key;
mod proto;
mod template;
mod ui;
mod test_integration;
mod rotate_key;

fn main() -> ::anyhow::Result<()> {
    let matches = ::clap::Command::new("Vault")
        .version(cargo_crate_version!())
        .subcommand(
            ::clap::Command::new("get").arg(
                Arg::new("key")
                    .required(true)
                    .help("lists test values"),
            ),
        )
        .subcommand(
            ::clap::Command::new("create-openssl-key")
                .about("does testing things")
                .arg(
                    Arg::new("username")
                        .required(true)
                        .help("lists test values"),
                ),
        )
        .subcommand(
            ::clap::Command::new("update")
                .about("updates vault")
                .arg(
                    Arg::new("current_version")
                        .default_value(cargo_crate_version!())
                        .required(false)
                        .help("lists test values"),
                ),
        )
        .subcommand(
            ::clap::Command::new("template")
                .about("does testing things")
                .arg(
                    Arg::new("filename")
                        .required(true)
                        .help("lists test values"),
                ),
        )
        .subcommand(
            ::clap::Command::new("rotate")
                .about("rotated the private key")
        )
        .subcommand(
            ::clap::Command::new("check-keys")
        )
        .get_matches();

    match Filesystem::check_filesystem() {
        FilesystemCheckResult::IsOk => {}
        FilesystemCheckResult::IsNotInstalled => enter_filesystem_wizard()?,
        FilesystemCheckResult::HasErrors(ref errors) => {
            eprintln!("issues with the filesystem.");
            for e in errors {
                eprintln!(" error: {}", e);
            }

            return Err(anyhow!("issues with the filesystem."));
        }
    };

    let path_private_key = ::std::env::vars()
        .find(|(ref key, _)| key == "VAULT_PRIVATE_KEY_PATH")
        .map(|(_, value)| value.to_string())
        .unwrap_or_else(|| "./.vault/private_keys".to_string());


    if let Some(_matches) = matches.subcommand_matches("check-keys") {
        for _ in 1..3 {
            let keymap = KeyMap::from_path(&KeyMapConfig {
                path_private_key: path_private_key.clone(),
            })?;

            println!("keys are fine");
            if keymap.get_private_pems().len() == 0 {
                eprintln!("there is no private key");
                ::std::process::exit(1);
            }
        }

        eprintln!("keys are fine");
        ::std::process::exit(1);
    }

    let mut keymap = KeyMap::from_path(&KeyMapConfig {
        path_private_key: path_private_key.clone(),
    })?;

    if let Some(matches) = matches.subcommand_matches("update") {
        let status = self_update::backends::github::Update::configure()
            .repo_owner("easybill")
            .repo_name("vault")
            .bin_name("vault")
            .show_download_progress(true)
            .current_version(matches.get_one::<String>("current_version").expect("current version has a default"))
            .build()?
            .update()?;
        println!("Update status: `{}`!", status.version());
        return Ok(())
    }

    // You can check the value provided by positional arguments, or option arguments
    if let Some(matches) = matches.subcommand_matches("get") {
        let key = matches.get_one::<String>("key").expect("key must exists");

        match keymap.decrypt(&key) {
            Ok(k) => {
                use std::io::Write;
                ::std::io::stdout().write_all(k.get_content())?;
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error: {}", &e);
                ::std::process::exit(1);
            }
        }
    }

    if let Some(matches) = matches.subcommand_matches("create-openssl-key") {
        let username = matches.get_one::<String>("username").expect("username must exists");

        create_keys(username)?;

        return Ok(());
    }

    if let Some(matches) = matches.subcommand_matches("template") {
        let filename = matches.get_one::<String>("filename").expect("filename must exists");

        let template = Template::new(&keymap);
        match template.parse_from_file(filename) {
            Ok(c) => {
                print!("{}", c);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                ::std::process::exit(1);
            }
        }

        return Ok(());
    }

    if let Some(_matches) = matches.subcommand_matches("rotate") {
        rotate_keys(&KeyMapConfig { path_private_key }).context("rotate keys")?;
        return Ok(());
    }

    println!();
    println!("create keymap.");
    println!();

    if scan_for_new_secrets(&keymap)? > 0 {
        // refresh the keymap
        keymap = KeyMap::from_path(&KeyMapConfig { path_private_key })?;
    }

    // check loaded keys:
    println!("loaded keys:");
    for pem in keymap.get_private_pems() {
        println!("- {}", pem.get_name());
    }

    // check if there are any subscriptions that we can fullfill
    for open_subscription in &keymap.get_open_subscriptions() {
        println!();
        println!("-- Open Subscription");
        println!("--    user: {}", open_subscription.get_username());
        println!("--    name: {}", open_subscription.get_name());

        if !keymap.could_fulfill_subscription(open_subscription) {
            println!(
                "no key found to fulfill the subscription, ask someone who has access to this key"
            );
            continue;
        }

        println!();

        if Question::confirm(
            "   you've the required right to fulfill the subscription, give him access?",
        ) {
            keymap.fulfill_subscription(open_subscription)?;
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

pub fn enter_filesystem_wizard() -> Result<(), Error> {
    eprintln!("seems that vault isnt \"installed\" here.");
    eprintln!("may you're just in the wrong directory?");

    if Question::confirm("do you want to create an empty ./.vault directory?") {
        Filesystem::create_basic_directory_structure()?
    }

    Ok(())
}

pub fn scan_for_new_secrets(keymap: &KeyMap) -> Result<usize, Error> {
    let mut new_secrets_created = 0;

    let secret_path = "./.vault/secrets/";

    let paths = fs::read_dir(&secret_path).context(format!(
        "could not read subscription path. directory is missing? {}",
        &secret_path
    ))?;

    for raw_path in paths {
        let path = raw_path.context(format_err!("could not parse path"))?;

        if !path
            .metadata()
            .context(format!("could not get metadata for file {:?}", path))?
            .is_file()
        {
            continue;
        }

        let path_as_string = path.path().display().to_string();

        if !Question::confirm(&format!(
            "do you want to add the new secret {}",
            path_as_string
        )) {
            continue;
        }

        keymap.add_new_secet(&path_as_string)?;

        new_secrets_created += 1;
    }

    Ok(new_secrets_created)
}


pub fn create_keys(username: &str) -> Result<Pem, Error> {
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
        if fs::metadata(&path).is_ok() {
            return Err(format_err!(
                "the file {} already exists. could not create the key.",
                path
            ));
        }
    }

    // create directory
    let public_directory = format!("./.vault/keys/{}", username);

    for directory in [&public_directory].iter() {
        fs::create_dir(&directory)
            .context(format_err!("could not create directory {}", directory))?;
    }

    // create config.toml
    {
        let mut f = File::create(&toml_config_path)
            .context(format_err!("could not create {}", &toml_config_path))?;

        f.write_all(b"subscriptions = []")
            .context(format_err!("could not write to {}", &toml_config_path))?;
    }

    let key = Rsa::generate(8096).context(format_err!("could not generate rsa code"))?;

    {
        let k0pkey = key
            .public_key_to_pem()
            .context(format_err!("could not run public_key_to_pem {}", username))?;

        let public_key = ::openssl::rsa::Rsa::public_key_from_pem(&k0pkey).unwrap();

        let mut f = File::create(&public_key_path).context(format_err!(
            "could not create .pem.pub, {}",
            &public_key_path
        ))?;
        f.write_all(&public_key.public_key_to_pem().unwrap())
            .context(format_err!("could not write to {}", &public_key_path))?;

        let mut f = File::create(&private_key_public_path).context(format!(
            "could not create .pem.pub, {}",
            &private_key_public_path
        ))?;
        f.write_all(&public_key.public_key_to_pem().unwrap())
            .context(format_err!(
                "could not write to {}",
                &private_key_public_path
            ))?;
    }

    {
        let privkey_pem = key.private_key_to_pem().context(format_err!(
            "could not translate private key to pem {}",
            &private_key_path
        ))?;

        let mut f = File::create(&private_key_path)
            .context(format_err!("could not create {}", &private_key_path))?;

        f.write_all(&privkey_pem)
            .context(format_err!("could not write to {}", &private_key_path))?
    }

    Ok(Pem::new(
        PrivateKey::load_from_file(&private_key_path).context(anyhow!(
                "failed, to add key, private key: {}",
                &private_key_path
            ))?,
        PublicKey::load_from_file(&public_key_path).context(anyhow!(
            "failed, to add key, public key: {}",
            &public_key_path
        ))?,
    ))
}
