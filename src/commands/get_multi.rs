use std::collections::HashMap;
use std::io::{Read, Write};
use anyhow::{Context, Error};
use serde_derive::{Deserialize, Serialize};
use crate::key::key_map::KeyMap;
use crate::template::Template;

#[derive(Deserialize, Serialize)]
struct InputJson {
    pub secrets: Option<Vec<InputJsonSecrets>>,
    pub templates: Option<Vec<InputJsonTemplates>>,
}

#[derive(Deserialize, Serialize)]
struct InputJsonSecrets {
    pub secret: String,
}

#[derive(Deserialize, Serialize)]
struct InputJsonTemplates {
    pub template: String,
}

#[derive(Deserialize, Serialize)]
struct OutputJson {
    pub secrets: HashMap<String, OutputJsonItem>,
    pub templates: HashMap<String, OutputJsonItemTemplate>,
}

#[derive(Deserialize, Serialize)]
struct OutputJsonItem {
    pub name: String,
    pub value: String,
}

#[derive(Deserialize, Serialize)]
struct OutputJsonItemTemplate {
    pub name: String,
    pub value: String,
}

pub fn get_multi(input: &str, keymap: &KeyMap) -> Result<(), Error> {

    let input: InputJson = serde_json::from_str(&input).expect("Fehler beim Deserialisieren");

    let mut secrets = HashMap::new();
    let mut errors = vec![];

    // keys
    for secret_key in input.secrets.unwrap_or(vec![]) {
        match keymap.decrypt(&secret_key.secret) {
            Ok(uncrypted_vault) => {
                match String::from_utf8(uncrypted_vault.get_content().clone()) {
                    Ok(uncrypted_vault_uft8) => {
                        secrets.insert(secret_key.secret.to_string(), OutputJsonItem {
                            name: secret_key.secret.to_string(),
                            value: uncrypted_vault_uft8
                        });
                    },
                    Err(e) => {
                        errors.push(format!("could decode key {}. may it's not valid utf8?, error: {}", &secret_key.secret, e));
                    }
                };
            }
            Err(e) => {
                errors.push(format!("could not decrypt key {}, error: {}", &secret_key.secret, e))
            }
        };
    }

    // templates
    let mut templates = HashMap::new();

    for template in input.templates.unwrap_or(vec![]) {
        match Template::new(&keymap).parse_from_str(&template.template) {
            Ok(parsed_template) => {
                templates.insert(template.template.to_string(), OutputJsonItemTemplate {
                    name: template.template.to_string(),
                    value: parsed_template
                });
            }
            Err(e) => {
                errors.push(format!("could decode template {}. error: {}", &template.template, e));
            }
        };
    }

    if errors.len() != 0 {
        eprintln!("could not decrypt some keys.");
        ::std::process::exit(1);
    }

    let output = OutputJson {
        secrets,
        templates
    };


    ::std::io::stdout().write_all(serde_json::to_string(&output).context("internal error, could not serialize output")?.as_bytes())?;

    Ok(())
}