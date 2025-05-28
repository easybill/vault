use crate::Result;
use crate::key::key_map::KeyMap;
use anyhow::Context;
use regex::Regex;
use std::fs::File;
use std::io::Read;

pub struct Template<'a> {
    keymap: &'a KeyMap,
}

impl<'a> Template<'a> {
    pub fn new(keymap: &'a KeyMap) -> Self {
        Template { keymap }
    }

    pub fn parse_from_file(&self, filename: &str) -> Result<String> {
        let file_content = {
            let mut f = File::open(filename)
                .with_context(|| format!("could not open template {filename}."))?;

            let mut buffer = String::new();

            f.read_to_string(&mut buffer)
                .with_context(|| format!("could not read content of template {filename}"))?;

            buffer
        };

        self.parse_from_str(&file_content)
    }

    pub fn parse_from_str(&self, template: &str) -> Result<String> {
        let mut file_content = template.to_string();

        {
            let regex = Regex::new(r#"\{vault\{(.+)}vault}"#).expect("failed to compile regex");

            let file_content_copy = file_content.clone();
            let captures = regex.captures_iter(&file_content_copy);

            for capture in captures {
                let from = capture
                    .get(0)
                    .context("could not extract capture")?
                    .as_str();

                let key = capture
                    .get(1)
                    .context("could not extract capture")?
                    .as_str()
                    .trim()
                    .to_string();

                let uncrypted_key = self.keymap.decrypt_to_string(&key).with_context(|| format!(
                    "template requires the key \"{key}\", but it's not possible to decrypt the key"
                ))?;

                file_content = file_content.replace(from, &uncrypted_key);
            }
        }

        Ok(file_content)
    }
}
