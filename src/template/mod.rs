use anyhow::{anyhow, Context, Error};
use crate::key::key_map::KeyMap;
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

    pub fn parse_from_file(&self, filename: &str) -> Result<String, Error> {
        let mut file_content = {
            let mut f =
                File::open(filename).context(anyhow!("could not open tempalte {}.", &filename))?;

            let mut buffer = String::new();

            f.read_to_string(&mut buffer)
                .context(anyhow!("could not read content of template {}", &filename))?;

            buffer
        };

        {
            let regex = Regex::new(r#"\{vault\{(.+)\}vault\}"#).expect("failed to compile regex");

            let file_content_copy = file_content.clone();
            let captures = regex.captures_iter(&file_content_copy);

            for capture in captures {
                let from = capture
                    .get(0)
                    .ok_or_else(|| anyhow!("could not extract capture"))?
                    .as_str();

                let key = capture
                    .get(1)
                    .ok_or_else(|| anyhow!("could not extract capture"))?
                    .as_str()
                    .trim()
                    .to_string();

                let uncrypted_key = self.keymap.decrypt_to_string(&key).context(anyhow!(
                    "template requires the key \"{}\", but it's not possible to decrypt the key",
                    key.clone()
                ))?;

                file_content = file_content.replace(from, &uncrypted_key);
            }
        }

        Ok(file_content)
    }
}
