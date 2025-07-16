use anyhow::{Context, Error, bail};
use std::fs::File;
use std::io::Read;
use std::process::Command;

pub mod key_map;

#[derive(Debug)]
pub struct PublicKey {
    pub(crate) data: Vec<u8>,
    pub(crate) name: String,
}

#[derive(Debug)]
pub struct PrivateKey {
    pub(crate) data: Vec<u8>,
    pub(crate) name: String,
}

#[derive(Debug)]
pub struct Pem {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl Pem {
    pub fn new(private_key: PrivateKey, public_key: PublicKey) -> Self {
        Pem {
            private_key,
            public_key,
        }
    }

    pub fn get_name(&self) -> &str {
        self.private_key.get_name()
    }

    pub fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

struct Key;

impl Key {
    pub fn load_from_file(path: &str) -> Result<Vec<u8>, Error> {
        if path.ends_with(".pgp") {
            return Self::load_from_file_pgp(path)
                .with_context(|| format!("could not decode key at {path}"));
        }

        let mut f = File::open(path).with_context(|| format!("could not open file at {path}"))?;
        let mut content: Vec<u8> = vec![];

        f.read_to_end(&mut content)
            .with_context(|| format!("could not read file at {path}"))?;

        Ok(content)
    }

    fn load_from_file_pgp(path: &str) -> Result<Vec<u8>, Error> {
        let mut child = Command::new("gpg")
            .arg("--decrypt")
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg(path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("could not call gpg")?;

        let mut output_stdout = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            stdout.read_to_string(&mut output_stdout)?;
        }
        let mut output_stderr = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            stderr.read_to_string(&mut output_stderr)?;
        }

        let status = child.wait()?;

        if !status.success() {
            bail!("could not run `gpg --decrypt {path}`, {output_stdout}, {output_stderr}");
        }

        Ok(output_stdout.into_bytes())
    }
}

impl PublicKey {
    pub fn load_from_file(path: &str) -> Result<Self, Error> {
        const FILE_EXTENSION: &str = ".pub.pem";

        Ok(PublicKey {
            data: Key::load_from_file(path)?,
            name: {
                let mut pieces = path.rsplit('/');
                let mut filename: String = match pieces.next() {
                    Some(p) => p.into(),
                    None => path.into(),
                };

                if !filename.ends_with(FILE_EXTENSION) {
                    bail!("public key '{path}' does not end with {FILE_EXTENSION}");
                }

                filename.truncate(filename.len() - FILE_EXTENSION.len());

                filename
            },
        })
    }

    pub fn get_data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }
}

impl PrivateKey {
    pub fn load_from_file(path: &str) -> Result<Self, Error> {
        Ok(PrivateKey {
            data: Key::load_from_file(path)?,
            name: {
                let mut pieces = path.rsplit('/');
                let filename: String = match pieces.next() {
                    Some(p) => p.into(),
                    None => path.into(),
                };

                if !filename.trim_end_matches(".pgp").ends_with(".pem") {
                    bail!("private key '{path}' does not end with .pem");
                }

                filename
                    .trim_end_matches(".pgp")
                    .trim_end_matches(".pem")
                    .to_string()
            },
        })
    }

    // is it 100% valid?
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            data: self.data.clone(),
            name: self.name.clone(),
        }
    }

    pub fn get_data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }
}
