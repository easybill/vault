use anyhow::{anyhow, Context, Error};
use std::fs::File;
use std::io::Read;
use std::process::Command;

pub mod key_map;

#[derive(Debug)]
pub struct PublicKey {
    path: String,
    data: Vec<u8>,
    name: String,
}

#[derive(Debug)]
pub struct PrivateKey {
    path: String,
    data: Vec<u8>,
    name: String,
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
            return Self::load_from_file_pgp(path).context(format!("try to decode key {}", path));
        }

        let mut f = File::open(path).context(format!("open file {}", path))?;
        let mut content: Vec<u8> = vec![];

        f.read_to_end(&mut content)
            .context(format!("could not read file {}", path))?;

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
            .spawn().context("could not call gpg")?;

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
            return Err(anyhow!("could not run gpg --decrypt {}, {}, {}", path, output_stdout, output_stderr));
        }

        Ok(output_stdout.into_bytes())
    }
}

impl PublicKey {
    pub fn load_from_file(path: &str) -> Result<Self, Error> {
        Ok(PublicKey {
            path: path.to_string(),
            data: Key::load_from_file(path)?,
            name: {
                let mut pieces = path.rsplit('/');
                let filename: String = match pieces.next() {
                    Some(p) => p.into(),
                    None => path.into(),
                };

                if !filename.ends_with(".pub.pem") {
                    return Err(anyhow!("public key '{}' does not end with .pub.pem", path));
                }

                filename[..filename.len() - 8].to_string()
            },
        })
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}

impl PrivateKey {
    pub fn load_from_file(path: &str) -> Result<Self, Error> {
        Ok(PrivateKey {
            path: path.to_string(),
            data: Key::load_from_file(path)?,
            name: {
                let mut pieces = path.rsplit('/');
                let filename: String = match pieces.next() {
                    Some(p) => p.into(),
                    None => path.into(),
                };

                if !filename.trim_end_matches(".pgp").ends_with(".pem") {
                    return Err(anyhow!("private key '{}' does not end with .pem", path));
                }

                filename.trim_end_matches(".pgp").trim_end_matches(".pem").to_string()
            },
        })
    }

    // is it 100% valid?
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            path: self.path.clone(),
            data: self.data.clone(),
            name: self.name.clone(),
        }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}
