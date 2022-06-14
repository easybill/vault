use anyhow::{anyhow, Context, Error};
use std::fs::File;
use std::io::Read;

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
        let mut f = File::open(path).context(anyhow!("open file {}", path))?;
        let mut content: Vec<u8> = vec![];

        f.read_to_end(&mut content)
            .context(anyhow!("could not read file {}", path))?;

        Ok(content)
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

                if !filename.ends_with(".pem") {
                    return Err(anyhow!("private key '{}' does not end with .pem", path));
                }

                filename[..filename.len() - 4].to_string()
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
