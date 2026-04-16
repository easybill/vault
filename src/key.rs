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

    pub fn name(&self) -> &str {
        self.private_key.name()
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl PublicKey {
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl PrivateKey {
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}
