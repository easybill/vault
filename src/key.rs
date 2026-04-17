use zeroize::Zeroize;

pub mod key_map;

#[derive(Debug)]
pub struct PublicKey {
    pub(crate) data: Vec<u8>,
    pub(crate) name: String,
    pub(crate) is_v2: bool,
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

    pub fn is_v2(&self) -> bool {
        self.public_key.is_v2
    }
}

impl PublicKey {
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn is_v2(&self) -> bool {
        self.is_v2
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

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
