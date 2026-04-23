#[derive(Clone)]
pub struct ExtendedPrivKey {
    pub kl: [u8; 32],         // signing scalar (clamped)
    pub kr: [u8; 32],         // nonce material for signing
    pub chain_code: [u8; 32],
}

#[derive(Clone)]
pub struct ExtendedPubKey {
    pub key: [u8; 32],        // compressed Edwards point
    pub chain_code: [u8; 32],
}

impl std::fmt::Display for ExtendedPrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kL:         {}\nkR:         {}\nchain_code: {}",
            hex::encode(self.kl),
            hex::encode(self.kr),
            hex::encode(self.chain_code),
        )
    }
}

impl std::fmt::Display for ExtendedPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pub_key:    {}\nchain_code: {}",
            hex::encode(self.key),
            hex::encode(self.chain_code),
        )
    }
}
