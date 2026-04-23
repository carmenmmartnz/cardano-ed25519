/// A BIP44 derivation path, e.g. `m/1852'/1815'/0'/0/0`.
/// Hardened indices are stored with bit 31 set (i + 2^31).
pub struct DerivationPath {
    pub indices: Vec<u32>,
}

pub const HARDENED_OFFSET: u32 = 0x8000_0000;

impl DerivationPath {
    /// Parse `"m/1852'/1815'/0'/0/0"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("m/").ok_or("path must start with 'm/'")?;
        let mut indices = Vec::new();
        for part in s.split('/') {
            let (num_str, hardened) = match part.strip_suffix('\'') {
                Some(n) => (n, true),
                None => (part, false),
            };
            let index: u32 = num_str
                .parse()
                .map_err(|_| format!("invalid index '{num_str}'"))?;
            let encoded = if hardened {
                index
                    .checked_add(HARDENED_OFFSET)
                    .ok_or(format!("index {index} overflows with hardened offset"))?
            } else {
                index
            };
            indices.push(encoded);
        }
        Ok(Self { indices })
    }

    pub fn is_hardened(index: u32) -> bool {
        index >= HARDENED_OFFSET
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m")?;
        for &i in &self.indices {
            if Self::is_hardened(i) {
                write!(f, "/{}'", i - HARDENED_OFFSET)?;
            } else {
                write!(f, "/{i}")?;
            }
        }
        Ok(())
    }
}
