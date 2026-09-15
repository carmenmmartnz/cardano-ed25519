/// A BIP44 derivation path, e.g. `m/1852'/1815'/0'/0/0`.
/// Hardened indices are stored with bit 31 set (i + 2^31).
pub struct DerivationPath {
    pub indices: Vec<u32>,
}

pub const HARDENED_OFFSET: u32 = 0x8000_0000;

impl DerivationPath {
    /// Parse `"m/1852'/1815'/0'/0/0"`.
    ///
    /// A hardened segment may be marked `'`, `H` or `h`. The bare root `"m"`
    /// parses to an empty path.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let s = match s.strip_prefix("m/") {
            Some(rest) => rest,
            // Accept the bare root, so the browser explorer can show `m`
            // on its own while the user is still typing a path.
            None if s == "m" || s.is_empty() => {
                return Ok(Self {
                    indices: Vec::new(),
                })
            }
            None => return Err("path must start with 'm/'".to_string()),
        };
        let mut indices = Vec::new();
        for part in s.split('/') {
            let (num_str, hardened) = match part.strip_suffix(['\'', 'H', 'h']) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_cardano_path() {
        let path = DerivationPath::parse("m/1852'/1815'/0'/0/0").unwrap();
        assert_eq!(
            path.indices,
            vec![
                1852 + HARDENED_OFFSET,
                1815 + HARDENED_OFFSET,
                HARDENED_OFFSET,
                0,
                0
            ]
        );
    }

    #[test]
    fn accepts_every_hardened_marker() {
        for marker in ["'", "H", "h"] {
            let path = DerivationPath::parse(&format!("m/44{marker}")).unwrap();
            assert_eq!(path.indices, vec![44 + HARDENED_OFFSET]);
        }
    }

    #[test]
    fn the_bare_root_is_an_empty_path() {
        assert!(DerivationPath::parse("m").unwrap().indices.is_empty());
        assert!(DerivationPath::parse("").unwrap().indices.is_empty());
    }

    #[test]
    fn display_round_trips() {
        let text = "m/1852'/1815'/0'/0/0";
        assert_eq!(DerivationPath::parse(text).unwrap().to_string(), text);
    }

    #[test]
    fn rejects_malformed_paths() {
        assert!(DerivationPath::parse("1852'/0").is_err());
        assert!(DerivationPath::parse("m/abc").is_err());
        assert!(DerivationPath::parse("m/4294967295'").is_err());
    }
}
