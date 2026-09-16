use crate::keys::{ExtendedPrivKey, ExtendedPubKey};
use crate::path::DerivationPath;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac}; // Hash-based Message Authentication Code (HMAC)
use sha2::Sha512; // Hash function

/// Compute the compressed public key A = [kL]B.
///
/// kL may be larger than the group order n (≈2^252), so we reduce it mod n
/// before scalar multiplication. [kL]B = [kL mod n]B is mathematically identical.
pub fn public_key_from_private(priv_key: &ExtendedPrivKey) -> ExtendedPubKey {
    let scalar = Scalar::from_bytes_mod_order(priv_key.kl);
    let point = scalar * ED25519_BASEPOINT_POINT;
    ExtendedPubKey {
        key: point.compress().to_bytes(),
        chain_code: priv_key.chain_code,
    }
}

pub fn derive_child_from_path(root: &ExtendedPrivKey, path: &DerivationPath) -> ExtendedPrivKey {
    let mut current = root.clone();
    for &index in &path.indices {
        current = derive_child(&current, index);
    }
    current
}

/// Derive a single child. Public so callers can walk a path one level at a
/// time and inspect every intermediate node (the browser explorer does this
/// to render the derivation tree).
pub fn derive_child(parent: &ExtendedPrivKey, index: u32) -> ExtendedPrivKey {
    let i_le = index.to_le_bytes();

    let (z_input, c_input) = if DerivationPath::is_hardened(index) {
        let mut z = vec![0x00u8];
        z.extend_from_slice(&parent.kl);
        z.extend_from_slice(&parent.kr);
        z.extend_from_slice(&i_le);

        let mut c = vec![0x01u8];
        c.extend_from_slice(&parent.kl);
        c.extend_from_slice(&parent.kr);
        c.extend_from_slice(&i_le);

        (z, c)
    } else {
        let pub_key = public_key_from_private(parent).key;
        let mut z = vec![0x02u8];
        z.extend_from_slice(&pub_key);
        z.extend_from_slice(&i_le);

        let mut c = vec![0x03u8];
        c.extend_from_slice(&pub_key);
        c.extend_from_slice(&i_le);

        (z, c)
    };

    let z_full: [u8; 64] = hmac_sha512(&parent.chain_code, &z_input);
    let zl: [u8; 28] = z_full[0..28].try_into().unwrap();
    let zr: [u8; 32] = z_full[32..64].try_into().unwrap();

    let kl = mul8_add(&zl, &parent.kl);
    let kr = add_le_mod256(&zr, &parent.kr);

    let c_full = hmac_sha512(&parent.chain_code, &c_input);
    let chain_code: [u8; 32] = c_full[32..64].try_into().unwrap();

    ExtendedPrivKey { kl, kr, chain_code }
}

/*

    Hash-based Message Authentication Code.
    It's a way to produce a fixed-size output from some input,
    using a secret key, built on top of a hash function (like
    SHA-512).

    The formula:
    HMAC(key, message) = H((key ⊕ opad) || H((key ⊕ ipad) ||
    message))
    Two nested hash calls, each using the key XORed with a
    different padding constant (ipad, opad).

    In plain terms:
    - Takes a key and a message
    - Produces a fixed-size output (64 bytes for SHA-512)
    - The same inputs always produce the same output
    (deterministic)
    - Without the key, you cannot reproduce or predict the
    output

    Why HMAC and not just a hash?

    A plain hash like SHA512(key || message) is vulnerable to
    length-extension attacks.
*/
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// Compute 8*ZL + kL in little-endian 256-bit arithmetic.
// ZL is 28 bytes (224-bit), so 8*ZL fits in 227 bits — no overflow past 256 bits.
fn mul8_add(zl: &[u8; 28], kl: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u32;
    for i in 0..32 {
        let zl_val = if i < 28 { zl[i] as u32 } else { 0u32 };
        let val = zl_val * 8 + kl[i] as u32 + carry;
        result[i] = val as u8;
        carry = val >> 8;
    }
    result
}

// Add two 32-byte little-endian integers mod 2^256.
fn add_le_mod256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u32;
    for i in 0..32 {
        let val = a[i] as u32 + b[i] as u32 + carry;
        result[i] = val as u8;
        carry = val >> 8;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::root_key_from_mnemonic;
    use crate::path::HARDENED_OFFSET;
    use curve25519_dalek::edwards::CompressedEdwardsY;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn root() -> ExtendedPrivKey {
        root_key_from_mnemonic(PHRASE, "").unwrap()
    }

    /// kL has to stay a clamped scalar at every level, which is the whole
    /// reason Icarus masks one bit more than plain Ed25519 does.
    fn assert_clamped(kl: &[u8; 32]) {
        assert_eq!(kl[0] & 0b0000_0111, 0, "low three bits must be clear");
        assert_eq!(kl[31] & 0b1000_0000, 0, "bit 255 must be clear");
        assert_eq!(kl[31] & 0b0100_0000, 0b0100_0000, "bit 254 must be set");
    }

    #[test]
    fn clamping_survives_the_whole_path() {
        let path = DerivationPath::parse("m/1852'/1815'/0'/0/0").unwrap();
        let mut current = root();
        assert_clamped(&current.kl);
        for &index in &path.indices {
            current = derive_child(&current, index);
            assert_clamped(&current.kl);
        }
    }

    /// The point of soft derivation: a child public key can be computed from
    /// the parent public key alone, as A' = A + [8·ZL]B. If this holds, the
    /// private derivation above agrees with public (watch-only) derivation.
    #[test]
    fn soft_derivation_matches_public_only_derivation() {
        let parent = root();
        let index = 0u32;
        let child = derive_child(&parent, index);

        let a_parent = public_key_from_private(&parent).key;
        let mut z_input = vec![0x02u8];
        z_input.extend_from_slice(&a_parent);
        z_input.extend_from_slice(&index.to_le_bytes());
        let z = hmac_sha512(&parent.chain_code, &z_input);

        let mut zl = [0u8; 32];
        zl[..28].copy_from_slice(&z[0..28]);
        let eight_zl = Scalar::from(8u8) * Scalar::from_bytes_mod_order(zl);

        let a_child =
            CompressedEdwardsY(a_parent).decompress().unwrap() + eight_zl * ED25519_BASEPOINT_POINT;

        assert_eq!(
            a_child.compress().to_bytes(),
            public_key_from_private(&child).key
        );
    }

    /// Hardened derivation feeds the private key into the HMAC, soft
    /// derivation feeds the public key, so index 0 and 0' must diverge.
    #[test]
    fn hardened_and_soft_children_differ() {
        let parent = root();
        let soft = derive_child(&parent, 0);
        let hardened = derive_child(&parent, HARDENED_OFFSET);
        assert_ne!(soft.kl, hardened.kl);
        assert_ne!(soft.chain_code, hardened.chain_code);
    }

    #[test]
    fn derivation_is_deterministic() {
        let path = DerivationPath::parse("m/1852'/1815'/0'/0/0").unwrap();
        let first = derive_child_from_path(&root(), &path);
        let second = derive_child_from_path(&root(), &path);
        assert_eq!(first.kl, second.kl);
        assert_eq!(first.chain_code, second.chain_code);
    }

    #[test]
    fn each_level_of_the_path_gives_a_different_key() {
        let path = DerivationPath::parse("m/1852'/1815'/0'/0/0").unwrap();
        let mut seen = vec![root().kl];
        let mut current = root();
        for &index in &path.indices {
            current = derive_child(&current, index);
            assert!(!seen.contains(&current.kl));
            seen.push(current.kl);
        }
    }
}
