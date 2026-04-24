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

fn derive_child(parent: &ExtendedPrivKey, index: u32) -> ExtendedPrivKey {
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
