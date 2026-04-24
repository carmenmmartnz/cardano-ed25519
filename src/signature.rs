use crate::derivation::public_key_from_private;
use crate::keys::{ExtendedPrivKey, ExtendedPubKey};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};

pub struct Signature(pub [u8; 64]);

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub fn sign(priv_key: &ExtendedPrivKey, message: &[u8]) -> Signature {
    let a_bytes = public_key_from_private(priv_key).key;

    // r = SHA-512(kR || message) mod n
    let r_hash: [u8; 64] = Sha512::new()
        .chain_update(&priv_key.kr)
        .chain_update(message)
        .finalize()
        .into();
    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    // R = [r]B, compressed to 32 bytes
    let R_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();

    // x = SHA-512(R || A || message) mod n
    let x_hash: [u8; 64] = Sha512::new()
        .chain_update(&R_bytes)
        .chain_update(&a_bytes)
        .chain_update(message)
        .finalize()
        .into();
    let x = Scalar::from_bytes_mod_order_wide(&x_hash);

    // S = r + x * kL
    let kl = Scalar::from_bytes_mod_order(priv_key.kl);
    let s = r + x * kl;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&R_bytes);
    sig[32..].copy_from_slice(s.as_bytes());
    Signature(sig)
}

pub fn verify(signature: &Signature, message: &[u8], pub_key: &ExtendedPubKey) -> bool {
    let r_bytes: [u8; 32] = signature.0[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = signature.0[32..].try_into().unwrap();

    let s = Scalar::from_bytes_mod_order(s_bytes);

    let x_hash : [u8; 64] = Sha512::new()
    .chain_update(&r_bytes)
    .chain_update(&pub_key.key)
    .chain_update(message)
    .finalize()
    .into();

    let x = Scalar::from_bytes_mod_order_wide(&x_hash);

    let r_point = CompressedEdwardsY(r_bytes).decompress();                                               
    let a_point = CompressedEdwardsY(pub_key.key).decompress(); 

    match (r_point, a_point) {
        (Some(r), Some(a)) => {
            let left = s * ED25519_BASEPOINT_POINT;
            let right = r + x * a;
            left == right
        }
        _ => false,   
    }   
}
