use crate::keys::{ExtendedPrivKey, ExtendedPubKey};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

/// Compute the compressed public key A = [kL]B.
///
/// kL may be larger than the group order n (≈2^252), so we reduce it mod n
/// before scalar multiplication. [kL]B = [kL mod n]B is mathematically identical.
pub fn public_key_from_private(priv_key: &ExtendedPrivKey) -> ExtendedPubKey {
    let scalar = Scalar::from_bytes_mod_order(priv_key.kl);
    let point  = scalar * ED25519_BASEPOINT_POINT;
    ExtendedPubKey {
        key:        point.compress().to_bytes(),
        chain_code: priv_key.chain_code,
    }
}
