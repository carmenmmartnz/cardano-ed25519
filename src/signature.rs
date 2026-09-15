//! Ed25519 signing and verification over the extended keys of
//! `derivation`.
//!
//! The scheme is the one from the BIP32-Ed25519 paper: `kR` is used directly
//! as the nonce seed, where plain Ed25519 would hash a 32-byte seed into
//! both the scalar and the nonce. Everything else — the challenge hash and
//! the verification equation — is standard Ed25519.

use crate::derivation::public_key_from_private;
use crate::keys::{ExtendedPrivKey, ExtendedPubKey};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// A 64-byte Ed25519 signature, laid out as `R || S`.
pub struct Signature(pub [u8; 64]);

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Sign `message` with the extended private key.
///
/// The nonce is deterministic: the same key and message always produce the
/// same signature, so there is no randomness to get wrong.
pub fn sign(priv_key: &ExtendedPrivKey, message: &[u8]) -> Signature {
    let a_bytes = public_key_from_private(priv_key).key;

    // r = SHA-512(kR || message) mod n
    let r_hash: [u8; 64] = Sha512::new()
        .chain_update(priv_key.kr)
        .chain_update(message)
        .finalize()
        .into();
    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    // R = [r]B, compressed to 32 bytes
    let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();

    // x = SHA-512(R || A || message) mod n
    let x_hash: [u8; 64] = Sha512::new()
        .chain_update(r_bytes)
        .chain_update(a_bytes)
        .chain_update(message)
        .finalize()
        .into();
    let x = Scalar::from_bytes_mod_order_wide(&x_hash);

    // S = r + x * kL
    let kl = Scalar::from_bytes_mod_order(priv_key.kl);
    let s = r + x * kl;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(s.as_bytes());
    Signature(sig)
}

/// Check `signature` over `message` against the public key.
///
/// Verification uses only public data, which is the whole point: `pub_key`
/// is enough, the private key never takes part.
///
/// This is the plain, non-cofactored equation `[S]B = R + [x]A`. A
/// production verifier would also reject a non-canonical `S` (one that is
/// larger than the group order) instead of reducing it, which this one does
/// not — signatures here stay malleable.
pub fn verify(signature: &Signature, message: &[u8], pub_key: &ExtendedPubKey) -> bool {
    let r_bytes: [u8; 32] = signature.0[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = signature.0[32..].try_into().unwrap();

    let s = Scalar::from_bytes_mod_order(s_bytes);

    // x = SHA-512(R || A || message) mod n, the same challenge the signer built
    let x_hash: [u8; 64] = Sha512::new()
        .chain_update(r_bytes)
        .chain_update(pub_key.key)
        .chain_update(message)
        .finalize()
        .into();
    let x = Scalar::from_bytes_mod_order_wide(&x_hash);

    // Both points have to decompress, or the signature is malformed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::derive_child_from_path;
    use crate::mnemonic::root_key_from_mnemonic;
    use crate::path::DerivationPath;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MESSAGE: &[u8] = b"Hello, Cardano!";

    fn leaf_key() -> ExtendedPrivKey {
        let root = root_key_from_mnemonic(PHRASE, "").unwrap();
        let path = DerivationPath::parse("m/1852'/1815'/0'/0/0").unwrap();
        derive_child_from_path(&root, &path)
    }

    #[test]
    fn a_signature_verifies_against_its_own_message() {
        let key = leaf_key();
        let sig = sign(&key, MESSAGE);
        assert!(verify(&sig, MESSAGE, &public_key_from_private(&key)));
    }

    #[test]
    fn a_changed_message_is_rejected() {
        let key = leaf_key();
        let sig = sign(&key, MESSAGE);
        assert!(!verify(
            &sig,
            b"Hello, Cardano?",
            &public_key_from_private(&key)
        ));
    }

    #[test]
    fn another_key_cannot_verify_the_signature() {
        let sig = sign(&leaf_key(), MESSAGE);
        let other = root_key_from_mnemonic(PHRASE, "different passphrase").unwrap();
        assert!(!verify(&sig, MESSAGE, &public_key_from_private(&other)));
    }

    #[test]
    fn a_corrupted_signature_is_rejected() {
        let key = leaf_key();
        let mut sig = sign(&key, MESSAGE);
        sig.0[0] ^= 0x01;
        assert!(!verify(&sig, MESSAGE, &public_key_from_private(&key)));
    }

    /// No randomness goes into signing, so the same key and message always
    /// produce the same 64 bytes.
    #[test]
    fn signing_is_deterministic() {
        let key = leaf_key();
        assert_eq!(sign(&key, MESSAGE).0, sign(&key, MESSAGE).0);
    }

    /// The signatures are ordinary Ed25519, so an independent implementation
    /// has to accept them. This is what keeps `verify` above honest: a shared
    /// mistake in sign/verify would pass every test but this one.
    #[test]
    fn an_independent_verifier_accepts_the_signature() {
        use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};

        let key = leaf_key();
        let sig = sign(&key, MESSAGE);
        let verifying_key = VerifyingKey::from_bytes(&public_key_from_private(&key).key).unwrap();

        assert!(verifying_key
            .verify(MESSAGE, &DalekSignature::from_bytes(&sig.0))
            .is_ok());
    }
}
