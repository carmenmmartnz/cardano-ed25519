use crate::keys::ExtendedPrivKey;
use bip39::Mnemonic;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

/// Derive the Cardano Icarus-style root extended private key from a BIP39 mnemonic.
///
/// Unlike standard BIP39 (which hashes the mnemonic sentence with PBKDF2),
/// Cardano uses the raw entropy bytes as the PBKDF2 salt:
///
///   PBKDF2-HMAC-SHA512(password = passphrase, salt = entropy, c = 4096, dkLen = 96)
///
/// Output layout:
///   bytes  0–31 → kL  (clamped to a valid Ed25519 scalar)
///   bytes 32–63 → kR  (nonce material for signing)
///   bytes 64–95 → chain_code
pub fn root_key_from_mnemonic(phrase: &str, passphrase: &str) -> Result<ExtendedPrivKey, String> {
    let mnemonic = Mnemonic::parse_normalized(phrase)
        .map_err(|e| format!("invalid mnemonic: {e}"))?;

    let entropy = mnemonic.to_entropy();

    let mut out = [0u8; 96];
    pbkdf2::<Hmac<Sha512>>(passphrase.as_bytes(), &entropy, 4096, &mut out)
        .map_err(|e| format!("PBKDF2 error: {e}"))?;

    let mut kl: [u8; 32] = out[0..32].try_into().unwrap();
    let kr: [u8; 32]      = out[32..64].try_into().unwrap();
    let chain_code: [u8; 32] = out[64..96].try_into().unwrap();

    // Clamp kL per Ed25519 / BIP32-Ed25519 §1.2 + §3.1
    kl[0]  &= 0b1111_1000; // clear bits 0-2  (cofactor-8 safety)
    kl[31] &= 0b0111_1111; // clear bit 7      (keep kL < 2^255)
    kl[31] |= 0b0100_0000; // set   bit 6      (constant-time scalar mult)

    Ok(ExtendedPrivKey { kl, kr, chain_code })
}
