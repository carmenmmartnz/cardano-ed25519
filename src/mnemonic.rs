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
    // 1. Parse the mnemonic → entropy (128-bit entropy)
    // words with 11-bit indices, 12 x 11 = 132 bits,
    // first 128 bits are entropy and last 4 are checksum: SHA256(entropy)
    let mnemonic =
        Mnemonic::parse_normalized(phrase).map_err(|e| format!("invalid mnemonic: {e}"))?;

    let entropy = mnemonic.to_entropy();

    // 2. PBKDF2 to stretch entropy → 96 bytes
    /*
        The algorithm hashes a seed $\tilde{k}$ once with SHA-512
        to get 64 bytes ($k_L | k_R$). The code uses
        PBKDF2-HMAC-SHA512 with 4096 iterations and outputs 96
        bytes directly — that's Cardano's Icarus deviation, which
        bakes the chain code into the same stretching operation
        instead of deriving it separately.

    */
    let mut out = [0u8; 96];
    pbkdf2::<Hmac<Sha512>>(passphrase.as_bytes(), &entropy, 4096, &mut out)
        .map_err(|e| format!("PBKDF2 error: {e}"))?;

    let mut kl: [u8; 32] = out[0..32].try_into().unwrap();
    let kr: [u8; 32] = out[32..64].try_into().unwrap();
    let chain_code: [u8; 32] = out[64..96].try_into().unwrap();

    // 3. Clamp kL per Ed25519
    kl[0] &= 0b1111_1000; // clear bits 0-2  (cofactor-8 safety)
    kl[31] &= 0b0111_1111; // clear bit 7      (keep kL < 2^255)
    kl[31] |= 0b0100_0000; // set   bit 6      (constant-time scalar mult)

    Ok(ExtendedPrivKey { kl, kr, chain_code })
}
