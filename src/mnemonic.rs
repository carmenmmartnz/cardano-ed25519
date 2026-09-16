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
    kl[0] &= 0b1111_1000; // clear bits 0-2   (cofactor-8 safety)
    kl[31] &= 0b0001_1111; // clear bits 5-7   (see below)
    kl[31] |= 0b0100_0000; // set   bit 6      (constant-time scalar mult)

    // On the 0b0001_1111 mask: standard Ed25519 clamps with 0b0111_1111,
    // which only clears bit 255. Icarus clears bit 253 as well.
    //
    // Child derivation computes kL' = 8*ZL + kL. With ZL truncated to 28
    // bytes, 8*ZL < 2^227, so the sum can only disturb bits above 227 by
    // carry. Forcing bit 253 to 0 at the root leaves enough headroom that
    // bit 254 stays set and bit 255 stays clear at every level of the tree
    // — the clamping invariant survives derivation instead of breaking at
    // the first child.
    //
    // The Khovratovich-Law paper rejects a master secret whose bit 253 is
    // set and retries; Icarus just clears it, which is deterministic and
    // gives the same guarantee. See documentation/BIP32-Ed25519.md §3.1.1.

    Ok(ExtendedPrivKey { kl, kr, chain_code })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn the_root_key_is_clamped_the_icarus_way() {
        let key = root_key_from_mnemonic(PHRASE, "").unwrap();
        assert_eq!(key.kl[0] & 0b0000_0111, 0);
        // Icarus clears bit 253 as well as bit 255, so the top three bits
        // of the last byte are 0b010.
        assert_eq!(key.kl[31] & 0b1110_0000, 0b0100_0000);
    }

    #[test]
    fn a_passphrase_changes_the_root_key() {
        let plain = root_key_from_mnemonic(PHRASE, "").unwrap();
        let with_passphrase = root_key_from_mnemonic(PHRASE, "hunter2").unwrap();
        assert_ne!(plain.kl, with_passphrase.kl);
        assert_ne!(plain.chain_code, with_passphrase.chain_code);
    }

    #[test]
    fn rejects_a_phrase_with_a_broken_checksum() {
        let bad = PHRASE.replace("about", "abandon");
        assert!(root_key_from_mnemonic(&bad, "").is_err());
    }
}
