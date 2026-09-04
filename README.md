# cardano-ed25519

A learning project that implements Cardano's extended Ed25519 key scheme
(BIP32-Ed25519) in Rust, from mnemonic to signature.

It covers:

- **Mnemonic to root key** — BIP-39 phrase + PBKDF2-HMAC-SHA512 to an
  extended private key (`src/mnemonic.rs`)
- **Child key derivation** — hardened and non-hardened derivation along a
  path such as `m/1852'/1815'/0'/0/0` (`src/derivation.rs`, `src/path.rs`)
- **Public key derivation** from an extended private key (`src/keys.rs`)
- **Signing and verification** with Ed25519 (`src/signature.rs`)

See [`documentation/BIP32-Ed25519.md`](documentation/BIP32-Ed25519.md) for
the underlying specification this implementation follows.

## Usage

```sh
cargo run
```

`src/main.rs` walks through the full flow: derive a root key from a test
mnemonic, derive a child key at Cardano's standard path, sign a message,
and verify the signature (including a check that a tampered message fails
verification).

The mnemonic used is BIP-39's standard all-zero-entropy test vector:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

## Status

This is a personal learning project, not audited and not intended for use
with real funds.
