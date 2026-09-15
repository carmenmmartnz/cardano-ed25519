//! Cardano's extended Ed25519 key scheme (BIP32-Ed25519 / Icarus), from
//! mnemonic to signature.
//!
//! The same modules back both the `cardano-ed25519` binary and the
//! WebAssembly build used by the browser explorer in `web/`, so the demo
//! and `cargo run` can never disagree about a key.

pub mod derivation;
pub mod keys;
pub mod mnemonic;
pub mod path;
pub mod signature;

#[cfg(target_arch = "wasm32")]
mod wasm;
