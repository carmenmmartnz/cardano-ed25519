//! WebAssembly bindings for the browser explorer in `web/`.
//!
//! This module holds no cryptography of its own. It walks a derivation path
//! with the same `mnemonic`/`derivation`/`signature` code the native binary
//! uses and serialises the result as JSON, so the explorer and `cargo run`
//! cannot drift apart.

use crate::derivation::{derive_child, public_key_from_private};
use crate::keys::ExtendedPrivKey;
use crate::mnemonic::root_key_from_mnemonic;
use crate::path::{DerivationPath, HARDENED_OFFSET};
use crate::signature::{sign, verify};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// One level of the derivation tree, with its keys already hex-encoded.
#[derive(Serialize)]
struct Node {
    label: String,
    hardened: bool,
    kl: String,
    kr: String,
    chain_code: String,
    public_key: String,
}

impl Node {
    fn new(label: String, hardened: bool, key: &ExtendedPrivKey) -> Self {
        Self {
            label,
            hardened,
            kl: hex::encode(key.kl),
            kr: hex::encode(key.kr),
            chain_code: hex::encode(key.chain_code),
            public_key: hex::encode(public_key_from_private(key).key),
        }
    }
}

#[derive(Serialize)]
struct SignatureReport {
    message: String,
    signature: String,
    public_key: String,
    valid: bool,
    /// The message the signature is checked against, which the caller may
    /// alter to watch verification fail.
    verify_message: String,
    /// Whether the signature verifies against `verify_message`. It holds only
    /// while the two messages are byte-for-byte equal.
    verify_valid: bool,
}

#[derive(Serialize)]
struct DeriveReport {
    nodes: Vec<Node>,
    signature: SignatureReport,
}

/// Label a segment the way it is written in a path, e.g. `1852'` or `0`.
fn segment_label(index: u32) -> String {
    if DerivationPath::is_hardened(index) {
        format!("{}'", index - HARDENED_OFFSET)
    } else {
        index.to_string()
    }
}

/// Derive every node along `path`, sign `message` with the leaf key and check
/// the signature against `verify_message`.
///
/// Returns a JSON string; the caller is expected to `JSON.parse` it. Errors
/// (a bad mnemonic, an unparseable path) surface as a rejected promise.
#[wasm_bindgen]
pub fn derive_path(
    phrase: &str,
    passphrase: &str,
    path: &str,
    message: &str,
    verify_message: &str,
) -> Result<String, JsError> {
    let root = root_key_from_mnemonic(phrase, passphrase).map_err(|e| JsError::new(&e))?;
    let parsed = DerivationPath::parse(path).map_err(|e| JsError::new(&e))?;

    let mut nodes = vec![Node::new("m".to_string(), false, &root)];
    let mut current = root;
    for &index in &parsed.indices {
        current = derive_child(&current, index);
        nodes.push(Node::new(
            segment_label(index),
            DerivationPath::is_hardened(index),
            &current,
        ));
    }

    let leaf_pub = public_key_from_private(&current);
    let sig = sign(&current, message.as_bytes());

    let report = DeriveReport {
        signature: SignatureReport {
            message: message.to_string(),
            signature: sig.to_string(),
            public_key: hex::encode(leaf_pub.key),
            valid: verify(&sig, message.as_bytes(), &leaf_pub),
            verify_message: verify_message.to_string(),
            verify_valid: verify(&sig, verify_message.as_bytes(), &leaf_pub),
        },
        nodes,
    };

    serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))
}
