# cardano-ed25519

A learning project that implements Cardano's extended Ed25519 key scheme
(BIP32-Ed25519 / Icarus) in Rust, from mnemonic to signature — with a browser
explorer driven by the same Rust code compiled to WebAssembly.

It covers:

- **Mnemonic to root key** — BIP-39 phrase + PBKDF2-HMAC-SHA512 to an
  extended private key (`src/mnemonic.rs`)
- **Child key derivation** — hardened and soft derivation along a path
  such as `m/1852'/1815'/0'/0/0` (`src/derivation.rs`, `src/path.rs`)
- **Public key derivation** — `A = [kL]B` from an extended private key
  (`src/derivation.rs`; the key types live in `src/keys.rs`)
- **Signing and verification** with Ed25519 (`src/signature.rs`)
- **Browser explorer** — the crate compiled to WebAssembly (`src/wasm.rs`,
  `web/`)

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

## Tests

```sh
cargo test
```

The suite checks the properties that matter rather than fixed hex strings:
clamping holds at every level of a path, soft derivation agrees with
public-only derivation (`A' = A + [8·ZL]B`), hardened and soft children
diverge, and a signature verifies while a changed message, a changed key or
a flipped bit does not. One test hands a signature to `ed25519-dalek`, an
independent implementation, so a matching mistake in `sign` and `verify`
cannot hide.

## Key derivation explorer

`web/` is a small React page that shows every level of the derivation tree,
with the keys at each level and a signature produced by the leaf key. Edit
the mnemonic, passphrase, path or message and the tree re-derives. A
second message box says what the signature is checked against, so changing
one byte there shows verification fail.

```sh
cd web
npm install
npm run dev
```

The page contains **no JavaScript cryptography**. `npm run dev` first runs
`wasm-pack` over this crate, and the UI calls `derive_path` from
`src/wasm.rs`, which walks the path with the same `mnemonic`, `derivation`
and `signature` modules the binary uses. The explorer and `cargo run`
therefore cannot disagree about a key — a second implementation in JS would
have been free to drift.

Requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) and the
`wasm32-unknown-unknown` target:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

`npm run build` produces a static bundle in `web/dist`.

## Layout

```
src/
  lib.rs          crate root, shared by the binary and the wasm build
  main.rs         CLI walkthrough
  mnemonic.rs     BIP-39 phrase -> root extended private key
  path.rs         derivation path parsing
  derivation.rs   hardened + soft child derivation, public keys
  signature.rs    Ed25519 sign / verify
  wasm.rs         wasm-bindgen layer for the explorer (no crypto of its own)
web/              React explorer (Vite)
documentation/    the BIP32-Ed25519 specification notes
```

## Note on clamping

Icarus clamps `kL` with `kL[31] &= 0x1F`, not the `0x7F` of plain Ed25519.
The extra masked bit is bit 253: child derivation computes
`kL' = 8·ZL + kL`, and forcing bit 253 to zero at the root leaves enough
headroom that bit 254 stays set and bit 255 stays clear at every level of
the tree. Plain Ed25519 clamping breaks that invariant on the first child
and produces keys other Cardano wallets will not agree with. See
`documentation/BIP32-Ed25519.md` §3.1.1.

## Status

This is a personal learning project, not audited and not intended for use
with real funds.
