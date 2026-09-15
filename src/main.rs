use cardano_ed25519::derivation::{derive_child_from_path, public_key_from_private};
use cardano_ed25519::mnemonic::root_key_from_mnemonic;
use cardano_ed25519::path::DerivationPath;
use cardano_ed25519::signature::{sign, verify};

fn main() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";

    let priv_key = root_key_from_mnemonic(phrase, passphrase).unwrap();
    println!("Root private key:\n{priv_key}\n");

    let pub_key = public_key_from_private(&priv_key);
    println!("Root public key:\n{pub_key}\n");

    let path = DerivationPath::parse("m/1852'/1815'/0'/0/0").unwrap();
    println!("Path: {path}\n");

    let child_key = derive_child_from_path(&priv_key, &path);
    println!("Child private key at {path}:\n{child_key}\n");

    let child_pub_key = public_key_from_private(&child_key);
    println!("Child public key at {path}:\n{child_pub_key}\n");

    let message = b"Hello, Cardano!";
    let sig = sign(&child_key, message);
    println!("Signature:\n{sig}\n");

    let valid = verify(&sig, message, &child_pub_key);
    println!("Signature valid: {valid}\n");

    let tampered = verify(&sig, b"tampered message", &child_pub_key);
    println!("Tampered message valid: {tampered}");
}
