//! Ed25519 keypair generator for evidence signing.
//!
//! Generates a new keypair, writes the private key to a file with mode 0600,
//! and prints the public key to stdout for trust bootstrapping.

use mecmcp_audit::signing::{encode_signing_key, encode_verifying_key, generate_keypair};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <private-key-path>", args[0]);
        eprintln!();
        eprintln!("Generates a new Ed25519 keypair for evidence signing.");
        eprintln!("The private key is written to <private-key-path> with mode 0600.");
        eprintln!("The public key is printed to stdout for distribution.");
        std::process::exit(1);
    }

    // Handle help flags
    if args[1] == "-h" || args[1] == "--help" {
        println!("Usage: {} <private-key-path>", args[0]);
        println!();
        println!("Generates a new Ed25519 keypair for evidence signing.");
        println!("The private key is written to <private-key-path> with mode 0600.");
        println!("The public key is printed to stdout for distribution.");
        std::process::exit(0);
    }

    let private_key_path = PathBuf::from(&args[1]);

    // Generate keypair
    let (signing_key, verifying_key) = generate_keypair();

    // Encode keys
    let private_encoded = encode_signing_key(&signing_key);
    let public_encoded = encode_verifying_key(&verifying_key);

    // Write private key with mode 0600
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&private_key_path)
            .unwrap_or_else(|e| {
                eprintln!("Failed to create private key file: {}", e);
                std::process::exit(1);
            });

        file.write_all(private_encoded.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .unwrap_or_else(|e| {
                eprintln!("Failed to write private key: {}", e);
                std::process::exit(1);
            });
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(&private_key_path).unwrap_or_else(|e| {
            eprintln!("Failed to create private key file: {}", e);
            std::process::exit(1);
        });

        file.write_all(private_encoded.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .unwrap_or_else(|e| {
                eprintln!("Failed to write private key: {}", e);
                std::process::exit(1);
            });

        eprintln!("WARNING: File permissions not enforced on non-Unix platform.");
        eprintln!("Ensure the private key file is manually protected.");
    }

    // Print public key to stdout
    println!("{}", public_encoded);

    // Print summary to stderr
    eprintln!();
    eprintln!("Ed25519 keypair generated successfully.");
    eprintln!("Private key: {}", private_key_path.display());
    eprintln!("Public key (printed above): distribute for verification");
}
