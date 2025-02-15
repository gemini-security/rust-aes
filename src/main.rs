// Gemini Cyber Security + ChatGPT 
extern crate aes;
extern crate block_modes;
extern crate pbkdf2;
extern crate sha2;
extern crate hex;
extern crate hmac;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use pbkdf2::{pbkdf2};
use sha2::Sha256;
use hmac::Hmac;
use std::fs::File;
use std::io::{Read, Write};
use std::env;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const KEY_SIZE: usize = 32; // AES-256
const IV_SIZE: usize = 16;  // AES block size
const SALT: &[u8] = &[];

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: ./rust -encrypt <input_filename>  ");
        eprintln!("Usage: ./rust -decrypt <input_filename> <key_filename> ");

        std::process::exit(1);
    }

    match args[1].as_str() {
        "-encrypt" => encrypt(&args[2]),
        "-decrypt" => {
            if args.len() != 4 {
                eprintln!("For decryption, provide the key.txt file.");
                std::process::exit(1);
            }
            decrypt(&args[2], &args[3])
        },
        _ => {
           eprintln!("Invalid option. Use -encrypt or -decrypt or -exec.");
           std::process::exit(1);
        }
    }
}

fn encrypt(input_filename: &str) -> std::io::Result<()> {
    let passphrase = "your_secure_passphrase";  // Replace with your passphrase

    // Derive the key from the passphrase
    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), SALT, 100_000, &mut key);

    // Read the file to be encrypted
    let mut file = File::open(input_filename)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Initialize the IV to zero
    let iv = vec![0u8; IV_SIZE];

    // Encrypt the data using AES-256-CBC
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let encrypted_data = cipher.encrypt_vec(&data);

    // Write the encrypted data to a new file
    let encrypted_filename = format!("{}_encrypted", input_filename);
    let mut encrypted_file = File::create(&encrypted_filename)?;
    encrypted_file.write_all(&encrypted_data)?;

    // Write the AES key to a file
    let mut key_file = File::create("key.txt")?;
    key_file.write_all(&key)?;

    println!("Encryption complete. Encrypted file: {}, key written to key.txt", encrypted_filename);
    Ok(())
}

fn decrypt(input_filename: &str, key_filename: &str) -> std::io::Result<()> {
    // Read the AES key from key.txt
    let mut key_file = File::open(key_filename)?;
    let mut key = Vec::new();
    key_file.read_to_end(&mut key)?;

    // Initialize the IV to zero (since you specified it)
    let iv = vec![0u8; IV_SIZE];

    let mut encrypted_file = File::open(input_filename)?;
    let mut encrypted_data = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_data)?;

    // Decrypt the data using AES-256-CBC
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).unwrap();

    // Write the decrypted data to a new file
    let decrypted_filename = "decrypted.bin".to_string();
    let mut decrypted_file = File::create(&decrypted_filename)?;
    decrypted_file.write_all(&decrypted_data)?;

    println!("Decryption complete. Decrypted file: {}", decrypted_filename);

    Ok(())
}
