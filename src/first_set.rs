use crypto::encoding::{base64, hex};
use crypto::frequency;
use crypto::symm::padding::{self, Padding};
use crypto::symm::AESCiphertext;
use crypto::{bytes, symm};
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{BufRead, BufReader};
use std::str;

#[allow(dead_code)]
pub fn xor_cypher() {
    // You have access to an encrypted message.
    // You know it has been xored against a single character
    // Find it.
    let cypher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let encrypted_as_hex = hex::from_string(&cypher_text).unwrap();

    // All ASCII characters can fill 7 bits: from zero to 127.
    for i in 0..127 {
        let xored = bytes::repeating_xor(&encrypted_as_hex, &[i as u8]);
        let text = match bytes::to_string(&xored) {
            Some(text) => text,
            None => continue,
        };
        let score = frequency::analysis(&text);
        if score > 0.6 {
            println!("{}, key: {}", text, i);
        }
    }
}

#[allow(dead_code)]
pub fn xor_file() {
    // There's one line in the file which has been encrypted against a single character.
    // Find the line and the character.
    let file = match File::open("./6.txt") {
        Ok(file) => file,
        Err(_) => panic!("file not found!"),
    };
    let buffer = BufReader::new(file);
    for encrypted_line in buffer.lines().map(|l| l.unwrap()) {
        let encrypted_bytes = hex::from_string(&encrypted_line).unwrap();
        for i in 0..127 {
            let xored = bytes::repeating_xor(&encrypted_bytes, &[i as u8]);
            let text = match bytes::to_string(&xored) {
                Some(text) => text,
                None => continue, // most probably our secret is utf8, at least?
            };
            let score = frequency::analysis(&text);
            if score > 0.7 {
                println!("score: {}, text: {}, key: {}", score, text, i);
            }
        }
    }
}

#[allow(dead_code)]
pub fn xor_encrypt() {
    // Encrypt the plain text using repeating-key XOR
    // with the key 'ICE'
    let plain_text = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let cypher_text = hex::to_string(&bytes::repeating_xor(
        &plain_text.as_bytes(),
        &['I' as u8, 'C' as u8, 'E' as u8],
    ));
    println!("0x{}", cypher_text);
}

#[allow(dead_code)]
pub fn decrypt_yellow_submarine() {
    // https://cryptopals.com/sets/1/challenges/7

    let cipher_text = read_to_string("./7.txt").expect("could not read file");
    let cipher_text = cipher_text.replace('\n', "");
    let cipher_text = base64::decode(&cipher_text).unwrap();
    let cipher_key = "YELLOW SUBMARINE".as_bytes();

    let plain = AESCiphertext::from_existing(cipher_text, symm::Mode::ECB, Padding::None)
        .decrypt(&cipher_key);
    let plain_ascii = str::from_utf8(&plain).unwrap();
    print!("{}", plain_ascii);
}

#[allow(dead_code)]
pub fn find_ecb() {
    // https://cryptopals.com/sets/1/challenges/8
    // In this file are a bunch of hex-encoded ciphertexts.
    // One of them has been encrypted with ECB.
    // Detect it.
    let mut blocks: HashMap<String, usize> = HashMap::new();

    let cipher_texts = read_to_string("./8.txt").expect("could not read file");
    let cipher_texts = cipher_texts.replace('\n', "");

    let bytes = hex::from_string(&cipher_texts).unwrap();

    // aes encrypts 16 bytes per block
    for block in bytes.chunks(16) {
        let hex = hex::to_string(&block);
        let counter = blocks.entry(hex).or_insert(0);
        *counter += 1
    }
    blocks
        .iter()
        .filter(|&(_, v)| *v != 1)
        .map(|(k, v)| println!("{}: {}", k, v))
        .collect()
}

#[allow(dead_code)]
pub fn implement_pkcs7() {
    let input = "YELLOW SUBMARINE";
    let padded = match padding::get_pad(&padding::Padding::PKCS7, input.as_bytes(), 20) {
        Some(bytes) => bytes,
        None => panic!("could not pad? why?"),
    };
    println!("{:?}", str::from_utf8(&padded));
}

#[allow(dead_code)]
pub fn decrypt_with_cbc() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0; 16];
    let cipher_text = read_to_string("./10.txt").expect("could not read file");
    let cipher_text = cipher_text.replace("\n", "");
    let cipher_text = base64::decode(&cipher_text).unwrap();
    let cbc = symm::Mode::CBC { iv };
    let plain = symm::AESCiphertext::from_existing(cipher_text, cbc, Padding::None).decrypt(&key);
    let plain_str = str::from_utf8(&plain).unwrap();
    println!("{}", plain_str);
}
