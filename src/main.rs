extern crate crypto;

use crypto::bytes;
use crypto::hex;
use crypto::text;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

fn main() {
    // xor_cypher();
    // xor_file();
    xor_encrypt();
}

#[allow(dead_code)]
fn xor_cypher() {
    // You have access to an encrypted message.
    // You know it has been xored against a single character
    // Find it.
    let cypher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let encrypted_as_hex = hex::from_string(&cypher_text).unwrap();
    let encrypted_bytes = hex::to_bytes(&encrypted_as_hex);

    // All ASCII characters can fill 7 bits: from zero to 127.
    for i in 0..127 {
        let xored = bytes::repeating_xor(&encrypted_bytes, &[i as u8]);
        let text = match bytes::to_string(&xored) {
            Some(text) => text,
            None => continue,
        };
        let score = text::frequency_analysis(&text);
        if score > 0.6 {
            println!("{}", text);
        }
    }
}

#[allow(dead_code)]
fn xor_file() {
    // There's one line in the file which has been encrypted against a single character.
    // Find the line and the character.

    let file = match File::open("./single-xor.txt") {
        Ok(file) => file,
        Err(_) => panic!("file not found!"),
    };
    let buffer = BufReader::new(file);
    // a lesson here:
    // at first, I spawned a thread every line.
    // target/release/crypto  0,24s user 0,02s system 385% cpu 0,066 total
    // then, i removed the threads...
    // target/release/crypto  0,03s user 0,00s system 99% cpu 0,032 total
    // remember kids. threads are not free!
    for encrypted_line in buffer.lines().map(|l| l.unwrap()) {
        let encrypted_as_hex = hex::from_string(&encrypted_line).unwrap();
        let encrypted_bytes = hex::to_bytes(&encrypted_as_hex);
        for i in 0..127 {
            let xored = bytes::repeating_xor(&encrypted_bytes, &[i as u8]);
            let text = match bytes::to_string(&xored) {
                Some(text) => text,
                None => continue, // most probably our secret is utf8, at least?
            };
            let score = text::frequency_analysis(&text);
            if score > 0.7 {
                println!("score: {}, text: {}, key: {}", score, text, i);
            }
        }
    }
}

fn xor_encrypt() {
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
