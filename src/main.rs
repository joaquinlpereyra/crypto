extern crate crypto;

use crypto::bytes;
use crypto::hex;
use crypto::text;

fn main() {
    xor_cypher()
}

fn xor_cypher() {
    // You have access to an encrypted message.
    // You know it has been xored against a single character
    // Find it.

    let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let encrypted_as_hex = hex::from_string(&encrypted).unwrap();
    let encrypted_bytes = hex::to_bytes(&encrypted_as_hex);

    for i in 0..127 {
        let xored = bytes::repeating_xor(&encrypted_bytes, i as u8);
        let text = bytes::to_string(&xored);
        let score = text::frequency_analysis(&text);
        if text == "Cooking MC's like a pound of bacon" {
            println!("score: {}, text: {}", score, text);
        }
    }
}
