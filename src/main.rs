use crypto::encoding::hex;
use crypto::symm::padding::{self, Padding};
use crypto::{bytes, random, symm, text};
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::str;

fn main() {
    // xor_cypher();
    // xor_file();
    // xor_encrypt();
    // decrypt_yellow_submarine();
    // find_ecb();
    // implement_pkcs7();
    // decrypt_with_cbc();
    cbc_ecb_oracle();
}

#[allow(dead_code)]
fn xor_cypher() {
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
        let score = text::frequency_analysis(&text);
        if score > 0.6 {
            println!("{}, key: {}", text, i);
        }
    }
}

#[allow(dead_code)]
fn xor_file() {
    // There's one line in the file which has been encrypted against a single character.
    // Find the line and the character.

    let file = match File::open("./6.txt") {
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
        let encrypted_bytes = hex::from_string(&encrypted_line).unwrap();
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn decrypt_yellow_submarine() {
    // https://cryptopals.com/sets/1/challenges/7

    let cipher_text = read_to_string("./7.txt").expect("could not read file");
    let cipher_text = cipher_text.replace('\n', "");
    let cipher_text = base64::decode(&cipher_text).unwrap();
    let cipher_key = "YELLOW SUBMARINE".as_bytes();

    let plain = symm::decrypt(&cipher_key, &cipher_text, symm::Mode::ECB, Padding::None);
    let plain_ascii = str::from_utf8(&plain).unwrap();
    print!("{}", plain_ascii);
}

#[allow(dead_code)]
fn find_ecb() {
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
fn implement_pkcs7() {
    let input = "YELLOW SUBMARINE";
    let padded = match padding::get_pad(padding::Padding::PKCS7, input.as_bytes(), 20) {
        Some(bytes) => bytes,
        None => panic!("could not pad? why?"),
    };
    println!("{:?}", str::from_utf8(&padded));
}

#[allow(dead_code)]
fn decrypt_with_cbc() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0; 16];
    let cipher_text = read_to_string("./10.txt").expect("could not read file");
    let cipher_text = cipher_text.replace("\n", "");
    let cipher_text = base64::decode(&cipher_text).unwrap();
    let cbc = symm::Mode::CBC { iv };
    let plain = symm::decrypt(&key, &cipher_text, cbc, Padding::None);
    let plain_str = str::from_utf8(&plain).unwrap();
    println!("{}", plain_str);
}

#[allow(dead_code)]
fn cbc_ecb_oracle() {
    /*
    This was one of the most interesting excercises so far and great example
    of a "chosen plain text attack".

    So let's recap what has been done. First, I must say that this is one
    of the most confusingly-worded challenges so far, and my search online
    confirmed that it was not only me.

    What the problem asks of you is to prepend and append a chosen plain text
    with random bytes from 5 to 10. Then you encrypt under an unknown key.
    The key part is that the input is DIFFERENT for each run, if not, the
    excercise becomes quite trivial and indeed IMPOSSIBLE if you happen
    to choose a small input.

    So the challenge is both in the coding and in figuring out an input
    which will leak information about the mode in which AES is operating in.

    The gist is that you have from five to ten bytes at the begginning, so
    you should write at least 11 "garbage" bytes at the begginning. Now you are
    at the second block, even if there were only five random bytes.

    Write 16 more of the SAME byte to fill a second block.

    So now we are either at the beginning of a third block (if there were
    only five bytes at the beginning) or somewhere in the middle of a third block.
    Make sure you fill this third block too! So 16 bytes more at least of the SAME byte.

    Now we are either at the beginning of the fourth or in the middle of the fourth
    AES block. Now we can just let go. We know we have one block with random data,
    two blocks with exclusively the same byte everywhere, and the fourth which will
    get the appendix and then padded.

    Now we have it easy: are the two blocks of the middle equal? Then, we are using ECB
    If not, we are using CBC.
     */

    fn encrypt_ecb_or_cbc(plain_text: &str) -> (Vec<u8>, String) {
        let random_key = random::get_random(16);
        let iv = random::get_random(16);
        let mut pretext = random::get_random(random::in_range(5, 10));
        let posttext = random::get_random(random::in_range(5, 10));

        pretext.extend(plain_text.as_bytes());
        pretext.extend(posttext);
        let mode = match random::flip_coin() {
            true => symm::Mode::CBC { iv },
            false => symm::Mode::ECB,
        };
        let mode_str = format!("{}", &mode);
        (
            symm::encrypt(&random_key, &pretext, mode, Padding::PKCS7),
            mode_str,
        )
    }

    fn is_ecb(cipher_text: &[u8]) -> bool {
        let mut blocks: HashMap<String, usize> = HashMap::new();

        // aes encrypts 16 bytes per block
        for block in cipher_text.chunks(16) {
            let hex = hex::to_string(&block);
            let counter = blocks.entry(hex).or_insert(0);
            *counter += 1
        }

        for (_, count) in blocks.iter() {
            if *count > 1 {
                return true;
            }
        }
        return false;
    }

    let plain_text = vec!["A"; 43];
    let plain_text = plain_text.join("");
    // io::stdin()
    //     .read_line(&mut plain_text)
    //     .expect("Failed to read line");
    let (encrypted, mode) = encrypt_ecb_or_cbc(&plain_text);
    if is_ecb(&encrypted) {
        println!("oracle says ECB!");
    } else {
        println!("oracle says CBC!");
    }
    println!("encryptor says {}", mode)
}
