mod aes;
mod modes;
pub mod padding;
use std::fmt;

use aes::Cipher;
use padding::{get_pad, unpad, Padding};

/// A simple list of encryption modes
/// supported by this module.
pub enum Mode {
    None,
    ECB,
    CBC { iv: Vec<u8> },
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self {
            Mode::ECB => "ECB",
            Mode::CBC { iv: _ } => "CBC",
            Mode::None => "None",
        };
        write!(f, "{}", mode)
    }
}

fn pad_to_sixteen(plain_text: &[u8], padding: Padding) -> Option<Vec<u8>> {
    let last_block = plain_text.chunks(16).last()?;
    let mut pad = get_pad(padding, &last_block, 16)?;
    let mut padded_plain_text = vec![0; plain_text.len()];
    padded_plain_text.copy_from_slice(plain_text);
    padded_plain_text.append(&mut pad);
    Some(padded_plain_text)
}

pub fn encrypt(key: &[u8], plain_text: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let padded_plain_text = pad_to_sixteen(plain_text, padding).unwrap();
    match mode {
        Mode::ECB => encrypt_with_ecb(key, &padded_plain_text),
        Mode::CBC { iv } => encrypt_with_cbc(key, &padded_plain_text, iv),
        Mode::None => encrypt_raw(key, &padded_plain_text),
    }
}

pub fn decrypt(key: &[u8], cipher_text: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let plain_text = match mode {
        Mode::ECB => decrypt_with_ecb(key, cipher_text),
        Mode::CBC { iv } => decrypt_with_cbc(key, cipher_text, iv),
        Mode::None => decrypt_raw(key, cipher_text),
    };
    println!("{:?}", &plain_text);
    unpad(padding, &plain_text).unwrap()
}

fn encrypt_with_ecb(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    let mut ecb = modes::ECB::new(&mut cipher);
    ecb.encrypt(plain_text)
}

fn encrypt_with_cbc(key: &[u8], plain_text: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    let mut cbc = modes::CBC::new(&mut cipher, iv);
    cbc.encrypt(plain_text)
}

fn encrypt_raw(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    cipher.set_state(plain_text);
    cipher.encrypt().to_vec()
}

pub fn decrypt_with_ecb(key: &[u8], cipher_text: &[u8]) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    let mut ecb = modes::ECB::new(&mut cipher);
    ecb.decrypt(cipher_text)
}

pub fn decrypt_with_cbc(key: &[u8], cipher_text: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    let mut cbc = modes::CBC::new(&mut cipher, iv);
    cbc.decrypt(cipher_text)
}

pub fn decrypt_raw(key: &[u8], cipher_text: &[u8]) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    cipher.set_state(cipher_text);
    cipher.decrypt().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn test_encrypt_hex() {
        let key = hex::from_string(&"000102030405060708090a0b0c0d0e0f").unwrap();
        let plain = hex::from_string(&"00112233445566778899aabbccddeeff").unwrap();
        let result = encrypt(&key, &plain, Mode::None, Padding::PKCS7);
        let result = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    #[test]
    fn test_decrypt_hex() {
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        let cipher_text = hex::from_string("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let result = decrypt(&key, &cipher_text, Mode::None, Padding::None);
        let plain_text = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(plain_text, "00112233445566778899aabbccddeeff");
    }
}
