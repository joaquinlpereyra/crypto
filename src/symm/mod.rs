mod aes;
pub mod modes;
pub mod padding;
use crate::hex;

use aes::Cipher;
use modes::Mode;

pub fn encrypt(key: &str, plain_text: &str, mode: Mode) -> String {
    match mode {
        Mode::None => encrypt_hex(key, plain_text),
        Mode::ECB => encrypt_hex_with_ecb(key, plain_text),
    }
}

pub fn decrypt(key: &str, plain_text: &str, mode: Mode) -> String {
    match mode {
        Mode::None => decrypt_hex(key, plain_text),
        Mode::ECB => decrypt_hex_with_ecb(key, plain_text),
    }
}

fn encrypt_hex(key: &str, plain_text: &str) -> String {
    let mut cipher = Cipher::new_from_hex(key, plain_text);
    let cipher_text = cipher.encrypt_to_hex();

    cipher_text
}

fn encrypt_hex_with_ecb(key: &str, plain_text: &str) -> String {
    let key_bytes = hex::from_string(key).expect("invalid key given");
    let plain_bytes = hex::from_string(plain_text).expect("uneven hex string given");
    let mut cipher = Cipher::new_blank(&key_bytes);
    let mut ecb = modes::ECB::new(&mut cipher);

    hex::to_string(&ecb.encrypt(&plain_bytes))
}

fn decrypt_hex_with_ecb(key: &str, cipher_text: &str) -> String {
    let key_bytes = hex::from_string(key).expect("invalid key given");
    let cipher_bytes = hex::from_string(cipher_text).expect("uneven hex string given");
    let mut cipher = Cipher::new_blank(&key_bytes);
    let mut ecb = modes::ECB::new(&mut cipher);

    hex::to_string(&ecb.decrypt(&cipher_bytes))
}

pub fn decrypt_hex(key: &str, cipher_text: &str) -> String {
    let mut cipher = Cipher::new_from_hex(key, cipher_text);
    let decryption = cipher.decrypt_hex();

    decryption
}

pub fn encrypt_raw(key: &[u8], plain_text: &[u8; 16]) -> [u8; 16] {
    let mut cipher = Cipher::new(key, plain_text);
    let cipher_text = cipher.encrypt();

    cipher_text
}

pub fn decrypt_raw(key: &[u8], cipher_text: &[u8; 16]) -> [u8; 16] {
    let mut cipher = Cipher::new(key, cipher_text);
    let decryption = cipher.decrypt();

    decryption
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_hex() {
        let key = "000102030405060708090a0b0c0d0e0f";
        let plain = "00112233445566778899aabbccddeeff";
        let result = encrypt_hex(&key, &plain);
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    #[test]
    fn test_decrypt_hex() {
        let key = "000102030405060708090a0b0c0d0e0f";
        let cipher_text = "69c4e0d86a7b0430d8cdb78070b4c55a";
        let plain_text = decrypt_hex(&key, cipher_text);
        assert_eq!(plain_text, "00112233445566778899aabbccddeeff");
    }
}
