mod aes;
mod modes;
pub mod padding;

use aes::Cipher;

/// A simple list of encryption modes
/// supported by this module.
pub enum Mode {
    None,
    ECB,
}

pub fn encrypt(key: &[u8], plain_text: &[u8], mode: Mode) -> Vec<u8> {
    match mode {
        Mode::ECB => encrypt_with_ecb(key, plain_text),
        Mode::None => encrypt_raw(key, plain_text),
    }
}

pub fn decrypt(key: &[u8], cipher_text: &[u8], mode: Mode) -> Vec<u8> {
    match mode {
        Mode::ECB => decrypt_with_ecb(key, cipher_text),
        Mode::None => decrypt_raw(key, cipher_text),
    }
}

fn encrypt_with_ecb(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
    let mut cipher = Cipher::new(key);
    let mut ecb = modes::ECB::new(&mut cipher);
    ecb.encrypt(plain_text)
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
        let result = encrypt(&key, &plain, Mode::None);
        let result = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    #[test]
    fn test_decrypt_hex() {
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        let cipher_text = hex::from_string("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let result = decrypt(&key, &cipher_text, Mode::None);
        let plain_text = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(plain_text, "00112233445566778899aabbccddeeff");
    }
}
