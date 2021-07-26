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
            Mode::ECB => "ECB".to_owned(),
            Mode::CBC { iv } => format!("CBC | IV: {:02x?}", iv.clone()),
            Mode::None => "None".to_owned(),
        };
        write!(f, "{}", mode)
    }
}

pub struct Ciphertext {
    pub bytes: Vec<u8>,
    pub mode: Mode,
    pub padding: Padding,
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x?}", &self.bytes)
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mode: {}\n{:02x?}", self.mode, &self.bytes)
    }
}

impl Ciphertext {
    pub fn new(key: &[u8], plain_text: &[u8], mode: Mode, padding: Padding) -> Self {
        let padded_plain_text = Ciphertext::pad_to_sixteen(plain_text, &padding).unwrap();
        let bytes = match &mode {
            Mode::ECB => Self::encrypt_with_ecb(key, &padded_plain_text),
            Mode::CBC { iv } => Self::encrypt_with_cbc(key, &padded_plain_text, iv),
            Mode::None => Self::encrypt_raw(key, &padded_plain_text),
        };
        Self {
            bytes,
            mode,
            padding,
        }
    }

    pub fn from_existing(bytes: Vec<u8>, mode: Mode, padding: Padding) -> Self {
        if bytes.len() % 16 != 0 {
            panic!("can't create AES ciphertext which len is not a multiple of 16")
        }
        Self {
            bytes,
            mode,
            padding,
        }
    }

    pub fn cbc_from_prepended_iv(mut bytes: Vec<u8>, padding: Padding) -> Self {
        // split_off will return (16, len) and leave (0, 16) in the original vec
        let ciphertext = bytes.split_off(16);
        let iv = bytes;
        Self::from_existing(ciphertext, Mode::CBC { iv }, padding)
    }

    pub fn decrypt(&self, key: &[u8]) -> Vec<u8> {
        let plain_text = self.decrypt_without_unpadding(key);
        unpad(&self.padding, &plain_text).unwrap()
    }

    pub fn decrypt_without_unpadding(&self, key: &[u8]) -> Vec<u8> {
        match &self.mode {
            Mode::ECB => Ciphertext::decrypt_with_ecb(key, &self.bytes),
            Mode::CBC { iv } => Ciphertext::decrypt_with_cbc(key, &self.bytes, iv),
            Mode::None => Ciphertext::decrypt_raw(key, &self.bytes),
        }
    }

    fn encrypt_with_ecb(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let mut cipher = Cipher::new(key);
        let mut ecb = modes::ECB::new(&mut cipher);
        ecb.encrypt(plain_text)
    }

    fn encrypt_with_cbc(key: &[u8], plain_text: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut cipher = Cipher::new(key);
        let mut cbc = modes::CBC::new(&mut cipher, iv);
        cbc.encrypt(plain_text)
    }

    fn encrypt_raw(key: &[u8], plain_text: &[u8]) -> Vec<u8> {
        let mut cipher = Cipher::new(key);
        cipher.set_state(plain_text);
        cipher.encrypt().to_vec()
    }

    fn decrypt_with_ecb(key: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        let mut cipher = Cipher::new(key);
        let mut ecb = modes::ECB::new(&mut cipher);
        ecb.decrypt(cipher_text)
    }

    fn decrypt_with_cbc(key: &[u8], cipher_text: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut cipher = Cipher::new(key);
        let mut cbc = modes::CBC::new(&mut cipher, iv);
        cbc.decrypt(cipher_text)
    }

    fn decrypt_raw(key: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        let mut cipher = Cipher::new(key);
        cipher.set_state(cipher_text);
        cipher.decrypt().to_vec()
    }

    fn pad_to_sixteen(plain_text: &[u8], padding: &Padding) -> Option<Vec<u8>> {
        let last_block = plain_text.chunks(16).last()?;
        let mut pad = get_pad(padding, &last_block, 16)?;
        let mut padded_plain_text = vec![0; plain_text.len()];
        padded_plain_text.copy_from_slice(plain_text);
        padded_plain_text.append(&mut pad);
        Some(padded_plain_text)
    }
}

pub fn encrypt(key: &[u8], plain_text: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let padded_plain_text = Ciphertext::pad_to_sixteen(plain_text, &padding).unwrap();
    let bytes = match &mode {
        Mode::ECB => Ciphertext::encrypt_with_ecb(key, &padded_plain_text),
        Mode::CBC { iv } => Ciphertext::encrypt_with_cbc(key, &padded_plain_text, iv),
        Mode::None => Ciphertext::encrypt_raw(key, &padded_plain_text),
    };
    bytes
}

pub fn decrypt(key: &[u8], cipher_text: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let plain_text = match &mode {
        Mode::ECB => Ciphertext::decrypt_with_ecb(key, &cipher_text),
        Mode::CBC { iv } => Ciphertext::decrypt_with_cbc(key, &cipher_text, iv),
        Mode::None => Ciphertext::decrypt_raw(key, &cipher_text),
    };
    unpad(&padding, &plain_text).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn test_encrypt_hex() {
        let key = hex::from_string(&"000102030405060708090a0b0c0d0e0f").unwrap();
        let plain = hex::from_string(&"00112233445566778899aabbccddeeff").unwrap();
        let result = Ciphertext::new(&key, &plain, Mode::None, Padding::PKCS7);
        let result = hex::to_string(&result.bytes).to_ascii_lowercase();
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    #[test]
    fn test_decrypt_hex() {
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        let cipher_text_bytes = hex::from_string("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let cipher_text = Ciphertext::from_existing(cipher_text_bytes, Mode::None, Padding::None);
        let result = cipher_text.decrypt(&key);
        let plain_text = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(plain_text, "00112233445566778899aabbccddeeff");
    }
}
