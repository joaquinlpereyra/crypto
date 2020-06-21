mod aes;
mod modes;
pub mod padding;

use aes::Cipher;

pub fn encrypt_raw(key: &[u8], plain_text: &[u8; 16]) -> [u8; 16] {
    let mut cipher = Cipher::new(key, plain_text);
    let cipher_text = cipher.encrypt();

    cipher_text
}

pub fn encrypt_hex(key: &str, plain_text: &str) -> String {
    let mut cipher = Cipher::new_from_hex(key, plain_text);
    let cipher_text = cipher.encrypt_to_hex();

    cipher_text
}

pub fn decrypt_raw(key: &[u8], cipher_text: &[u8; 16]) -> [u8; 16] {
    let mut cipher = Cipher::new(key, cipher_text);
    let decryption = cipher.decrypt();

    decryption
}

pub fn decrypt_hex(key: &str, cipher_text: &str) -> String {
    let mut cipher = Cipher::new_from_hex(key, cipher_text);
    let decryption = cipher.decrypt_hex();

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
