mod aes;
mod padding;

use aes::Cipher;

pub fn encrypt(key: &[u8], plain_text: &[u8; 16]) -> [u8; 16] {
    let mut cipher = Cipher::new(key, plain_text);
    let encryption = cipher.encrypt();

    return encryption;
}

pub fn encrypt_hex(key: &str, plain_text: &str) -> String {
    let mut cipher = Cipher::new_from_hex(key, plain_text);
    let encryption = cipher.encrypt_to_hex();

    return encryption;
}

#[cfg(test)]
mod tests {
    use super::encrypt_hex;

    #[test]
    fn test_encrypt_hex() {
        let key = "000102030405060708090a0b0c0d0e0f";
        let plain = "00112233445566778899aabbccddeeff";
        let result = encrypt_hex(&key, &plain);
        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }
}
