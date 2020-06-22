/// A cipher according to modes.
pub trait Cipher {
    fn set_state(&mut self, state: &[u8]);
    fn encrypt(&mut self) -> Vec<u8>;
    fn decrypt(&mut self) -> Vec<u8>;
    fn get_block_size(&self) -> usize;
}

/// An ECB mode of operation for an arbitrary block cypher
/// ECB mode will just encrypt every block and concatenate
/// the outputs to form the cyphertext. Idem for decryption.
/// Operation on the ECB mode require a working block cipher
/// and do not assume the plain or cipher text to be padded.
pub struct ECB<'a> {
    cipher: &'a mut dyn Cipher,
    block_size: usize,
}

impl<'a> ECB<'a> {
    pub fn new(cipher: &'a mut dyn Cipher) -> ECB<'a> {
        let block_size = cipher.get_block_size();
        ECB { cipher, block_size }
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut plain_text = Vec::with_capacity(msg.len());

        for i in (0..msg.len()).step_by(self.block_size) {
            self.cipher.set_state(&msg[i..i + self.block_size]);
            plain_text.append(&mut self.cipher.encrypt());
        }

        plain_text
    }

    pub fn decrypt(&mut self, cipher_text: &[u8]) -> Vec<u8> {
        let mut plain_text = Vec::with_capacity(cipher_text.len());

        for i in (0..cipher_text.len()).step_by(self.block_size) {
            self.cipher.set_state(&cipher_text[i..i + self.block_size]);
            plain_text.append(&mut self.cipher.decrypt())
        }

        plain_text
    }
}

#[cfg(test)]
mod tests {
    use super::super::aes;
    use super::*;
    use crate::encoding::hex;

    fn cipher() -> aes::Cipher {
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        aes::Cipher::new(&key)
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_simple_ECB() {
        let mut cipher = cipher();
        let mut ecb = ECB::new(&mut cipher);
        let plain_text = hex::from_string("00112233445566778899aabbccddeeff").unwrap();
        let result = ecb.encrypt(&plain_text);
        let hex_result = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(hex_result, "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_duplicated_ECB() {
        let mut cipher = cipher();
        let mut ecb = ECB::new(&mut cipher);
        let plain_text =
            hex::from_string("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap();
        let result = ecb.encrypt(&plain_text);
        let hex_result = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(
            hex_result,
            "69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_decrypt_ECB() {
        let mut cipher = cipher();
        let mut ecb = ECB::new(&mut cipher);
        let cipher_text =
            hex::from_string("69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a")
                .unwrap();
        let result = ecb.decrypt(&cipher_text);
        let hex_result = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(
            hex_result,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
    }
}
