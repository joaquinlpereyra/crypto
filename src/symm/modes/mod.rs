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

/// XORs array of bytes of the same size.
fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.into_iter().zip(y).map(|(x, y)| x ^ y).collect()
}

impl<'a> ECB<'a> {
    pub fn new(cipher: &'a mut dyn Cipher) -> ECB<'a> {
        let block_size = cipher.get_block_size();
        ECB { cipher, block_size }
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut cipher_text = Vec::with_capacity(msg.len());

        for i in (0..msg.len()).step_by(self.block_size) {
            self.cipher.set_state(&msg[i..i + self.block_size]);
            cipher_text.append(&mut self.cipher.encrypt());
        }

        cipher_text
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

pub struct CBC<'a> {
    cipher: &'a mut dyn Cipher,
    block_size: usize,
    iv: Vec<u8>,
}

impl<'a> CBC<'a> {
    pub fn new(cipher: &'a mut dyn Cipher, iv: Vec<u8>) -> CBC<'a> {
        let block_size = cipher.get_block_size();
        if block_size != iv.len() {
            panic!("IV must be the safe length as the block of the cipher");
        }
        CBC {
            cipher,
            block_size,
            iv,
        }
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut cipher_text = Vec::with_capacity(msg.len());

        let mut last_block = self.iv.clone();

        for plain_block in msg.chunks_exact(self.block_size) {
            let xored = xor(plain_block, &last_block);
            self.cipher.set_state(&xored);
            let mut block = self.cipher.encrypt();
            last_block = block.clone();
            cipher_text.append(&mut block);
        }

        cipher_text
    }

    pub fn decrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut plain_text = Vec::with_capacity(msg.len());

        let mut last_block = self.iv.clone();

        for cipher_block in msg.chunks_exact(self.block_size) {
            self.cipher.set_state(&cipher_block);
            let decrypted = self.cipher.decrypt();
            let mut plain = xor(&decrypted, &last_block);

            last_block = cipher_block.clone().to_vec();
            plain_text.append(&mut plain);
        }

        plain_text
    }
}

#[cfg(test)]
mod tests {
    use super::super::aes;
    use super::*;
    use crate::encoding::hex;
    use std::str;

    #[test]
    #[allow(non_snake_case)]
    fn test_simple_ECB() {
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut cipher = aes::Cipher::new(&key);
        let mut ecb = ECB::new(&mut cipher);
        let plain_text = hex::from_string("00112233445566778899aabbccddeeff").unwrap();
        let result = ecb.encrypt(&plain_text);
        let hex_result = hex::to_string(&result).to_ascii_lowercase();
        assert_eq!(hex_result, "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_duplicated_ECB() {
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut cipher = aes::Cipher::new(&key);
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
        let key = hex::from_string("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut cipher = aes::Cipher::new(&key);
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

    #[test]
    #[allow(non_snake_case)]
    fn test_decrypt_CBC() {
        let cipher_text = hex::from_string(
            "0912 30aa de3e b330 dbaa 4358 f88d 2a6c d5cf 8355 cb68 2339 7ad4 3906 df43 4455",
        )
        .unwrap();
        let iv = [0x00; 16];
        let mut cipher = aes::Cipher::new("YELLOW SUBMARINE".as_bytes());
        let mut cbc = CBC::new(&mut cipher, iv.to_vec());
        let plain = cbc.decrypt(&cipher_text);
        let plain = str::from_utf8(&plain).unwrap();
        assert_eq!("I'm back and I'm ringin' the bel", plain)
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_encrypt_CBC() {
        let plain = "I'm back and I'm ringin' the bel".as_bytes();
        let iv = [0x00; 16];
        let mut cipher = aes::Cipher::new("YELLOW SUBMARINE".as_bytes());
        let mut cbc = CBC::new(&mut cipher, iv.to_vec());
        let cypher = cbc.encrypt(&plain);
        let expected = hex::from_string(
            "0912 30aa de3e b330 dbaa 4358 f88d 2a6c d5cf 8355 cb68 2339 7ad4 3906 df43 4455",
        )
        .unwrap();
        assert_eq!(cypher, expected)
    }
}
