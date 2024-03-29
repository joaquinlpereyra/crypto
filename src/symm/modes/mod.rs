/// A cipher according to modes.
pub trait BlockCipher {
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
    cipher: &'a mut dyn BlockCipher,
    block_size: usize,
}

/// XORs array of bytes of the same size.
fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.into_iter().zip(y).map(|(x, y)| x ^ y).collect()
}

impl<'a> ECB<'a> {
    pub fn new(cipher: &'a mut dyn BlockCipher) -> ECB<'a> {
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
    cipher: &'a mut dyn BlockCipher,
    block_size: usize,
    iv: &'a [u8],
}

impl<'a> CBC<'a> {
    pub fn new(cipher: &'a mut dyn BlockCipher, iv: &'a [u8]) -> CBC<'a> {
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

        for plain_block in msg.chunks_exact(self.block_size) {
            let xor_right_hand = cipher_text
                .rchunks_exact(self.block_size)
                .next()
                .unwrap_or(self.iv);

            let xored = xor(plain_block, xor_right_hand);
            self.cipher.set_state(&xored);
            let mut block = self.cipher.encrypt();
            cipher_text.append(&mut block);
        }

        cipher_text
    }

    pub fn decrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut plain_text = Vec::with_capacity(msg.len());

        let mut last_block = self.iv;

        for cipher_block in msg.chunks_exact(self.block_size) {
            self.cipher.set_state(&cipher_block);
            let decrypted = self.cipher.decrypt();
            let mut plain = xor(&decrypted, &last_block);
            last_block = &cipher_block;
            plain_text.append(&mut plain);
        }

        plain_text
    }
}

pub struct CTR<'a> {
    cipher: &'a mut dyn BlockCipher,
    block_size: usize,
    // counter format:
    // 8 bytes little endian arbitrary nonce
    // 8 bytes little endian incremental number
    counter: [u8; 16],
    counter_int: u64,
}

impl<'a> CTR<'a> {
    pub fn new(cipher: &'a mut dyn BlockCipher, nonce: u64) -> CTR<'a> {
        let block_size = cipher.get_block_size();
        let counter_int = 0;
        let counter = Self::new_counter(nonce);

        CTR {
            cipher,
            block_size,
            counter,
            counter_int,
        }
    }

    fn new_counter(nonce: u64) -> [u8; 16] {
        // Init counter
        let mut counter = [0; 16];
        let counter_int = 0;
        let nonce_bytes = nonce.to_le_bytes();
        for i in 0..8 {
            counter[i] = nonce_bytes[i];
        }
        for i in 8..16 {
            counter[i] = counter_int;
        }
        counter
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::new();
        for chunk in msg.chunks(self.block_size) {
            self.cipher.set_state(&self.counter);
            let counter_block = self.cipher.encrypt();
            let mut xored = xor(&counter_block, chunk);
            xored.resize(16, 0);
            ciphertext.append(&mut xored);
            self.increase_counter();
        }
        ciphertext
    }

    pub fn decrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        self.encrypt(msg)
    }

    fn increase_counter(&mut self) {
        self.counter_int += 1;
        let new_nonce_bytes = (self.counter_int).to_le_bytes();
        for i in 8..16 {
            self.counter[i] = new_nonce_bytes[i - 8]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::aes;
    use super::*;
    use crate::encoding::base64;
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
        let mut cbc = CBC::new(&mut cipher, &iv);
        let plain = cbc.decrypt(&cipher_text);
        let plain = str::from_utf8(&plain).unwrap();
        assert_eq!("I'm back and I'm ringin' the bel", plain)
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_encrypt_decrypt_CBC_problematic_key() {
        let key = [
            252, 79, 217, 52, 129, 236, 103, 160, 241, 221, 81, 130, 242, 82, 41, 255,
        ]
        .to_vec();
        let iv = [
            0x17, 0x5A, 0x29, 0x75, 0xC8, 0xBB, 0x80, 0x8B, 0x8F, 0xA2, 0xA7, 0x81, 0x79, 0x24,
            0xFF, 0x3D,
        ]
        .to_vec();
        // Exactly 3 blocks long... when encrypted will have 4
        let mut plaintext = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
            .as_bytes()
            .to_owned();
        // Pad manually
        plaintext.extend([0x10; 0x10].iter());
        let mut cipher = aes::Cipher::new(&key);
        let mut cbc = CBC::new(&mut cipher, &iv);
        let ciphertext = cbc.encrypt(&plaintext);

        let decrypted = cbc.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_encrypt_CBC() {
        let plain = "I'm back and I'm ringin' the bel".as_bytes();
        let iv = [0x00; 16];
        let mut cipher = aes::Cipher::new("YELLOW SUBMARINE".as_bytes());
        let mut cbc = CBC::new(&mut cipher, &iv);
        let cypher = cbc.encrypt(&plain);
        let expected = hex::from_string(
            "0912 30aa de3e b330 dbaa 4358 f88d 2a6c d5cf 8355 cb68 2339 7ad4 3906 df43 4455",
        )
        .unwrap();
        assert_eq!(cypher, expected)
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_CTR_create_iv() {
        let mut cipher = aes::Cipher::new("YELLOW SUBMARINE".as_bytes());
        let ctr = CTR::new(&mut cipher, 0);

        assert_eq!(
            [
                0, 0, 0, 0, 0, 0, 0, 0, // second part should be exactly the block coount
                0, 0, 0, 0, 0, 0, 0, 0, // first part should be the counter zero on first
            ],
            ctr.counter,
        )
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_CTR_add_to_counter() {
        let mut cipher = aes::Cipher::new("YELLOW SUBMARINE".as_bytes());
        let mut ctr = CTR::new(&mut cipher, 2);
        for i in 0..1024 {
            let mut expected_counter = [0; 16];
            expected_counter[0] = 2; // nonce should stay fixed
            let expected_incremental_number = (i as u64).to_le_bytes();
            for j in 8..16 {
                expected_counter[j] = expected_incremental_number[j - 8]
            }
            assert_eq!(expected_counter, ctr.counter);
            ctr.increase_counter();
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_CTR_decrypt() {
        let ciphertext = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        let mut cipher = aes::Cipher::new("YELLOW SUBMARINE".as_bytes());
        let mut ctr = CTR::new(&mut cipher, 0);
        let plaintext = ctr.decrypt(&ciphertext);
        str::from_utf8(&plaintext).unwrap();
    }
}
