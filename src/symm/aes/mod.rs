mod bytes;
mod constants;
mod key;

use super::modes;
use bytes::{Block, Byte, Bytes, Endian, Word, NB};
use key::Key;

/// A low-level AES Cipher.
/// It provides the basic primitives of the AES algorithm.
/// It does **NOT** implement anything like modes, padding
/// or anything like that.
/// Clients are supposed to check for sanity of input parameters
/// or the Cipher will either malfunction or just panic.
/// Sanity requirements:
/// - Key is either 16, 24 or 32 bytes long
/// - A call to set_state is made before trying to encrypt or decrypt
pub struct Cipher {
    nr: u8,
    state: Block,
    key: Key,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Self {
        let nr = match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            other => panic!(format!("impossible key length: {}", other)),
        };

        let key_bytes = Bytes::new(key, Endian::Big);
        let key = Key::new(key_bytes, nr).unwrap_or_else(|| panic!("could not generate key"));
        Self {
            nr,
            state: Block::new([Word::zero(), Word::zero(), Word::zero(), Word::zero()]),
            key,
        }
    }

    pub fn set_state(&mut self, state: &[u8]) {
        let block = Block::new_from_u8([
            [state[0], state[1], state[2], state[3]],
            [state[4], state[5], state[6], state[7]],
            [state[8], state[9], state[10], state[11]],
            [state[12], state[13], state[14], state[15]],
        ]);
        self.state = block;
    }

    pub fn encrypt(&mut self) -> [u8; 16] {
        self.add_round_key(0);

        for round in 1..self.nr {
            self.substitute_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(round);
        }

        self.substitute_bytes();
        self.shift_rows();
        self.add_round_key(self.nr);

        self.state.flatten_into_u8()
    }

    pub fn decrypt(&mut self) -> [u8; 16] {
        self.add_round_key(self.nr);

        for round in 1..self.nr {
            self.inverse_shift_rows();
            self.inverse_substitute_bytes();
            self.add_round_key(self.nr - round);
            self.inverse_mix_columns();
        }

        self.inverse_shift_rows();
        self.inverse_substitute_bytes();
        self.add_round_key(0);

        self.state.flatten_into_u8()
    }

    // Known as "SubBytes()" in the AES specification.
    fn substitute_bytes(&mut self) {
        let new_columns: Vec<Word> = self
            .state
            .clone_columns()
            .iter_mut()
            .map(|clm| clm.subword(constants::SBOX))
            .collect();
        self.state = Block::new([
            new_columns[0].clone(),
            new_columns[1].clone(),
            new_columns[2].clone(),
            new_columns[3].clone(),
        ])
    }

    fn inverse_substitute_bytes(&mut self) {
        let new_columns: Vec<Word> = self
            .state
            .clone_columns()
            .iter_mut()
            .map(|clm| clm.subword(constants::INVERSE_SBOX))
            .collect();
        self.state = Block::new([
            new_columns[0].clone(),
            new_columns[1].clone(),
            new_columns[2].clone(),
            new_columns[3].clone(),
        ])
    }

    fn shift_rows(&mut self) {
        let old = self.state.clone_columns();
        let mut new = old.clone();

        // grab the Nth byte of each column
        // and set it it to the Nth byte
        // of the column to its Nth-right
        // example, the second byte of the second column
        // will get the value of the second byte in the
        // fourth column
        for clm in 0..4 {
            new[clm].set_byte(1, old[(clm + 1) % 4][1]);
        }
        for clm in 0..4 {
            new[clm].set_byte(2, old[(clm + 2) % 4][2]);
        }
        for clm in 0..4 {
            new[clm].set_byte(3, old[(clm + 3) % 4][3]);
        }

        self.state = Block::new(new);
    }

    fn inverse_shift_rows(&mut self) {
        let old = self.state.clone_columns();
        let mut new = old.clone();

        let mod_four = |x: isize| x.rem_euclid(4) as usize;
        for clm in 0..4 {
            new[clm].set_byte(1, old[mod_four(clm as isize - 1)][1]);
        }
        for clm in 0..4 {
            new[clm].set_byte(2, old[mod_four(clm as isize - 2)][2]);
        }
        for clm in 0..4 {
            new[clm].set_byte(3, old[mod_four(clm as isize - 3)][3]);
        }
        self.state = Block::new(new);
    }

    fn mix_columns(&mut self) {
        let old = self.state.clone_columns();
        let mut new = old.clone();

        let _2 = Byte::new(2);
        let _3 = Byte::new(3);

        for (i, clm) in old.iter().enumerate() {
            new[i].set_byte(0, _2 * clm[0] + _3 * clm[1] + clm[2] + clm[3]);
            new[i].set_byte(1, clm[0] + _2 * clm[1] + _3 * clm[2] + clm[3]);
            new[i].set_byte(2, clm[0] + clm[1] + _2 * clm[2] + _3 * clm[3]);
            new[i].set_byte(3, _3 * clm[0] + clm[1] + clm[2] + _2 * clm[3]);
        }

        self.state = Block::new(new)
    }

    fn inverse_mix_columns(&mut self) {
        let old = self.state.clone_columns();
        let mut new = old.clone();

        let _9 = Byte::new(9);
        let _11 = Byte::new(11);
        let _13 = Byte::new(13);
        let _14 = Byte::new(14);

        for (i, clm) in old.iter().enumerate() {
            new[i].set_byte(0, _14 * clm[0] + _11 * clm[1] + _13 * clm[2] + _9 * clm[3]);
            new[i].set_byte(1, _9 * clm[0] + _14 * clm[1] + _11 * clm[2] + _13 * clm[3]);
            new[i].set_byte(2, _13 * clm[0] + _9 * clm[1] + _14 * clm[2] + _11 * clm[3]);
            new[i].set_byte(3, _11 * clm[0] + _13 * clm[1] + _9 * clm[2] + _14 * clm[3]);
        }
        self.state = Block::new(new);
    }

    fn add_round_key(&mut self, round: u8) {
        let round_by_nb = (round * NB) as usize;
        let block_with_key = Block::new([
            self.key[round_by_nb + 0].clone(),
            self.key[round_by_nb + 1].clone(),
            self.key[round_by_nb + 2].clone(),
            self.key[round_by_nb + 3].clone(),
        ]);
        // mem swap who even needs u suckerrrrr
        self.state = self.state.clone() ^ block_with_key;
    }
}

impl modes::Cipher for Cipher {
    fn set_state(&mut self, state: &[u8]) {
        self.set_state(state)
    }

    fn encrypt(&mut self) -> Vec<u8> {
        self.encrypt().to_vec()
    }

    fn decrypt(&mut self) -> Vec<u8> {
        self.decrypt().to_vec()
    }

    fn get_block_size(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    fn cipher() -> Cipher {
        let cipher_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        Cipher::new(&cipher_key)
    }

    #[test]
    fn test_encrypt_simple() {
        let key = hex::from_string(&"000102030405060708090a0b0c0d0e0f").unwrap();
        let plain = hex::from_string("00112233445566778899aabbccddeeff").unwrap();
        let cipher = &mut Cipher::new(&key);
        cipher.set_state(&plain);

        let result = hex::to_string(&cipher.encrypt()).to_ascii_lowercase();

        assert_eq!(result, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    #[test]
    fn test_add_round_key() {
        let expected = Block::new([
            Word::new_from_hex("193de3be"),
            Word::new_from_hex("a0f4e22b"),
            Word::new_from_hex("9ac68d2a"),
            Word::new_from_hex("e9f84808"),
        ]);
        let mut cipher = cipher();
        cipher.set_state(&[
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ]);
        cipher.add_round_key(0);
        assert_eq!(cipher.state, expected)
    }

    #[test]
    fn test_inverse_add_round_key() {
        let mut cipher = cipher();
        let plain = hex::from_string("00112233445566778899aabbccddeeff").unwrap();
        cipher.set_state(&plain);
        let original = cipher.state.clone();
        cipher.add_round_key(0);
        cipher.add_round_key(0);
        assert_eq!(cipher.state, original);
    }

    #[test]
    fn test_substitute_bytes() {
        let expected = Block::new([
            Word::new_from_hex("d42711ae"),
            Word::new_from_hex("e0bf98f1"),
            Word::new_from_hex("b8b45de5"),
            Word::new_from_hex("1e415230"),
        ]);
        let input = Block::new([
            Word::new_from_hex("193de3be"),
            Word::new_from_hex("a0f4e22b"),
            Word::new_from_hex("9ac68d2a"),
            Word::new_from_hex("e9f84808"),
        ]);
        let mut cipher = cipher();
        cipher.state = input;
        cipher.substitute_bytes();
        assert_eq!(cipher.state, expected);
    }

    #[test]
    fn test_inverse_substitute_bytes() {
        let input = Block::new([
            Word::new_from_hex("d42711ae"),
            Word::new_from_hex("e0bf98f1"),
            Word::new_from_hex("b8b45de5"),
            Word::new_from_hex("1e415230"),
        ]);
        let expected = Block::new([
            Word::new_from_hex("193de3be"),
            Word::new_from_hex("a0f4e22b"),
            Word::new_from_hex("9ac68d2a"),
            Word::new_from_hex("e9f84808"),
        ]);
        let mut cipher = cipher();
        cipher.state = input;
        cipher.inverse_substitute_bytes();
        assert_eq!(cipher.state, expected);
    }

    #[test]
    fn test_shift_rows() {
        let expected = Block::new([
            Word::new_from_hex("d4bf5d30"),
            Word::new_from_hex("e0b452ae"),
            Word::new_from_hex("b84111f1"),
            Word::new_from_hex("1e2798e5"),
        ]);
        let input = Block::new([
            Word::new_from_hex("d42711ae"),
            Word::new_from_hex("e0bf98f1"),
            Word::new_from_hex("b8b45de5"),
            Word::new_from_hex("1e415230"),
        ]);
        let mut cipher = cipher();
        cipher.state = input;
        cipher.shift_rows();
        assert_eq!(cipher.state, expected);
    }

    #[test]
    fn test_inverse_shift_rows() {
        let input = Block::new([
            Word::new_from_hex("d4bf5d30"),
            Word::new_from_hex("e0b452ae"),
            Word::new_from_hex("b84111f1"),
            Word::new_from_hex("1e2798e5"),
        ]);
        let expected = Block::new([
            Word::new_from_hex("d42711ae"),
            Word::new_from_hex("e0bf98f1"),
            Word::new_from_hex("b8b45de5"),
            Word::new_from_hex("1e415230"),
        ]);
        let mut cipher = cipher();
        cipher.state = input;
        cipher.inverse_shift_rows();
        assert_eq!(cipher.state, expected);
    }

    #[test]
    fn test_mix_columns() {
        let expected = Block::new([
            Word::new_from_hex("046681e5"),
            Word::new_from_hex("e0cb199a"),
            Word::new_from_hex("48f8d37a"),
            Word::new_from_hex("2806264c"),
        ]);
        let input = Block::new([
            Word::new_from_hex("d4bf5d30"),
            Word::new_from_hex("e0b452ae"),
            Word::new_from_hex("b84111f1"),
            Word::new_from_hex("1e2798e5"),
        ]);
        let mut cipher = cipher();
        cipher.state = input;
        cipher.mix_columns();
        assert_eq!(cipher.state, expected);
    }

    #[test]
    fn test_inverse_mix_columns() {
        let input = Block::new([
            Word::new_from_hex("046681e5"),
            Word::new_from_hex("e0cb199a"),
            Word::new_from_hex("48f8d37a"),
            Word::new_from_hex("2806264c"),
        ]);
        let expected = Block::new([
            Word::new_from_hex("d4bf5d30"),
            Word::new_from_hex("e0b452ae"),
            Word::new_from_hex("b84111f1"),
            Word::new_from_hex("1e2798e5"),
        ]);
        let mut cipher = cipher();
        cipher.state = input;
        cipher.inverse_mix_columns();
        assert_eq!(cipher.state, expected);
    }
}
