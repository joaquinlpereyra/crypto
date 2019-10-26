mod bytes;
mod constants;
mod key;

use bytes::{Block, Byte, Bytes, Endian, Word};
use key::Key;

#[allow(non_upper_case_globals)]
static Nb: u8 = 4;

#[allow(non_snake_case)]
pub struct Cipher {
    Nr: u8,
    state: Block,
    key: Key,
}

impl Cipher {
    pub fn new(key: &[u8], msg: &[u8; 16]) -> Self {
        let Nr = match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            other => panic!(format!("impossible key length: {}", other)),
        };

        let key_bytes = Bytes::new(key, Endian::Big);
        let key = Key::new(key_bytes, Nr).unwrap_or_else(|| panic!("could not generate key"));
        let state = Block::new_from_u8([
            [msg[0], msg[1], msg[2], msg[3]],
            [msg[4], msg[5], msg[6], msg[7]],
            [msg[8], msg[9], msg[10], msg[11]],
            [msg[12], msg[13], msg[14], msg[15]],
        ]);

        Self { Nr, state, key }
    }

    pub fn new_from_hex(key: &str, msg: &str) -> Self {
        let Nr = match key.len() {
            32 => 10,
            48 => 12,
            64 => 14,
            other => panic!(format!("impossible key length: {}", other)),
        };
        let key_bytes = Bytes::new_from_hex_string(key);
        let key = Key::new(key_bytes, Nr).unwrap_or_else(|| panic!("could not generate key"));
        let msg = Bytes::new_from_hex_string(msg);
        let state = Block::new([
            Word::new([msg[0], msg[1], msg[2], msg[3]], Endian::Big),
            Word::new([msg[4], msg[5], msg[6], msg[7]], Endian::Big),
            Word::new([msg[8], msg[9], msg[10], msg[11]], Endian::Big),
            Word::new([msg[12], msg[13], msg[14], msg[15]], Endian::Big),
        ]);
        Self { Nr, state, key }
    }

    pub fn encrypt_to_hex(&mut self) -> String {
        let cipher_text = self.encrypt();
        Bytes::new(&cipher_text, Endian::Big).to_hex()
    }

    pub fn encrypt(&mut self) -> [u8; 16] {
        self.add_round_key(0);

        for round in 1..self.Nr {
            self.substitute_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(round);
        }

        self.substitute_bytes();
        self.shift_rows();
        self.add_round_key(self.Nr);

        let clms = self.state.get_columns();
        [
            clms[0][0].get_number(),
            clms[0][1].get_number(),
            clms[0][2].get_number(),
            clms[0][3].get_number(),
            clms[1][0].get_number(),
            clms[1][1].get_number(),
            clms[1][2].get_number(),
            clms[1][3].get_number(),
            clms[2][0].get_number(),
            clms[2][1].get_number(),
            clms[2][2].get_number(),
            clms[2][3].get_number(),
            clms[3][0].get_number(),
            clms[3][1].get_number(),
            clms[3][2].get_number(),
            clms[3][3].get_number(),
        ]
    }

    /// Known as "SubBytes()" in the AES specification.
    fn substitute_bytes(&mut self) {
        let new_columns: Vec<Word> = self
            .state
            .get_columns()
            .iter_mut()
            .map(|clm| clm.subword())
            .collect();
        self.state = Block::new([
            new_columns[0].clone(),
            new_columns[1].clone(),
            new_columns[2].clone(),
            new_columns[3].clone(),
        ])
    }

    fn shift_rows(&mut self) {
        let old = self.state.get_columns();
        let mut new = old.clone();

        // for loops, who needs them, right???
        // this looks like a mess but it is
        // pretty easy to folow

        // consider the second row of the state
        // shift it rightwise by one
        new[0].set_byte(1, old[1][1]);
        new[1].set_byte(1, old[2][1]);
        new[2].set_byte(1, old[3][1]);
        new[3].set_byte(1, old[0][1]);

        // consider the third row of the state
        // shift it rightwise by two
        new[0].set_byte(2, old[2][2]);
        new[1].set_byte(2, old[3][2]);
        new[2].set_byte(2, old[0][2]);
        new[3].set_byte(2, old[1][2]);

        // you get the meaning, this time
        // shifting by three..
        new[0].set_byte(3, old[3][3]);
        new[1].set_byte(3, old[0][3]);
        new[2].set_byte(3, old[1][3]);
        new[3].set_byte(3, old[2][3]);

        self.state = Block::new(new);
    }

    fn mix_columns(&mut self) {
        let old = self.state.get_columns();
        let mut new = old.clone();

        let two = Byte::new(2);
        let three = Byte::new(3);

        for (i, clm) in old.iter().enumerate() {
            new[i].set_byte(0, two * clm[0] + three * clm[1] + clm[2] + clm[3]);
            new[i].set_byte(1, clm[0] + two * clm[1] + three * clm[2] + clm[3]);
            new[i].set_byte(2, clm[0] + clm[1] + two * clm[2] + three * clm[3]);
            new[i].set_byte(3, three * clm[0] + clm[1] + clm[2] + two * clm[3]);
        }

        self.state = Block::new(new)
    }

    fn add_round_key(&mut self, round: u8) {
        let round_by_nb = (round * Nb) as usize;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> Cipher {
        let input = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let cipher_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        Cipher::new(&cipher_key, &input)
    }

    #[test]
    fn creates_state_ok() {
        let expected = Block::new([
            Word::new_from_hex("3243f6a8"),
            Word::new_from_hex("885a308d"),
            Word::new_from_hex("313198a2"),
            Word::new_from_hex("e0370734"),
        ]);
        assert_eq!(cipher().state, expected);
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
        cipher.add_round_key(0);
        assert_eq!(cipher.state, expected)
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
}
