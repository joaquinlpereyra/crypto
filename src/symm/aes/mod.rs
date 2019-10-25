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
    fn new(key: &[u8], msg: &[u8; 16]) -> Self {
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

    fn new_from_hex(key: &str, msg: &str) -> Self {
        let Nr = match key.len() {
            8 => 10,
            10 => 12,
            12 => 14,
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

    fn encrypt(mut self) -> [u8; 16] {
        self.add_round_key(0);
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
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
}
