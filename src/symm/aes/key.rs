use super::bytes::{Bytes, Endian, Word, NB};
use super::constants::SBOX;
use std::fmt::Write;
use std::ops::Index;
use std::vec;

pub struct Key {
    words: Vec<Word>,
}

impl Key {
    pub fn new(key: Bytes, rounds: u8) -> Option<Key> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return None;
        }
        let words = Self::key_expansion(key, rounds);
        return Some(Key { words });
    }

    /// Expands the given keys.
    /// Will generate Nb * (rounds + 1) words as a key.
    fn key_expansion(key: Bytes, rounds: u8) -> Vec<Word> {
        // "The key expansion generates a total of Nb * (Nr+1) words"
        // FIPS-197 seciont 5.2
        // Nb is the number of columns in a block, always 4, and Nr the number of rounds.
        let mut i = 0 as usize;
        let mut words = Vec::with_capacity((NB * (rounds + 1)) as usize);
        let key_length = key.len() as u8 / 4;
        while i < key_length as usize {
            let bytes = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
            let word = Word::new(bytes, Endian::Big);
            words.push(word);
            i += 1;
        }
        assert!(i == key_length as usize);

        while i < (NB * (rounds + 1)) as usize {
            let mut temp = words[i - 1].clone();
            if i as u8 % key_length == 0 {
                temp = temp.rotword().subword(SBOX) ^ Word::rcon(i as u8 / key_length);
            } else if key_length == 8 && i as u8 % key_length == 4 {
                temp = temp.subword(SBOX);
            }
            // i could use mem::swap but heck why not clone
            // im doing more complicated things here cowboy
            let new_word = words[i - key_length as usize].clone() ^ temp;
            words.push(new_word);
            i += 1;
        }
        assert!(words.len() == (NB * (rounds + 1)) as usize);
        words
    }

    pub fn len(&self) -> u8 {
        self.words.len() as u8
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::new();
        for word in &self.words {
            if let Err(_) = write!(hex, "{}", word.to_hex()) {
                panic!("could not write to stdout.")
            }
        }
        hex
    }
}

impl Index<usize> for Key {
    type Output = Word;

    fn index(&self, i: usize) -> &Word {
        return &self.words[i];
    }
}

impl IntoIterator for Key {
    type Item = Word;
    type IntoIter = vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        return self.words.into_iter();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_expansion_128_bits() {
        let key = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
        let bytes = Bytes::new_from_hex_string(key);
        let key = Key::new(bytes, 10).unwrap();
        assert_eq!(key.len(), 4 * 11);
        assert_eq!(key.words[4].to_hex(), "a0fafe17");
        assert_eq!(key.words[8].to_hex(), "f2c295f2");
        assert_eq!(key.words[20].to_hex(), "d4d1c6f8");
        assert_eq!(key.words[43].to_hex(), "b6630ca6");
    }

    #[test]
    fn test_key_expansion_192_bits() {
        let key = "8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b";
        let bytes = Bytes::new_from_hex_string(key);
        let key = Key::new(bytes, 12).unwrap();
        assert_eq!(key.len(), 4 * 13, "key length is wrong");
        assert_eq!(key.words[6].to_hex(), "fe0c91f7");
        assert_eq!(key.words[8].to_hex(), "ec12068e");
        assert_eq!(key.words[20].to_hex(), "a448f6d9");
        assert_eq!(key.words[43].to_hex(), "ad07d753");
        assert_eq!(key.words[51].to_hex(), "01002202");
    }

    #[test]
    fn test_key_expansion_256_bits() {
        let key = "
60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81
1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4";
        let bytes = Bytes::new_from_hex_string(key);
        let key = Key::new(bytes, 14).unwrap();
        assert_eq!(key.len(), 4 * 15, "key length is wrong");
        assert_eq!(key.words[8].to_hex(), "9ba35411");
        assert_eq!(key.words[20].to_hex(), "b5a9328a");
        assert_eq!(key.words[43].to_hex(), "9674ee15");
        assert_eq!(key.words[51].to_hex(), "7401905a");
        assert_eq!(key.words[59].to_hex(), "706c631e");
    }
}
