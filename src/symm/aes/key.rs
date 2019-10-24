use super::bytes::{Bytes, Endian, Word};
use super::Nb;
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
        let mut words = Vec::with_capacity((Nb * (rounds + 1)) as usize);
        let key_length = key.len() as u8 / 4;
        while i < key_length as usize {
            let bytes = [
                key.get_bg(4 * i),
                key.get_bg(4 * i + 1),
                key.get_bg(4 * i + 2),
                key.get_bg(4 * i + 3),
            ];
            let word = Word::new(bytes, Endian::Big);
            words.push(word);
            i += 1;
        }
        assert!(i == key_length as usize);

        while i < (Nb * (rounds + 1)) as usize {
            let mut temp = words[i - 1].clone();
            if i as u8 % key_length == 0 {
                temp = temp.rotword().subword() ^ Word::rcon(i as u8 / key_length);
            } else if key_length == 8 && i as u8 % key_length == 4 {
                temp = temp.subword();
            }
            // i could use mem::swap but heck why not clone
            // im doing more complicated things here cowboy
            let new_word = words[i - key_length as usize].clone() ^ temp;
            words.push(new_word);
            i += 1;
        }
        assert!(words.len() == (Nb * (rounds + 1)) as usize);
        words
    }

    pub fn len(&self) -> u8 {
        self.words.len() as u8
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
    fn test_key_expansion() {
        let key = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
        let bytes = Bytes::new_from_hex_string(key);
        let key = Key::new(bytes, 10).unwrap();
        assert_eq!(key.len(), 4 * 11);
        assert_eq!(key.words[4].to_hex(), "a0fafe17");
        assert_eq!(key.words[8].to_hex(), "f2c295f2");
        assert_eq!(key.words[20].to_hex(), "d4d1c6f8");
        assert_eq!(key.words[43].to_hex(), "b6630ca6");
    }

}
