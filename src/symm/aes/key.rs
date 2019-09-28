use super::bytes::{Byte, Bytes};
use super::constants::SBOX;
use super::Nb;
use super::Rounds;
use std::ops::Index;
use std::vec;

pub struct Key {
    bytes: Bytes,
}

/// There are three possible key length for AES
/// In the AES Specification, the key length
/// is given the name `Nk`, representing the
/// number of bytes the key has: 4, 6 or 8.
#[derive(Clone, Copy)]
pub enum KeyLen {
    Four = 4,
    Six = 6,
    Eight = 8,
}

impl Key {
    pub fn new_of_128_bits(key: &[u8; 4]) -> Key {
        Key {
            bytes: Bytes::new(key),
        }
    }

    pub fn new_of_192_bits(key: &[u8; 6]) -> Key {
        Key {
            bytes: Bytes::new(key),
        }
    }

    pub fn new_of_256_bits(key: &[u8; 8]) -> Key {
        Key {
            bytes: Bytes::new(key),
        }
    }

    pub fn len(&self) -> KeyLen {
        match self.bytes.len() {
            4 => KeyLen::Four,
            6 => KeyLen::Six,
            8 => KeyLen::Eight,
            _ => panic!("impossible length for key"),
        }
    }
}

impl Index<usize> for Key {
    type Output = Byte;

    fn index(&self, i: usize) -> &Byte {
        return &self.bytes[i];
    }
}

impl IntoIterator for Key {
    type Item = Byte;
    type IntoIter = vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        return self.bytes.into_iter();
    }
}

/// AES generates a `Key Schedule` from the given key using
/// a key expansion algorithm.
pub struct KeySchedule {}

pub fn key_expansion(key: Key, rounds: Rounds) {
    let i = 0;
    // "The key expansion generates a total of Nb * (Nr+1) words"
    // FIPS-197 seciont 5.2
    // Nb is the number of bytes in a block, always 16, and Nr the number of rounds.
    let result = Vec::with_capacity((Nb * rounds as u8) as usize);
    for byte in key {}
}
