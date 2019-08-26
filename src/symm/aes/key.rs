use super::bytes::Bytes;
use super::constants::SBOX;

pub struct Key {
    key: Bytes,
    len: KeyLen,
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
            key: Bytes::new(key),
            len: KeyLen::Four,
        }
    }

    pub fn new_of_192_bits(key: &[u8; 6]) -> Key {
        Key {
            key: Bytes::new(key),
            len: KeyLen::Six,
        }
    }

    pub fn new_of_256_bits(key: &[u8; 8]) -> Key {
        Key {
            key: Bytes::new(key),
            len: KeyLen::Eight,
        }
    }

    pub fn len(&self) -> KeyLen {
        self.len
    }
}

/// AES generates a `Key Schedule` from the given key using
/// a key expansion algorithm.
pub struct KeySchedule {}

pub fn key_expansion(key: Key) {}
