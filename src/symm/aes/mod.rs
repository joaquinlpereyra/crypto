mod block;
mod bytes;
mod constants;
mod key;

use block::Block;
use bytes::{Bytes, Endian};
use key::Key;

#[allow(non_upper_case_globals)]
static Nb: u8 = 4;

#[allow(non_snake_case)]
pub struct Cypher {
    Nr: u8,
    state: Block,
    key: Key,
}

impl Cypher {
    fn new(key: &[u8], msg: &[u8; 16]) -> Cypher {
        let rounds = match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            other => panic!(format!("impossible key length: {}", other)),
        };

        let key_bytes = Bytes::new(key, Endian::Big);
        let key = Key::new(key_bytes, rounds).unwrap_or_else(|| panic!("could not generate key"));

        Cypher {
            Nr: rounds,
            state: Block::new(&msg),
            key: key,
        }
    }
}
