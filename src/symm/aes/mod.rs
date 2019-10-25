mod bytes;
mod constants;
mod key;

use bytes::{Block, Byte, Bytes, Endian};
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

        Cypher { Nr, state, key }
    }
}
