mod block;
mod bytes;

use block::Block;
use bytes::Byte;

pub enum KeyLength {
    Bits128,
    Bits192,
    Bits256,
}
