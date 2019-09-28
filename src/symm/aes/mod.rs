mod block;
mod bytes;
mod constants;
mod key;

use block::Block;
use key::{Key, KeyLen};

static Nb: u8 = 16;

/// There are three possible round setting in AES
/// They are entirely dependant on the KeyLength,
/// and are called `Nr` in the AES specification.
enum Rounds {
    Nr10 = 10,
    Nr12 = 12,
    Nr14 = 14,
}

#[allow(non_snake_case)]
pub struct Cypher {
    Nr: Rounds,
    state: Block,
    key: Key,
}

impl Cypher {
    fn new(key: Key, msg: &[u8; 16]) -> Cypher {
        let rounds = match key.len() {
            KeyLen::Four => Rounds::Nr10,
            KeyLen::Six => Rounds::Nr12,
            KeyLen::Eight => Rounds::Nr14,
        };

        Cypher {
            Nr: rounds,
            state: Block::new(&msg),
            key: key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}
