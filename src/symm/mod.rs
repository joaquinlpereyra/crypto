pub mod aes;
mod padding;

use padding::Padding;

pub fn encrypt(plain_text: &[u8], key: &[u8]) -> Vec<u8> {
    if plain_text.len() != 16 || key.len() != 128 {
        panic!()
    }
    return vec![];
}
