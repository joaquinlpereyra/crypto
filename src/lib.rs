pub mod bytes;
pub mod encoding;
pub mod frequency;
pub mod random;
pub mod symm;

pub fn position_of_block_in(ciphertext: &[u8], block: &[u8]) -> usize {
    let mut position = 0;
    for cipherblock in ciphertext.chunks(16) {
        if cipherblock != block {
            position += 1;
        } else {
            break;
        }
    }
    position
}

pub fn count_block_in_ciphertext(ciphertext: &[u8], block: &[u8]) -> usize {
    let mut repetitions = 0;
    for cipherblock in ciphertext.chunks(16) {
        if cipherblock == block {
            repetitions += 1;
        }
    }
    repetitions
}
