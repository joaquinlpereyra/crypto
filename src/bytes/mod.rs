/// XORs all bytes in bigger with smaller, cycling through.
/// If `smaller > bigger`, as most of smaller as possible will be xored
/// agains bigger, effectively switching places.
pub fn repeating_xor(bigger: &[u8], smaller: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for (plain_byte, key_byte) in bigger.iter().zip(smaller.iter().cycle()) {
        result.push(plain_byte ^ key_byte);
    }
    result
}

// Return an UTF8 encoded string from the bytes,
// if it can.
pub fn to_string(bytes: &[u8]) -> Option<String> {
    match String::from_utf8(bytes.to_owned()) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn test_repeating_xor() {
        assert_eq!(
            repeating_xor(&[0b01010111, 0b01101001], &[0b11110011]),
            vec![0b10100100, 0b10011010]
        )
    }
}
