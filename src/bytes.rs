/// XORs all bytes in bigger with smaller, cycling through.
/// If `smaller > bigger`, as most of smaller as possible will be xored
/// agains bigger, effectively switching places.
pub fn repeating_xor(bigger: &[u8], smaller: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for (plain_byte, key_byte) in bigger.into_iter().zip(smaller.into_iter().cycle()) {
        result.append(&mut xor(&[*plain_byte], &[*key_byte]).unwrap())
    }
    result
}

/// XORs array of bytes of the same size.
fn xor(x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
    if x.len() != y.len() {
        return None;
    }
    let mut result = vec![0; x.len()];
    for i in 0..x.len() {
        result[i] = x[i] ^ y[i]
    }
    Some(result)
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

    #[test]
    fn test_xor() {
        assert_eq!(
            xor(
                &hex::from_string("1c0111001f010100061a024b53535009181c").unwrap(),
                &hex::from_string("686974207468652062756c6c277320657965").unwrap()
            )
            .unwrap(),
            hex::from_string("746865206b696420646f6e277420706c6179").unwrap()
        )
    }
}
