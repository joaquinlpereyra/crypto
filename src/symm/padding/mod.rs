/// A collection of padding algorithms.
#[derive(Clone)]
pub enum Padding {
    PKCS7,
    None,
}

/// Returns the padding of the data
pub fn get_pad(with: &Padding, data: &[u8], desired_len: u8) -> Option<Vec<u8>> {
    match with {
        Padding::PKCS7 => pad_PKCS7(data, desired_len),
        Padding::None => Some(data.to_owned()),
    }
}

pub fn pad(with: &Padding, mut data: Vec<u8>, desired_len: u8) {
    let pad = get_pad(with, &data, desired_len).unwrap();
    data.extend_from_slice(&pad);
}

/// Reverses the padding processes, returning the original data.
pub fn unpad(with: &Padding, data: &[u8]) -> Option<Vec<u8>> {
    match with {
        Padding::PKCS7 => unpad_PKCS7(data),
        Padding::None => Some(data.to_owned()),
    }
}

#[allow(non_snake_case)]
fn pad_PKCS7(data: &[u8], target_len: u8) -> Option<Vec<u8>> {
    // What a weird padding, this one, where even data
    // which fits the desired len will be padded... doubling its length!
    // if "hola" desired length is 0x04, so then shall i have
    // the string "hola\x04\x04\x04\x04" as return.
    // https://tools.ietf.org/html/rfc5652#section-6.3

    if data.len() as u8 > target_len {
        return None;
    }
    let data_len = data.len() as u8;
    let padding: u8 = target_len - module(data_len.into(), target_len.into()) as u8;
    let mut result: Vec<u8> = Vec::with_capacity(padding as usize);
    for _ in 0..padding {
        result.push(padding)
    }
    Some(result)
}

#[allow(non_snake_case)]
fn unpad_PKCS7(data: &[u8]) -> Option<Vec<u8>> {
    let len = data.len();
    let padding = *data.last().unwrap() as usize;
    if padding > len || padding == 0 {
        return None;
    }

    if data[len - padding..len]
        .iter()
        .all(|byte| *byte == padding as u8)
    {
        Some(data[0..len - padding].to_vec())
    } else {
        None
    }
}

/// Returns a `mod` b.
fn module(a: u64, b: u64) -> u64 {
    ((a % b) + b) % b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_no_pad_neccesary_but_PKCS7_is_weird() {
        let data = "YELLOW SUBMARINE";
        let expected =
            "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10".as_bytes();
        assert_eq!(pad_PKCS7(data.as_bytes(), 16).unwrap(), expected)
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_pad_with_PKCS7() {
        let data = "YELLOW S";
        let expected = "\x08\x08\x08\x08\x08\x08\x08\x08".as_bytes();
        assert_eq!(pad_PKCS7(data.as_bytes(), 16).unwrap(), expected)
    }

    #[test]
    #[allow(non_snake_case)]
    fn unpad_with_PKCS7() {
        let input = "YELLOW S\x08\x08\x08\x08\x08\x08\x08\x08".as_bytes();
        assert_eq!(unpad_PKCS7(input).unwrap(), "YELLOW S".as_bytes().to_vec())
    }

    #[test]
    #[allow(non_snake_case)]
    fn unpad_data_end_with_zero_is_none() {
        let input = "YELLOW S\x08\x08\x08\x08\x08\x08\x08\x00".as_bytes();
        assert!(unpad_PKCS7(input).is_none())
    }

    #[test]
    #[allow(non_snake_case)]
    fn unpad_invalid_is_none() {
        let input = "YELLOWSSSS";
        assert!(unpad_PKCS7(input.as_bytes()).is_none())
    }
}
