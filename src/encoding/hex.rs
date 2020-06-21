/// Convert an array of bytes to a hex string.
pub fn to_string(src: &[u8]) -> String {
    src.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Convert a string of hex characters to bytes.
pub fn from_string(src: &str) -> Option<Vec<u8>> {
    let mut vec = vec![0; src.len()];
    for (i, c) in src.to_ascii_lowercase().char_indices() {
        vec[i] = match c {
            '0' => 0x0,
            '1' => 0x1,
            '2' => 0x2,
            '3' => 0x3,
            '4' => 0x4,
            '5' => 0x5,
            '6' => 0x6,
            '7' => 0x7,
            '8' => 0x8,
            '9' => 0x9,
            'a' => 0xa,
            'b' => 0xb,
            'c' => 0xc,
            'd' => 0xd,
            'e' => 0xe,
            'f' => 0xf,
            _ => return None,
        }
    }
    Some(to_bytes(&vec))
}

fn to_byte(a: u8, b: u8) -> u8 {
    a << 4 | b
}

fn to_bytes(src: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(src.len() / 2);
    for i in (0..src.len()).step_by(2) {
        match src.get(i + 1) {
            Some(_) => result.push(to_byte(src[i], src[i + 1])),
            None => result.push(to_byte(0x0, src[i])),
        }
    }
    result
}
