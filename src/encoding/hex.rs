/// Convert an array of bytes to a hex string.
pub fn to_string(src: &[u8]) -> String {
    src.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Convert a hex string to a vector of bytes.
pub fn from_string(src: &str) -> Option<Vec<u8>> {
    let chars: Vec<char> = src.chars().filter(|c| !c.is_whitespace()).collect();
    let mut vec = Vec::new();
    for (i, _) in chars.iter().enumerate().step_by(2) {
        let a = chars[i];
        let b = chars[i + 1];
        let hex_u8 = format!("{}{}", a, b);
        let number = u8::from_str_radix(&hex_u8, 16).unwrap();
        vec.push(number);
    }
    Some(vec)
}
