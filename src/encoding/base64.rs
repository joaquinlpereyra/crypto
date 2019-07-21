/// The base64 alphabet table.
const TABLE: [char; 65] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/', '=',
];

/// Encodes arbitrary bytes to a base64 string.
pub fn encode(data: &[u8]) -> String {
    let encoded = raw_encode(data);
    let mut string = String::with_capacity(data.len() * (4 / 3));
    for byte in encoded {
        string.push(TABLE[byte as usize])
    }
    string
}

/// Encode arbitrary bytes and returns a vector
/// with bytes. Each byte in the returning vector
/// indicates the position of the encoding character.
fn raw_encode(data: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    for i in (0..data.len()).step_by(3) {
        let first_byte = data.get(i);
        let second_byte = data.get(i + 1);
        let third_byte = data.get(i + 2);

        for byte in &encode_group(&[first_byte, second_byte, third_byte]) {
            result.push(*byte)
        }
    }

    result
}

/// Encodes a group of three bytes to a group of 4 base64 bytes.
/// The first byte of the group must always be something.
/// The other two bytes are optional, and data will  be padded
/// accordingly.
fn encode_group(bytes: &[Option<&u8>; 3]) -> [u8; 4] {
    // Warning, here be dragons.
    // base64 wants you to pad with zeroes, but only the byte needing it.
    // after that, you should just ouput '='.
    // that forces you to backtrack and check if the previous byte is present...
    // even if you already padded it with zeroes.
    let first = bytes[0].unwrap(); // the first one is always present.
    let second = bytes[1].unwrap_or(&0);
    let third = bytes[2].unwrap_or(&0);
    let second_is_some = bytes[1].is_some();
    let third_is_some = bytes[2].is_some();

    // took me only two hours to came with the
    // simplest mask idea.
    // this comment is the only place i'll ever admit to it.
    [
        (first & 0b_1111_1100) >> 2,
        (first & 0b_0000_0011) << 4 | (second & 0b_1111_0000) >> 4,
        match second_is_some {
            true => (second & 0b_0000_1111) << 2 | (third & 0b_1100_0000) >> 6,
            _ => 64,
        },
        match third_is_some {
            true => third & 0b_0011_1111,
            _ => 64,
        },
    ]
}

/// Decode an ASCII base64 string to bytes.
pub fn decode(data: &str) -> Option<Vec<u8>> {
    if data.len() % 4 != 0 {
        return None;
    }
    decode_raw(data.as_bytes())
}

/// Decode a group of raw bytes to a vector of bytes.
fn decode_raw(bytes: &[u8]) -> Option<Vec<u8>> {
    let non_ascii = match ascii_to_base64(bytes) {
        Some(bytes) => bytes,
        None => return None,
    };
    let mut decoded = Vec::with_capacity(bytes.len() * (3 / 4));
    for i in (0..non_ascii.len()).step_by(4) {
        let decoded_group = decode_group(&[
            non_ascii[i],
            non_ascii[i + 1],
            non_ascii[i + 2],
            non_ascii[i + 3],
        ]);
        let decoded_group: Vec<u8> = decoded_group
            .iter()
            .filter(|b| b.is_some())
            .map(|b| b.unwrap())
            .collect();
        decoded.extend_from_slice(&decoded_group);
    }
    Some(decoded)
}

/// Return the base64 values of each byte in an ASCII-encoded
/// byte slice.
fn ascii_to_base64(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut non_ascii = Vec::with_capacity(bytes.len());
    for b in bytes {
        non_ascii.push(match *b as char {
            'A'...'Z' => b - 65,
            'a'...'z' => b - 71,
            '0'...'9' => b + 4,
            '+' => 62,
            '/' => 63,
            '=' => 64,
            _ => return None,
        });
    }
    Some(non_ascii)
}

/// Decode a group of 4 base64 bytes to 3 raw bytes.
fn decode_group(bytes: &[u8; 4]) -> [Option<u8>; 3] {
    let (first, second, third, fourth) = (bytes[0], bytes[1], bytes[2], bytes[3]);
    [
        Some((first & 0b_0011_1111) << 2 | (second & 0b_0011_0000) >> 4),
        match third {
            64 => None,
            _ => Some((second & 0b_0000_1111) << 4 | (third & 0b_0011_1100) >> 2),
        },
        match fourth {
            64 => None,
            _ => Some((third & 0b_0000_0011) << 6 | fourth),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::super::super::hex;
    use super::*;
    use std::str;

    #[test]
    fn test_encoding() {
        assert_eq!(encode("hola".as_bytes()), "aG9sYQ==");
    }

    #[test]
    fn test_decoding() {
        assert_eq!(str::from_utf8(&decode("aG9sYXhh").unwrap()), Ok("holaxa"));
        assert_eq!(str::from_utf8(&decode("aG9sYQ==").unwrap()), Ok("hola"));
    }
    #[test]
    fn test_easiest() {
        let input = [255, 255, 255];
        assert_eq!(&encode(&input), "////");
    }

    #[test]
    fn test_padding_needed() {
        let input = [255, 255, 255, 255];
        assert_eq!(&encode(&input), "/////w==");
    }

    #[test]
    fn test_ultimate() {
        let input = [0x49, 0x27, 0x6d];
        assert_eq!(&encode(&input), "SSdt");
    }

    #[test]
    fn test_the_real_thing() {
        let input = hex::from_string(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
        )
        .unwrap();
        assert_eq!(
            &encode(&input),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }
}
