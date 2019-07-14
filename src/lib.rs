pub mod text {
    use std::collections::HashMap;
    type Score = f32;

    /// Only supports English right now.
    pub fn frequency_analysis(ascii_text: &str) -> Score {
        // set the letter frequency table.
        let letter_by_frequency: HashMap<char, u8> = vec![
            ('e', 26),
            ('t', 25),
            ('a', 24),
            ('o', 23),
            ('i', 22),
            ('n', 21),
            ('s', 20),
            ('r', 19),
            ('h', 18),
            ('l', 17),
            ('d', 16),
            ('c', 15),
            ('u', 14),
            ('m', 13),
            ('f', 12),
            ('p', 11),
            ('g', 10),
            ('w', 9),
            ('y', 8),
            ('b', 7),
            ('v', 6),
            ('k', 5),
            ('x', 4),
            ('j', 3),
            ('q', 2),
            ('z', 1),
        ]
        .into_iter()
        .collect();
        let ascii_text: Vec<char> = ascii_text
            .chars()
            .filter(|c| {
                !c.is_ascii_punctuation()
                    && !c.is_numeric()
                    && c != &' '
                    && c != &'\''
                    && c != &' '
                    && c != &'\n'
                    && c != &'\t'
            })
            .map(|c| c.to_ascii_lowercase())
            .collect();

        let mut score = 0.0;
        for letter in &ascii_text {
            score += match letter_by_frequency.get(&letter) {
                Some(s) => *s as f64,
                // remove points for every weird character around
                None if letter.is_ascii_control() => -1000 as f64,
                None => -1000 as f64,
            }
        }

        // normalize the score.
        (score / (ascii_text.len() * 26) as f64) as f32
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_song() {
            let song = "cooking MC's like a pound of bacon";
            let score = frequency_analysis(song);
            assert!(score > 0.50);
        }

        #[test]
        fn test_full_of_e() {
            let txt = "eeeee";
            let score = frequency_analysis(txt);
            assert!(score == 1.00);
        }

        #[test]
        fn test_gibberish() {
            let txt = "lKTnLxpqDbwgNstXMdkPPKZmtAmBBKnqkQclYXBT";
            let score = frequency_analysis(txt);
            assert!(score < 0.50);
        }
    }
}

pub mod bytes {
    /// XORs all bytes in bigger with smaller.
    pub fn repeating_xor(bigger: &[u8], smaller: u8) -> Vec<u8> {
        let mut result = Vec::new();
        for byte in bigger {
            result.append(&mut xor(&[*byte], &[smaller]))
        }
        result
    }

    /// XORs array of bytes of the same size.
    pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut result = vec![0; x.len()];
        for i in 0..x.len() {
            result[i] = x[i] ^ y[i]
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
        use super::super::hex;
        use super::*;

        #[test]
        fn test_repeating_xor() {
            assert_eq!(
                repeating_xor(&[0b01010111, 0b01101001], 0b11110011),
                vec![0b10100100, 0b10011010]
            )
        }

        #[test]
        fn test_xor() {
            assert_eq!(
                xor(
                    &hex::from_string("1c0111001f010100061a024b53535009181c").unwrap(),
                    &hex::from_string("686974207468652062756c6c277320657965").unwrap()
                ),
                hex::from_string("746865206b696420646f6e277420706c6179").unwrap()
            )
        }
    }

}

pub mod hex {
    fn to_byte(a: u8, b: u8) -> u8 {
        a << 4 | b
    }

    pub fn to_bytes(src: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(src.len() / 2);
        for i in (0..src.len()).step_by(2) {
            match src.get(i + 1) {
                Some(_) => result.push(to_byte(src[i], src[i + 1])),
                None => result.push(to_byte(0x0, src[i])),
            }
        }
        result
    }

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
        Some(vec)
    }

    // Return an ASCII encoded string from a slice of hex numbers
    pub fn to_chars(src: &[u8]) -> Option<Vec<char>> {
        if src.len() % 2 != 0 {
            return None;
        }
        let mut result = Vec::new();
        for i in (0..src.len()).step_by(2) {
            let byte = to_byte(src[i], src[i + 1]);
            result.push(byte as char)
        }
        Some(result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_to_chars() {
            assert_eq!(to_chars(&[0x4, 0x1]).unwrap(), vec!['A'])
        }

    }
}

pub mod base64 {
    use super::hex;

    pub fn from_hex(input: &str) -> Option<Vec<u8>> {
        // base64 is only specified for octets.
        // a single hex character is only 4 bits.
        if input.len() % 2 != 0 {
            return None;
        }

        match hex::from_string(input) {
            Some(vec) => Some(from_raw_hex(&vec)),
            None => None,
        }
    }

    fn from_raw_hex(input: &[u8]) -> Vec<u8> {
        let table = [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
            'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '=',
        ];
        let mut result = vec![];

        // 24 bits needed, 6 hex.
        for i in (0..input.len()).step_by(6) {
            // base64 works in octets. two pairs of hex numbers make an octet
            // make three of those beautiful bytes. encode_group() will deal
            // with possibly non-existent bytes.
            let first_byte = to_byte(input.get(i), input.get(i + 1));
            let second_byte = to_byte(input.get(i + 2), input.get(i + 3));
            let third_byte = to_byte(input.get(i + 4), input.get(i + 5));

            for byte in &encode_group(&[first_byte, second_byte, third_byte]) {
                result.push(table[*byte as usize] as u8)
            }
        }

        result
    }

    fn encode_group(bytes: &[Option<u8>; 3]) -> [u8; 4] {
        // Warning, here be dragons.
        // base64 wants you to pad with zeroes, but only the byte needing it.
        // after that, you should just ouput '='.
        // that forces you to backtrack and check if the previous byte is present...
        // even if you already padded it with zeroes.
        let first = bytes[0].unwrap(); // the first one is always present.
        let second = bytes[1].unwrap_or(0);
        let third = bytes[2].unwrap_or(0);
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

    fn to_byte(a: Option<&u8>, b: Option<&u8>) -> Option<u8> {
        match (a, b) {
            (Some(a), Some(b)) => Some(hex::to_bytes(&[*a, *b])[0]),
            (Some(a), None) => Some(hex::to_bytes(&[*a, 0])[0]),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::str;

        #[test]
        fn test_easiest() {
            assert_eq!(str::from_utf8(&from_hex("FFFFFF").unwrap()), Ok("////"))
        }

        #[test]
        fn test_padding_needed() {
            assert_eq!(
                str::from_utf8(&from_hex("FFFFFFFF").unwrap()),
                Ok("/////w==")
            )
        }

        #[test]
        fn test_ultimate() {
            assert_eq!(str::from_utf8(&from_hex("49276d").unwrap()), Ok("SSdt"));
        }

        #[test]
        fn test_the_real_thing() {
            let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            assert_eq!(
                str::from_utf8(&from_hex(input).unwrap()),
                Ok("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
            )
        }
    }

}
