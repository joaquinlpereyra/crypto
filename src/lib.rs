pub mod encoding;
pub mod symm;

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
        use super::super::hex;
        use super::*;

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

    pub fn to_string(src: &[u8]) -> String {
        src.iter().map(|b| format!("{:02X}", b)).collect()
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
        Some(to_bytes(&vec))
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
