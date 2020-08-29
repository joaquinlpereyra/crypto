pub mod encoding;
pub mod random;
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
}
