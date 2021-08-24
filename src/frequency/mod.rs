use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;
type Score = f32;

pub const LETTER_BY_FREQUENCY: [(char, u8); 26] = [
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
];

pub fn commonth_byte(ciphertext: &[u8]) -> Vec<(&u8, usize)> {
    let mut counts = BTreeMap::new();
    for byte in ciphertext.iter() {
        *counts.entry(byte).or_insert(0) += 1;
    }

    let mut v = Vec::from_iter(counts.into_iter());
    v.sort_by(|&(_, a), &(_, b)| b.cmp(&a));
    v
}

pub fn triagrams_present(ascii_text: &str) -> Score {
    if ascii_text.contains("the") {
        return 13.0;
    } else if ascii_text.contains("and") {
        return 12.0;
    } else if ascii_text.contains("tha") {
        return 11.0;
    } else if ascii_text.contains("ent") {
        return 10.0;
    } else if ascii_text.contains("ing") {
        return 9.0;
    } else if ascii_text.contains("ion") {
        return 8.0;
    }
    return 0.0;
}

/// Given an ASCII Text, return a Score.
/// The higher the score, the more likely the
/// text is in English.
pub fn analysis(ascii_text: &str) -> Score {
    // set the letter frequency table.
    let letter_by_frequency: HashMap<char, u8> = LETTER_BY_FREQUENCY.to_vec().into_iter().collect();
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
        let score = analysis(song);
        assert!(score > 0.50);
    }

    #[test]
    fn test_full_of_e() {
        let txt = "eeeee";
        let score = analysis(txt);
        assert!(score == 1.00);
    }

    #[test]
    fn test_gibberish() {
        let txt = "lKTnLxpqDbwgNstXMdkPPKZmtAmBBKnqkQclYXBT";
        let score = analysis(txt);
        assert!(score < 0.50);
    }
}
