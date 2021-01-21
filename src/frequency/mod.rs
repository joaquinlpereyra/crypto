use std::collections::HashMap;
type Score = f32;

/// Given an ASCII Text, return a Score.
/// The higher the score, the more likely the
/// text is in English.
pub fn analysis(ascii_text: &str) -> Score {
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
