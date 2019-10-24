use super::constants::{RCON, SBOX};
use std::fmt::Write;
use std::ops::{Add, BitXor, Div, Index, Mul, Rem};
use std::vec;

// This module is used to create and manipulate
// bytes in the AES Galoies Field of G(2^8).
// I got some help from the following pages,
// which I leave both for you to check out
// and for myself as reminders.
// (1) GF arithmetic: https://crypto.stackexchange.com/questions/2700/galois-fields-in-cryptography/2718#2718
// (2) Finite field arithmetic: https://en.wikipedia.org/wiki/Finite_field_arithmetic

pub enum Endian {
    Big,
    Little,
}

/// A simple collection of four bytes.
/// The bytes are arranged in little endian
/// order, but there are several methods on
/// a Word to pretend it is in big endian
/// if that's easier for some reason.
#[derive(Debug, Clone)]
pub struct Word {
    bytes: Bytes,
}

impl Word {
    /// Create a new word consisting of an array
    /// of four bytes.
    /// The bytes maybe ordered in small or little endian
    /// and that can be specified through the second parameter.
    pub fn new(src: [Byte; 4], endianness: Endian) -> Word {
        match endianness {
            Endian::Big => Self::new_from_big_endian(src),
            Endian::Little => Self::new_from_little_endian(src),
        }
    }

    /// Create a new word.
    /// The source bytes are expected to be
    /// in big endian.
    fn new_from_big_endian(src: [Byte; 4]) -> Word {
        Word {
            bytes: Bytes::new_from_array(src.to_vec(), Endian::Big),
        }
    }

    /// Creates a new word.
    /// The source bytes are expected to be in
    /// little endian.
    fn new_from_little_endian(src: [Byte; 4]) -> Word {
        Word {
            bytes: Bytes::new_from_array(src.to_vec(), Endian::Little),
        }
    }

    /// Gets a byte from the word.
    /// Acts as if the word is in big endian,
    /// so the most significant byte will be the
    /// one at position zero.
    pub fn get_bg(&self, i: u8) -> Byte {
        self.bytes.get_bg(i as usize)
    }

    /// Create a new word from a hex string.
    /// The hex string must have
    /// a length of exactly 8.
    pub fn new_from_hex(src: &str) -> Word {
        if src.len() != 8 {
            panic!("wrong length for hex string: {}", src);
        }
        Word::new_raw(Bytes::new_from_hex_string(src))
    }

    /// Returns a hex string
    /// representing the word.
    pub fn to_hex(&self) -> String {
        self.bytes.to_hex()
    }

    /// Return a new word filled with zeroes.
    fn new_zeroed() -> Word {
        Word {
            bytes: Bytes::new(&[0; 4], Endian::Big),
        }
    }

    /// Return a new word from some already
    /// create bytes.
    fn new_raw(src: Bytes) -> Word {
        if src.len() != 4 {
            panic!("wrong amount of bytes for word, got {}", src.len());
        }
        Word { bytes: src }
    }

    /// Sets a byte, acting as if the word is in big endian.
    fn set_byte_bg(&mut self, position: u8, new: Byte) {
        self.bytes.bytes[(4 - position - 1) as usize] = new;
    }

    /// Rotates a word.
    pub fn rotword(self) -> Word {
        Self::new(
            [
                self.get_bg(1),
                self.get_bg(2),
                self.get_bg(3),
                self.get_bg(0),
            ],
            Endian::Big,
        )
    }

    /// Performs the round constant operation on the word.
    pub fn rcon(i: u8) -> Word {
        let rcon = RCON[(i - 1) as usize];
        Word::new(
            [Byte::new(rcon), Byte::new(0), Byte::new(0), Byte::new(0)],
            Endian::Big,
        )
    }

    /// Creates a new word through the AES sbox.
    pub fn subword(self) -> Word {
        let mut word = Word::new_zeroed();
        for i in 0..4 {
            let polynomial = self.get_bg(i).polynomial;
            let x = Byte::new_from_polynomial([
                polynomial[0],
                polynomial[1],
                polynomial[2],
                polynomial[3],
                0,
                0,
                0,
                0,
            ])
            .n;
            let y = Byte::new_from_polynomial([
                polynomial[4],
                polynomial[5],
                polynomial[6],
                polynomial[7],
                0,
                0,
                0,
                0,
            ])
            .n;
            let substitution = SBOX[y as usize][x as usize];
            word.set_byte_bg(i as u8, Byte::new(substitution));
        }
        word
    }
}

impl BitXor for Word {
    type Output = Self;

    /// Adds the two AES bytes.
    /// Addition in AES is defined as the XOR
    /// of the two bytes.
    /// See section 2.1.1 of the AES Proposal.
    fn bitxor(self, rhs: Self) -> Self {
        let mut res = Self::new_zeroed();
        for i in 0..4 {
            res.bytes.bytes[i] = self.bytes.bytes[i] + rhs.bytes.bytes[i];
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotword() {
        let temp = Word::new_raw(Bytes::new_from_hex_string("09cf4f3c"));
        assert_eq!(temp.clone().rotword().to_hex(), "cf4f3c09");
        assert_eq!(temp.clone().rotword().subword().to_hex(), "8a84eb01");
        assert_eq!(Word::rcon(1).to_hex(), "01000000");
        assert_eq!(
            (temp.clone().rotword().subword() ^ Word::rcon(1)).to_hex(),
            "8b84eb01"
        );
    }

    #[test]
    fn test_hex() {
        let one = Bytes::new_from_hex_string("09cf4f3c");
        assert_eq!(one.to_hex(), "09cf4f3c");
    }

}

/// A nice holder for an arbitrary amount of bytes.
/// NOTE: the bytes are stored in little endian order.
/// Number 0x0901 is stored as [0x01, 0x09]
#[derive(Debug, Clone)]
pub struct Bytes {
    bytes: Vec<Byte>,
}

impl Bytes {
    /// Create a new array of bytes.
    pub fn new(src: &[u8], endianness: Endian) -> Bytes {
        match endianness {
            Endian::Big => Self::new_from_big_endian(src),
            Endian::Little => Self::new_from_little_endian(src),
        }
    }

    fn new_from_big_endian(src: &[u8]) -> Bytes {
        let mut bytes = Vec::with_capacity(src.len());
        for s in src.iter().rev() {
            bytes.push(Byte::new(*s));
        }
        Bytes { bytes }
    }

    fn new_from_little_endian(src: &[u8]) -> Bytes {
        let mut bytes = Vec::with_capacity(src.len());
        for s in src {
            bytes.push(Byte::new(*s));
        }
        Bytes { bytes }
    }

    /// Gets a byte from the word.
    /// Acts as if the word is in big endian,
    /// so the most significant byte will be the
    /// one at position zero.
    pub fn get_bg(&self, i: usize) -> Byte {
        let target = self.bytes.len() - i - 1;
        self.bytes[target as usize]
    }

    pub fn new_from_array(src: Vec<Byte>, endianess: Endian) -> Bytes {
        let nums: Vec<u8> = src.iter().map(|b| b.n).collect();
        Self::new(&nums, endianess)
    }

    /// Must be padded!
    pub fn new_from_hex_string(src: &str) -> Bytes {
        let chars: Vec<char> = src.chars().filter(|c| !c.is_whitespace()).collect();
        let mut vec = Vec::new();
        for (i, _) in chars.iter().enumerate().step_by(2) {
            let a = chars[i];
            let b = chars[i + 1];
            let hex_u8 = format!("{}{}", a, b);
            let number = u8::from_str_radix(&hex_u8, 16).unwrap();
            vec.push(number);
        }
        Bytes::new(&vec, Endian::Big)
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::new();
        for byte in self.bytes.iter().rev() {
            write!(&mut hex, "{:02x}", byte.n);
        }
        hex
    }

    pub fn len(&self) -> usize {
        return self.bytes.len();
    }
}

impl Index<usize> for Bytes {
    type Output = Byte;
    fn index(&self, i: usize) -> &Self::Output {
        &self.bytes[i]
    }
}

impl IntoIterator for Bytes {
    type Item = Byte;
    type IntoIter = vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        return self.bytes.into_iter();
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Byte {
    n: u8,
    polynomial: [u8; 8],
}

impl Byte {
    /// Create a new AES byte from an unsigned integer.
    pub fn new(n: u8) -> Self {
        let polynomial = Self::make_polynomial(n);
        Self { n, polynomial }
    }

    /// Create a new AES byte from an array of bits.
    /// The array is expected in little endian.
    pub fn new_from_polynomial(polynomial: [u8; 8]) -> Self {
        Self {
            n: Self::make_number(&polynomial) as u8,
            polynomial: polynomial,
        }
    }

    /// Returns the binary representation of a number
    /// in little-endian format.
    fn make_polynomial(n: u8) -> [u8; 8] {
        let mut n = n;
        let mut polynomial = [0; 8];
        let base: u8 = 2;
        for i in (0..8).rev() {
            let position_value = base.pow(i as u32);
            polynomial[i] = n / position_value;
            if polynomial[i] == 1 {
                n -= position_value
            }
        }
        polynomial
    }

    /// Returns a number from a polynomial representation
    fn make_number(polynomial: &[u8]) -> u32 {
        polynomial
            .iter()
            .enumerate()
            .rev()
            .map(|(i, b)| (*b as u32) * (2 as i32).pow(i as u32) as u32)
            .sum()
    }

    /// Gets the position of the most significant bit from an slice
    /// of bits in big endian.
    fn most_significant(polynomial: &[u8]) -> u8 {
        (polynomial.len() - polynomial.iter().rev().position(|b| *b == 1).unwrap_or(0)) as u8
    }

    /// Divides and returns the result and the remainder.
    /// Unexposed, just use / and % operators.
    /// NOTE: both arguments must be passed in little endian
    /// [1] https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field
    fn divide(polynomial: &[u8], by: &[u8]) -> (u8, u8) {
        // the shift makes the divisor aligned with the dividend
        let diff = Self::most_significant(polynomial) - Self::most_significant(by);
        let mut divisor = Self::make_number(by) << diff;
        let mut remainder = Self::make_number(polynomial);

        // Do while we can push the divisor to the right.
        // If a new temporal remainder is bigger than the last one,
        // we must not update its value, instead just try with a
        // smaller divisor.
        let mut result = 0;
        for _ in 0..diff + 1 {
            let new_remainder = remainder ^ divisor;
            if new_remainder <= remainder {
                remainder = new_remainder;
                result += 1;
            }
            divisor = divisor >> 1;
        }

        (result, remainder as u8)
    }
}

impl Add for Byte {
    type Output = Self;

    /// Adds the two AES bytes.
    /// Addition in AES is defined as the XOR
    /// of the two bytes.
    /// See section 2.1.1 of the AES Proposal.
    fn add(self, rhs: Self) -> Self {
        Byte::new(self.n ^ rhs.n)
    }
}

impl Div for Byte {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        // A division by two bytes will always be
        // less than the first parameter, so it is
        // safe to asume it is a byte too and will
        // not overflow.
        let res = Self::divide(&self.polynomial, &rhs.polynomial);
        Byte::new(res.0)
    }
}

impl Rem for Byte {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self {
        let res = Self::divide(&self.polynomial, &rhs.polynomial);
        Byte::new(res.1)
    }
}

impl Mul for Byte {
    type Output = Self;

    /// Multiplies two AES bytes.
    ///
    /// Multiplication in AES is defined
    /// as the multiplication of the two bytes
    /// modulo M(x), which is 0x11B.
    /// See section 2.1.2 of the AES proposal.
    fn mul(self, rhs: Self) -> Self {
        let mut mult = [0; 16];
        for (i, a) in self.polynomial.iter().enumerate() {
            for (j, b) in rhs.polynomial.iter().enumerate() {
                if a * b == 1 {
                    mult[i + j] ^= 1
                }
            }
        }
        let mx = [1, 1, 0, 1, 1, 0, 0, 0, 1];
        let (_, remainder) = Self::divide(&mult, &mx);
        Self::new(remainder as u8)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_make_polynomial() {
        assert_eq!(Byte::make_polynomial(255), [1, 1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(Byte::make_polynomial(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Byte::make_polynomial(97), [1, 0, 0, 0, 0, 1, 1, 0]);
    }

    #[test]
    fn test_new_from_polynomial() {
        assert_eq!(0, Byte::new_from_polynomial([0, 0, 0, 0, 0, 0, 0, 0]).n);
        assert_eq!(255, Byte::new_from_polynomial([1, 1, 1, 1, 1, 1, 1, 1]).n);
        assert_eq!(97, Byte::new_from_polynomial([1, 0, 0, 0, 0, 1, 1, 0]).n);
    }

    #[test]
    fn test_multiplication() {
        assert_eq!((Byte::new(0x57) * Byte::new(0x83)).n, 0xC1);
    }

    #[test]
    fn test_remainder() {
        let first = [1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0];
        let second = vec![1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0];
        let (_, remainder) = Byte::divide(&first, &second);
        assert_eq!(remainder, 193);
    }

    #[test]
    fn test_divition() {
        let first = vec![0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0];
        let second = vec![1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0];
        let result = Byte::divide(&first, &second);
        assert_eq!(result.0, 0x05);
        assert_eq!(result.1, 0x01)
    }

}
