use super::constants::{RCON, SBOX};
use std::fmt::{self, Debug, Write};
use std::ops::{Add, BitXor, Div, Index, Mul, Rem};
use std::vec;

// This module is used to create and manipulate
// bytes, words and other data structures
// in the AES Galoies Field of G(2^8).
// I got some help from the following pages,
// which I leave both for you to check out
// and for myself as reminders.
// (1) GF arithmetic: https://crypto.stackexchange.com/questions/2700/galois-fields-in-cryptography/2718#2718
// (2) Finite field arithmetic: https://en.wikipedia.org/wiki/Finite_field_arithmetic

/// The number of columns on a block.
/// Absolutely always four.
pub static NB: u8 = 4;

/// A block is a 4x4 matrix of words.
/// It is generally addresses by column.
#[derive(PartialEq, Clone)]
pub struct Block {
    columns: [Word; 4],
}

impl Block {
    /// Return a new block with the data given.
    /// The order of the columns will be respected.
    pub fn new(columns: [Word; 4]) -> Block {
        Self { columns }
    }

    /// Return a new block from the matrix given.
    /// Each inner array represents a column.
    pub fn new_from_u8(numbers: [[u8; 4]; 4]) -> Block {
        let mut zero = Self::zero();
        for (i, clm) in numbers.iter().enumerate() {
            let word = Word::new_from_numbers(&clm, Endian::Big);
            zero.columns[i] = word;
        }
        zero
    }

    /// Return the new _zero_ block.
    fn zero() -> Block {
        Block {
            columns: [Word::zero(), Word::zero(), Word::zero(), Word::zero()],
        }
    }

    /// Clone the columns of the block.
    pub fn clone_columns(&self) -> [Word; 4] {
        self.columns.clone()
    }

    /// Returns a flattened array of bytes
    pub fn flatten(&self) -> [Byte; 16] {
        let mut bytes = Vec::new();
        for clm in &self.columns.clone() {
            for i in 0..4 {
                bytes.push(clm[i])
            }
        }
        let mut arr = [Byte::new(0); 16];
        arr.copy_from_slice(&bytes);
        arr
    }

    /// Returns a flattened array of bytes
    pub fn flatten_into_u8(&self) -> [u8; 16] {
        let numbers: Vec<u8> = self.flatten().into_iter().map(|b| b.get_number()).collect();
        let mut arr = [0; 16];
        arr.copy_from_slice(&numbers);
        arr
    }

    /// Set a new value in the state
    fn set(&mut self, x: usize, y: usize, value: u8) {
        let clm = &self.columns[x as usize];
        let mut new_column = clm.clone();
        new_column.set_byte(y, Byte::new(value));
        self.columns[x as usize] = new_column;
    }

    /// Retrieve a value from the state
    fn get(&self, x: usize, y: usize) -> Byte {
        self.columns[x as usize][y]
    }

    fn get_column(&self, i: usize) -> Word {
        self.columns[i].clone()
    }
}

impl BitXor for Block {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut block = Block::zero();
        for i in 0..4 {
            let xor = self.get_column(i) ^ rhs.get_column(i);
            block.columns[i] = xor;
        }
        block
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\nclm1: {}\nclm2: {}\nclm3: {}\nclm4: {}\n",
            self.columns[0].to_hex(),
            self.columns[1].to_hex(),
            self.columns[2].to_hex(),
            self.columns[3].to_hex(),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Endian {
    Big,
    Little,
}

/// A simple collection of four bytes.
// The bytes are arranged in big endian.
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

    /// Creat a zero word
    pub fn zero() -> Word {
        Word {
            bytes: Bytes::new(&[0], Endian::Big),
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

    pub fn new_from_numbers(src: &[u8; 4], endianess: Endian) -> Word {
        let src_bytes = Bytes::new(src, endianess);
        let src_bytes = [src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3]];
        match endianess {
            Endian::Big => Self::new_from_big_endian(src_bytes),
            Endian::Little => Self::new_from_little_endian(src_bytes),
        }
    }

    /// Create a new word from a hex string.
    /// The hex string must have
    /// a length of exactly 8.
    pub fn new_from_hex(src: &str) -> Word {
        if src.len() != 8 {
            panic!("wrong length for hex string: {}", src);
        }
        Word {
            bytes: Bytes::new_from_hex_string(src),
        }
    }

    /// Return a new Word from the round constant
    pub fn rcon(i: u8) -> Word {
        let rcon = RCON[(i - 1) as usize];
        Word::new(
            [Byte::new(rcon), Byte::new(0), Byte::new(0), Byte::new(0)],
            Endian::Big,
        )
    }

    /// Returns a hex string
    /// representing the word.
    pub fn to_hex(&self) -> String {
        self.bytes.to_hex()
    }

    /// Sets a byte at a certain position to a new value.
    pub fn set_byte(&mut self, position: usize, new_byte: Byte) {
        self.bytes.bytes[position] = new_byte
    }

    /// Rotates a word.
    pub fn rotword(self) -> Word {
        Self::new([self[1], self[2], self[3], self[0]], Endian::Big)
    }

    /// Creates a new word through the AES sbox.
    pub fn subword(&mut self) -> Word {
        for i in 0..4 {
            let polynomial = self[i].polynomial;
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
            self.set_byte(i, Byte::new(substitution));
        }
        self.clone()
    }
}

impl PartialEq for Word {
    fn eq(&self, another: &Self) -> bool {
        self.bytes == another.bytes
    }
}

impl Index<usize> for Word {
    type Output = Byte;
    fn index(&self, i: usize) -> &Self::Output {
        &self.bytes[i]
    }
}

impl BitXor for Word {
    type Output = Self;

    /// Adds the two AES bytes.
    /// Addition in AES is defined as the XOR
    /// of the two bytes.
    /// See section 2.1.1 of the AES Proposal.
    fn bitxor(self, rhs: Self) -> Self {
        let mut res = self.clone();
        for i in 0..4 {
            res.set_byte(i, self.bytes[i] + rhs.bytes[i]);
        }
        res
    }
}

/// A nice holder for an arbitrary amount of bytes.
/// NOTE: the bytes are stored in big endian order.
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
        for s in src {
            bytes.push(Byte::new(*s));
        }
        Bytes { bytes }
    }

    fn new_from_little_endian(src: &[u8]) -> Bytes {
        let mut bytes = Vec::with_capacity(src.len());
        for s in src.iter().rev() {
            bytes.push(Byte::new(*s));
        }
        Bytes { bytes }
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
        for byte in &self.bytes {
            if let Err(_) = write!(&mut hex, "{:02x}", byte.n) {
                panic!("could not write to stdout.")
            }
        }
        hex
    }

    pub fn len(&self) -> usize {
        return self.bytes.len();
    }
}

impl PartialEq for Bytes {
    fn eq(&self, another: &Self) -> bool {
        self.bytes == another.bytes
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
    fn new_from_polynomial(polynomial: [u8; 8]) -> Self {
        Self {
            n: Self::make_number(&polynomial) as u8,
            polynomial: polynomial,
        }
    }

    pub fn get_number(&self) -> u8 {
        self.n
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
        polynomial.len() as u8 - polynomial.iter().rev().position(|b| *b == 1).unwrap_or(0) as u8
    }

    /// Divides and returns the result and the remainder.
    /// Unexposed, just use / and % operators.
    /// NOTE: both arguments must be passed in little endian
    /// [1] https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field
    fn divide(polynomial: &[u8], by: &[u8]) -> (u8, u8) {
        // check for an already reduced polynomial,
        let most_significant_polynomial = Self::most_significant(polynomial);
        let most_significant_by = Self::most_significant(by);
        if most_significant_polynomial < most_significant_by {
            return (0, Self::make_number(&polynomial) as u8);
        }

        // this shift makes the divisor aligned with the dividend
        let diff = most_significant_polynomial - most_significant_by;
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

impl PartialEq for Byte {
    fn eq(&self, another: &Self) -> bool {
        self.n == another.n
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

    #[test]
    fn test_rotword() {
        let temp = Word::new_from_hex("09cf4f3c");
        assert_eq!(temp.clone().rotword().to_hex(), "cf4f3c09");
    }

    #[test]
    fn test_rotword_then_subword() {
        let temp = Word::new_from_hex("09cf4f3c");
        assert_eq!(temp.clone().rotword().subword().to_hex(), "8a84eb01");
    }

    #[test]
    fn test_rcon() {
        assert_eq!(Word::rcon(1).to_hex(), "01000000");
    }

    #[test]
    fn test_rotword_then_subword_then_xor() {
        let temp = Word::new_from_hex("09cf4f3c");
        assert_eq!(
            (temp.clone().rotword().subword() ^ Word::rcon(1)).to_hex(),
            "8b84eb01"
        );
    }

    #[test]
    fn test_hex() {
        let one = Word::new_from_hex("09cf4f3c");
        assert_eq!(one.to_hex(), "09cf4f3c");
    }

    #[test]
    fn test_set_and_get_block() {
        let mut s = Block {
            columns: [
                Word::new_from_hex("00000000"),
                Word::new_from_hex("00000000"),
                Word::new_from_hex("00000000"),
                Word::new_from_hex("00000000"),
            ],
        };
        s.set(0, 1, 2);
        assert_eq!(Byte::new(2), s.get(0, 1));
    }

    #[test]
    fn test_get_column() {
        let block = Block::new([
            Word::new_from_hex("01020304"),
            Word::new_from_hex("05060708"),
            Word::new_from_hex("090a0b0c"),
            Word::new_from_hex("0d0e0f00"),
        ]);
        assert_eq!(Word::new_from_hex("05060708"), block.get_column(1));
    }

    #[test]
    fn test_xor_two_blocks() {
        let one = Block::new([
            Word::new_from_hex("aaaa0000"),
            Word::new_from_hex("aaaa0000"),
            Word::new_from_hex("aaaa0000"),
            Word::new_from_hex("aaaa0000"),
        ]);
        let two = Block::new([
            Word::new_from_hex("0000aaaa"),
            Word::new_from_hex("0000aaaa"),
            Word::new_from_hex("0000aaaa"),
            Word::new_from_hex("0000aaaa"),
        ]);
        let expected = Block::new([
            Word::new_from_hex("aaaaaaaa"),
            Word::new_from_hex("aaaaaaaa"),
            Word::new_from_hex("aaaaaaaa"),
            Word::new_from_hex("aaaaaaaa"),
        ]);
        assert_eq!(one ^ two, expected);
    }
}
