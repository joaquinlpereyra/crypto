use std::ops::{Add, Div, Mul, Rem};

#[derive(Debug)]
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
    /// The array is expected in big endian.
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
    /// NOTE: both arguments must be passed in big endian
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
