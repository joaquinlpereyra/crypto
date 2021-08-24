use std::fs::File;
use std::io::{Error, Read};
use std::{error, result};

type Result<T> = result::Result<T, Box<dyn error::Error>>;

pub fn get_random(bytes: usize) -> Vec<u8> {
    let mut source = Urandom::new().unwrap();
    source.get(bytes).unwrap()
}

pub fn in_range(floor: usize, ceiling: usize) -> usize {
    let mut source = Urandom::new().unwrap();
    source.in_range(floor, ceiling).unwrap()
}

pub fn flip_coin() -> bool {
    let mut source = Urandom::new().unwrap();
    source.flip_coin().unwrap()
}

pub trait Random {
    fn in_range(&mut self, floor: usize, ceiling: usize) -> Result<usize>;
    fn flip_coin(&mut self) -> Result<bool>;
    fn get(&mut self, bytes: usize) -> Result<Vec<usize>>;
}

pub struct Urandom {
    file: File,
}

impl Urandom {
    pub fn new() -> Result<Self> {
        Ok(Urandom {
            file: File::open("/dev/urandom")?,
        })
    }
}

impl Random for Urandom {
    fn in_range(&mut self, floor: usize, ceiling: usize) -> Result<usize> {
        let random = self.get(1)?[0];
        Ok((random as usize + floor).rem_euclid(floor + ceiling))
    }

    fn flip_coin(&mut self) -> Result<bool> {
        Ok(self.in_range(0, 2)? == 0)
    }

    fn get(&mut self, bytes: usize) -> Result<Vec<usize>> {
        let mut randoms = vec![0; bytes];
        &self.file.read_exact(&mut randoms)?;
        Ok(randoms.into_iter().map(|i| i as usize).collect())
    }
}

pub struct MersenneTwister {
    n: usize, // degree
    m: usize, // middle word, 1 <= m < n
    a: usize, // coefficients of matrix
    b: usize, // bitmasks
    c: usize,
    s: usize,
    t: usize,
    u: usize,
    d: usize, // something & d is a w-sized workd
    l: usize,

    lower_mask: usize,
    upper_mask: usize,
    state: Vec<usize>,
    index: usize,
}

impl MersenneTwister {
    pub fn new(seed: usize) -> Self {
        let (w, n, m, r) = (32, 624, 397, 31);
        let (u, d) = (11, 0xFFFFFFFF);
        let (s, b) = (7, 0x9D2C5680);
        let (t, c) = (15, 0xEFC60000);
        let a = 0x9908B0DF;
        let l = 18;
        let f = 1812433253;

        // lower mask will get the least
        // signifcant r bits
        let lower_mask = (1 << r) - 1;

        // upper mask will get the most significant
        // w - r bits
        let upper_mask = ((1 << (w - r)) - 1) << (w - 1);

        let mut state = vec![seed; n];
        for i in 1..state.len() {
            let prev = state[i - 1];
            state[i] = (f * (prev ^ (prev >> (w - 2))) + i) & d;
        }

        Self {
            n,
            m,
            a,
            b,
            c,
            s,
            t,
            u,
            d,
            l,
            state,
            index: n, // force twist() on first call to next()
            lower_mask,
            upper_mask,
        }
    }

    fn twist(&mut self) {
        for i in 0..self.state.len() {
            let x = (self.state[i] & self.upper_mask)
                + (self.state[(i + 1).rem_euclid(self.n)] & self.lower_mask);
            let mut x_a = x >> 1;
            if x.rem_euclid(2) != 0 {
                x_a = x_a ^ self.a;
            }
            self.state[i] = self.state[(i + self.m).rem_euclid(self.n)] ^ x_a
        }
        self.index = 0;
    }
}

impl Random for MersenneTwister {
    fn in_range(&mut self, floor: usize, ceiling: usize) -> Result<usize> {
        let random = self.next().unwrap();
        Ok((random + floor).rem_euclid(floor + ceiling))
    }

    fn flip_coin(&mut self) -> Result<bool> {
        Ok(self.in_range(0, 2)? == 0)
    }

    fn get(&mut self, bytes: usize) -> Result<Vec<usize>> {
        Ok(self.take(bytes).collect())
    }
}

impl Iterator for MersenneTwister {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.index > self.n {
            panic!("impossible, index is bigger than degree");
        }
        if self.index == self.n {
            self.twist();
        }

        let mut y = self.state[self.index];
        y = y ^ ((y >> self.u) & self.d);
        y = y ^ ((y << self.s) & self.b);
        y = y ^ ((y << self.t) & self.c);
        y = y ^ (y >> self.l);

        self.index += 1;
        Some(y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, BufRead};

    #[test]
    fn test_mersenne_twister() -> Result<()> {
        let mut mersenne = MersenneTwister::new(5489);
        let test_vector = File::open("src/random/tests/mersenne_vector.txt")?;
        let lines = io::BufReader::new(test_vector)
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.starts_with("//") && !l.is_empty()); // skip comments

        for (i, line) in lines.enumerate() {
            let expected: usize = line.parse()?;
            let got = mersenne.next();
            assert_eq!(expected, got, "at {}", i);
        }
        Ok(())
    }
}
