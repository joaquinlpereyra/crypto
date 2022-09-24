use crate::random::MersenneTwister;

// A PRNG is just an iterator. next()
// should gives a random numbers.
pub trait PRNG: Iterator<Item = usize> {}

impl PRNG for MersenneTwister {}

pub struct Cipher {
    prng: Box<dyn PRNG>,
    state: Vec<u8>,
}

impl Cipher {
    pub fn new(prng: Box<dyn PRNG>) -> Self {
        Cipher {
            prng,
            state: Vec::new(),
        }
    }
    pub fn set_state(&mut self, msg: &[u8]) {
        self.state = msg.to_vec()
    }

    pub fn encrypt(&mut self) -> Vec<u8> {
        for i in 0..self.state.len() {
            self.state[i] = self.state[i] ^ self.prng.next().unwrap() as u8;
        }
        self.state.clone()
    }

    pub fn decrypt(mut self) -> Vec<u8> {
        let mut plain = Vec::with_capacity(self.state.len());
        for i in 0..self.state.len() {
            plain.push(self.state[i] ^ self.prng.next().unwrap() as u8)
        }
        plain
    }
}
