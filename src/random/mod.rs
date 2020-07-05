use std::fs::File;
use std::io::Read;

/// Returns a `mod` b.
fn module(a: u64, b: u64) -> u64 {
    ((a % b) + b) % b
}

pub fn in_range(floor: u8, ceiling: u8) -> usize {
    let random = get_random(1)[0];
    module(random as u64 + floor as u64, ceiling as u64) as usize
}

pub fn get_random(bytes: usize) -> Vec<u8> {
    let mut randoms = vec![0; bytes];
    let mut file = match File::open("/dev/urandom") {
        Ok(file) => file,
        Err(_) => panic!("cant open urandom"),
    };
    file.read_exact(&mut randoms).unwrap();
    randoms
}

pub fn flip_coin() -> bool {
    let random = get_random(1);
    return random[0] < 128;
}
