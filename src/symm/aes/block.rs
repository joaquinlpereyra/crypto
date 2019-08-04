use std::ops::BitXor;

enum Column {
    First = 0,
    Second = 1,
    Third = 2,
    Fourth = 3,
}

// A block is a 4x4 matrix of bytes
#[derive(Debug, PartialEq)]
pub struct Block([[u8; 4]; 4]);

impl Block {
    /// Return a new uninitialized state
    fn new_blank() -> Block {
        Block {
            0: [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]],
        }
    }

    /// Return a new block with the data given.
    pub fn new(data: &[u8; 16]) -> Block {
        Self {
            0: [
                [data[0], data[4], data[8], data[12]],
                [data[1], data[5], data[9], data[13]],
                [data[2], data[6], data[10], data[14]],
                [data[3], data[7], data[11], data[15]],
            ],
        }
    }

    /// Set a new value in the state
    fn set(&mut self, x: u8, y: u8, value: u8) {
        self.0[y as usize][x as usize] = value;
    }

    /// Retrieve a value from the state
    fn get(&self, x: u8, y: u8) -> u8 {
        self.0[y as usize][x as usize]
    }

    pub fn get_column(&self, clm: Column) -> [u8; 4] {
        let i = clm as u8;
        [
            self.get(i, 0),
            self.get(i, 1),
            self.get(i, 2),
            self.get(i, 3),
        ]
    }
}

impl BitXor for Block {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let zipped_rows = self.0.iter().zip(rhs.0.iter());
        let mut result = Block::new_blank();
        for (y, (left_row, right_row)) in zipped_rows.enumerate() {
            let zipped_bytes = left_row.iter().zip(right_row.iter());
            for (x, (left_byte, right_byte)) in zipped_bytes.enumerate() {
                result.set(x as u8, y as u8, left_byte ^ right_byte)
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_block() {
        let mut s = Block::new_blank();
        s.set(0, 1, 2);
        assert_eq!(2, s.get(0, 1));
    }

    #[test]
    fn test_get_column() {
        let block = Block::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!([5, 6, 7, 8], block.get_column(Column::Second));
        assert_eq!([13, 14, 15, 16], block.get_column(Column::Fourth));
    }
}
