#![warn(clippy::all, clippy::pedantic)]
#![warn(clippy::unwrap_used)]
pub mod custom_md4 {
    pub struct CustomMD4 {
        state: [u32; 4],
        size: usize,
        total_size: u64,
        buffer: [u8; 64]
    }

    impl CustomMD4 {
        pub fn new(
            a: Option<u32>, 
            b: Option<u32>, 
            c: Option<u32>, 
            d: Option<u32>,
            fake_len: u64) -> CustomMD4 {
            CustomMD4 {
                state: [
                    a.unwrap_or(0x67452301), 
                    b.unwrap_or(0xefcdab89), 
                    c.unwrap_or(0x98badcfe), 
                    d.unwrap_or(0x10325476)],
                size: 0,
                total_size: fake_len,
                buffer: [0u8; 64]
            }
        }

        pub fn update(&mut self, message: &Vec<u8>) -> () {
            let mut length = message.len();
            let mut vec_ptr = 0;

            while 0 < length {
                let n = if length <= (64 - self.size) {
                    length
                } else {
                    64 - self.size
                };

                self.buffer[self.size..self.size + n].copy_from_slice(&message[vec_ptr..vec_ptr + n]);

                vec_ptr += n;
                self.size += n;
                self.total_size += n as u64;
                length -= n;

                if 64 == self.size {
                    self.process();
                    self.size = 0;
                }
            }
        }

        pub fn process(&mut self) -> () {
            let mut x = [0u32; 16];
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];

            for i in 0..16 {
                x[i] = u32::from_le_bytes(self.buffer[i * 4..(i + 1) * 4].try_into().unwrap());
            }

            for i in [0, 4, 8, 12] {
                a = self.ff(a, b, c, d, x[i], 3);
                d = self.ff(d, a, b, c, x[i + 1], 7);
                c = self.ff(c, d, a, b, x[i + 2], 11);
                b = self.ff(b, c, d, a, x[i + 3], 19);
            }

            for i in 0..4 {
                a = self.gg(a, b, c, d, x[i], 3);
                d = self.gg(d, a, b, c, x[i + 4], 5);
                c = self.gg(c, d, a, b, x[i + 8], 9);
                b = self.gg(b, c, d, a, x[i + 12], 13);
            }

            for i in [0, 2, 1, 3] {
                a = self.hh(a, b, c, d, x[i], 3);
                d = self.hh(d, a, b, c, x[i + 8], 9);
                c = self.hh(c, d, a, b, x[i + 4], 11);
                b = self.hh(b, c, d, a, x[i + 12], 15);
            }

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
        }

        pub fn finalize(&mut self) -> [u8; 16] {
            let mut total_size: u64 = self.total_size * 8;
            let pad_size = if 56 > self.size {
                56 - self.size
            } else {
                64 + 56 - self.size
            };
            let mut padding = vec![0u8; pad_size];

            if pad_size >= 1 {
                padding[0] = 0x80;
            }

            self.update(&padding);

            for i in 56..64 {
                self.buffer[i] = total_size as u8 & 0xFF;
                total_size >>= 8;
            }

            self.process();

            let mut ret_array = [0u8; 16];

            for i in 0..self.state.len() {
                ret_array[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_le_bytes());
            }

            ret_array
        }

        fn ff(&self, a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(self.f(b, c, d))
                .wrapping_add(x)
                .rotate_left(s)
        }

        fn gg(&self, a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(self.g(b, c, d))
                .wrapping_add(x)
                .wrapping_add(0x5A827999)
                .rotate_left(s)
        }

        fn hh(&self, a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(self.h(b, c, d))
                .wrapping_add(x)
                .wrapping_add(0x6ED9EBA1)
                .rotate_left(s)
        }

        fn f(&self, x: u32, y: u32, z: u32) -> u32 {
            z ^ (x & (y ^ z))
        }

        fn g(&self, x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        fn h(&self, x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }
    }
}

use custom_md4::CustomMD4;

fn attack(
    hash: &[u8; 16], 
    old_message: Vec<u8>, 
    new_message: Vec<u8>) -> [u8; 16] {
    let mut state = [0u32; 4];

    for i in 0..4 {
        state[i] = u32::from_le_bytes(hash[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    let mut size = old_message.len();

    let pad_size = if 56 > size {
        56 - size + 8
    } else {
        64 + 56 - size + 8
    };
    let mut padding = vec![0u8; pad_size];

    if pad_size >= 1 {
        padding[0] = 0x80;
    }

    size *= 8;
    for i in (pad_size - 8)..pad_size {
        padding[i] = size as u8 & 0xFF;
        size >>= 8;
    }

    let mut attack_message = vec![];
    attack_message.extend_from_slice(&old_message);
    attack_message.extend_from_slice(&padding);
    attack_message.extend_from_slice(&new_message);

    let fake_len = attack_message.len() as u64;
    let mut fake_md4 = CustomMD4::new(
        Some(state[0]), 
        Some(state[1]), 
        Some(state[2]), 
        Some(state[3]), 
        fake_len - new_message.len() as u64);
    fake_md4.update(&new_message);
    fake_md4.finalize()
}

fn main() -> () {
    let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    let addition = b";admin=true".to_vec();
    let mut custom_hash = CustomMD4::new(None, None, None, None, 0);
    custom_hash.update(&message);
    let custom_result = custom_hash.finalize();

    let attack_hash = attack(&custom_result, message, addition);

    println!("{:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}", 
    custom_result[0],
    custom_result[1],
    custom_result[2],
    custom_result[3],
    custom_result[4],
    custom_result[5],
    custom_result[6],
    custom_result[7],
    custom_result[8],
    custom_result[9],
    custom_result[10],
    custom_result[11],
    custom_result[12],
    custom_result[13],
    custom_result[14],
    custom_result[15]);

    println!("{:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}", 
    attack_hash[0],
    attack_hash[1],
    attack_hash[2],
    attack_hash[3],
    attack_hash[4],
    attack_hash[5],
    attack_hash[6],
    attack_hash[7],
    attack_hash[8],
    attack_hash[9],
    attack_hash[10],
    attack_hash[11],
    attack_hash[12],
    attack_hash[13],
    attack_hash[14],
    attack_hash[15]);
}

#[cfg(test)]
mod tests {
    use super::custom_md4::CustomMD4;
    use md4::{Md4, Digest};

    #[test]
    fn hash_compare_1() {
        let mut hasher = Md4::new();
        hasher.update(b"Hello World");
        let result = hasher.finalize();
        let slice_result = result.as_slice();

        let message = b"Hello World".to_vec();
        let mut custom_hash = CustomMD4::new(None, None, None, None, 0);
        custom_hash.update(&message);
        let custom_result = custom_hash.finalize();

        assert!(custom_result == slice_result);
    }
}
