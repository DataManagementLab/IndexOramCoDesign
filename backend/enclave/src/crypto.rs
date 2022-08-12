use rand::{Rng};
use serde::{Deserialize, Serialize};
use std::string::String;

use EMPTY_NONCE;

/// Provider for new & safe AES nonces (must be new for every encryption process).
/// Our nonces have a size of 96 bit. Since there is no Rust std representation for that,
/// we concatenate a 64 bit (current) with a 32 bit (prefix).
#[derive(Serialize, Deserialize, Clone)]
pub struct NonceProvider {
    current: u64,
    prefix: u32,
}

impl NonceProvider {
    pub fn new() -> Self {
        NonceProvider {
            current: 1u64,
            prefix: 0u32,
        }
    }
    pub fn make_nonce(&mut self) -> [u8; 12] {
        let mut nonce: [u8; 12] = EMPTY_NONCE;
        match nonce.get_mut(4..) {
            None => {
                panic!("Could not write to new nonce suffix.");
            }
            Some(some_nonce) => {
                some_nonce.copy_from_slice(self.current.to_be_bytes().as_slice());
            }
        }
        if self.prefix > 0 {
            match nonce.get_mut(0..4) {
                None => {
                    panic!("Could not write to new nonce prefix.");
                }
                Some(some_nonce) => {
                    some_nonce.copy_from_slice(self.prefix.to_be_bytes().as_slice());
                }
            }
        }

        if self.current == u64::MAX {
            self.current = 1;
            if self.prefix == u32::MAX {
                panic!("Security incidence: New key needed! All nonces are used.");
            }
            self.prefix += 1;
        } else {
            self.current += 1;
        }
        nonce
    }
}

/// Generation of a safe encryption key for usage in ORAM bucket encryption.
pub fn generate_random_key(key_len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
    let mut rng = rand::thread_rng();
    let password: String = (0..key_len)
        .map(|_| {
            let idx: usize = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("{:?}", password)
}

/// Generation of a random RID for new records.
pub fn generate_random_rid(key_len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    let password: String = (0..key_len)
        .map(|_| {
            let idx: usize = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("{:?}", password)
}
