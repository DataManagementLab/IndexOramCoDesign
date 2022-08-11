//use crypto_bigint::{Checked, Encoding, U192};
use rand::Rng;

/*
use ring::hmac::Key;
use ring::{error, hmac, rand as rand2};
pub fn generate_hmac_signature_key() -> Result<Key, error::Unspecified> {
    let rng = rand2::SystemRandom::new();
    let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng);
    key
}
pub fn hmac_signature(data: &str, key: Key) -> Vec<u8> {
    hmac::sign(&key, data.as_bytes()).as_ref().to_vec()
}
 */

pub fn generate_random_key(key_len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
    let mut rng = rand::thread_rng();

    let password: String = (0..key_len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("{:?}", password)
}
