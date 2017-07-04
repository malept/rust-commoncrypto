extern crate commoncrypto;
extern crate hex;

use commoncrypto::hmac::{CCHmacAlgorithm, HMAC};
use hex::ToHex;
use std::io::Write;

const TO_HMAC   : &str = "The quick brown fox jumps over the lazy dog";
const TO_HMAC_MD5: &str = "80070713463e7749b90c2dc24911e275";

#[test]
fn md5_hmac() {
    let mut hmac = HMAC::new(CCHmacAlgorithm::kCCHmacAlgMD5, b"key");
    assert!(hmac.write_all(TO_HMAC.as_bytes()).is_ok());
    let result = hmac.finish();
    assert_eq!(result.to_hex(), TO_HMAC_MD5)
}
