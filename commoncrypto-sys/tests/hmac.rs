extern crate commoncrypto_sys;
extern crate hex;

use commoncrypto_sys::{CCHmacAlgorithm, CCHmacContext, CCHmacInit, CCHmacUpdate, CCHmacFinal};
use hex::ToHex;

// From Wikipedia
const HMAC_MD5_BLANK: &str = "74e6f7298a9c2d168935f58c001bad88";
const HMAC_SHA1_BLANK: &str = "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d";
const HMAC_SHA256_BLANK: &str = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
// Generated via Python's HMAC implementation
const HMAC_SHA224_BLANK: &str = "5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524";
const HMAC_SHA384_BLANK: &str = concat!(
    "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792",
    "302840234adc"
);
const HMAC_SHA512_BLANK: &str = concat!(
    "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69",
    "402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
);

macro_rules! test_cchmaccontext {
    (
        $test_name: ident,
        $algorithm: ident,
        $digest_len: ident,
        $key: expr,
        $message: ident,
        $expected_hash: ident
    ) => {
        #[test]
        fn $test_name() {
            let mut ctx = CCHmacContext::default();
            let mut md = [0u8; commoncrypto_sys::$digest_len];
            unsafe {
                CCHmacInit(&mut ctx, CCHmacAlgorithm::$algorithm, $key.as_ptr(), $key.len());
                CCHmacUpdate(&mut ctx, $message.as_ptr(), $message.len());
                CCHmacFinal(&mut ctx, md.as_mut_ptr());
            }
            assert_eq!(md.to_vec().to_hex(), $expected_hash);
        }
    }
}

const BLANK: &str = "";

test_cchmaccontext!(
    md5_cchmaccontext,
    kCCHmacAlgMD5,
    MD5_DIGEST_LENGTH,
    BLANK,
    BLANK,
    HMAC_MD5_BLANK
);
test_cchmaccontext!(
    sha1_cchmaccontext,
    kCCHmacAlgSHA1,
    SHA1_DIGEST_LENGTH,
    BLANK,
    BLANK,
    HMAC_SHA1_BLANK
);
test_cchmaccontext!(
    sha224_cchmaccontext,
    kCCHmacAlgSHA224,
    SHA224_DIGEST_LENGTH,
    BLANK,
    BLANK,
    HMAC_SHA224_BLANK
);
test_cchmaccontext!(
    sha256_cchmaccontext,
    kCCHmacAlgSHA256,
    SHA256_DIGEST_LENGTH,
    BLANK,
    BLANK,
    HMAC_SHA256_BLANK
);
test_cchmaccontext!(
    sha384_cchmaccontext,
    kCCHmacAlgSHA384,
    SHA384_DIGEST_LENGTH,
    BLANK,
    BLANK,
    HMAC_SHA384_BLANK
);
test_cchmaccontext!(
    sha512_cchmaccontext,
    kCCHmacAlgSHA512,
    SHA512_DIGEST_LENGTH,
    BLANK,
    BLANK,
    HMAC_SHA512_BLANK
);
