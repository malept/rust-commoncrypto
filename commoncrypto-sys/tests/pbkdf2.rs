extern crate commoncrypto_sys;
extern crate hex;

use hex::{ToHex, FromHex};

// These password, salts, rounds and derived key values come from the test
// vectors stated in RFC 6070
const PASSWORD: &'static str = "password";
const SALT: &'static str = "salt";

const PASSWORD2: &'static str = "passwordPASSWORDpassword";
const SALT2: &'static str = "saltSALTsaltSALTsaltSALTsaltSALTsalt";

const PASSWORD3: &'static str = "pass\0word";
const SALT3: &'static str = "sa\0lt";

const DERIVED1: &'static str = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
const DERIVED2: &'static str = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
const DERIVED4096: &'static str = "4b007901b765489abead49d926f721d065a429c1";
const DERIVED16777216: &'static str = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
const DERIVED4096_2: &'static str = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
const DERIVED4096_3: &'static str = "56fa6aa75548099dcc37d7f03425e0c3";

macro_rules! test_pbkdf2 {
    (
        $test_name: ident,
        $prf_algorithm: ident,
        $pw: ident,
        $salt: ident,
        $rounds: expr,
        $expected_dkey: ident
    ) => {
        #[test]
        fn $test_name() {
            let derived_len = Vec::<u8>::from_hex($expected_dkey).expect("dkey from hex").len();
            let mut pw_derived = vec![0u8; derived_len];
            unsafe {
                assert_eq!(0, commoncrypto_sys::CCKeyDerivationPBKDF(
                    commoncrypto_sys::CCPBKDFAlgorithm::kCCPBKDF2,
                    $pw.as_ptr(), $pw.len(),
                    $salt.as_ptr(), $salt.len(),
                    commoncrypto_sys::CCPseudoRandomAlgorithm::$prf_algorithm,
                    $rounds,
                    pw_derived.as_mut_ptr(), pw_derived.len()
                ));
            }
            assert_eq!($expected_dkey, pw_derived.to_hex());
        }
    }
}

test_pbkdf2!(pbkdf2_1, kCCPRFHmacAlgSHA1, PASSWORD, SALT, 1, DERIVED1);
test_pbkdf2!(pbkdf2_2, kCCPRFHmacAlgSHA1, PASSWORD, SALT, 2, DERIVED2);
test_pbkdf2!(pbkdf2_4096,
             kCCPRFHmacAlgSHA1,
             PASSWORD,
             SALT,
             4096,
             DERIVED4096);
test_pbkdf2!(pbkdf2_16777216,
             kCCPRFHmacAlgSHA1,
             PASSWORD,
             SALT,
             16777216,
             DERIVED16777216);
test_pbkdf2!(pbkdf2_4096_2,
             kCCPRFHmacAlgSHA1,
             PASSWORD2,
             SALT2,
             4096,
             DERIVED4096_2);
test_pbkdf2!(pbkdf2_4096_3,
             kCCPRFHmacAlgSHA1,
             PASSWORD3,
             SALT3,
             4096,
             DERIVED4096_3);
