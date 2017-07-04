// Copyright (c) 2016, 2017 Mark Lee
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Idiomatic Rust wrapper for `CommonCrypto`'s `CCHmacContext` struct.

use commoncrypto_sys::{CCHmacAlgorithm, CCHmacContext, CCHmacFinal, CCHmacInit, CCHmacUpdate,
                       MD5_DIGEST_LENGTH, SHA1_DIGEST_LENGTH, SHA224_DIGEST_LENGTH,
                       SHA256_DIGEST_LENGTH, SHA384_DIGEST_LENGTH, SHA512_DIGEST_LENGTH};
use std::io;

macro_rules! hmac_finish {
    (
        $function_name: ident,
        $digest_len: ident
    ) => {
        fn $function_name(ctx: &mut CCHmacContext) -> Vec<u8> {
            let mut hmac = [0u8; $digest_len];
            unsafe { CCHmacFinal(ctx, hmac[..].as_mut_ptr()); }
            hmac.to_vec()
        }
    }
}

/// Generator of Hash-based Message Authentication Codes (HMACs).
///
/// # Examples
///
/// ```rust
/// use crypto_hash::{Algorithm, HMAC};
/// use std::io::Write;
///
/// let mut hmac = HMAC::new(Algorithm::SHA256, b"");
/// hmac.write_all(b"crypto");
/// hmac.write_all(b"-");
/// hmac.write_all(b"hash");
/// let result = hmac.finish();
/// let expected = concat!(
///     b"\x8e\xd6\xcd0\xba\xc2\x9e\xdc\x0f\xcc3\x07\xd4D\xdb6\xa6\xe8/\xf3\x94\xe6\xac",
///     b"\xa2\x01l\x03/*1\x1f$"
/// ).to_vec();
/// assert_eq!(expected, result)
/// ```
#[derive(Debug)]
pub struct HMAC {
    algorithm: CCHmacAlgorithm,
    context: CCHmacContext,
}

hmac_finish!(hmac_md5_finish, MD5_DIGEST_LENGTH);
hmac_finish!(hmac_sha1_finish, SHA1_DIGEST_LENGTH);
hmac_finish!(hmac_sha224_finish, SHA224_DIGEST_LENGTH);
hmac_finish!(hmac_sha256_finish, SHA256_DIGEST_LENGTH);
hmac_finish!(hmac_sha384_finish, SHA384_DIGEST_LENGTH);
hmac_finish!(hmac_sha512_finish, SHA512_DIGEST_LENGTH);

impl HMAC {
    /// Create a new `HMAC` for the given `Algorithm` and `key`.
    pub fn new(algorithm: CCHmacAlgorithm, key: &[u8]) -> HMAC {
        let mut ctx = CCHmacContext::default();
        unsafe {
            CCHmacInit(&mut ctx, algorithm.clone(), key.as_ptr(), key.len());
        }
        HMAC {
            algorithm: algorithm,
            context: ctx,
        }
    }

    /// Generate an HMAC from the key + data written to the `HMAC` instance.
    pub fn finish(&mut self) -> Vec<u8> {
        match self.algorithm {
            CCHmacAlgorithm::kCCHmacAlgMD5 => hmac_md5_finish(&mut self.context),
            CCHmacAlgorithm::kCCHmacAlgSHA1 => hmac_sha1_finish(&mut self.context),
            CCHmacAlgorithm::kCCHmacAlgSHA224 => hmac_sha224_finish(&mut self.context),
            CCHmacAlgorithm::kCCHmacAlgSHA256 => hmac_sha256_finish(&mut self.context),
            CCHmacAlgorithm::kCCHmacAlgSHA384 => hmac_sha384_finish(&mut self.context),
            CCHmacAlgorithm::kCCHmacAlgSHA512 => hmac_sha512_finish(&mut self.context),
        }
    }
}

impl io::Write for HMAC {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            CCHmacUpdate(&mut self.context, buf.as_ptr(), buf.len());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
