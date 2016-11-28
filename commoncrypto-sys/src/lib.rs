// Copyright (c) 2016 Mark Lee
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

//! Low-level bindings to OSX/macOS/iOS's `CommonCrypto` library.

#![warn(missing_docs)]

extern crate hex;
extern crate libc;

use libc::{c_int, c_uint};

/// Total number of operations.
const MD5_CBLOCK: usize = 64;
/// Number of operations per round.
const MD5_LBLOCK: usize = MD5_CBLOCK / 4;
/// Number of bytes for an MD5 hash.
pub const MD5_DIGEST_LENGTH: usize = 16;

const SHA_LBLOCK: usize = 16;
/// Number of bytes for an SHA1 hash.
pub const SHA1_DIGEST_LENGTH: usize = 20;
/// Number of bytes for an SHA256 hash.
pub const SHA256_DIGEST_LENGTH: usize = 32;
/// Number of bytes for an SHA384 hash.
pub const SHA384_DIGEST_LENGTH: usize = 48;
/// Number of bytes for an SHA512 hash.
pub const SHA512_DIGEST_LENGTH: usize = 64;

/// Struct used to generate MD5 hashes.
#[allow(non_camel_case_types, non_snake_case)]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct CC_MD5_CTX {
    A: c_uint,
    B: c_uint,
    C: c_uint,
    D: c_uint,
    Nl: c_uint,
    Nh: c_uint,
    data: [c_uint; MD5_LBLOCK],
    num: c_uint,
}

/// Struct used to generate SHA1 hashes.
#[allow(non_camel_case_types, non_snake_case)]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct CC_SHA_CTX {
    h0: c_uint,
    h1: c_uint,
    h2: c_uint,
    h3: c_uint,
    h4: c_uint,
    Nl: c_uint,
    Nh: c_uint,
    data: [c_uint; SHA_LBLOCK],
    num: c_uint,
}

macro_rules! cc_sha2_struct {
    ($ctx_name: ident, $ty: ty) => {
        /// Struct used to generate SHA2 hashes with the given bits.
        #[allow(non_camel_case_types, non_snake_case)]
        #[derive(Clone, Debug, Default, PartialEq)]
        #[repr(C)]
        pub struct $ctx_name {
            count: [$ty; 2],
            hash: [$ty; 8],
            wbuf: [$ty; 16],
        }
    }
}

cc_sha2_struct!(CC_SHA256_CTX, u32);
cc_sha2_struct!(CC_SHA512_CTX, u64);

/// Digest algorithm used in `CCDigest*()` functions.
#[repr(C)]
pub enum CCDigestAlgorithm {
    /// No digest algorithm
    kCCDigestNone = 0,
    /// MD2
    kCCDigestMD2 = 1,
    /// MD4
    kCCDigestMD4 = 2,
    /// MD5
    kCCDigestMD5 = 3,
    /// RIPEMD-128
    kCCDigestRMD128 = 4,
    /// RIPEMD-160
    kCCDigestRMD160 = 5,
    /// RIPEMD-256
    kCCDigestRMD256 = 6,
    /// RIPEMD-320
    kCCDigestRMD320 = 7,
    /// SHA1
    kCCDigestSHA1 = 8,
    /// SHA224
    kCCDigestSHA224 = 9,
    /// SHA256
    kCCDigestSHA256 = 10,
    /// SHA384
    kCCDigestSHA384 = 11,
    /// SHA512
    kCCDigestSHA512 = 12,
    /// Skein, 128 bit (Deprecated in iPhoneOS 6.0 and MacOSX10.9)
    kCCDigestSkein128 = 13,
    /// Skein, 160 bit (Deprecated in iPhoneOS 6.0 and MacOSX10.9)
    kCCDigestSkein160 = 14,
    /// Skein, 224 bit (Deprecated in iPhoneOS 6.0 and MacOSX10.9)
    kCCDigestSkein224 = 16,
    /// Skein, 256 bit (Deprecated in iPhoneOS 6.0 and MacOSX10.9)
    kCCDigestSkein256 = 17,
    /// Skein, 384 bit (Deprecated in iPhoneOS 6.0 and MacOSX10.9)
    kCCDigestSkein384 = 18,
    /// Skein, 512 bit (Deprecated in iPhoneOS 6.0 and MacOSX10.9)
    kCCDigestSkein512 = 19,
}

const CC_DIGEST_SIZE: usize = 1032;

/// Context used in `CCDigest*()` functions.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub struct CCDigestCtx {
    context: [u8; CC_DIGEST_SIZE],
}

extern "C" {
    /// Initializes MD5 hasher. See `man 3cc CC_MD5` for details.
    pub fn CC_MD5_Init(ctx: *mut CC_MD5_CTX) -> c_int;
    /// Appends data to be hashed. See `man 3cc CC_MD5` for details.
    pub fn CC_MD5_Update(ctx: *mut CC_MD5_CTX, data: *const u8, n: usize) -> c_int;
    /// Generates MD5 hash. See `man 3cc CC_MD5` for details.
    pub fn CC_MD5_Final(md: *mut u8, ctx: *mut CC_MD5_CTX) -> c_int;
    /// Initializes SHA1 hasher. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA1_Init(ctx: *mut CC_SHA_CTX) -> c_int;
    /// Appends data to be hashed. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA1_Update(ctx: *mut CC_SHA_CTX, data: *const u8, n: usize) -> c_int;
    /// Generates SHA1 hash. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA1_Final(md: *mut u8, ctx: *mut CC_SHA_CTX) -> c_int;
    /// Initializes SHA256 hasher. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA256_Init(ctx: *mut CC_SHA256_CTX) -> c_int;
    /// Appends data to be hashed. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA256_Update(ctx: *mut CC_SHA256_CTX, data: *const u8, n: usize) -> c_int;
    /// Generates SHA256 hash. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA256_Final(md: *mut u8, ctx: *mut CC_SHA256_CTX) -> c_int;
    /// Initializes SHA384 hasher. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA384_Init(ctx: *mut CC_SHA512_CTX) -> c_int;
    /// Appends data to be hashed. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA384_Update(ctx: *mut CC_SHA512_CTX, data: *const u8, n: usize) -> c_int;
    /// Generates SHA384 hash. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA384_Final(md: *mut u8, ctx: *mut CC_SHA512_CTX) -> c_int;
    /// Initializes SHA512 hasher. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA512_Init(ctx: *mut CC_SHA512_CTX) -> c_int;
    /// Appends data to be hashed. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA512_Update(ctx: *mut CC_SHA512_CTX, data: *const u8, n: usize) -> c_int;
    /// Generates SHA512 hash. See `man 3cc CC_SHA` for details.
    pub fn CC_SHA512_Final(md: *mut u8, ctx: *mut CC_SHA512_CTX) -> c_int;
    /// Generic digest hasher.
    pub fn CCDigest(algorithm: CCDigestAlgorithm,
                    data: *const u8,
                    length: usize,
                    output: *mut u8)
                    -> c_int;
    /// Allocate and initialize a `CCDigestCtx` for a digest.
    pub fn CCDigestCreate(algorithm: CCDigestAlgorithm) -> *mut CCDigestCtx;
    /// Continue to digest data. Returns `0` on success.
    pub fn CCDigestUpdate(ctx: *mut CCDigestCtx, data: *const u8, length: usize) -> c_int;
    /// Conclude digest operations and produce the digest output. Returns `0` on success.
    pub fn CCDigestFinal(ctx: *mut CCDigestCtx, output: *mut u8) -> c_int;
    /// Clear and free a `CCDigestCtx`.
    pub fn CCDigestDestroy(ctx: *mut CCDigestCtx);
    /// Clear and re-initialize a `CCDigestCtx` for the same algorithm.
    pub fn CCDigestReset(ctx: *mut CCDigestCtx);
    /// Produce the digest output result for the bytes currently processed. Returns `0` on success.
    pub fn CCDigestGetDigest(ctx: *mut CCDigestCtx, output: *mut u8) -> c_int;
    /// Provides the block size of the digest algorithm. Returns `0` on failure.
    pub fn CCDigestGetBlockSize(algorithm: CCDigestAlgorithm) -> usize;
    /// Provides the digest output size of the digest algorithm. Returns `0` on failure.
    pub fn CCDigestGetOutputSize(algorithm: CCDigestAlgorithm) -> usize;
    /// Provides the block size of the digest algorithm. Returns `0` on failure.
    pub fn CCDigestGetBlockSizeFromRef(ctx: *mut CCDigestCtx) -> usize;
    /// Provides the digest output size of the digest algorithm. Returns `0` on failure.
    pub fn CCDigestGetOutputSizeFromRef(ctx: *mut CCDigestCtx) -> usize;
}

#[cfg(test)]
mod test {
    use hex::ToHex;

    const TO_HASH: &'static str = "The quick brown fox jumps over the lazy dog";
    const TO_HASH_MD5: &'static str = "9e107d9d372bb6826bd81d3542a419d6";
    const TO_HASH_SHA1: &'static str = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
    const TO_HASH_SHA256: &'static str = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    const TO_HASH_SHA384: &'static str = "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1";
    const TO_HASH_SHA512: &'static str = "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6";

    macro_rules! test_cc_hash {
        (
            $test_name: ident,
            $ctx_ty: ident,
            $digest_len: ident,
            $init_func: ident,
            $update_func: ident,
            $final_func: ident,
            $expected_hash: ident
        ) => {
            #[test]
            fn $test_name() {
                let mut ctx = super::$ctx_ty::default();
                let mut md = [0u8; super::$digest_len];
                unsafe {
                    assert_eq!(super::$init_func(&mut ctx), 1);
                    assert_eq!(super::$update_func(&mut ctx, TO_HASH.as_ptr(), TO_HASH.len()), 1);
                    assert_eq!(super::$final_func(md.as_mut_ptr(), &mut ctx), 1);
                }
                assert_eq!(md.to_vec().to_hex(), $expected_hash);
            }
        }
    }

    macro_rules! test_ccdigest {
        (
            $test_name: ident,
            $algorithm: ident,
            $digest_len: ident,
            $expected_hash: ident
        ) => {
            #[test]
            fn $test_name() {
                let mut md = [0u8; super::$digest_len];
                unsafe {
                    assert_eq!(super::CCDigest(super::CCDigestAlgorithm::$algorithm,
                                               TO_HASH.as_ptr(),
                                               TO_HASH.len(),
                                               md.as_mut_ptr()), 0)
                }
                assert_eq!(md.to_vec().to_hex(), $expected_hash);
            }
        }
    }

    macro_rules! test_ccdigestgetoutputsize {
        (
            $test_name: ident,
            $algorithm: ident,
            $expected_digest_len: ident
        ) => {
            #[test]
            fn $test_name() {
                unsafe {
                    assert_eq!(super::CCDigestGetOutputSize(super::CCDigestAlgorithm::$algorithm),
                               super::$expected_digest_len);
                }
            }
        }
    }

    test_cc_hash!(md5_hash,
                  CC_MD5_CTX,
                  MD5_DIGEST_LENGTH,
                  CC_MD5_Init,
                  CC_MD5_Update,
                  CC_MD5_Final,
                  TO_HASH_MD5);
    test_cc_hash!(sha1_hash,
                  CC_SHA_CTX,
                  SHA1_DIGEST_LENGTH,
                  CC_SHA1_Init,
                  CC_SHA1_Update,
                  CC_SHA1_Final,
                  TO_HASH_SHA1);
    test_cc_hash!(sha256_hash,
                  CC_SHA256_CTX,
                  SHA256_DIGEST_LENGTH,
                  CC_SHA256_Init,
                  CC_SHA256_Update,
                  CC_SHA256_Final,
                  TO_HASH_SHA256);
    test_cc_hash!(sha384_hash,
                  CC_SHA512_CTX,
                  SHA384_DIGEST_LENGTH,
                  CC_SHA384_Init,
                  CC_SHA384_Update,
                  CC_SHA384_Final,
                  TO_HASH_SHA384);
    test_cc_hash!(sha512_hash,
                  CC_SHA512_CTX,
                  SHA512_DIGEST_LENGTH,
                  CC_SHA512_Init,
                  CC_SHA512_Update,
                  CC_SHA512_Final,
                  TO_HASH_SHA512);

    test_ccdigest!(md5_ccdigest, kCCDigestMD5, MD5_DIGEST_LENGTH, TO_HASH_MD5);
    test_ccdigest!(sha1_ccdigest,
                   kCCDigestSHA1,
                   SHA1_DIGEST_LENGTH,
                   TO_HASH_SHA1);
    test_ccdigest!(sha256_ccdigest,
                   kCCDigestSHA256,
                   SHA256_DIGEST_LENGTH,
                   TO_HASH_SHA256);
    test_ccdigest!(sha384_ccdigest,
                   kCCDigestSHA384,
                   SHA384_DIGEST_LENGTH,
                   TO_HASH_SHA384);
    test_ccdigest!(sha512_ccdigest,
                   kCCDigestSHA512,
                   SHA512_DIGEST_LENGTH,
                   TO_HASH_SHA512);

    test_ccdigestgetoutputsize!(md5_ccdigestoutputsize, kCCDigestMD5, MD5_DIGEST_LENGTH);
    test_ccdigestgetoutputsize!(sha1_ccdigestoutputsize, kCCDigestSHA1, SHA1_DIGEST_LENGTH);
    test_ccdigestgetoutputsize!(sha256_ccdigestoutputsize,
                                kCCDigestSHA256,
                                SHA256_DIGEST_LENGTH);
    test_ccdigestgetoutputsize!(sha384_ccdigestoutputsize,
                                kCCDigestSHA384,
                                SHA384_DIGEST_LENGTH);
    test_ccdigestgetoutputsize!(sha512_ccdigestoutputsize,
                                kCCDigestSHA512,
                                SHA512_DIGEST_LENGTH);
}
