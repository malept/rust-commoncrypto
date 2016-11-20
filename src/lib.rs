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

extern crate libc;

use libc::{c_int, c_uint, c_ulong, c_ulonglong};

pub const MD5_CBLOCK: usize = 64;
pub const MD5_LBLOCK: usize = MD5_CBLOCK / 4;
pub const MD5_DIGEST_LENGTH: usize = 16;

pub const SHA_LBLOCK: usize = 16;
pub const SHA1_DIGEST_LENGTH: usize = 20;
pub const SHA256_DIGEST_LENGTH: usize = 32;
pub const SHA512_DIGEST_LENGTH: usize = 64;

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

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct CC_SHA256_CTX {
    h: [c_ulong; 8],
    Nl: c_ulong,
    Nh: c_ulong,
    data: [c_ulong; SHA_LBLOCK],
    num: c_uint,
    md_len: c_uint,
}

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct CC_SHA512_CTX {
    h: [c_ulonglong; 8],
    Nl: c_ulonglong,
    Nh: c_ulonglong,
    data: [c_ulonglong; SHA_LBLOCK],
    num: c_uint,
    md_len: c_uint,
}

extern "C" {
    pub fn CC_MD5_Init(ctx: *mut CC_MD5_CTX) -> c_int;
    pub fn CC_MD5_Update(ctx: *mut CC_MD5_CTX, data: *const u8, n: usize) -> c_int;
    pub fn CC_MD5_Final(md: *mut u8, ctx: *mut CC_MD5_CTX) -> c_int;
    pub fn CC_SHA1_Init(ctx: *mut CC_SHA_CTX) -> c_int;
    pub fn CC_SHA1_Update(ctx: *mut CC_SHA_CTX, data: *const u8, n: usize) -> c_int;
    pub fn CC_SHA1_Final(md: *mut u8, ctx: *mut CC_SHA_CTX) -> c_int;
    pub fn CC_SHA256_Init(ctx: *mut CC_SHA256_CTX) -> c_int;
    pub fn CC_SHA256_Update(ctx: *mut CC_SHA256_CTX, data: *const u8, n: usize) -> c_int;
    pub fn CC_SHA256_Final(md: *mut u8, ctx: *mut CC_SHA256_CTX) -> c_int;
    pub fn CC_SHA512_Init(ctx: *mut CC_SHA512_CTX) -> c_int;
    pub fn CC_SHA512_Update(ctx: *mut CC_SHA512_CTX, data: *const u8, n: usize) -> c_int;
    pub fn CC_SHA512_Final(md: *mut u8, ctx: *mut CC_SHA512_CTX) -> c_int;
}
