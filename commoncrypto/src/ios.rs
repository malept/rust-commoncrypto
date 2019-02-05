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

//! Idiomatic Rust wrapper for `CommonCrypto`'s `CCDigestCtx` struct.

use commoncrypto_sys::*;
use std::io;
use std::os::raw::{c_int, c_void};

pub use commoncrypto_sys::CCDigestAlgorithm;

const MAX_DIGEST_SIZE: usize = 64;

macro_rules! err_from_ccdigest_retval {
    ($func_name: expr, $val: expr) => {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("{} returned nonzero: {}", $func_name, $val),
        ))
    };
}

#[derive(PartialEq, Copy, Clone, Debug)]
enum State {
    Reset,
    Updated,
    Finalized,
}

#[derive(Debug)]
enum AlgoData {
    None,
    MD5(CC_MD5_CTX),
    SHA(CC_SHA512_CTX),
}

impl AlgoData {
    fn as_ptr(&mut self) -> *mut c_void {
        match self {
            AlgoData::None => std::ptr::null_mut(),
            AlgoData::MD5(ref mut md5) => md5 as *mut CC_MD5_CTX as *mut c_void,
            AlgoData::SHA(ref mut sha) => sha as *mut CC_SHA512_CTX as *mut c_void,
        }
    }
}

/// Generates cryptographic hashes.
#[derive(Debug)]
pub struct Hasher {
    state: State,
    ctx: AlgoData,
    init_f: unsafe extern "C" fn(*mut c_void) -> c_int,
    update_f: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
    final_f: unsafe extern "C" fn(*mut u8, *mut c_void) -> c_int,
    len: usize,
}

impl Hasher {
    /// Creates a new `Hasher` which will use the given cryptographic `algorithm`.
    pub fn new(algorithm: CCDigestAlgorithm) -> Hasher {
        unsafe {
            let mut out = match algorithm {
                CCDigestAlgorithm::kCCDigestMD5 => Hasher {
                    state: State::Reset,
                    ctx: AlgoData::MD5(CC_MD5_CTX::default()),
                    init_f: std::mem::transmute(CC_MD5_Init as usize),
                    update_f: std::mem::transmute(CC_MD5_Update as usize),
                    final_f: std::mem::transmute(CC_MD5_Final as usize),
                    len: MD5_DIGEST_LENGTH,
                },
                CCDigestAlgorithm::kCCDigestSHA1 => Hasher {
                    state: State::Reset,
                    ctx: AlgoData::SHA(CC_SHA512_CTX::default()),
                    init_f: std::mem::transmute(CC_SHA1_Init as usize),
                    update_f: std::mem::transmute(CC_SHA1_Update as usize),
                    final_f: std::mem::transmute(CC_SHA1_Final as usize),
                    len: SHA1_DIGEST_LENGTH,
                },
                CCDigestAlgorithm::kCCDigestSHA256 => Hasher {
                    state: State::Reset,
                    ctx: AlgoData::SHA(CC_SHA512_CTX::default()),
                    init_f: std::mem::transmute(CC_SHA256_Init as usize),
                    update_f: std::mem::transmute(CC_SHA256_Update as usize),
                    final_f: std::mem::transmute(CC_SHA256_Final as usize),
                    len: SHA256_DIGEST_LENGTH,
                },
                CCDigestAlgorithm::kCCDigestSHA384 => Hasher {
                    state: State::Reset,
                    ctx: AlgoData::SHA(CC_SHA512_CTX::default()),
                    init_f: std::mem::transmute(CC_SHA384_Init as usize),
                    update_f: std::mem::transmute(CC_SHA384_Update as usize),
                    final_f: std::mem::transmute(CC_SHA384_Final as usize),
                    len: SHA384_DIGEST_LENGTH,
                },
                CCDigestAlgorithm::kCCDigestSHA512 => Hasher {
                    state: State::Reset,
                    ctx: AlgoData::SHA(CC_SHA512_CTX::default()),
                    init_f: std::mem::transmute(CC_SHA512_Init as usize),
                    update_f: std::mem::transmute(CC_SHA512_Update as usize),
                    final_f: std::mem::transmute(CC_SHA512_Final as usize),
                    len: SHA512_DIGEST_LENGTH,
                },
                _ => Hasher {
                    state: State::Reset,
                    ctx: AlgoData::None,
                    init_f: std::mem::transmute(CC_SHA512_Init as usize),
                    update_f: std::mem::transmute(CC_SHA512_Update as usize),
                    final_f: std::mem::transmute(CC_SHA512_Final as usize),
                    len: 0,
                },
            };
            (out.init_f)(out.ctx.as_ptr());
            out
        }
    }

    fn init(&mut self) {
        match self.state {
            State::Reset => return,
            State::Updated => {
                let _ = self.finish();
            }
            State::Finalized => (),
        }
        match self.ctx {
            AlgoData::MD5(_) => {
                self.ctx = AlgoData::MD5(CC_MD5_CTX::default());
            }
            AlgoData::SHA(_) => {
                self.ctx = AlgoData::SHA(CC_SHA512_CTX::default());
            }
            AlgoData::None => {}
        }
        self.state = State::Reset;
        unsafe { (self.init_f)(self.ctx.as_ptr()) };
    }

    /// Feeds data into the hasher.
    pub fn update(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.state == State::Finalized {
            self.init();
        }
        match self.ctx {
            AlgoData::None => {
                return Ok(0);
            }
            _ => {}
        }
        let result =
            unsafe { (self.update_f)(self.ctx.as_ptr(), data.as_ptr() as *mut _, data.len()) };
        if result == 1 {
            self.state = State::Updated;
            Ok(data.len())
        } else {
            err_from_ccdigest_retval!("digest_update", result)
        }
    }

    /// Finalizes digest operations and produces the digest output.
    pub fn finish(&mut self) -> io::Result<Vec<u8>> {
        if self.state == State::Finalized {
            self.init();
        }
        match self.ctx {
            AlgoData::None => {
                return Ok(Vec::new());
            }
            _ => {}
        }
        let mut md = vec![0; MAX_DIGEST_SIZE];
        // let result = unsafe { CCDigestFinal(self.ctx, md.as_mut_ptr()) };
        let result = unsafe { (self.final_f)(md.as_mut_ptr(), self.ctx.as_ptr()) };
        if result == 1 {
            self.state = State::Finalized;
            md.truncate(self.len);
            Ok(md)
        } else {
            err_from_ccdigest_retval!("digest_final", result)
        }
    }
}

impl io::Write for Hasher {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        if self.state != State::Finalized {
            let _ = self.finish();
        }
        // unsafe { CCDigestDestroy(self.ctx) }
    }
}
