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

extern crate commoncrypto_sys;
extern crate hex;

use commoncrypto_sys::{CCDigestCreate, CCDigestCtx, CCDigestDestroy, CCDigestFinal,
                       CCDigestGetOutputSizeFromRef, CCDigestUpdate};
use std::io;

pub use commoncrypto_sys::CCDigestAlgorithm;

const MAX_DIGEST_SIZE: usize = 64;

macro_rules! err_from_ccdigest_retval{
    ($func_name: expr, $val: expr) => {
        Err(io::Error::new(io::ErrorKind::Other,
                           format!("{} returned nonzero: {}", $func_name, $val)))
    }
}

pub struct Hasher {
    ctx: *mut CCDigestCtx,
}

impl Hasher {
    pub fn new(algorithm: CCDigestAlgorithm) -> Hasher {
        let ctx: *mut CCDigestCtx;
        unsafe {
            ctx = CCDigestCreate(algorithm);
        }
        Hasher { ctx: ctx }
    }

    pub fn update(&mut self, data: &[u8]) -> io::Result<usize> {
        let result = unsafe { CCDigestUpdate(self.ctx, data.as_ptr() as *mut _, data.len()) };
        if result == 0 {
            Ok(data.len())
        } else {
            err_from_ccdigest_retval!("CCDigestCreate", result)
        }
    }

    pub fn finish(&mut self) -> io::Result<Vec<u8>> {
        let expected_len = unsafe { CCDigestGetOutputSizeFromRef(self.ctx) };
        let mut md = vec![0; MAX_DIGEST_SIZE];
        let result = unsafe { CCDigestFinal(self.ctx, md.as_mut_ptr()) };
        if result == 0 {
            md.truncate(expected_len);
            Ok(md)
        } else {
            err_from_ccdigest_retval!("CCDigestFinal", result)
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
        unsafe { CCDigestDestroy(self.ctx) }
    }
}

#[cfg(test)]
mod test {
    use hex::ToHex;
    use std::io::Write;
    use super::*;

    const TO_HASH: &'static str = "The quick brown fox jumps over the lazy dog";
    const TO_HASH_MD5: &'static str = "9e107d9d372bb6826bd81d3542a419d6";

    #[test]
    fn md5_hasher() {
        let mut hasher = Hasher::new(CCDigestAlgorithm::kCCDigestMD5);
        assert!(hasher.write_all(TO_HASH.as_bytes()).is_ok());
        let result = hasher.finish();
        assert!(result.is_ok());
        assert_eq!(result.expect("Hash failed").to_hex(), TO_HASH_MD5)
    }
}
