use crc::{Crc, CRC_32_ISCSI};
use rand::{rngs::ThreadRng, thread_rng, Rng};

use crate::{api, WritableFile};

struct Oops {}
impl WritableFile for Oops {
    fn append(&mut self, data: &[u8]) -> api::Result<()> {
        todo!()
    }
    fn close(&mut self) -> api::Result<()> {
        todo!()
    }
    fn flush(&mut self) -> api::Result<()> {
        todo!()
    }
    fn sync(&mut self) -> api::Result<()> {
        todo!()
    }
}

pub fn new_writable_file(fname: String) -> api::Result<impl WritableFile> {
    todo!();
    Ok(Oops {})
}

static B: u8 = 0x80;

pub fn varint_length(v: u64) -> usize {
    let mut len = 1;
    let mut vv = v;
    while vv >= B as u64 {
        vv >>= 7;
        len += 1;
    }
    len
}

// Using vec because length variant
pub fn put_varint64(dst: &mut Vec<u8>, v: u64) {
    let mut x = v;
    while x >= B as u64 {
        // large than 0b1000_0000
        dst.push(x as u8 | B as u8); // continuation
        x >>= 7;
    }
    dst.push(x as u8);
}

pub fn put_varint32(dst: &mut Vec<u8>, v: u32) {
    let mut x = v;
    while x >= B as u32 {
        // large than 0b1000_0000
        dst.push(x as u8 | B as u8); // continuation
        x >>= 7;
    }
    dst.push(x as u8);
}

#[derive(Debug)]
pub struct UtilError {
    reason: String,
}

impl UtilError {
    fn new(reason: String) -> Self {
        Self { reason }
    }
}

const VAR32_LIMIT: usize = 28;
// usize 0 error
pub fn get_varint32(src: &[u8]) -> std::result::Result<(u32, usize), UtilError> {
    let mut value: u32 = 0;
    let mut shift: usize = 0;

    for i in 0..src.len() {
        let b = src[i];
        if b < B {
            return Ok((value | (b as u32) << shift, i + 1));
        }
        value |= ((b & 0x7f) as u32) << shift; //0b0111_1111
        shift += 7;
        if shift > VAR32_LIMIT {
            break;
        }
    }
    Err(UtilError::new("get_varint32 error".to_string()))
}

const VAR64_LIMIT: usize = 63;

pub fn get_varint64(src: &[u8]) -> std::result::Result<(u64, usize), UtilError> {
    let mut value: u64 = 0;
    let mut shift: usize = 0;

    for i in 0..src.len() {
        let b = src[i];
        if b < B {
            return Ok((value | (b as u64) << shift, i + 1));
        }
        value |= ((b & 0x7f) as u64) << shift; //0b0111_1111
        shift += 7;
        if shift > VAR64_LIMIT {
            break;
        }
    }
    Err(UtilError::new("get_varint64 error".to_string()))
}

pub fn put_fixed64(dst: &mut Vec<u8>, v: u64) {
    let mut buf = [0; 8];
    encode_fixed64(&mut buf, v);
    dst.extend_from_slice(&buf);
}

pub fn encode_fixed64(dst: &mut [u8], v: u64) {
    dst[0] = v as u8;
    dst[1] = (v >> 8) as u8;
    dst[2] = (v >> 16) as u8;
    dst[3] = (v >> 24) as u8;
    dst[4] = (v >> 32) as u8;
    dst[5] = (v >> 40) as u8;
    dst[6] = (v >> 48) as u8;
    dst[7] = (v >> 56) as u8;
}

pub fn encode_fixed32(dst: &mut [u8], v: u32) {
    dst[0] = v as u8;
    dst[1] = (v >> 8) as u8;
    dst[2] = (v >> 16) as u8;
    dst[3] = (v >> 24) as u8;
}

pub fn decode_fixed64(src: &[u8]) -> u64 {
    assert_eq!(src.len(), 8);
    let mut value: u64 = 0;
    value = src[0] as u64
        | (src[1] as u64) << 8
        | (src[2] as u64) << 16
        | (src[3] as u64) << 24
        | (src[4] as u64) << 32
        | (src[5] as u64) << 40
        | (src[6] as u64) << 48
        | (src[7] as u64) << 56;
    value
}

pub fn decode_fixed32(src: &[u8]) -> u32 {
    src[0] as u32 | (src[1] as u32) << 8 | (src[2] as u32) << 16 | (src[3] as u32) << 24
}

/*
return data slice and offset position
 */
pub fn get_length_prefixed_slice(data: &[u8]) -> std::result::Result<(&[u8], usize), UtilError> {
    let (len, off) = get_varint32(data)?;
    let end = off + len as usize;
    Ok((&data[off..end], end))
}

pub fn put_length_prefixed_slice(dst: &mut Vec<u8>, value: &[u8]) {
    put_varint32(dst, value.len() as u32);
    dst.extend_from_slice(value);
}

pub const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub fn crc(data: &[u8]) -> u32 {
    CASTAGNOLI.checksum(data)
}

pub fn crcs(datas: &[&[u8]]) -> u32 {
    let mut digest = CASTAGNOLI.digest();
    for data in datas {
        digest.update(*data);
    }
    digest.finalize()
}

// can be replay
pub(crate) struct Random {
    seed: u32,
}

const M: u32 = 0x7fff_ffff; // 2^31-1
const A: u64 = 16807; // bits 14, 8, 7, 5, 2, 1, 0

impl Random {
    pub fn new(s: u32) -> Self {
        let mut seed = s & M;
        // Avoid bad seeds.
        if seed == 0 || seed == M {
            seed = 1;
        }
        Random { seed }
    }

    fn next(&mut self) -> u32 {
        // We are computing
        //       seed_ = (seed_ * A) % M,    where M = 2^31-1
        //
        // seed_ must not be zero or M, or else all subsequent computed values
        // will be zero or M respectively.  For all other values, seed_ will end
        // up cycling through every number in [1,M-1]
        let product = self.seed as u64 * A;

        // Compute (product % M) using the fact that ((x << 31) % M) == x.
        self.seed = ((product >> 31) + (product & M as u64)) as u32;

        // The first reduction may overflow by 1 bit, so we may need to
        // repeat.  mod == M is not possible; using > allows the faster
        // sign-bit-based test.
        if self.seed > M {
            self.seed -= M;
        }
        self.seed
    }

    // Returns a uniformly distributed value in the range [0..n-1]
    // REQUIRES: n > 0
    fn uniform(&mut self, n: u32) -> u32 {
        self.next() % n
    }

    // Skewed: pick "base" uniformly from range [0,max_log] and then
    // return "base" random bits.  The effect is to pick a number in the
    // range [0,2^max_log-1] with exponential bias towards smaller numbers.
    pub fn skewed(&mut self, max_log: u32) -> u32 {
        let x = self.uniform(max_log + 1);
        self.uniform(1 << x)
    }
}
