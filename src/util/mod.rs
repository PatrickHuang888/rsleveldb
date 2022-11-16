use crc::{Crc, CRC_32_ISCSI};

use crate::api;

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

pub fn encode_varint64(dst: &mut Vec<u8>, v: u64) {
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

// usize 0 error
pub fn get_varint32(src: &[u8]) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut shift: usize = 0;

    for i in 0..src.len() {
        let b = src[i];
        if b < B {
            return (value | (b as u32) << shift, i + 1);
        }
        value |= ((b & 0x7f) as u32) << shift; //0b0111_1111
        shift += 7;
    }
    (0, 0)
}

pub fn get_varint64(src: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift: usize = 0;

    for i in 0..src.len() {
        let b = src[i];
        if b < B {
            return (value | (b as u64) << shift, i + 1);
        }
        value |= ((b & 0x7f) as u64) << shift; //0b0111_1111
        shift += 7;
    }
    (0, 0)
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
pub fn get_length_prefixed_slice(data: &[u8]) -> (&[u8], usize) {
    let (len, off) = get_varint32(data);
    let end = off + len as usize;
    (&data[off..end], off + len as usize)
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
