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

pub fn encode_varint32(dst: &mut Vec<u8>, v: u32) {
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
    assert!(src.len() <= 5);
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
    assert!(src.len() <= 10);
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

pub fn encode_fixed64(dst: &mut Vec<u8>, v: u64) {
    dst.push(v as u8);
    dst.push((v >> 8) as u8);
    dst.push((v >> 16) as u8);
    dst.push((v >> 24) as u8);
    dst.push((v >> 32) as u8);
    dst.push((v >> 40) as u8);
    dst.push((v >> 48) as u8);
    dst.push((v >> 56) as u8);
}

pub fn decode_fixed64(src: &[u8]) -> u64 {
    assert_eq!(src.len(), 8);
    let mut value:u64= 0;
    value = src[0] as u64 | (src[1] as u64) << 8 | (src[2] as u64) << 16 | (src[3] as u64) << 24 | (src[4] as u64) << 32 | (src[5] as u64) << 40 |
    (src[6] as u64) << 48 | (src[7] as u64) << 56;
    value
}
