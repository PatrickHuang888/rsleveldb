use std::cmp::Ordering;
use std::result;
use std::{io::Write, rc::Rc};

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::CompressionType;
use crate::api::{Comparator, Key, Value};
use crate::errors::{DbError, Result};
use crate::api::BytesComparator;

use super::{BLOCK_TRAILER_SIZE, BLOCK_TYPE_NO_COMPRESSION};

use crate::journal::CASTAGNOLI;

pub struct BlockWriter {
    buf: Vec<u8>,
    //compressed_buf: Vec<u8>,

    counter: usize,
    restart_interval: usize,
    restarts: Vec<u32>,

    last_key: Key,

    finished: bool,
}

impl BlockWriter {
    pub fn new(restart_interval: usize) -> Self {
        assert!(restart_interval>=1);

        let mut r = Vec::new();
        r.push(0);
        Self {
            buf: Vec::new(),
            //compressed_buf: Vec::new(),
            counter: 0,
            restart_interval: restart_interval,
            restarts: r,
            last_key: Vec::new(),
            finished: false,
        }
    }

    pub fn append(&mut self, key: &Key, value: &Value) {
        assert!(!self.finished);
        assert!(self.counter <= self.restart_interval);
        // todo: key ascend verificaton

        let mut shared: usize = 0;

        if self.counter < self.restart_interval {
            // See how much sharing to do with previous string
            shared = share_prefix_len(&self.last_key, key);
        } else {
            self.restarts.push(self.buf.len() as u32);
            self.counter = 0;
        }
        let non_shared = key.len() - shared;

        // Add "<shared><non_shared><value_size>" to buffer
        put_uvarint(&mut self.buf, shared as u64);
        put_uvarint(&mut self.buf, non_shared as u64);
        put_uvarint(&mut self.buf, value.len() as u64);

        // Add string delta to buffer_ followed by value
        let _ = self.buf.write_all(&key[shared..]);
        let _ = self.buf.write_all(value);

        // refactor: no need rewrite all, just write no_shared
        self.last_key.clear();
        let _ = self.last_key.write_all(key);

        self.counter += 1;
    }

    pub fn finish(&mut self) -> &[u8]{
        for x in &self.restarts {
            let _ = self.buf.write_u32::<LittleEndian>(*x);
        }
        let _ = self
            .buf
            .write_u32::<LittleEndian>(self.restarts.len() as u32);
        self.finished = true;
        &self.buf
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn bytes_len(&self) -> usize {
        self.buf.len() + 4 * self.restarts.len() + 4 // block trailer every restart has 4 bytes, and 4 bytes restart points len.
    }

    fn reset(&mut self) {
        self.buf.clear();
        //self.compressed_buf.clear();

        self.counter = 0;
        self.restarts.clear();
        self.restarts.push(0); // First restart point is at offset 0

        self.finished = false;
        self.last_key.clear();
    }

    /* pub fn write(
        &mut self,
        writer: &mut dyn Write,
        compression: CompressionType,
    ) -> result::Result<usize, std::io::Error> {
        self.finish();

        let mut trailer = [0; BLOCK_TRAILER_SIZE];
        let l;

        match compression {
            CompressionType::SnappyCompression => {
                {
                    let mut w = snap::write::FrameEncoder::new(&mut self.compressed_buf);
                    w.write_all(&self.buf)?;
                    w.flush()?;
                }

                writer.write_all(&self.compressed_buf)?;

                let checksum = CASTAGNOLI.checksum(&self.compressed_buf);
                LittleEndian::write_u32(&mut trailer[1..], checksum);
                writer.write_all(&trailer)?;
                l = self.compressed_buf.len();
            }

            CompressionType::NoCompression => {
                writer.write_all(&self.buf)?;

                trailer[0] = BLOCK_TYPE_NO_COMPRESSION;
                let checksum = CASTAGNOLI.checksum(&self.buf);
                LittleEndian::write_u32(&mut trailer[1..], checksum);
                writer.write_all(&trailer)?;
                l = self.buf.len();
            }
        }

        self.reset();
        Ok(l)
    } */
}

fn share_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let mut n = a.len();
    if n > b.len() {
        n = b.len();
    }
    let mut i: usize = 0;
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i
}

// Copy from golang binary.putUvarint()
// PutUvarint encodes a uint64 into buf and returns the number of bytes written.
// If the buffer is too small, PutUvarint will panic.
// unsigned integers are serialized 7 bits at a time, starting with the
//   least significant bits
// - the most significant bit (msb) in each output byte indicates if there
//   is a continuation byte (msb = 1)
// Design note:
// At most 10 bytes are needed for 64-bit values. The encoding could
// be more dense: a full 64-bit value needs an extra byte just to hold bit 63.
// Instead, the msb of the previous byte could be used to hold bit 63 since we
// know there can't be more than 64 bits. This is a trivial improvement and
// would reduce the maximum encoding length to 9 bytes. However, it breaks the
// invariant that the msb is always the "continuation bit" and thus makes the
// format incompatible with a varint encoding for larger numbers (say 128-bit).
fn put_uvarint(buf: &mut Vec<u8>, v: u64) {
    let mut x = v;
    while x >= 0x80 {
        // large than 0b1000_0000
        buf.push(x as u8 | 0x80); // continuation
        x >>= 7;
    }
    buf.push(x as u8);
}

pub struct BlockReader<'a> {
    data: &'a Vec<u8>,
    num_restarts: usize,
    restart_offset: usize,
    cmp: Rc<dyn Comparator>,
}

impl<'a> BlockReader<'a> {
    pub fn new(data: &'a Vec<u8>) -> Self {
        let mut num_restarts = 0;
        let mut restart_offset = 0;
        if data.len() >= 4 {
            num_restarts = LittleEndian::read_u32(&data[data.len() - 4..]);
            restart_offset = data.len() - ((num_restarts + 1) * 4) as usize;
        }
        Self {
            data: data,
            num_restarts: num_restarts as usize,
            restart_offset: restart_offset,
            cmp: Rc::new(BytesComparator {}),
        }
    }

    pub fn iter(&self) -> BlockIter {
        BlockIter::new(
            self.data,
            self.num_restarts,
            self.restart_offset,
            self.cmp.clone(),
        )
    }
}

struct BlockIter<'a> {
    key: Vec<u8>,
    value: Vec<u8>,

    restarts: usize,     // Offset of trailer restart array (list of fixed32)
    current: usize,      // current_ is offset in data_ of current entry.  >= restarts_ if !Valid]
    value_offset: usize, // value offset of a entry

    restart_index: usize, // Index of restart block in which current_ falls
    num_restarts: usize,  // Number of uint32_t entries in restart array
    status: Option<String>,

    data: &'a Vec<u8>, // underlying block contents

    cmp: Rc<dyn Comparator>,
}

impl<'a> BlockIter<'a> {
    fn new(data: &'a Vec<u8>, num_restarts: usize, restarts: usize, cmp: Rc<dyn Comparator>) -> Self {
        assert!(num_restarts > 0);
        Self {
            key: Vec::new(),
            value: Vec::new(),
            restarts: restarts,
            current: restarts,
            value_offset: 0,
            restart_index: 0,
            num_restarts: num_restarts,
            status: None,
            data: data,
            cmp: cmp.clone(),
        }
    }

    fn seek_to_first(&mut self) -> Result<()> {
        self.seek_to_restart_point(0);
        self.parse_next_key().map(|_| ())
    }

    fn seek_to_last(&mut self) -> Result<()> {
        self.seek_to_restart_point(self.num_restarts - 1);
        while self.parse_next_key()? && self.next_entry_offset() < self.restarts {
            // Keep skipping
        }
        Ok(())
    }

    // return key offset
    fn decode_entry(
        &mut self,
        entry: usize,
        limit: usize,
        shared: &mut usize,
        non_shared: &mut usize,
        value_length: &mut usize,
    ) -> Result<usize> {
        if limit - entry < 3 {
            return Err("error entry length".to_string().into());
        }

        // no consideration of 32 bit usize
        let (s, n) = super::get_uvarint(&self.data[entry..limit]).map_err(|s| {
            println!("{}", s);
            self.corrupted()
        })?;
        *shared = s as usize;

        let (ns, nn) = super::get_uvarint(&self.data[entry + n..limit]).map_err(|s| {
            println!("{}", s);
            self.corrupted()
        })?;
        *non_shared = ns as usize;

        let (vl, nnl) = super::get_uvarint(&self.data[entry + n + nn..limit]).map_err(|s| {
            println!("{}", s);
            self.corrupted()
        })?;
        *value_length = vl as usize;

        Ok(entry + n + nn + nnl)
    }

    fn parse_next_key(&mut self) -> Result<bool> {
        self.current = self.next_entry_offset();

        if self.current >= self.restarts {
            // No more entries to return.  Mark as invalid.
            self.current = self.restarts;
            self.restart_index = self.num_restarts;
            return Ok(false);
        };

        // Decode next entry
        let mut shared = 0;
        let mut non_shared = 0;
        let mut value_length = 0;
        let key_offset = self.decode_entry(
            self.current,
            self.restarts,
            &mut shared,
            &mut non_shared,
            &mut value_length,
        )?;
        if self.key.len() < shared {
            return Err(self.corrupted().into());
        }
        self.key.truncate(shared);
        let _ = self
            .key
            .write_all(&self.data[key_offset..key_offset + non_shared]);

        self.value_offset = key_offset + non_shared;
        self.value.clear();
        let _ = self
            .value
            .write_all(&self.data[self.value_offset..self.value_offset + value_length]);

        // entry end
        while self.restart_index + 1 < self.num_restarts
            && self.get_restart_point(self.restart_index + 1) < self.current
        {
            self.restart_index += 1;
        }
        Ok(true)
    }

    fn next_entry_offset(&self) -> usize {
        self.value_offset + self.value.len()
    }

    fn seek_to_restart_point(&mut self, index: usize) {
        self.key.clear();
        self.value.clear();
        self.restart_index = index;

        // current_ will be fixed by ParseNextKey();
        self.value_offset = self.get_restart_point(index);
    }

    // Return the offset in data_ just past the end of the current entry.
    fn get_restart_point(&self, index: usize) -> usize {
        assert!(index < self.num_restarts);
        LittleEndian::read_u32(&self.data[self.restarts + index * 4..]) as usize
    }

    fn corrupted(&mut self) -> String {
        self.key.clear();
        self.value.clear();
        self.current = self.restarts;
        self.restart_index = self.num_restarts;
        let s = "bad entry in block".to_string();
        self.status = Some(s.clone());
        s
    }

    fn status(&self) -> Result<()> {
        match &self.status {
            None => Ok(()),
            Some(s) => Err(s.clone().into()),
        }
    }
}

impl<'a> super::Iterator for BlockIter<'a> {
    fn next(&mut self) -> Result<()> {
        if !self.valid()? {
            return Err("Iterator invalid".to_string().into());
        }
        self.parse_next_key()?;
        Ok(())
    }

    fn prev(&mut self) -> Result<()> {
        if !self.valid()? {
            return Err("Iterator invalid".to_string().into());
        }

        // Scan backwards to a restart point before current_
        let original = self.current;
        while self.get_restart_point(self.restart_index) >= original {
            if self.restart_index == 0 {
                // No more entries
                self.current = self.restarts;
                self.restart_index = self.num_restarts;
                return Ok(());
            }
            self.restart_index -= 1;
        }

        self.seek_to_restart_point(self.restart_index);
        while {
            // Loop until end of current entry hits the start of original entry
            self.parse_next_key()? && self.next_entry_offset() < original
        } {}
        Ok(())
    }

    fn seek(&mut self, target: &Key) -> Result<()> {
        // Binary search in restart array to find the last restart point
        // with a key < target
        let mut left = 0;
        let mut right = self.num_restarts - 1;
        let mut current_compare = Ordering::Equal;

        if self.valid()? {
            // If we're already scanning, use the current position as a starting
            // point. This is beneficial if the key we're seeking to is ahead of the
            // current position.
            current_compare = self.cmp.compare(&self.key, target);
            match current_compare {
                Ordering::Less => {
                    left = self.restart_index;
                }
                Ordering::Greater => {
                    right = self.restart_index;
                }
                Ordering::Equal => return Ok(()),
            };
        }

        while left < right {
            let mid = (left + right + 1) / 2;
            let region_offset = self.get_restart_point(mid);

            let mut shared = 0;
            let mut non_shared = 0;
            let mut value_length = 0;
            let key_offset = self.decode_entry(
                region_offset,
                self.restarts,
                &mut shared,
                &mut non_shared,
                &mut value_length,
            )?;
            if shared != 0 {
                return Err(self.corrupted().into());
            }
            let mut mid_key: Vec<u8> = Vec::with_capacity(non_shared);
            let _ = mid_key.write_all(&self.data[key_offset..key_offset + non_shared]);

            if self.cmp.compare(&mid_key, target).is_lt() {
                left = mid;
            } else {
                right = mid - 1;
            }
        }

        // We might be able to use our current position within the restart block.
        // This is true if we determined the key we desire is in the current block
        // and is after than the current key.
        assert!(current_compare.is_eq() || self.valid().unwrap());
        let skip_seek = left == self.restart_index && current_compare.is_lt();
        if !skip_seek {
            self.seek_to_restart_point(left);
        }

        // Linear search (within restart block) for first key >= target
        loop {
            if !self.parse_next_key()? {
                return Ok(());
            }
            if self.cmp.compare(&self.key, target).is_ge() {
                return Ok(());
            }
        }
    }

    fn key(&self) -> &Key {
        &self.key
    }

    fn value(&self) -> &Value {
        &self.value
    }

    fn valid(&self) -> Result<bool> {
        self.status()?;
        Ok(self.current < self.restarts)
    }
}

mod rnd {
    use rand::{prelude::ThreadRng, thread_rng, Rng};

    // Skewed: pick "base" uniformly from range [0,max_log] and then
    // return "base" random bits.  The effect is to pick a number in the
    // range [0,2^max_log-1] with exponential bias towards smaller numbers.
    pub fn skewed(max_log: i64) -> usize {
        let mut rng = thread_rng();
        let r = rng.gen_range(0..max_log + 1);
        rng.gen_range(0..(1 << r))
    }
}

#[cfg(test)]
mod tests {
    use rand::prelude::ThreadRng;
    use rand::thread_rng;
    use rand::Rng;

    use crate::api::BytesComparator;
    use crate::api::Key;
    use crate::api::Value;
    use crate::table::Iterator;
    use crate::test::KeyValue;

    use super::BlockReader;
    use super::BlockWriter;

    static intervals: [usize; 3] = [1, 16, 1024];

    #[test]
    fn test_block_empty() {
        let cmp = BytesComparator::default();
        let kv = KeyValue::new(&cmp);

        test(&kv)
    }

    #[test]
    fn test_simple_single() {
        let cmp = BytesComparator::default();
        let mut kv = KeyValue::new(&cmp);
        kv.append(&"abc".as_bytes().to_vec(), &"v".as_bytes().to_vec());

        test(&kv)
    }

    #[test]
    fn test_simple_specical_key() {
        let cmp = BytesComparator::default();
        let mut kv = KeyValue::new(&cmp);
        let key = vec![0xff, 0xff];
        kv.append(&key, &"v3".as_bytes().to_vec());

        test(&kv)
    }

    #[test]
    fn test_simple_multi() {
        let cmp = BytesComparator::default();
        let mut kv = KeyValue::new(&cmp);
        kv.append(&"abc".as_bytes().to_vec(), &"v".as_bytes().to_vec());
        kv.append(&"abcd".as_bytes().to_vec(), &"v".as_bytes().to_vec());
        kv.append(&"ac".as_bytes().to_vec(), &"v2".as_bytes().to_vec());

        test(&kv)
    }

    #[test]
    fn test_randomized() {
        let cmp = BytesComparator::default();
        let mut kv = KeyValue::new(&cmp);

        let mut rng = thread_rng();
        let mut num_entries = 0;
        while num_entries < 2000 {
            kv.clear();

            if (num_entries % 10) == 0 {
                println!("num_entries = {}", num_entries);
            }
            for _ in 0..num_entries {
                let k = random_key(&mut rng, super::rnd::skewed(4));
                let v = random_value(&mut rng, 5);
                kv.put_u(&k, &v);
            }

            if num_entries < 50 {
                num_entries += 1
            } else {
                num_entries += 200
            }

            test(&kv)
        }
    }

    static test_bytes: [u8; 10] = [0x0, 0x1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xf, 0xf];

    fn random_key(rng: &mut ThreadRng, len: usize) -> Key {
        let mut r = Vec::with_capacity(len);
        for _ in 0..len {
            r.push(test_bytes[rng.gen_range(0..10)]);
        }
        r
    }

    fn random_value(rng: &mut ThreadRng, len: usize) -> Value {
        let mut r = Vec::with_capacity(len);
        for _ in 0..len {
            r.push(test_bytes[rng.gen_range(0..10)]);
        }
        r
    }

    fn test(kv: &KeyValue) {
        for v in intervals {
            let mut w = BlockWriter::new(v);
            for i in 0..kv.len() {
                let (k, v) = kv.index_at(i);
                w.append(k, v);
            }
            w.finish();

            let br = BlockReader::new(&w.buf);

            test_forward_scan(&br, &kv);
            test_backward_scan(&br, &kv);

            let mut rng = thread_rng();
            test_random_access(&mut rng, &br, &kv);
        }
    }

    fn test_forward_scan(br: &BlockReader, kv: &KeyValue) {
        let mut it = br.iter();
        assert!(!it.valid().unwrap());
        assert!(it.seek_to_first().is_ok());
        let mut i = 0;
        while i < kv.len() {
            assert_eq!(kv.index_at(i), (it.key(), it.value()));
            assert!(it.next().is_ok());
            i += 1;
        }
        assert!(!it.valid().unwrap());
    }

    fn test_backward_scan(br: &BlockReader, kv: &KeyValue) {
        let mut it = br.iter();
        assert!(!it.valid().unwrap());

        assert!(it.seek_to_last().is_ok());
        for i in (0..kv.len()).rev() {
            assert_eq!((it.key(), it.value()), kv.index_at(i));
            assert!(it.prev().is_ok());
        }
    }

    fn test_random_access(rng: &mut ThreadRng, br: &BlockReader, kv: &KeyValue) {
        let verbose = true;
        let mut kv_index = 0;

        let mut it = br.iter();
        assert!(!it.valid().unwrap());

        if verbose {
            println!("---");
        }
        for _ in 0..200 {
            let toss = rng.gen_range(0..5);
            match toss {
                0 => {
                    if it.valid().unwrap() {
                        if verbose {
                            println!("next");
                        }
                        assert!(it.next().is_ok());
                        if kv_index < kv.len() - 1 {
                            kv_index += 1;
                            assert_eq!((it.key(), it.value()), kv.index_at(kv_index));
                        } else {
                            assert!(!it.valid().unwrap());
                        }
                    }
                }
                1 => {
                    if verbose {
                        println!("seek_to_first");
                    }
                    let r = it.seek_to_first();
                    assert!(r.is_ok(), "seek_to_first error {}", r.unwrap_err());
                    if kv.len() != 0 {
                        kv_index = 0;
                        assert_eq!((it.key(), it.value()), kv.index_at(kv_index));
                    }
                }
                2 => {
                    if kv.len() != 0 {
                        kv_index = rng.gen_range(0..kv.len());
                        let (k, v) = kv.index_at(kv_index);
                        if verbose {
                            println!("seek {:?}", k.clone())
                        }
                        let s = it.seek(&k);
                        assert!(s.is_ok(), "seek err {}", s.unwrap_err());
                        assert_eq!((it.key(), it.value()), (k, v));
                    }
                }
                3 => {
                    if it.valid().unwrap() {
                        if verbose {
                            println!("prev");
                        }
                        assert!(it.prev().is_ok());
                        if kv_index == 0 {
                            assert!(!it.valid().unwrap());
                        } else {
                            kv_index -= 1;
                            assert_eq!((it.key(), it.value()), kv.index_at(kv_index));
                        }
                    }
                }
                4 => {
                    if verbose {
                        println!("seek_to_last");
                    }
                    let r = it.seek_to_last();
                    assert!(r.is_ok(), "seek_to_last err {}", r.unwrap_err());
                    if kv.len() == 0 {
                        assert!(!it.valid().unwrap());
                    } else {
                        kv_index = kv.len() - 1;
                        assert_eq!((it.key(), it.value()), kv.index_at(kv_index));
                    }
                }
                _ => {
                    panic!("rng error")
                }
            }
        }
    }
}
