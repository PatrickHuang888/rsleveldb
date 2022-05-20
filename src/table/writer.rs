use std::io::Write;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

use crate::errors::DbError;
use crate::journal::CASTAGNOLI;
use crate::memdb::{Comparer, Key, Value};

use super::{BLOCK_TRAILER_LEN, FOOTER_LEN};
use super::{BLOCK_TYPE_NO_COMPRESSION, DEFAULT_BLOCK_SIZE};
use crate::table::MAGIC;

struct Writer<'a, 'b, 'c> {
    closed: bool,
    status: Option<String>,

    writer: &'a mut dyn Write,
    cmp: &'b dyn Comparer,

    block_size: usize, // block size from option setting

    data_block: BlockWriter,
    index_block: BlockWriter,

    filter_block: Option<FilterBlock<'c>>,

    // comment from leveldb
    // We do not emit the index entry for a block until we have seen the
    // first key for the next data block.  This allows us to use shorter
    // keys in the index block.  For example, consider a block boundary
    // between the keys "the quick brown fox" and "the who".  We can use
    // "the r" as the key for the index block entry since it is >= all
    // entries in the first block and < all entries in subsequent
    // blocks.
    //
    // Invariant: r->pending_index_entry is true only if data_block is empty.
    pending_index_entry: bool,
    pending_handle: BlockHandle, // handle to add to index block

    offset: usize,
    n_entries: usize,

    compression: CompressionType,
    compressed_buf: Vec<u8>,

    last_key: Key,
}

impl<'a, 'b, 'c> Writer<'a, 'b, 'c> {
    fn new(w: &'a mut dyn Write, cmp: &'b dyn Comparer) -> Self {
        Writer {
            closed: false,
            status: None,
            writer: w,
            cmp: cmp,
            block_size: DEFAULT_BLOCK_SIZE,
            data_block: BlockWriter::new(),
            index_block: BlockWriter::new(),
            filter_block: None,
            pending_index_entry: false,
            pending_handle: BlockHandle {
                offset: 0,
                length: 0,
            },
            offset: 0,
            n_entries: 0,
            compression: CompressionType::NoCompression,
            compressed_buf: Vec::new(),
            last_key: Vec::new(),
        }
    }

    // append appends key/value pair to the table. The keys passed must
    // be in increasing order.
    fn append(&mut self, key: &Key, value: &Value) -> Result<(), DbError> {
        assert!(!self.closed);
        self.ok()?;

        if self.n_entries > 0 && self.cmp.compare(&self.data_block.last_key, key).is_ge() {
            return Err("Writer: keys are not in increasing order"
                .to_string()
                .into());
        }

        if self.pending_index_entry {
            assert!(self.data_block.buf.is_empty());
            let k = self.cmp.separator(&self.last_key, key);
            let v = self.pending_handle.encode();
            self.index_block.append(&k, &v);
            self.pending_index_entry = false;
        }

        match &mut self.filter_block {
            None => {}
            Some(fb) => {
                fb.add(key);
            }
        }

        self.last_key = key.clone();
        self.n_entries += 1;
        self.data_block.append(key, value);

        // finish the data block if block size target reached.
        let size = self.data_block.bytes_len();
        if size >= self.block_size {
            self.flush()?;
        }

        Ok(())
    }

    fn ok(&self) -> Result<(), DbError> {
        match &self.status {
            None => Ok(()),
            Some(s) => Err(s.clone().into()),
        }
    }

    // Advanced operation: flush any buffered key/value pairs to file.
    // Can be used to ensure that two adjacent entries never live in
    // the same data block.  Most clients should not need to use this method.
    // REQUIRES: Finish(), Abandon() have not been called
    pub fn flush(&mut self) -> Result<(), DbError> {
        assert!(!self.closed);
        assert!(!self.pending_index_entry);
        self.ok()?;

        if self.data_block.is_empty() {
            return Ok(());
        }

        let bl = match self.data_block.write(self.writer, self.compression) {
            Ok(n) => n,
            Err(e) => {
                self.set_status(format!("status error: {}", e.to_string()));
                return Err(e.into());
            }
        };
        self.pending_handle.offset = self.offset;
        self.pending_handle.length = bl - BLOCK_TRAILER_LEN;
        self.pending_index_entry = true;
        self.offset += bl;

        match self.writer.flush() {
            Ok(()) => {}
            Err(e) => {
                self.set_status(format!("status error: {}", e.to_string()));
                return Err(e.into());
            }
        }

        // todo:
        //self.filter_block.flush(self.offset);

        Ok(())
    }

    fn set_status(&mut self, msg: String) {
        self.status = Some(msg);
    }

    // Finalize the table. calling append is not possible
    // after finalize, but calling blocks_len, entries_len and bytes_len
    // is still possible.
    pub fn finish(&mut self) -> Result<(), DbError> {
        self.flush()?;

        assert!(!self.closed);
        self.closed = true;

        self.ok()?;

        match &mut self.filter_block {
            None => {}
            Some(fb) => {
                fb.finish();
                fb.write(self.writer)? // no compression
            }
        }

        // todo: write metaindex block
        let mut meta_index_block: BlockWriter = BlockWriter::new();
        match &self.filter_block {
            None => {}
            Some(fb) => {
                // todo:
                /* let mut k= "filter.".to_string();
                let buf= fb.encode();
                meta_index_block.append(&k, &buf) */
            }
        }
        let bl = meta_index_block.write(self.writer, self.compression)?;
        let metaindex_handle: BlockHandle = BlockHandle {
            offset: self.offset,
            length: bl - BLOCK_TRAILER_LEN,
        };
        self.offset += bl;

        // write index block
        if self.pending_index_entry {
            let k = self.cmp.successor(&self.last_key);
            let v = self.pending_handle.encode();
            self.index_block.append(&k, &v);
            self.pending_index_entry = false;
        }
        let bl = self.index_block.write(self.writer, self.compression)?;
        let indexblock_handle = BlockHandle {
            offset: self.offset,
            length: bl - BLOCK_TRAILER_LEN,
        };
        self.offset += bl;

        // write footer
        let footer = Footer {
            metaindex_handle: metaindex_handle,
            index_handle: indexblock_handle,
        };
        let mut footer_buf = footer.encode();
        self.writer.write_all(&footer_buf)?;
        self.offset += footer_buf.len();

        Ok(())
    }

    fn entries_len(&self) -> usize {
        self.n_entries
    }

    fn bytes_len(&self) -> usize {
        self.offset
    }

    // blocks_len returns number of blocks written so far.
    fn blocks_len(&self) -> usize {
        let mut n = self.index_block.counter;
        if self.pending_handle.length > 0 {
            n += 1;
        }
        n
    }
}

struct Footer {
    metaindex_handle: BlockHandle,
    index_handle: BlockHandle,
}

impl Footer {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let _ = v.write_all(&self.metaindex_handle.encode());
        let _ = v.write_all(&self.index_handle.encode());
        let _ = v.write_u64::<LittleEndian>(MAGIC);
        assert_eq!(v.len(), FOOTER_LEN);
        v
    }
}

struct BlockHandle {
    offset: usize,
    length: usize,
}

impl BlockHandle {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        super::put_uvarint(&mut v, self.offset as u64);
        super::put_uvarint(&mut v, self.length as u64);
        v
    }

    fn decode(buf: &[u8]) -> Self {
        //todo:
        Self {
            offset: 0,
            length: 0,
        }
    }

    fn clear(&mut self) {
        self.offset = 0;
        self.length = 0;
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum CompressionType {
    SnappyCompression,
    NoCompression,
}

struct BlockWriter {
    buf: Vec<u8>,
    compressed_buf: Vec<u8>,

    counter: usize,
    restart_interval: usize,
    restarts: Vec<u32>,

    last_key: Key,

    finished: bool,
}

impl BlockWriter {
    fn new() -> Self {
        let mut r = Vec::new();
        r.push(0);
        Self {
            buf: Vec::new(),
            compressed_buf: Vec::new(),
            counter: 0,
            restart_interval: 0,
            restarts: r,
            last_key: Vec::new(),
            finished: false,
        }
    }

    fn append(&mut self, key: &Key, value: &Value) {
        assert!(!self.finished);
        assert!(self.counter <= self.restart_interval);
        // todo: key ascend verificaton

        let mut shared: usize = 0;

        if self.counter < self.restart_interval {
            self.restarts.push(self.buf.len() as u32);
            self.counter = 0;
        } else {
            shared = share_prefix_len(&self.last_key, key);
        }

        // Add "<shared><non_shared><value_size>" to buffer
        put_uvarint(&mut self.buf, shared as u64);
        put_uvarint(&mut self.buf, (key.len() - shared) as u64);
        put_uvarint(&mut self.buf, value.len() as u64);

        // Add string delta to buffer_ followed by value
        let _ = self.buf.write_all(&key[shared..]);
        let _ = self.buf.write_all(value);

        // refactor: no need rewrite all, just write no_shared
        self.last_key.clear();
        let _ = self.last_key.write_all(key);

        self.counter += 1;
    }

    fn finish(&mut self) {
        for x in &self.restarts {
            let _ = self.buf.write_u32::<LittleEndian>(*x);
        }
        let _ = self
            .buf
            .write_u32::<LittleEndian>(self.restarts.len() as u32);
        self.finished = true;
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn bytes_len(&self) -> usize {
        self.buf.len() + 4 * self.restarts.len() + 4 // block trailer every restart has 4 bytes, and 4 bytes restart points len.
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.compressed_buf.clear();

        self.counter = 0;
        self.restarts.clear();
        self.restarts.push(0); // First restart point is at offset 0

        self.finished = false;
        self.last_key.clear();
    }

    fn write(
        &mut self,
        writer: &mut dyn Write,
        compression: CompressionType,
    ) -> Result<usize, std::io::Error> {
        self.finish();

        let mut trailer = [0; BLOCK_TRAILER_LEN];
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
    }
}

struct FilterBlock<'c> {
    policy: &'c dyn FilterPolicy,
    num_keys: usize,
    offsets: Vec<usize>,
    baseLg: usize,

    starts: Vec<usize>, // Starting index in keys_ of each key
    keys: Vec<u8>,      // Flattened key contents
    filter_offsets: Vec<usize>,
    result: Vec<u8>, // Filter data computed so far
    tmp_keys: Vec<Key>,
}

impl<'c> FilterBlock<'c> {
    fn add(&mut self, key: &Key) {
        self.starts.push(key.len());
        self.keys.write_all(key);
    }

    fn finish(&mut self) {
        if !self.starts.is_empty() {
            self.generate_filter();
        }

        // Append array of per-filter offsets
        self.filter_offsets.push(self.result.len());
        for o in &self.filter_offsets {
            self.result.write_u32::<LittleEndian>(*o as u32);
        }
        self.result.push(self.baseLg as u8) // Save encoding parameter in result
    }

    fn write(&self, writer: &dyn std::io::Write) -> std::io::Result<()> {
        Ok(())
    }

    fn generate_filter(&mut self) {
        let num_keys = self.starts.len();
        if num_keys == 0 {
            // Fast path if there are no keys for this filter
            self.filter_offsets.push(self.result.len());
            return;
        }

        // Make list of keys from flattened key structure
        self.starts.push(self.keys.len()); // Simplify length computation

        // todo:
        /* self.tmp_keys.resize(self.num_keys, b0);
        for i in 0..self.num_keys {
            let base = self.starts[i];
            let length = self.starts[i+1] - self.starts[i];
            self.tmp_keys[i]= self.keys[base..base+length].clon;
        } */

        // Generate filter for current set of keys and append to result_.
        self.filter_offsets.push(self.result.len());
        self.policy
            .create_filter(&self.tmp_keys, num_keys, &mut self.result);
    }
}

trait FilterPolicy {
    // Add adds a key to the filter generator.
    //
    // The key may become invalid after call to this method end, therefor
    // key must be copied if implementation require keeping key for later
    // use. The key should not modified directly, doing so may cause
    // undefined results.
    fn add(&self, key: &Key);

    // Generate generates filters based on keys passed so far. After call
    // to Generate the filter generator maybe resetted, depends on implementation.

    // keys[0,n-1] contains a list of keys (potentially with duplicates)
    // that are ordered according to the user supplied comparator.
    // Append a filter that summarizes keys[0,n-1] to *dst.
    //
    // Warning: do not change the initial contents of *dst.  Instead,
    // append the newly constructed filter to *dst.
    fn create_filter(&self, key: &Vec<Key>, n: usize, buf: &mut Vec<u8>);
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
