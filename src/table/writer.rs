use std::io::Write;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

use crate::errors::DbError;
use crate::journal::CASTAGNOLI;
use crate::memdb::{Comparer, Key, Value};

use super::{BLOCK_TRAILER_LEN, FOOTER_LEN, TableOption};
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

    opt: TableOption,
}

impl<'a, 'b, 'c> Writer<'a, 'b, 'c> {



    

    // Advanced operation: flush any buffered key/value pairs to file.
    // Can be used to ensure that two adjacent entries never live in
    // the same data block.  Most clients should not need to use this method.
    // REQUIRES: Finish(), Abandon() have not been called
    

    fn set_status(&mut self, msg: String) {
        self.status = Some(msg);
    }

    // Finalize the table. calling append is not possible
    // after finalize, but calling blocks_len, entries_len and bytes_len
    // is still possible.
    

    

    

    // blocks_len returns number of blocks written so far.
    fn blocks_len(&self) -> usize {
        let mut n = self.index_block.counter;
        if self.pending_handle.length > 0 {
            n += 1;
        }
        n
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


