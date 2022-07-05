use crate::{
    errors,
    table::{FOOTER_LEN, MAGIC},
};
use std::{fmt::format, io::Write, vec};

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

use crate::{
    api::{Comparator, Key, Value},
    errors::DbError,
    journal::CASTAGNOLI,
    table::MAX_VARINT_LEN64,
    CompressionType, Options,
};

use super::{block::BlockWriter, BLOCK_TRAILER_SIZE};

struct TableWriter<'a> {
    writer: &'a mut dyn Write,

    data_block: BlockWriter,
    index_block: BlockWriter,

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

    compressed_buf: Vec<u8>,
    last_key: Key,

    num_entries: usize,
    offset: usize,
    closed: bool,

    status: Option<String>,

    opts: Options,
    //index_opts:Options<'a>,

    //filter_block: Option<FilterBlock<'c>>,
}

impl<'a> TableWriter<'a> {
    fn new(w: &'a mut dyn Write, options: &Options) -> Self {
        let opts = options.clone();

        Self {
            writer: w,

            data_block: BlockWriter::new(opts.block_restart_interval),
            index_block: BlockWriter::new(1),

            //filter_block: None,
            pending_index_entry: false,
            pending_handle: BlockHandle { offset: 0, size: 0 },

            closed: false,
            status: None,
            offset: 0,
            num_entries: 0,

            compressed_buf: Vec::new(),
            last_key: Vec::new(),

            opts: opts,
        }
    }

    // Add key,value to the table being constructed.
    // REQUIRES: key is after any previously added key according to comparator.
    // REQUIRES: Finish(), Abandon() have not been called
    fn add(&mut self, key: &Key, value: &Value) -> Result<(), DbError> {
        assert!(!self.closed);

        self.ok()?;

        if self.num_entries > 0 && self.opts.comparator.compare(key, &self.last_key).is_le() {
            return Err("table writer: keys are not in increasing order"
                .to_string()
                .into());
        }

        if self.pending_index_entry {
            assert!(self.data_block.is_empty());
            self.opts
                .comparator
                .find_shortest_separator(&mut self.last_key, key);
            let mut handle_encoding = Vec::with_capacity(2 * MAX_VARINT_LEN64);
            self.pending_handle.encode_to(&mut handle_encoding);
            self.index_block.append(&self.last_key, &handle_encoding);
            self.pending_index_entry = false;
        }

        /* match &mut self.filter_block {
            None => {}
            Some(fb) => {
                fb.add(key);
            }
        } */

        self.last_key = key.clone();
        self.num_entries += 1;
        self.data_block.append(key, value);

        // finish the data block if block size target reached.
        let size = self.data_block.bytes_len();
        if size >= self.opts.block_size {
            self.flush()?;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), DbError> {
        assert!(!self.closed);
        self.ok()?;

        if self.data_block.is_empty() {
            return Ok(());
        }

        assert!(!self.pending_index_entry);

        let l = self
            .data_block
            .write(self.writer, self.opts.compression)
            .map_err(|e| {
                let s = format!("data block write error {}", e.to_string());
                self.status = Some(s.clone());
                s
            })?;

        self.pending_handle.offset = self.offset;
        self.pending_handle.size = l - BLOCK_TRAILER_SIZE;
        self.pending_index_entry = true;
        self.offset += l;

        self.writer.flush()?;

        // todo:
        //self.filter_block.flush(self.offset);

        Ok(())
    }

    pub fn finish(&mut self) -> crate::errors::Result<()> {
        self.flush()?;

        assert!(!self.closed);
        self.closed = true;

        self.ok()?;

        // todo: write filterindex block
        /* match &mut self.filter_block {
            None => {}
            Some(fb) => {
                fb.finish();
                fb.write(self.writer)? // no compression
            }
        } */

        let mut meta_index_block: BlockWriter = BlockWriter::new(self.opts.block_restart_interval);
        /* match &self.filter_block {
            None => {}
            Some(fb) => {
                // todo:
                let mut k= "filter.".to_string();
                let buf= fb.encode();
                meta_index_block.append(&k, &buf)
            }
        } */
        let l = meta_index_block
            .write(self.writer, self.opts.compression)
            .map_err(|e| {
                let s = format!("meta index block write error {}", e.to_string());
                self.status = Some(s.clone());
                s
            })?;
        let meta_index_handle: BlockHandle = BlockHandle {
            offset: self.offset,
            size: l - BLOCK_TRAILER_SIZE,
        };
        self.offset += l;

        // write index block
        let mut index_block_handle = BlockHandle { offset: 0, size: 0 };
        if self.pending_index_entry {
            self.opts
                .comparator
                .find_short_successor(&mut self.last_key);
            let mut handle_encoding = Vec::with_capacity(2 * MAX_VARINT_LEN64);
            self.pending_handle.encode_to(&mut handle_encoding);
            self.index_block.append(&self.last_key, &handle_encoding);
            self.pending_index_entry = false;
        }
        let l = self
            .index_block
            .write(self.writer, self.opts.compression)
            .map_err(|e| {
                let s = format!("index block write error {}", e.to_string());
                self.status = Some(s.clone());
                s
            })?;
        index_block_handle.offset = self.offset;
        index_block_handle.size = l - BLOCK_TRAILER_SIZE;
        self.offset += l;

        // write footer
        let footer = Footer {
            metaindex_handle: meta_index_handle,
            index_handle: index_block_handle,
        };
        let footer_encoding = footer.encode();
        self.writer.write_all(&footer_encoding)?;
        self.offset += footer_encoding.len();

        Ok(())
    }

    fn ok(&self) -> Result<(), DbError> {
        match &self.status {
            None => Ok(()),
            Some(s) => Err(s.clone().into()),
        }
    }

    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    pub fn file_size(&self) -> usize {
        self.offset
    }

}

impl<'a> Drop for TableWriter<'a> {
    fn drop(&mut self) {
        assert!(self.closed) // Catch errors where caller forgot to call Finish()
    }
}

struct Footer {
    metaindex_handle: BlockHandle,
    index_handle: BlockHandle,
}

impl Footer {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 * MAX_VARINT_LEN64);
        self.metaindex_handle.encode_to(&mut v);
        self.index_handle.encode_to(&mut v);
        v.resize(2 * MAX_VARINT_LEN64, 0); // Padding
        let _ = v.write_u64::<LittleEndian>(MAGIC); // make sure is littlen endian
        assert_eq!(v.len(), FOOTER_LEN);
        v
    }
}

// a pointer to the extent of a file that stores a data
// block or a meta block.
struct BlockHandle {
    offset: usize,
    size: usize,
}

impl BlockHandle {
    fn encode_to(&self, dst: &mut Vec<u8>) {
        assert!(self.offset != 0);
        assert!(self.size != 0);

        super::put_uvarint(dst, self.offset as u64);
        super::put_uvarint(dst, self.size as u64);
    }

    fn decode_from(buf: &[u8]) -> std::result::Result<BlockHandle, String> {
        let (offset, num_offset) =
            super::get_uvarint(buf).map_err(|s| format!("bad block handle {}", s))?;

        let (size, _) = super::get_uvarint(&buf[num_offset..])
            .map_err(|s| format!("bad block handle {}", s))?;

        Ok(BlockHandle {
            offset: offset as usize,
            size: size as usize,
        })
    }
}
