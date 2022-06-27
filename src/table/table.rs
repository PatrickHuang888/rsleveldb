use std::io::Write;

use crate::{api::{Comparer, Key, Value}, errors::DbError, Options};

use super::{block::BlockWriter};


struct TableWriter<'a, 'b> {

    writer: &'a mut dyn Write,
    cmp: &'b dyn Comparer,

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
    index_opts:Options,

    //filter_block: Option<FilterBlock<'c>>,
}

impl<'a, 'b> TableWriter<'a, 'b> {
    fn new(w: &'a mut dyn Write, cmp: &'b dyn Comparer, opt:&Options) -> Self {
        let opts= opt.clone();
        let mut index_opts= opt.clone();
        index_opts.block_restart_interval= 1;

        Self {
            writer: w,
            cmp: cmp,

            data_block: BlockWriter::new(opts.block_restart_interval),
            index_block: BlockWriter::new(index_opts.block_restart_interval),
            //filter_block: None,

            pending_index_entry: false,
            pending_handle: BlockHandle {
                offset: 0,
                size: 0,
            },

            closed: false,
            status: None,
            offset: 0,
            num_entries: 0,

            compressed_buf: Vec::new(),
            last_key: Vec::new(),

            opts:opts,
            index_opts:index_opts,
        }
    }

  // Add key,value to the table being constructed.
  // REQUIRES: key is after any previously added key according to comparator.
  // REQUIRES: Finish(), Abandon() have not been called
  fn add(&mut self, key: &Key, value: &Value) -> Result<(), DbError> {
        assert!(!self.closed);

        self.ok()?;

        if self.num_entries > 0 && self.cmp.compare(&self.data_block.last_key, key).is_ge() {
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
        match self.status {
            None => Ok(()),
            Some(s) => {
                Err(s.clone().into())
            },
        }
    }

}

impl<'a, 'b> Drop for TableWriter<'a, 'b> {
    fn drop(&mut self) {
        assert!(self.closed) // Catch errors where caller forgot to call Finish()
    }
}

// a pointer to the extent of a file that stores a data
// block or a meta block.
struct BlockHandle {
    offset: usize,
    size: usize,
}

impl BlockHandle {
    fn encode_to(&self, dst:&mut Vec<u8>) {
        assert!(self.offset!=0);
        assert!(self.size!=0);

        super::put_uvarint(dst, self.offset as u64);
        super::put_uvarint(dst, self.size as u64);
    }

    fn decode_from(buf: &[u8]) -> std::result::Result<BlockHandle, String> {
        let (offset, num_offset)= super::get_uvarint(buf).map_err(|s|{
            format!("bad block handle {}", s)
        })?;
        
        let (size, _) = super::get_uvarint(&buf[num_offset..]).map_err(|s|{
            format!("bad block handle {}", s)
        })?;
        
        Ok(BlockHandle {
            offset: offset as usize,
            size: size as usize,
        })
    }

}