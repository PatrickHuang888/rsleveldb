use std::{io::Write, vec};
use crate::errors;

use byteorder::{LittleEndian, ByteOrder};

use crate::{api::{Comparator, Key, Value}, errors::DbError, Options, table::MAX_VARINT_LEN64, CompressionType, journal::CASTAGNOLI};

use super::{block::BlockWriter, BLOCK_TRAILER_SIZE};


struct TableWriter<'a, 'b> {

    writer: &'b mut dyn Write,

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

    opts: Options<'a>,
    index_opts:Options<'a>,

    //filter_block: Option<FilterBlock<'c>>,
}

impl<'a, 'b> TableWriter<'a, 'b> {
    fn new(w: &'b mut dyn Write, opt:&Options<'a>) -> Self {
        let opts= opt.clone();
        let mut index_opts= opt.clone();
        index_opts.block_restart_interval= 1;

        Self {
            writer: w,

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

        if self.num_entries > 0 && self.opts.comparator.compare( key, &self.last_key).is_le() {
            return Err("table writer: keys are not in increasing order"
                .to_string()
                .into());
        }

        if self.pending_index_entry {
            assert!(self.data_block.is_empty());
            self.opts.comparator.find_shortest_separator(&mut self.last_key, key);
            let mut handle_encoding= Vec::with_capacity(2*MAX_VARINT_LEN64);
            self.pending_handle.encode_to(& mut handle_encoding);
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
        assert!(!self.pending_index_entry);
        self.ok()?;

        if self.data_block.is_empty() {
            return Ok(());
        }

        let bl = match self.data_block.write(self.writer, self.opts.compression) {
            Ok(n) => n,
            Err(e) => {
                self.set_status(format!("status error: {}", e.to_string()));
                return Err(e.into());
            }
        };

        self.pending_index_entry = true;
        self.pending_handle.offset = self.offset;
        self.pending_handle.length = bl - BLOCK_TRAILER_LEN;
        
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

    fn  write_block(&mut self, block:&mut BlockWriter, handle : &BlockHandle) -> errors::Result<()> {
        // File format contains a sequence of blocks where each block has:
        //    block_data: uint8[n]
        //    type: uint8
        //    crc: uint32
        self.ok()?;

        let raw= block.finish();

        let mut  block_contents:&[u8];
        match self.opts.compression {
            CompressionType::NoCompression => {
                block_contents= raw;
            },
            CompressionType::SnappyCompression => {

            }
        }

        self.write_raw_block(block_contents, compression_type, handle)

        Ok(())
    }
    
    fn write_raw_block(&mut self, block_contents : &[u8], compression_type: CompressionType, handle:&mut BlockHandle) -> std::io::Result<()> {
        handle.offset= self.offset;
        handle.size= block_contents.len();
        
        let mut count=0;
        while count < block_contents.len() {
            // todo: handling Interrupted error and n==0
            count += self.writer.write(&block_contents[count..])?;
        }

        let mut trailer:[u8;BLOCK_TRAILER_SIZE]= [0; BLOCK_TRAILER_SIZE];
        trailer[0]= compression_type as u8;
        
        let mut digest= CASTAGNOLI.digest();
        digest.update(block_contents);
        digest.update(&trailer[0..1]);
        let crc= digest.finalize();
        // leveldb has a mask operation

        LittleEndian::write_u32(&mut trailer[1..], crc);

        count= 0;
        while count < BLOCK_TRAILER_SIZE {
            // todo: handling Interrupted error and n==0
            count += self.writer.write(&trailer)?
        }

        self.offset += block_contents.len() + BLOCK_TRAILER_SIZE;

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