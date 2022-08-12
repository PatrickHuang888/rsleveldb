use crate::{
    api,
    table::{FOOTER_LEN, MAGIC},
};
use std::{
    fmt::format,
    io::{Error, Read, Write},
    rc::Rc,
    vec,
};

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::{
    api::DbError,
    api::Iterator,
    api::{Comparator, Key, Value},
    journal::CASTAGNOLI,
    table::MAX_VARINT_LEN64,
    CompressionType, Options,
};

use super::{
    block::{BlockIterator, BlockReader, BlockWriter},
    BLOCK_TRAILER_SIZE,
};

pub struct TableWriter<'a, W: Write, C: Comparator> {
    writer: &'a mut W,

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

    opts: Options<C>,
    //index_opts:Options<'a>,

    //filter_block: Option<FilterBlock<'c>>,
}

impl<'a, W: Write, C: Comparator> TableWriter<'a, W, C> {
    pub fn new(w: &'a mut W, options: &Options<C>) -> Self {
        let opts = options.clone();

        TableWriter {
            writer: w,

            data_block: BlockWriter::new(opts.block_restart_interval),
            index_block: BlockWriter::new(1),

            //filter_block: None,
            pending_index_entry: false,
            pending_handle: Default::default(),

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
    pub fn add(&mut self, key: &Key, value: &Value) -> Result<(), DbError> {
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

    pub fn finish(&mut self) -> crate::api::Result<()> {
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
        let mut index_block_handle = BlockHandle::default();
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
        self.offset += FOOTER_LEN;

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

impl<'a, W: Write, C: Comparator> Drop for TableWriter<'a, W, C> {
    fn drop(&mut self) {
        assert!(self.closed) // Catch errors where caller forgot to call Finish()
    }
}

#[derive(Default)]
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
    fn decode_from(input: &[u8]) -> std::result::Result<Self, String> {
        let magic = LittleEndian::read_u64(&input[FOOTER_LEN - 8..]);
        if magic != MAGIC {
            return Err("not an sstable (bad magic number)".to_string().into());
        }
        let mut metaindex_handle = BlockHandle::default();
        let l = BlockHandle::decode_from(input, &mut metaindex_handle)?;
        let mut index_handle = BlockHandle::default();
        let _ = BlockHandle::decode_from(&input[l..], &mut index_handle)?;

        Ok(Self {
            metaindex_handle: metaindex_handle,
            index_handle: index_handle,
        })
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
        assert!(self.offset != !0);
        assert!(self.size != !0);

        super::put_uvarint(dst, self.offset as u64);
        super::put_uvarint(dst, self.size as u64);
    }

    fn decode_from(buf: &[u8], handle: &mut BlockHandle) -> std::result::Result<usize, String> {
        let (offset, num_offset) =
            super::get_uvarint(buf).map_err(|s| format!("bad block handle, {}", s))?;

        let (size, num_size) = super::get_uvarint(&buf[num_offset..])
            .map_err(|s| format!("bad block handle, {}", s))?;

        handle.offset = offset as usize;
        handle.size = size as usize;

        Ok(num_offset + num_size)
    }
}

impl Default for BlockHandle {
    fn default() -> Self {
        BlockHandle {
            offset: !0,
            size: !0,
        }
    }
}

pub trait RandomAccessRead {
    // Read up to "n" bytes from the file starting at "offset".
    // Safe for concurrent use by multiple threads.
    fn read(&self, offset: usize, n: usize, dst: &mut Vec<u8>) -> std::io::Result<(usize)>;
}

pub struct TableReader<'f, C: Comparator, F> {
    opts: Options<C>,
    status: Option<String>,

    file: &'f F,

    meta_index_handle: BlockHandle,
    index_block: BlockReader,
}

impl<'f, C: Comparator, F: RandomAccessRead> TableReader<'f, C, F> {
    pub fn open(opts: Options<C>, file: &'f F, size: usize) -> crate::api::Result<Self> {
        if size < FOOTER_LEN {
            return Err("Corruption: file is too short to be an sstable"
                .to_string()
                .into());
        }

        //let footer_space: [u8;FOOTER_LEN]= [0;FOOTER_LEN];
        let mut footer_input = Vec::with_capacity(FOOTER_LEN);
        file.read(size - FOOTER_LEN, FOOTER_LEN, &mut footer_input)?;
        let mut footer = Footer::decode_from(&footer_input)?;

        // Read index block
        let mut opt = ReadOptions::default();
        if opts.paranoid_checks {
            opt.verify_checksums = true;
        }
        let index_contents = read_block_content(file, &opt, &mut footer.index_handle)?;
        let r = TableReader {
            opts: opts.clone(),
            status: None,
            file: file,
            index_block: BlockReader::new(index_contents),
            meta_index_handle: footer.metaindex_handle,
        };
        r.read_meta()?;
        Ok(r)
    }

    fn read_meta(&self) -> std::io::Result<()> {
        // todo:
        Ok(())
    }

    pub fn new_iterator(self, option: &ReadOptions) -> TableIterator<'f, F, C> {
        let index_iter = self.index_block.iter(self.opts.comparator.clone());
        TableIterator::new(
            index_iter,
            self.file,
            self.opts.comparator.clone(),
            option.clone(),
        )
    }
}

fn block_reader<'a, 'data, F: RandomAccessRead>(
    file: &F,
    opts: &ReadOptions,
    index_value: &Vec<u8>,
) -> api::Result<BlockReader> {
    let mut handle = BlockHandle::default();
    BlockHandle::decode_from(index_value, &mut handle)?;

    // We intentionally allow extra stuff in index_value so that we
    // can add more features in the future.

    // todo: block cache

    let block_contents = read_block_content(file, opts, &mut handle)?;
    let block = BlockReader::new(block_contents);
    Ok(block)
}

#[derive(Default, Clone)]
pub struct ReadOptions {
    // If true, all data read from underlying storage will be
    // verified against corresponding checksums.
    verify_checksums: bool,
}

fn read_block_content<'a, F: RandomAccessRead>(
    file: &'a F,
    opts: &ReadOptions,
    handle: &mut BlockHandle,
) -> api::Result<Vec<u8>> {
    // Read the block contents as well as the type/crc footer.
    let n = handle.size;
    let mut buf = Vec::with_capacity(n + BLOCK_TRAILER_SIZE);
    file.read(handle.offset, n + BLOCK_TRAILER_SIZE, &mut buf)?;
    if buf.len() != n + BLOCK_TRAILER_SIZE {
        return Err("Block Corruption: truncated block read".to_string().into());
    }

    // Check the crc of the type and the block contents
    if opts.verify_checksums {
        // fixme: unmask ??
        let crc = LittleEndian::read_u32(&buf[n + 1..]);
        let actul = CASTAGNOLI.checksum(&buf[..n + 1]);
        if actul != crc {
            return Err("block checksum mismatch".to_string().into());
        }
    }

    // think: heap allocated, cachable ?

    match buf[n].into() {
        CompressionType::NoCompression => {
            buf.truncate(n);
            let contents = buf;
            return Ok(contents);
        }
        CompressionType::SnappyCompression => {
            let mut contents = Vec::new();
            let mut r = snap::read::FrameDecoder::new(&buf[..n]);
            r.read_to_end(&mut contents)?;
            return Ok(contents);
        }
    }
}

// Return a new two level iterator.  A two-level iterator contains an
// index iterator whose values point to a sequence of blocks where
// each block is itself a sequence of key,value pairs.  The returned
// two-level iterator yields the concatenation of all key/value pairs
// in the sequence of blocks.  Takes ownership of "index_iter" and
// will delete it when no longer needed.
//
// Uses a supplied function to convert an index_iter value into
// an iterator over the contents of the corresponding block.
pub struct TableIterator<'f, F: RandomAccessRead, C: Comparator> {
    option: ReadOptions,
    index_iter: BlockIterator<C>,
    data_iter: Option<BlockIterator<C>>,
    data_block_handle: Vec<u8>,
    file: &'f F,
    comparator: C,
}

impl<'f, F, C> TableIterator<'f, F, C>
where
    F: RandomAccessRead,
    C: Comparator,
{
    fn new(index_iter: BlockIterator<C>, file: &'f F, cmp: C, option: ReadOptions) -> Self {
        TableIterator {
            option: option,
            index_iter: index_iter,
            data_iter: None,
            data_block_handle: vec![],
            file: file,
            comparator: cmp,
        }
    }

    fn init_data_block(&mut self) -> api::Result<()> {
        if !self.index_iter.valid()? {
            // set error status ?
            self.data_iter = None;
        } else {
            let handle = self.index_iter.value();
            if self.data_iter.is_some() && handle.eq(&self.data_block_handle) {
                // data_iter_ is already constructed with this iterator, so
                // no need to change anything
            } else {
                let block = block_reader(self.file, &self.option, handle)?;
                self.data_block_handle = handle.clone();
                self.data_iter = Some(block.iter(self.comparator.clone()));
            }
        }
        Ok(())
    }

    fn skip_empty_data_block_forward(&mut self) -> api::Result<()> {
        while self.data_iter.is_none() || !self.data_iter.as_ref().unwrap().valid()? {
            // Move to next block
            if !self.index_iter.valid()? {
                self.data_iter = None;
                return Ok(());
            }
            self.index_iter.next()?;
            self.init_data_block()?;
            if let Some(data_iter) = self.data_iter.as_mut() {
                data_iter.seek_to_first()?;
            }
        }
        Ok(())
    }

    fn skip_empty_data_block_backward(&mut self) -> api::Result<()> {
        while self.data_iter.is_none() || !self.data_iter.as_ref().unwrap().valid()? {
            // Move to next block
            if !self.index_iter.valid()? {
                self.data_iter = None;
                return Ok(());
            }
            self.index_iter.prev()?;
            self.init_data_block()?;
            if let Some(data_iter) = self.data_iter.as_mut() {
                data_iter.seek_to_last()?;
            }
        }
        Ok(())
    }
}

impl<'f, F, C> api::Iterator for TableIterator<'f, F, C>
where
    F: RandomAccessRead,
    C: Comparator,
{
    fn next(&mut self) -> api::Result<()> {
        assert!(self.valid()?);
        self.data_iter.as_mut().unwrap().next()?;
        self.skip_empty_data_block_forward()?;
        Ok(())
    }

    fn prev(&mut self) -> api::Result<()> {
        assert!(self.valid()?);
        self.data_iter.as_mut().unwrap().prev()?;
        self.skip_empty_data_block_backward()?;
        Ok(())
    }

    fn seek(&mut self, target: &Key) -> api::Result<()> {
        self.index_iter.seek(target)?;
        self.init_data_block()?;
        if let Some(it) = self.data_iter.as_mut() {
            it.seek(target)?;
        }

        Ok(())
    }

    fn seek_to_first(&mut self) -> api::Result<()> {
        self.index_iter.seek_to_first()?;
        self.init_data_block()?;
        if let Some(data_it) = self.data_iter.as_mut() {
            data_it.seek_to_first()?;
        }
        self.skip_empty_data_block_forward()?;
        Ok(())
    }

    fn seek_to_last(&mut self) -> api::Result<()> {
        self.index_iter.seek_to_last()?;
        self.init_data_block()?;
        if let Some(data_it) = self.data_iter.as_mut() {
            data_it.seek_to_last()?;
        }
        self.skip_empty_data_block_backward()?;
        Ok(())
    }

    fn key(&self) -> &Key {
        assert!(self.valid().unwrap());
        self.data_iter.as_ref().unwrap().key()
    }

    fn value(&self) -> &Value {
        assert!(self.valid().unwrap());
        self.data_iter.as_ref().unwrap().value()
    }

    fn valid(&self) -> api::Result<bool> {
        match &self.data_iter {
            None => Ok(false),
            Some(it) => it.valid(),
        }
    }
}
