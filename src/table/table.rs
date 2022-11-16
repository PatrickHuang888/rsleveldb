use crate::{
    api::{self, Error},
    table::{BLOCK_TRAILER_SIZE, FOOTER_LEN, MAGIC},
    util, WritableFile,
};
use std::{
    io::{Read, Write},
    rc::Rc,
    vec,
};

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};

use crate::{api::Comparator, api::Iterator, table::MAX_VARINT_LEN64, CompressionType, Options};

use super::block::{Block, BlockBuilder, BlockIterator};

pub struct TableBuilder<'a, W: WritableFile> {
    writer: &'a mut W,

    data_block: BlockBuilder,
    index_block: BlockBuilder,

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

    compressed_output: Vec<u8>,
    last_key: Vec<u8>,

    num_entries: usize,
    offset: usize,
    closed: bool,

    status: Option<Error>,

    options: Options,
    //index_opts:Options<'a>,

    //filter_block: Option<FilterBlock<'c>>,
}

impl<'a, W: WritableFile> TableBuilder<'a, W> {
    pub fn new(w: &'a mut W, options: Options) -> Self {
        TableBuilder {
            writer: w,

            data_block: BlockBuilder::new(options.block_restart_interval),
            index_block: BlockBuilder::new(1),

            //filter_block: None,
            pending_index_entry: false,
            pending_handle: Default::default(),

            closed: false,
            status: None,
            offset: 0,
            num_entries: 0,

            compressed_output: Vec::new(),
            last_key: Vec::new(),

            options,
        }
    }

    // Add key,value to the table being constructed.
    // REQUIRES: key is after any previously added key according to comparator.
    // REQUIRES: Finish(), Abandon() have not been called
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> api::Result<()> {
        assert!(!self.closed);

        self.ok()?;

        if self.num_entries > 0 && self.options.comparator.compare(key, &self.last_key).is_le() {
            return Err(Error::Other(String::from(
                "table writer: keys are not in increasing order",
            )));
        }

        if self.pending_index_entry {
            assert!(self.data_block.is_empty());
            self.options
                .comparator
                .find_shortest_separator(&mut self.last_key, key);
            let mut handle_encoding = Vec::with_capacity(2 * MAX_VARINT_LEN64);
            self.pending_handle.encode_to(&mut handle_encoding);
            self.index_block.add(&self.last_key, &handle_encoding);
            self.pending_index_entry = false;
        }

        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.num_entries += 1;
        self.data_block.add(key, value);

        // finish the data block if block size target reached.
        let size = self.data_block.bytes_len();
        if size >= self.options.block_size {
            self.flush()?;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> api::Result<()> {
        assert!(!self.closed);
        self.ok()?;

        if self.data_block.is_empty() {
            return Ok(());
        }

        assert!(!self.pending_index_entry);

        let l = write_block(
            self.writer,
            &mut self.data_block,
            self.options.compression,
            &mut self.compressed_output,
        )
        .map_err(|e| {
            let s = e.push_message("data block write error");
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

        let mut meta_index_block: BlockBuilder =
            BlockBuilder::new(self.options.block_restart_interval);
        /* match &self.filter_block {
            None => {}
            Some(fb) => {
                // todo:
                let mut k= "filter.".to_string();
                let buf= fb.encode();
                meta_index_block.append(&k, &buf)
            }
        } */
        let l = write_block(
            self.writer,
            &mut meta_index_block,
            self.options.compression,
            &mut self.compressed_output,
        )
        .map_err(|e| {
            let s = e.push_message("meta index block write error");
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
            self.options
                .comparator
                .find_short_successor(&mut self.last_key);
            let mut handle_encoding = Vec::with_capacity(2 * MAX_VARINT_LEN64);
            self.pending_handle.encode_to(&mut handle_encoding);
            self.index_block.add(&self.last_key, &handle_encoding);
            self.pending_index_entry = false;
        }
        let l = write_block(
            self.writer,
            &mut self.index_block,
            self.options.compression,
            &mut self.compressed_output,
        )
        .map_err(|e| {
            let s = e.push_message("index block write error {}");
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
        self.writer.append(&footer_encoding)?;
        self.offset += FOOTER_LEN;

        Ok(())
    }

    fn ok(&self) -> api::Result<()> {
        match &self.status {
            None => Ok(()),
            Some(s) => Err(s.clone()),
        }
    }

    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    pub fn file_size(&self) -> usize {
        self.offset
    }
}

pub fn write_block<W: WritableFile>(
    writer: &mut W,
    block: &mut BlockBuilder,
    compression: CompressionType,
    compressed: &mut Vec<u8>,
) -> api::Result<usize> {
    let raw = block.finish();
    // File format contains a sequence of blocks where each block has:
    //    block_data: uint8[n]
    //    type: uint8
    //    crc: uint32
    let n: usize;
    match compression {
        CompressionType::SnappyCompression => {
            let mut w = snap::write::FrameEncoder::new(compressed);
            w.write_all(raw)?;
            w.flush()?;
            let esc = w.into_inner().unwrap();
            n = write_raw_block(writer, &esc, compression)?;
            esc.clear();
        }
        CompressionType::NoCompression => {
            n = write_raw_block(writer, raw, compression)?;
        }
    }
    block.reset();
    Ok(n)
}

fn write_raw_block<W: WritableFile>(
    writer: &mut W,
    contents: &[u8],
    compression: CompressionType,
) -> api::Result<usize> {
    let n = contents.len();

    writer.append(contents)?;

    let mut trailer: [u8; BLOCK_TRAILER_SIZE] = [0; BLOCK_TRAILER_SIZE];
    trailer[0] = compression as u8;

    let cs = [contents, &trailer[0..1]];
    let crc = util::crcs(&cs);

    LittleEndian::write_u32(&mut trailer[1..], crc);
    writer.append(&trailer)?;

    Ok(n + BLOCK_TRAILER_SIZE)
}

impl<'a, W: WritableFile> Drop for TableBuilder<'a, W> {
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
    fn decode_from(input: &[u8]) -> api::Result<Self> {
        let magic = LittleEndian::read_u64(&input[FOOTER_LEN - 8..]);
        if magic != MAGIC {
            return Err(Error::Corruption(String::from(
                "not an sstable (bad magic number)",
            )));
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

        util::encode_varint64(dst, self.offset as u64);
        util::encode_varint64(dst, self.size as u64);
    }

    fn decode_from(buf: &[u8], handle: &mut BlockHandle) -> api::Result<usize> {
        let (offset, num_offset) = super::get_uvarint(buf)
            .map_err(|s| Error::Other(format!("bad block handle, {}", s)))?;

        let (size, num_size) = super::get_uvarint(&buf[num_offset..])
            .map_err(|s| Error::Other(format!("bad block handle, {}", s)))?;

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

pub trait RandomAccessFile {
    // Read up to "n" bytes from the file starting at "offset".
    // Safe for concurrent use by multiple threads.
    fn read(&self, offset: usize, n: usize, dst: &mut Vec<u8>) -> api::Result<usize>;
}

// A Table is a sorted map from strings to strings.  Tables are
// immutable and persistent.  A Table may be safely accessed from
// multiple threads without external synchronization.
pub struct Table {
    options: Options,
    status: Option<String>,

    file: Rc<dyn RandomAccessFile>,

    meta_index_handle: BlockHandle,
    index_iter: BlockIterator,
}

impl Table {
    pub fn open(
        options: Options,
        file: Rc<dyn RandomAccessFile>,
        size: usize,
    ) -> api::Result<Self> {
        if size < FOOTER_LEN {
            return Err(Error::Corruption(String::from(
                "file is too short to be an sstable",
            )));
        }

        //let footer_space: [u8;FOOTER_LEN]= [0;FOOTER_LEN];
        let mut footer_input = Vec::with_capacity(FOOTER_LEN);
        file.read(size - FOOTER_LEN, FOOTER_LEN, &mut footer_input)?;
        let mut footer = Footer::decode_from(&footer_input)?;

        // Read index block
        let mut opt = ReadOptions::default();
        if options.paranoid_checks {
            opt.verify_checksums = true;
        }
        let index_contents = read_block_content(&file, &opt, &mut footer.index_handle)?;
        let index_block = Block::new(index_contents);
        let comparator = options.comparator.clone();
        let r = Table {
            options,
            status: None,
            file,
            index_iter: index_block.new_iter(comparator),
            meta_index_handle: footer.metaindex_handle,
        };
        r.read_meta()?;
        Ok(r)
    }

    fn read_meta(&self) -> std::io::Result<()> {
        // todo:
        Ok(())
    }

    pub fn iter(&self, option: ReadOptions) -> TableIterator {
        //let index_iter = self.index_block.iter(self.options.comparator.clone());
        TableIterator::new(
            option,
            self.index_iter.clone(),
            self.file.clone(),
            self.options.comparator.clone(),
        )
    }
}

fn block_reader(
    file: &Rc<dyn RandomAccessFile>,
    opts: &ReadOptions,
    index_value: &[u8],
) -> api::Result<Block> {
    let mut handle = BlockHandle::default();
    BlockHandle::decode_from(index_value, &mut handle)?;

    // We intentionally allow extra stuff in index_value so that we
    // can add more features in the future.

    // todo: block cache

    let block_contents = read_block_content(file, opts, &mut handle)?;
    let block = Block::new(block_contents);
    Ok(block)
}

#[derive(Default, Clone)]
pub struct ReadOptions {
    // If true, all data read from underlying storage will be
    // verified against corresponding checksums.
    verify_checksums: bool,
}

fn read_block_content(
    file: &Rc<dyn RandomAccessFile>,
    opts: &ReadOptions,
    handle: &mut BlockHandle,
) -> api::Result<Vec<u8>> {
    // Read the block contents as well as the type/crc footer.
    let n = handle.size;
    let mut buf = Vec::with_capacity(n + BLOCK_TRAILER_SIZE);
    file.read(handle.offset, n + BLOCK_TRAILER_SIZE, &mut buf)?;
    if buf.len() != n + BLOCK_TRAILER_SIZE {
        return Err(Error::Corruption(String::from("truncated block read")));
    }

    // Check the crc of the type and the block contents
    if opts.verify_checksums {
        // fixme: unmask ??
        let crc = LittleEndian::read_u32(&buf[n + 1..]);
        let actul = util::crc(&buf[..n + 1]);
        if actul != crc {
            return Err(Error::Corruption(String::from("block checksum mismatch")));
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
pub struct TableIterator {
    option: ReadOptions,
    index_iter: BlockIterator,
    data_iter: Option<BlockIterator>,
    data_block_handle: Vec<u8>,
    file: Rc<dyn RandomAccessFile>,
    comparator: Rc<dyn Comparator>,
}

impl TableIterator {
    fn new(
        option: ReadOptions,
        index_iter: BlockIterator,
        file: Rc<dyn RandomAccessFile>,
        cmp: Rc<dyn Comparator>,
    ) -> Self {
        TableIterator {
            option,
            index_iter,
            data_iter: None,
            data_block_handle: vec![],
            file,
            comparator: cmp,
        }
    }

    fn init_data_block(&mut self) -> api::Result<()> {
        if !self.index_iter.valid()? {
            // set error status ?
            self.data_iter = None;
        } else {
            let handle = self.index_iter.value().unwrap();
            if self.data_iter.is_some() && handle.eq(&self.data_block_handle) {
                // data_iter_ is already constructed with this iterator, so
                // no need to change anything
            } else {
                let block = block_reader(&self.file, &self.option, handle)?;
                self.data_block_handle.clear();
                self.data_block_handle.extend_from_slice(handle);
                self.data_iter = Some(block.new_iter(self.comparator.clone()));
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

impl api::Iterator for TableIterator {
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

    fn seek(&mut self, target: &[u8]) -> api::Result<()> {
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

    fn key(&self) -> api::Result<&[u8]> {
        assert!(matches!(self.valid(), Ok(true)));
        self.data_iter.as_ref().unwrap().key()
    }

    fn value(&self) -> api::Result<&[u8]> {
        assert!(matches!(self.valid(), Ok(true)));
        self.data_iter.as_ref().unwrap().value()
    }

    fn valid(&self) -> api::Result<bool> {
        match &self.data_iter {
            None => Ok(false),
            Some(it) => it.valid(),
        }
    }
}
