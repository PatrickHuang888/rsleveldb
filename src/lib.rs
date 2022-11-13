use std::rc::Rc;

use api::{ByteswiseComparator, Comparator};

mod api;
mod config;
mod db;
mod journal;
pub mod memdb;
mod table;
mod util;

#[derive(Clone)]
pub struct Options {
    // Number of keys between restart points for delta encoding of keys.
    // This parameter can be changed dynamically.  Most clients should
    // leave this parameter alone.
    block_restart_interval: usize,

    // Approximate size of user data packed per block.  Note that the
    // block size specified here corresponds to uncompressed data.  The
    // actual size of the unit read from disk may be smaller if
    // compression is enabled.  This parameter can be changed dynamically.
    block_size: usize,

    // Compress blocks using the specified compression algorithm.  This
    // parameter can be changed dynamically.
    //
    // Default: kSnappyCompression, which gives lightweight but fast
    // compression.
    //
    // Typical speeds of kSnappyCompression on an Intel(R) Core(TM)2 2.4GHz:
    //    ~200-500MB/s compression
    //    ~400-800MB/s decompression
    // Note that these speeds are significantly faster than most
    // persistent storage speeds, and therefore it is typically never
    // worth switching to kNoCompression.  Even if the input data is
    // incompressible, the kSnappyCompression implementation will
    // efficiently detect that and will switch to uncompressed mode.
    compression: CompressionType,

    // Comparator used to define the order of keys in the table.
    // Default: a comparator that uses lexicographic byte-wise ordering
    //
    // REQUIRES: The client must ensure that the comparator supplied
    // here has the same name and orders keys *exactly* the same as the
    // comparator provided to previous open calls on the same DB.
    comparator: Rc<dyn Comparator>,

    // If true, the implementation will do aggressive checking of the
    // data it is processing and will stop early if it detects any
    // errors.  This may have unforeseen ramifications: for example, a
    // corruption of one DB entry may cause a large number of entries to
    // become unreadable or for the entire DB to become unopenable.
    paranoid_checks: bool,
}

impl Options {
    fn default() -> Self {
        Options {
            block_restart_interval: 16,
            block_size: 4 * 1024,
            compression: CompressionType::SnappyCompression,
            comparator: Rc::new(ByteswiseComparator {}),
            paranoid_checks: false,
        }
    }
}

// DB contents are stored in a set of blocks, each of which holds a
// sequence of key,value pairs.  Each block may be compressed before
// being stored in a file.  The following enum describes which
// compression method (if any) is used to compress a block.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompressionType {
    // NOTE: do not change the values of existing entries, as these are
    // part of the persistent format on disk.
    NoCompression = 0x0,
    SnappyCompression = 0x1,
}

impl From<u8> for CompressionType {
    fn from(c: u8) -> Self {
        match c {
            0x0 => CompressionType::NoCompression,
            0x01 => CompressionType::SnappyCompression,
            _ => CompressionType::NoCompression,
        }
    }
}

// A file abstraction for sequential writing.  The implementation
// must provide buffering since callers may append small fragments
// at a time to the file.
pub trait WritableFile {
    fn append(&mut self, data: &[u8]) -> api::Result<()>;
    fn close(&mut self) -> api::Result<()>;
    fn flush(&mut self) -> api::Result<()>;
    fn sync(&mut self) -> api::Result<()>;
}

// Destroy the contents of the specified database.
// Be very careful using this method.
//
// Note: For backwards compatibility, if DestroyDB is unable to list the
// database files, Status::OK() will still be returned masking this failure.
/* fn DestroyDB(name:&String, options:&Options<C>) {

} */
