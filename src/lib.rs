use std::{
    env,
    fs::{self, FileType},
    path::{Path, PathBuf},
    sync::Arc,
};

use api::{ByteswiseComparator, Comparator, Error, ReadOptions, WriteOptions};
use db::filename;
use file_lock::{FileLock, FileOptions};

mod api;
mod config;
mod db;
mod journal;
pub mod memdb;
mod table;
mod util;

#[derive(Clone)]
pub struct Options<C: Comparator + 'static> {
    // Number of keys between restart points for delta encoding of keys.
    // This parameter can be changed dynamically.  Most clients should
    // leave this parameter alone.
    block_restart_interval: usize,

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

    // If true, the database will be created if it is missing.
    create_if_missing: bool,

    // Comparator used to define the order of keys in the table.
    // Default: a comparator that uses lexicographic byte-wise ordering
    //
    // REQUIRES: The client must ensure that the comparator supplied
    // here has the same name and orders keys *exactly* the same as the
    // comparator provided to previous open calls on the same DB.
    comparator: &'static C,

    // If true, the implementation will do aggressive checking of the
    // data it is processing and will stop early if it detects any
    // errors.  This may have unforeseen ramifications: for example, a
    // corruption of one DB entry may cause a large number of entries to
    // become unreadable or for the entire DB to become unopenable.
    paranoid_checks: bool,

    // Any internal progress/error information generated by the db will
    // be written to info_log if it is non-null, or to a file stored
    // in the same directory as the DB contents if info_log is null.
    //info_log: Option<Arc<dyn Logger + Sync + Send>>,

    // -------------------
    // Parameters that affect performance

    // Amount of data to build up in memory (backed by an unsorted log
    // on disk) before converting to a sorted on-disk file.
    //
    // Larger values increase performance, especially during bulk loads.
    // Up to two write buffers may be held in memory at the same time,
    // so you may wish to adjust this parameter to control memory usage.
    // Also, a larger write buffer will result in a longer recovery time
    // the next time the database is opened.
    write_buffer_size: usize,

    // Number of open files that can be used by the DB.  You may need to
    // increase this if your database has a large working set (budget
    // one open file per 2MB of working set).
    max_open_files: usize,

    // Approximate size of user data packed per block.  Note that the
    // block size specified here corresponds to uncompressed data.  The
    // actual size of the unit read from disk may be smaller if
    // compression is enabled.  This parameter can be changed dynamically.
    block_size: usize,

    // Leveldb will write up to this amount of bytes to a file before
    // switching to a new one.
    // Most clients should leave this parameter alone.  However if your
    // filesystem is more efficient with larger files, you could
    // consider increasing the value.  The downside will be longer
    // compactions and hence longer latency/performance hiccups.
    // Another reason to increase this parameter might be when you are
    // initially populating a large database.
    max_file_size: usize,

    // Control over blocks (user data is stored in a set of blocks, and
    // a block is the unit of reading from disk).

    // If non-null, use the specified cache for blocks.
    // If null, leveldb will automatically create and use an 8MB internal cache.
    block_cache: Option<Arc<dyn Cache>>,

    env: &'static dyn Env,
}

pub const NUM_NON_TABLE_CACHE_FILES: usize = 10;

impl Options<ByteswiseComparator> {
    fn default() -> Self {
        Options {
            block_restart_interval: 16,
            block_size: 4 * 1024,
            compression: CompressionType::SnappyCompression,
            comparator: &ByteswiseComparator {},
            paranoid_checks: false,
            max_open_files: 1000,
            write_buffer_size: 4 * 1024 * 1024,
            max_file_size: 2 * 1024 * 1024,
            create_if_missing: false,
            block_cache: None,
            env: &PosixEnv {},
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

pub trait RandomAccessFile {
    // Read up to "n" bytes from the file starting at "offset".
    // "scratch[0..n-1]" may be written by this routine.  Sets "*result"
    // to the data that was read (including if fewer than "n" bytes were
    // successfully read).  May set "*result" to point at data in
    // "scratch[0..n-1]", so "scratch[0..n-1]" must be live when
    // "*result" is used.  If an error was encountered, returns a non-OK
    // status.
    //
    // Safe for concurrent use by multiple threads.
    fn read(&self, offset: u64, n: u64, dst: &mut Vec<u8>) -> api::Result<u64>;
}

pub trait SequentialFile {
    // Read up to "n" bytes from the file.  "scratch[0..n-1]" may be
    // written by this routine.  Sets "*result" to the data that was
    // read (including if fewer than "n" bytes were successfully read).
    // May set "*result" to point at data in "scratch[0..n-1]", so
    // "scratch[0..n-1]" must be live when "*result" is used.
    // If an error was encountered, returns a non-OK status.
    //
    // REQUIRES: External synchronization
    fn read(
        &mut self,
        n: usize,
        result: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> std::io::Result<()>;

    // Skip "n" bytes from the file. This is guaranteed to be no
    // slower that reading the same data, but may be faster.
    //
    // If end of file is reached, skipping will stop at the end of the
    // file, and Skip will return OK.
    //
    // REQUIRES: External synchronization
    fn skip(&mut self, n: usize) -> std::io::Result<()>;
}

pub trait Logger {}

// Create a new cache with a fixed size capacity.  This implementation
// of Cache uses a least-recently-used eviction policy.
pub trait Cache: Sync + Send {}

// A DB is a persistent ordered map from keys to values.
// A DB is safe for concurrent access from multiple threads without
// any external synchronization.
pub trait DB<C: Comparator + Send + Sync + 'static> {
    // If the database contains an entry for "key" store the
    // corresponding value in *value and return OK.
    //
    // If there is no entry for "key" leave *value unchanged and return
    // a status for which Status::IsNotFound() returns true.
    //
    // May return some other Status on an error.
    fn get(&mut self, options: &ReadOptions, key: &[u8], value: &mut Vec<u8>) -> api::Result<()>;

    // Set the database entry for "key" to "value".  Returns OK on success,
    // and a non-OK status on error.
    // Note: consider setting options.sync = true.
    fn put(&mut self, options: &WriteOptions, key: &[u8], value: &[u8]) -> api::Result<()>;

    // Remove the database entry (if any) for "key".  Returns OK on
    // success, and a non-OK status on error.  It is not an error if "key"
    // did not exist in the database.
    // Note: consider setting options.sync = true.
    fn delete(&mut self, options: &WriteOptions, key: &[u8]) -> api::Result<()>;

    // Apply the specified updates to the database.
    // Returns OK on success, non-OK on failure.
    // Note: consider setting options.sync = true.
    fn write(&mut self, options: &WriteOptions, updates: Option<WriteBatch>) -> api::Result<()>;
}

// Destroy the contents of the specified database.
// Be very careful using this method.
//
// Note: For backwards compatibility, if DestroyDB is unable to list the
// database files, Status::OK() will still be returned masking this failure.
pub fn destroy_db<C: api::Comparator>(
    dbname: &'static str,
    home_path: &Path,
    options: &Options<C>,
) -> api::Result<()> {
    let env = options.env;
    let lockname = lock_file_name(dbname);
    let lock = env.lock_file(lockname.as_path())?;
    let mut result = Ok(());
    let mut path = PathBuf::new();

    let db_dir = Path::new(dbname);

    let files = env.get_children(db_dir);
    if files.is_err() {
        // Ignore error in case directory does not exist
        return Ok(());
    }
    for f in files.unwrap() {
        let (tp, _) = filename::parse_file_name(f.as_path())?;
        if tp != filename::FileType::DB_LOCK_FILE {
            // Lock file will be deleted at end
            path.clear();
            path.push(db_dir);
            path.push(&f);
            result = env.remove_file(&path);
        }
    }
    let _ = env.unlock_file(&lock);
    let _ = env.remove_file(&lockname);
    let _ = env.remove_dir(db_dir);
    result
}

// Return the name of the lock file for the db named by
// "dbname".  The result will be prefixed with "dbname".
pub(crate) fn lock_file_name(dbname: &str) -> PathBuf {
    let p = Path::new(dbname);
    p.join("LOCK")
}

// WriteBatch header has an 8-byte sequence number followed by a 4-byte count.
const WRITEBATCH_HEADER: usize = 12;

#[derive(PartialEq, Clone)]
pub struct WriteBatch {
    space: Vec<u8>,
}

impl WriteBatch {
    pub fn new() -> Self {
        WriteBatch {
            space: vec![0; WRITEBATCH_HEADER],
        }
    }

    // Store the mapping "key->value" in the database.
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        self.set_count(self.count() + 1);
        self.space.push(ValueType::TypeValue as u8);
        util::put_length_prefixed_slice(&mut self.space, key);
        util::put_length_prefixed_slice(&mut self.space, value);
    }

    // Copies the operations in "source" to this batch.
    //
    // This runs in O(source size) time. However, the constant factor is better
    // than calling Iterate() over the source batch with a Handler that replicates
    // the operations into this batch.
    pub fn append(&mut self, source: &WriteBatch) {
        self.set_count(self.count() + source.count());
        assert!(source.space.len() >= WRITEBATCH_HEADER);
        self.space
            .extend_from_slice(&source.space[WRITEBATCH_HEADER..])
    }

    // If the database contains a mapping for "key", erase it.  Else do nothing.
    pub fn delete(&mut self, key: &[u8]) {
        self.set_count(self.count() + 1);
        self.space.push(ValueType::TypeDeletion as u8);
        util::put_length_prefixed_slice(&mut self.space, key);
    }

    // Clear all updates buffered in this batch.
    pub fn clear(&mut self) {
        todo!()
    }

    // Support for iterating over the contents of a batch.
    pub fn iterate(&self, handler: &mut dyn Handler) -> api::Result<()> {
        if self.space.len() < WRITEBATCH_HEADER {
            return Err(api::Error::Corruption(String::from(
                "malformed WriteBatch (too small)",
            )));
        }

        let input = &self.space[WRITEBATCH_HEADER..];
        let mut key: &[u8];
        let mut value: &[u8];
        let mut found = 0;
        let mut offset = 0;
        while offset < input.len() {
            found += 1;
            let tag: ValueType = ValueType::from(input[offset]);
            offset += 1;
            match tag {
                ValueType::TypeValue => {
                    let (key, key_size) = util::get_length_prefixed_slice(&input[offset..])
                        .map_err(|_| {
                            api::Error::Corruption("bad WriteBatch put, key".to_string())
                        })?;
                    offset += key_size;
                    let (value, value_size) = util::get_length_prefixed_slice(&input[offset..])
                        .map_err(|_| {
                            api::Error::Corruption("bad WriteBatch put, value".to_string())
                        })?;
                    offset += value_size;
                    handler.put(key, value);
                }
                ValueType::TypeDeletion => {
                    let (key, key_size) = util::get_length_prefixed_slice(&input[offset..])
                        .map_err(|_| {
                            api::Error::Corruption(String::from("bad WriteBatch delete, key"))
                        })?;
                    offset += key_size;
                    handler.delete(key);
                }
                _ => {
                    return Err(Error::Corruption("unknown ValueType".to_string()));
                }
            }
        }
        if found != self.count() {
            return Err(Error::Corruption(String::from(
                "WriteBatch has wrong count",
            )));
        }
        Ok(())
    }

    fn contents(&self) -> &[u8] {
        todo!()
    }

    fn sequence(&self) -> SequenceNumber {
        util::decode_fixed64(&self.space[..8])
    }

    fn set_sequence(&mut self, seq: SequenceNumber) {
        util::encode_fixed64(&mut self.space[0..8], seq);
    }

    // Return the number of entries in the batch.
    fn count(&self) -> u32 {
        util::decode_fixed32(&self.space[8..12])
    }

    // Set the count for the number of entries in the batch.
    fn set_count(&mut self, n: u32) {
        util::encode_fixed32(&mut self.space[8..12], n)
    }

    fn byte_size(&self) -> usize {
        self.space.len()
    }

    fn insert_into<C: api::Comparator>(
        &self,
        memtable: &mut db::memtable::MemTable<C>,
    ) -> api::Result<()> {
        let mut inserter = db::write_batch::MemTableInserter {
            sequence: self.sequence(),
            mem: memtable,
        };
        self.iterate(&mut inserter)?;
        Ok(())
    }
}

pub trait Handler {
    fn put(&mut self, key: &[u8], value: &[u8]);
    fn delete(&mut self, key: &[u8]);
}

type SequenceNumber = u64;

// Value types encoded as the last component of internal keys.
// DO NOT CHANGE THESE ENUM VALUES: they are embedded in the on-disk
// data structures.
pub enum ValueType {
    TypeDeletion = 0x0,
    TypeValue = 0x1,
}

// kValueTypeForSeek defines the ValueType that should be passed when
// constructing a ParsedInternalKey object for seeking to a particular
// sequence number (since we sort sequence numbers in decreasing order
// and the value type is embedded as the low 8 bits in the sequence
// number in internal keys, we need to use the highest-numbered
// ValueType, not the lowest).
const TYPE_FOR_SEEK: ValueType = ValueType::TypeValue;

impl From<u8> for ValueType {
    fn from(v: u8) -> Self {
        match v {
            0x0 => Self::TypeDeletion,
            0x1 => Self::TypeValue,
            _ => unreachable!(),
        }
    }
}

// We leave eight bits empty at the bottom so a type and sequence#
// can be packed together into 64-bits.
pub const MAX_SEQUENCE_NUMBER: SequenceNumber = (0x1u64 << 56) - 1;

pub(crate) fn pack_sequence_and_type(seq: u64, t: ValueType) -> u64 {
    assert!(seq <= MAX_SEQUENCE_NUMBER);
    //assert!(t<=ValueTypeForSeek);
    (seq << 8) | t as u64
}

pub(crate) fn parse_internal_key<'a>(
    internal_key: &'a [u8],
) -> api::Result<(&'a [u8], SequenceNumber, ValueType)> {
    // user_key, sequence, valuetype
    let mut n = internal_key.len();
    if n < 8 {
        return Err(api::Error::Other(("internal key < 8").to_string()));
    }
    let num = util::decode_fixed64(&internal_key[n - 8..]);
    let c = num as u8;
    let sequence = num >> 8;
    let t = ValueType::from(c);
    let user_key = &internal_key[..n - 8];
    Ok((user_key, sequence, t))
}

// Modules in this directory should keep internal keys wrapped inside
// the following class instead of plain strings so that we do not
// incorrectly use string comparisons instead of an InternalKeyComparator.
#[derive(Clone, Default, PartialEq, Debug)]
struct InternalKey {
    rep: Vec<u8>,
}

impl InternalKey {
    fn new(user_key: &[u8], s: SequenceNumber, t: ValueType) -> Self {
        let mut rep = Vec::new();
        rep.extend_from_slice(user_key);
        util::put_fixed64(&mut rep, pack_sequence_and_type(s, t));
        InternalKey { rep }
    }

    fn new_with_str_key(key: &str, s: SequenceNumber, t: ValueType) -> Self {
        let user_key = key.as_bytes();
        Self::new(user_key, s, t)
    }

    fn user_key(&self) -> &[u8] {
        extract_user_key(&self.rep)
    }

    fn decode_from(&mut self, s: &[u8]) -> bool {
        self.rep.clear();
        self.rep.extend_from_slice(s);
        !self.rep.is_empty()
    }

    fn encode(&self) -> &[u8] {
        assert!(!self.rep.is_empty());
        &self.rep
    }
}

fn extract_user_key(internal_key: &[u8]) -> &[u8] {
    assert!(internal_key.len() >= 8);
    return &internal_key[..internal_key.len() - 8];
}

struct PosixEnv {}
impl Env for PosixEnv {
    fn new_posix_random_access_file(&self, filename: &Path) -> api::Result<PosixReadableFile> {
        todo!()
    }
    fn new_posix_writable_file(&self, filename: &Path) -> api::Result<PosixWritableFile> {
        todo!()
    }
    fn now_micros(&self) -> u64 {
        todo!()
    }
    fn remove_file(&self, filename: &Path) -> api::Result<()> {
        fs::remove_file(filename)?;
        Ok(())
    }
    fn rename_file(&self, s: &Path, t: &Path) -> api::Result<()> {
        todo!()
    }
    fn lock_file(&self, lockname: &Path) -> api::Result<FileLock> {
        let should_block = true;
        let options = FileOptions::new().write(true).create(true);
        let lock = FileLock::lock(lockname, should_block, options)?;
        Ok(lock)
    }

    fn get_children(&self, dir: &Path) -> api::Result<Vec<PathBuf>> {
        let mut result = vec![];
        for entry in std::fs::read_dir(dir)? {
            result.push(entry?.path())
        }
        Ok(result)
    }

    fn unlock_file(&self, lock: &FileLock) -> api::Result<()> {
        lock.unlock()?;
        Ok(())
    }

    fn remove_dir(&self, dir: &Path) -> api::Result<()> {
        fs::remove_dir(dir)?;
        Ok(())
    }
}

pub trait Env:Sync {
    fn new_posix_writable_file(&self, filename: &Path) -> api::Result<PosixWritableFile>;

    fn remove_file(&self, filename: &Path) -> api::Result<()>;

    fn rename_file(&self, s: &Path, t: &Path) -> api::Result<()>;

    fn new_posix_random_access_file(&self, filename: &Path) -> api::Result<PosixReadableFile>;

    fn now_micros(&self) -> u64;

    fn lock_file(&self, lockname: &Path) -> api::Result<FileLock>;

    fn get_children(&self, dir: &Path) -> api::Result<Vec<PathBuf>>;

    fn unlock_file(&self, lock: &FileLock) -> api::Result<()>;

    fn remove_dir(&self, dir: &Path) -> api::Result<()>;
}

pub struct PosixReadableFile {}

impl RandomAccessFile for PosixReadableFile {
    fn read(&self, offset: u64, n: u64, dst: &mut Vec<u8>) -> api::Result<u64> {
        todo!()
    }
}
pub struct PosixWritableFile {}

impl WritableFile for PosixWritableFile {
    fn append(&mut self, data: &[u8]) -> api::Result<()> {
        todo!()
    }
    fn close(&mut self) -> api::Result<()> {
        todo!()
    }
    fn flush(&mut self) -> api::Result<()> {
        todo!()
    }
    fn sync(&mut self) -> api::Result<()> {
        todo!()
    }
}
