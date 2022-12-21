use std::{
    cmp,
    fmt::{self, Display},
};

use crate::db::Snapshot;

pub trait Comparator {
    fn name(&self) -> &'static str;

    // Three-way comparison.  Returns value:
    //   Less iff "a" < "b",
    //   Equal iff "a" == "b",
    //   Greater iff "a" > "b"
    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering;

    // Bellow are advanced functions used to reduce the space requirements
    // for internal data structures such as index blocks.

    // Separator appends a sequence of bytes x to dst such that a <= x && x < b,
    // where 'less than' is consistent with Compare. An implementation should
    // return nil if x equal to a.
    //
    // Either contents of a or b should not by any means modified. Doing so
    // may cause corruption on the internal state.
    fn find_shortest_separator(&self, start: &mut [u8], limit: &[u8]);

    // Successor appends a sequence of bytes x to dst such that x >= b, where
    // 'less than' is consistent with Compare. An implementation should return
    // nil if x equal to b.
    fn find_short_successor(&self, b: &mut [u8]);
}

#[derive(Default, Clone)]
pub struct ByteswiseComparator {}

impl Comparator for ByteswiseComparator {
    fn name(&self) -> &'static str {
        "leveldb.BytewiseComparator"
    }

    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering {
        a.iter().cmp(b.iter())
    }

    fn find_shortest_separator(&self, mut start: &mut [u8], limit: &[u8]) {
        // Find length of common prefix
        let min_length = cmp::min(start.len(), limit.len());
        let mut diff_index = 0;
        while diff_index < min_length && start[diff_index] == limit[diff_index] {
            diff_index += 1;
        }
        if diff_index >= min_length {
            // Do not shorten if one string is a prefix of the other
        } else {
            let diff_byte = start[diff_index];
            if diff_byte < 0xff && diff_byte + 1 < limit[diff_index] {
                start[diff_index] += 1;
                start = &mut start[..diff_index + 1];
                assert!(self.compare(start, limit).is_lt());
            }
        }
    }

    fn find_short_successor(&self, mut key: &mut [u8]) {
        // Find first character that can be incremented
        for i in 0..key.len() {
            if key[i] != 0xff {
                key[i] += 1;
                key = &mut key[..i + 1];
                return;
            }
        }
        // *key is a run of 0xffs.  Leave it alone.
    }
}

pub type Result<E> = std::result::Result<E, Error>;

pub trait Iterator {
    fn next(&mut self) -> Result<()>;
    fn prev(&mut self) -> Result<()>;

    fn seek(&mut self, key: &[u8]) -> Result<()>;

    // Position at the first key in the source.  The iterator is Valid()
    // after this call iff the source is not empty.
    fn seek_to_first(&mut self) -> Result<()>;

    // Position at the last key in the source.  The iterator is
    // Valid() after this call iff the source is not empty.
    fn seek_to_last(&mut self) -> Result<()>;

    fn key(&self) -> Result<&[u8]>;
    fn value(&self) -> Result<&[u8]>;

    fn valid(&self) -> Result<bool>;
}

#[derive(Debug)]
pub struct DbError {
    reason: String,
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self {
            reason: e.to_string(),
        }
    }
}

impl From<String> for DbError {
    fn from(s: String) -> Self {
        Self { reason: s }
    }
}

impl Clone for DbError {
    fn clone(&self) -> Self {
        Self {
            reason: self.reason.clone(),
        }
    }
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({})", self.reason)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NotFound,
    Corruption(String),
    NotSupported(String),
    InvalidArgument(String),
    IOError(String),
    Other(String),
    InternalNotFound(bool), // bool used for Memtable get, true found deleted
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IOError(err.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "Not Found"),
            Self::Corruption(s) => write!(f, "Corruption, {}", s),
            Self::NotSupported(s) => write!(f, "Not Supported, {}", s),
            Self::InvalidArgument(s) => write!(f, "Invalid Argument, {}", s),
            Self::IOError(s) => write!(f, "IO Error, {}", s),
            Self::Other(s) => write!(f, "Other, {}", s),
            Self::InternalNotFound(b) => write!(f, "Internal Not Found {}", b),
        }
    }
}

impl Error {
    pub fn push_message(&self, msg: &str) -> Self {
        match self {
            Self::NotFound => Self::NotFound,
            Self::Corruption(s) => Self::Corruption(format! {"{}, {}", msg, s}),
            Self::NotSupported(s) => Self::NotSupported(format! {"{}, {}", msg, s}),
            Self::InvalidArgument(s) => Self::InvalidArgument(format! {"{}, {}", msg, s}),
            Self::IOError(s) => Self::IOError(format! {"{}, {}", msg, s}),
            Self::Other(s) => Self::Other(format!("{}, {}", msg, s)),
            Self::InternalNotFound(b) => Self::InternalNotFound(*b),
        }
    }
}

pub struct WriteOptions {
    // If true, the write will be flushed from the operating system
    // buffer cache (by calling WritableFile::Sync()) before the write
    // is considered complete.  If this flag is true, writes will be
    // slower.
    //
    // If this flag is false, and the machine crashes, some recent
    // writes may be lost.  Note that if it is just the process that
    // crashes (i.e., the machine does not reboot), no writes will be
    // lost even if sync==false.
    //
    // In other words, a DB write with sync==false has similar
    // crash semantics as the "write()" system call.  A DB write
    // with sync==true has similar crash semantics to a "write()"
    // system call followed by "fsync()".
    pub sync: bool,
}

#[derive(Default)]
pub struct ReadOptions {
    // If true, all data read from underlying storage will be
    // verified against corresponding checksums.
    pub verify_checksums: bool,

    // Should the data read for this iteration be cached in memory?
    // Callers may wish to set this field to false for bulk scans.
    pub fill_cache: bool,

    // If "snapshot" is non-null, read as of the supplied snapshot
    // (which must belong to the DB that is being read and which must
    // not have been released).  If "snapshot" is null, use an implicit
    // snapshot of the state at the beginning of this read operation.
    pub snapshot: Option<Snapshot>,
}
