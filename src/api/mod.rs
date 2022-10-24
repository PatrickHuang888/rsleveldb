use std::{cmp, fmt};


pub trait Comparator: Clone {
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
    //
    // Contents of b should not by any means modified. Doing so may cause
    // corruption on the internal state.
    fn find_short_successor(&self, b: &mut [u8]);
}

#[derive(Default, Clone)]
pub struct BytesComparator {}

impl Comparator for BytesComparator {
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

pub type Result<E> = std::result::Result<E, DbError>;
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

    fn key(&self) -> &[u8];
    fn value(&self) -> &[u8];

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
