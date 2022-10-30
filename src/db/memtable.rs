use std::cmp;

use crate::{
    api::{self, ByteswiseComparator, Comparator},
    util,
};

use super::{
    skiplist::{Iterator, SkipList, SkipListIterator},
    SequenceNumber, ValueType,
};

type Table = SkipList<KeyComparator, Vec<u8>>;
type TableIterator<'a> = SkipListIterator<'a, KeyComparator, Vec<u8>>;

const LookupKeySpaceSize: usize = 200;

pub struct LookupKey {
    // We construct a char array of the form:
    //    klength  varint32               <-- start_
    //    userkey  char[klength]          <-- kstart_
    //    tag      uint64
    //                                    <-- end_
    // The array is a suitable MemTable key.
    // The suffix starting with "userkey" can be used as an InternalKey.
    kstart: usize,
    end: usize,
    space: Vec<u8>,
}

// kValueTypeForSeek defines the ValueType that should be passed when
// constructing a ParsedInternalKey object for seeking to a particular
// sequence number (since we sort sequence numbers in decreasing order
// and the value type is embedded as the low 8 bits in the sequence
// number in internal keys, we need to use the highest-numbered
// ValueType, not the lowest).
const ValueTypeForSeek: ValueType = ValueType::TypeValue;

// We leave eight bits empty at the bottom so a type and sequence#
// can be packed together into 64-bits.
const MaxSequenceNumber: SequenceNumber = (0x1u64 << 56) - 1;

fn pack_sequence_and_type(seq: u64, t: ValueType) -> u64 {
    assert!(seq <= MaxSequenceNumber);
    //assert!(t<=ValueTypeForSeek);
    (seq << 8) | t as u64
}

impl LookupKey {
    pub fn new(user_key: &[u8], s: SequenceNumber) -> Self {
        let mut needed = user_key.len() + 13; // A conservative estimate
        if needed <= LookupKeySpaceSize {
            needed = LookupKeySpaceSize;
        }
        let mut space = Vec::with_capacity(needed);
        util::encode_varint32(&mut space, (user_key.len() + 8) as u32);
        let kstart = space.len();
        space.extend_from_slice(user_key);
        util::encode_fixed64(&mut space, pack_sequence_and_type(s, ValueTypeForSeek));
        let end = space.len();
        LookupKey { kstart, end, space }
    }

    fn user_key(&self) -> &[u8] {
        &self.space[self.kstart..self.end - 8]
    }

    fn memtable_key(&self) -> &[u8] {
        &self.space[..self.end]
    }

    fn internal_key(&self) -> &[u8] {
        &self.space[self.kstart..self.end]
    }
}

pub struct MemTable {
    table: Table,
    comparator: ByteswiseComparator,
}

impl MemTable {
    // If memtable contains a value for key, store it in value and return true.
    // If memtable contains a deletion for key, store a NotFound() error in status and return true.
    // Else, return false.
    pub fn get(&self, key: &LookupKey) -> std::result::Result<Vec<u8>, (bool, api::Error)> {
        let memkey = key.memtable_key();
        let mut iter = self.table.new_iterator();
        iter.seek(&Vec::from(memkey));
        if iter.valid() {
            // entry format is:
            //    klength  varint32
            //    userkey  char[klength]
            //    tag      uint64
            //    vlength  varint32
            //    value    char[vlength]
            // Check that it belongs to same user key.  We do not check the
            // sequence number since the Seek() call above should have skipped
            // all entries with overly large sequence numbers.
            let entry = iter.key();
            let (key_length, key_start) = util::get_varint32(&entry[..5]);
            let key_end = key_start + (key_length as usize);
            if self
                .comparator
                .compare(&entry[key_start..key_end - 8], key.user_key())
                .is_eq()
            {
                // correct user key
                let tag = util::decode_fixed64(&entry[key_end - 8..key_end]);
                match (tag & 0xff).into() {
                    ValueType::TypeValue => {
                        let v = util::get_length_prefixed_slice(&entry[key_end..]);
                        let mut value = Vec::with_capacity(v.len());
                        value.extend_from_slice(v);
                        return Ok(value);
                    }
                    ValueType::TypeDeletion => {
                        return Err((true, api::Error::NotFound));
                    }
                }
            }
        };
        Err((false, api::Error::NotFound))
    }

    // Add an entry into memtable that maps key to value at the
    // specified sequence number and with the specified type.
    // Typically value will be empty if type==kTypeDeletion.
    pub fn add(&mut self, seq: SequenceNumber, type_: ValueType, key: &[u8], value: &[u8]) {
        // Format of an entry is concatenation of:
        //  key_size     : varint32 of internal_key.size()
        //  key bytes    : char[internal_key.size()]
        //  tag          : uint64((sequence << 8) | type)
        //  value_size   : varint32 of value.size()
        //  value bytes  : char[value.size()]
        let key_size = key.len();
        let val_size = value.len();
        let internal_key_size = key_size + 8;
        let encoded_len = util::varint_length(internal_key_size as u64)
            + internal_key_size
            + util::varint_length(val_size as u64)
            + val_size;
        let mut buf: Vec<u8> = Vec::with_capacity(encoded_len);
        util::encode_varint32(&mut buf, internal_key_size as u32);
        buf.extend_from_slice(key);
        util::encode_fixed64(&mut buf, (seq << 8) | type_ as u64);
        util::encode_varint32(&mut buf, val_size as u32);
        buf.extend_from_slice(value);
        assert!(buf.len() == encoded_len);
        self.table.insert(&buf);
    }

    fn iter(&self) -> MemTableIterator {
        MemTableIterator {
            iter: self.table.new_iterator(),
            scratch: Vec::new(),
        }
    }
}

struct MemTableIterator<'a> {
    iter: TableIterator<'a>,
    scratch: Vec<u8>,
}

impl<'a> api::Iterator for MemTableIterator<'a> {
    fn key(&self) -> &[u8] {
        util::get_length_prefixed_slice(self.iter.key())
    }

    fn value(&self) -> &[u8] {
        let key_slice = util::get_length_prefixed_slice(self.iter.key());
        util::get_length_prefixed_slice(key_slice)
    }

    fn next(&mut self) -> api::Result<()> {
        self.iter.next();
        Ok(())
    }

    fn prev(&mut self) -> api::Result<()> {
        self.iter.prev();
        Ok(())
    }

    fn seek(&mut self, key: &[u8]) -> api::Result<()> {
        encode_key(&mut self.scratch, key);
        self.iter.seek(&self.scratch);
        Ok(())
    }

    fn seek_to_first(&mut self) -> api::Result<()> {
        self.iter.seek_to_first();
        Ok(())
    }

    fn seek_to_last(&mut self) -> api::Result<()> {
        self.iter.seek_to_last();
        Ok(())
    }

    fn valid(&self) -> api::Result<bool> {
        Ok(self.iter.valid())
    }
}

/* #[derive(Clone)]
struct InternalKeyComparator<C:Comparator>{
    user_comparator: C,
}

impl api::Comparator for InternalKeyComparator{
    // Order by:
  //    increasing user key (according to user-supplied comparator)
  //    decreasing sequence number
  //    decreasing type (though sequence# should be enough to disambiguate)
    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering {
        let mut ord= self.user_comparator.compare(extract_user_key(a), extract_user_key(b));
        if ord==cmp::Ordering::Equal {
            //
        }
        ord
    }
    fn find_short_successor(&self, b: &mut [u8]) {

    }
    fn find_shortest_separator(&self, start: &mut [u8], limit: &[u8]) {

    }
} */

fn extract_user_key(internal_key: &[u8]) -> &[u8] {
    assert!(internal_key.len() >= 8);
    return &internal_key[..internal_key.len() - 8];
}

fn encode_key(scratch: &mut Vec<u8>, key: &[u8]) {
    scratch.clear();
    util::encode_varint32(scratch, key.len() as u32);
    scratch.extend_from_slice(&key);
}

struct KeyComparator {
    cmp: ByteswiseComparator,
}

impl super::skiplist::Comparator<Vec<u8>> for KeyComparator {
    fn compare(&self, key_a: &Vec<u8>, key_b: &Vec<u8>) -> cmp::Ordering {
        // Internal keys are encoded as length-prefixed strings.
        let a = util::get_length_prefixed_slice(key_a);
        let b = util::get_length_prefixed_slice(key_b);
        self.cmp.compare(a, b)
    }
}

// Modules in this directory should keep internal keys wrapped inside
// the following class instead of plain strings so that we do not
// incorrectly use string comparisons instead of an InternalKeyComparator.
#[derive(Clone)]
struct InternalKey {
    key: Vec<u8>,
}

impl InternalKey {
    fn user_key(&self) -> &[u8] {
        extract_user_key(&self.key)
    }

    /* fn encode(&self) -> &[u8] {

    } */
}
