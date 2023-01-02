use std::{
    cmp::{self, Ordering},
    rc::Rc,
};

use crate::{
    api::{self},
    extract_user_key, pack_sequence_and_type,
    util::{self, decode_fixed64},
    InternalKey, SequenceNumber, ValueType, MAX_SEQUENCE_NUMBER,
};

use super::skiplist::{Comparator as SkipListComparator, Iterator, SkipList, SkipListIterator};

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
const VALUE_TYPE_FOR_SEEK: ValueType = ValueType::TypeValue;

impl LookupKey {
    pub fn new(user_key: &[u8], s: SequenceNumber) -> Self {
        let mut needed = user_key.len() + 13; // A conservative estimate
        if needed <= LookupKeySpaceSize {
            needed = LookupKeySpaceSize;
        }
        let mut space = Vec::with_capacity(needed);
        util::put_varint32(&mut space, (user_key.len() + 8) as u32);
        let kstart = space.len();
        space.extend_from_slice(user_key);
        util::encode_fixed64(&mut space, pack_sequence_and_type(s, VALUE_TYPE_FOR_SEEK));
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
    comparator: KeyComparator,
}

impl MemTable {
    pub fn new(cmp: InternalKeyComparator) -> Self {
        let head_key = vec![0];
        let key_cmp = KeyComparator { comparator: cmp };
        let table = Table::new(key_cmp.clone(), &head_key);
        MemTable {
            comparator: key_cmp,
            table,
        }
    }

    // If memtable contains a value for key, store it in value and return true.
    // If memtable contains a deletion for key, store a NotFound() error in status and return true.
    // Else, return false.
    pub fn get(&mut self, key: &LookupKey, value: &mut Vec<u8>) -> api::Result<()> {
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
            let (key_length, key_start) = util::get_varint32(&entry[..5])
                .map_err(|_| api::Error::Corruption("decode key".to_string()))?;
            let key_end = key_start + (key_length as usize);
            if self
                .comparator
                .compare(
                    &entry[key_start..key_end - 8].to_vec(),
                    &key.user_key().to_vec(),
                )
                .is_eq()
            {
                // correct user key
                let tag = util::decode_fixed64(&entry[key_end - 8..key_end]) as u8;
                match (tag & 0xff).into() {
                    ValueType::TypeValue => {
                        let (v, _) = util::get_length_prefixed_slice(&entry[key_end..])
                            .map_err(|_| api::Error::Corruption("decode value".to_string()))?;
                        value.extend_from_slice(v);
                        return Ok(());
                    }
                    ValueType::TypeDeletion => {
                        return Err(api::Error::InternalNotFound(true));
                    }
                    _ => {
                        panic!("value type unknown");
                    }
                }
            }
        };
        Err(api::Error::InternalNotFound(false))
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
        let internal_key_size = key_size + 8; // key + tag
        let encoded_len = util::varint_length(internal_key_size as u64)
            + internal_key_size
            + util::varint_length(val_size as u64)
            + val_size;
        let mut buf: Vec<u8> = Vec::with_capacity(encoded_len);
        util::put_varint32(&mut buf, internal_key_size as u32);
        buf.extend_from_slice(key);
        util::put_fixed64(&mut buf, (seq << 8) | type_ as u64);
        util::put_varint32(&mut buf, val_size as u32);
        buf.extend_from_slice(value);
        assert!(buf.len() == encoded_len);
        self.table.insert(&buf);
    }

    pub(crate) fn new_iter(&mut self) -> MemTableIterator {
        MemTableIterator {
            scratch: Vec::new(),
            iter: self.table.new_iterator(),
        }
    }
}

pub(crate) struct MemTableIterator<'a> {
    iter: TableIterator<'a>,
    scratch: Vec<u8>,
}

impl<'a> api::Iterator for MemTableIterator<'a> {
    fn key(&self) -> api::Result<&[u8]> {
        let (key, _) = util::get_length_prefixed_slice(self.iter.key())
            .map_err(|_| api::Error::Corruption("key".to_string()))?;
        Ok(key)
    }

    fn value(&self) -> api::Result<&[u8]> {
        let kv = self.iter.key();
        let (_, offset) = util::get_length_prefixed_slice(kv)
            .map_err(|_| api::Error::Corruption("value".to_string()))?;
        let (value, _) = util::get_length_prefixed_slice(&kv[offset..])
            .map_err(|_| api::Error::Corruption("value".to_string()))?;
        Ok(value)
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

#[derive(Clone)]
pub struct InternalKeyComparator {
    user_comparator: Rc<dyn api::Comparator>,
}

impl InternalKeyComparator {
    pub fn new(user_comparator: Rc<dyn api::Comparator>) -> Self {
        Self { user_comparator }
    }
    pub fn user_comparator(&self) -> &dyn api::Comparator {
        self.user_comparator.as_ref()
    }
}

impl super::skiplist::Comparator<InternalKey> for InternalKeyComparator {
    fn compare(&self, a: &InternalKey, b: &InternalKey) -> cmp::Ordering {
        api::Comparator::compare(self, &a.rep, &b.rep)
    }
}

impl api::Comparator for InternalKeyComparator {
    fn name(&self) -> &'static str {
        "leveldb.InternalKeyComparator"
    }

    // Order by:
    //    increasing user key (according to user-supplied comparator)
    //    decreasing sequence number
    //    decreasing type (though sequence# should be enough to disambiguate)
    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering {
        match self
            .user_comparator
            .compare(extract_user_key(a), extract_user_key(b))
        {
            Ordering::Equal => {
                let anum = decode_fixed64(&a[a.len() - 8..]);
                let bnum = decode_fixed64(&b[b.len() - 8..]);
                if anum > bnum {
                    return Ordering::Less;
                } else if anum < bnum {
                    return Ordering::Greater;
                }
                return Ordering::Equal;
            }
            Ordering::Greater => {
                return Ordering::Greater;
            }
            Ordering::Less => {
                return Ordering::Less;
            }
        }
    }

    fn find_shortest_separator(&self, mut start: &mut [u8], limit: &[u8]) {
        // Attempt to shorten the user portion of the key
        let user_start = extract_user_key(start);
        let user_limit = extract_user_key(limit);
        let mut tmp = Vec::from(user_start);
        self.user_comparator
            .find_shortest_separator(&mut tmp, user_limit);
        if tmp.len() < user_start.len() && self.user_comparator.compare(user_start, &tmp).is_lt() {
            // User key has become shorter physically, but larger logically.
            // Tack on the earliest possible number to the shortened user key.
            util::put_fixed64(
                &mut tmp,
                pack_sequence_and_type(MAX_SEQUENCE_NUMBER, VALUE_TYPE_FOR_SEEK),
            );
            assert!(api::Comparator::compare(self, start, &tmp).is_lt());
            assert!(api::Comparator::compare(self, &tmp, limit).is_lt());
            start = &mut start[..tmp.len()];
            start.copy_from_slice(&tmp);
        }
    }

    fn find_short_successor(&self, mut key: &mut [u8]) {
        let user_key = extract_user_key(key);
        let mut tmp = Vec::from(user_key);
        self.user_comparator.find_short_successor(&mut tmp);
        if tmp.len() < user_key.len() && self.user_comparator.compare(user_key, &tmp).is_lt() {
            // User key has become shorter physically, but larger logically.
            // Tack on the earliest possible number to the shortened user key.
            util::put_fixed64(
                &mut tmp,
                pack_sequence_and_type(MAX_SEQUENCE_NUMBER, VALUE_TYPE_FOR_SEEK),
            );
            assert!(api::Comparator::compare(self, key, &tmp).is_lt());
            key = &mut key[..tmp.len()];
            key.copy_from_slice(&tmp);
        }
    }
}

fn encode_key(scratch: &mut Vec<u8>, key: &[u8]) {
    scratch.clear();
    util::put_varint32(scratch, key.len() as u32);
    scratch.extend_from_slice(&key);
}

#[derive(Clone)]
struct KeyComparator {
    comparator: InternalKeyComparator,
}

impl super::skiplist::Comparator<Vec<u8>> for KeyComparator {
    fn compare(&self, key_a: &Vec<u8>, key_b: &Vec<u8>) -> cmp::Ordering {
        // Internal keys are encoded as length-prefixed strings.
        let (a, _) = util::get_length_prefixed_slice(key_a).unwrap();
        let (b, _) = util::get_length_prefixed_slice(key_b).unwrap();
        api::Comparator::compare(&self.comparator, a, b)
    }
}
