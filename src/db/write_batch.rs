use crate::{
    api::{self, Error},
    util,
};

use super::{memtable::MemTable, SequenceNumber, ValueType};

// WriteBatch header has an 8-byte sequence number followed by a 4-byte count.
const Header: usize = 12;

#[derive(PartialEq)]
pub struct WriteBatch {
    space: Vec<u8>,
}

impl WriteBatch {
    pub fn new() -> Self {
        WriteBatch {
            space: vec![0; Header],
        }
    }

    pub fn append(&mut self, src: &WriteBatch) {
        self.set_count(self.count() + src.count());
        assert!(src.space.len() >= Header);
        self.space.extend_from_slice(&src.space[Header..])
    }

    // Store the mapping "key->value" in the database.
    pub fn put(&mut self, key: &[u8], value: &[u8]) {
        //self.space.push(ValueType::TypeValue)
        todo!()
    }

    pub fn contents(&self) -> &[u8] {
        todo!()
    }

    pub fn sequence(&self) -> SequenceNumber {
        util::decode_fixed64(&self.space[..8])
    }

    pub fn set_sequence(&mut self, seq: SequenceNumber) {
        util::encode_fixed64(&mut self.space[0..7], seq);
    }

    pub fn count(&self) -> u32 {
        util::decode_fixed32(&self.space[8..12])
    }

    fn set_count(&mut self, n: u32) {
        util::encode_fixed32(&mut self.space[8..12], n)
    }

    pub fn byte_size(&self) -> usize {
        self.space.len()
    }

    pub fn insert_into(&self, memtable: &mut super::memtable::MemTable) -> api::Result<()> {
        let mut inserter = MemTableInserter {
            sequence: self.sequence(),
            mem: memtable,
        };
        self.iterate(&mut inserter)?;
        Ok(())
    }

    fn iterate(&self, handler: &mut dyn Handler) -> api::Result<()> {
        if self.space.len() < Header {
            return Err(api::Error::Corruption(String::from(
                "malformed WriteBatch (too small)",
            )));
        }

        let mut input = &self.space[Header..];
        let mut key: &[u8];
        let mut value: &[u8];
        let mut found = 0;
        while !input.is_empty() {
            found += 1;
            let tag: ValueType = (input[0] as u64).into();
            input = &input[1..];
            match tag {
                ValueType::TypeValue => {
                    key = util::get_length_prefixed_slice(&input);
                    input = &input[key.len()..];
                    value = util::get_length_prefixed_slice(&input);
                    input = &input[value.len()..];
                    if key.len() == 0 || value.len() == 0 {
                        return Err(Error::Corruption(String::from("bad WriteBatch Put")));
                    }
                    handler.put(key, value);
                }
                ValueType::TypeDeletion => {
                    key = util::get_length_prefixed_slice(&input);
                    input = &input[key.len()..];
                    if key.len() == 0 {
                        return Err(Error::Corruption(String::from("bad WriteBatch Delete")));
                    }
                    handler.delete(key);
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
}

trait Handler {
    fn put(&mut self, key: &[u8], value: &[u8]);
    fn delete(&mut self, key: &[u8]);
}

struct MemTableInserter<'a> {
    sequence: SequenceNumber,
    mem: &'a mut MemTable,
}
impl<'a> Handler for MemTableInserter<'a> {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.mem
            .add(self.sequence, ValueType::TypeValue, key, value);
        self.sequence += 1;
    }

    fn delete(&mut self, key: &[u8]) {
        self.mem
            .add(self.sequence, ValueType::TypeDeletion, key, &[0]);
        self.sequence += 1;
    }
}
