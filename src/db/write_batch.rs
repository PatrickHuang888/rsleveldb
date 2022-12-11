use crate::{
    api::{self, Error},
    util, Handler, SequenceNumber, ValueType,
};

use super::memtable::MemTable;

pub(crate) struct MemTableInserter<'a> {
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
