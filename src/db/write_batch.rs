use crate::{
    api::{self, Error},
    util, Handler, SequenceNumber, ValueType,
};

use super::memtable::MemTable;

pub(crate) struct MemTableInserter<'a, C: api::Comparator + 'static> {
    pub(crate) sequence: SequenceNumber,
    pub(crate) mem: &'a mut MemTable<C>,
}
impl<'a, C: api::Comparator> Handler for MemTableInserter<'a, C> {
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
