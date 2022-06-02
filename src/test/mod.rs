use crate::api::{Comparator, Key, Value};

struct KeyValueEntry {
    key: Key,
    value: Value,
}

pub struct KeyValue<'a, C: Comparator> {
    entries: Vec<KeyValueEntry>, // entries in ascend order
    n_bytes: usize,

    comparator: &'a C,
}

impl<'a, C: Comparator> KeyValue<'a, C> {
    pub fn new(cmp: &'a C) -> Self {
        KeyValue {
            entries: Vec::new(),
            n_bytes: 0,
            comparator: cmp,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn size(&self) -> usize {
        self.n_bytes
    }

    pub fn key_at(&self, i: usize) -> Key {
        self.entries[i].key.clone()
    }

    pub fn index_at(&self, i: usize) -> (&Key, &Value) {
        (&self.entries[i].key, &self.entries[i].value)
    }

    pub fn value_at(&self, i: usize) -> Value {
        self.entries[i].value.clone()
    }

    pub fn search(&self, key: &Key) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|entry| self.comparator.compare(&entry.key, &key))
    }

    /* fn get(&self, key:Key) -> Option<usize> {
        self.search(key)
    } */

    pub fn delete_index(&mut self, i: usize) -> Option<Value> {
        if i < self.len() {
            self.n_bytes -= self.key_at(i).len() + self.value_at(i).len();
            return Some(self.entries.remove(i).value);
        }
        None
    }

    pub fn delete(&mut self, key: &Key) -> Option<Value> {
        match self.search(&key) {
            Err(_) => None,
            Ok(i) => self.delete_index(i),
        }
    }

    // insert return true, update return false
    pub fn put_u(&mut self, key: &Key, value: &Value) -> bool {
        match self.search(&key) {
            Ok(i) => {
                self.n_bytes += value.len() - self.value_at(i).len();
                self.entries[i].value = value.clone();
            }
            Err(i) => {
                self.n_bytes += key.len() + value.len();
                self.entries.insert(
                    i,
                    KeyValueEntry {
                        key: key.clone(),
                        value: value.clone(),
                    },
                );
                return true;
            }
        }
        false
    }

    pub fn append(&mut self, key: &Key, value: &Value) {
        let n = self.entries.len();
        if n > 0
            && self
                .comparator
                .compare(key, &self.entries[n - 1].key)
                .is_le()
        {
            panic!("append, keys not in increasing order");
        }
        self.entries.push(KeyValueEntry {
            key: key.clone(),
            value: value.clone(),
        });
        self.n_bytes += key.len() + value.len();
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.n_bytes = 0;
    }
}
