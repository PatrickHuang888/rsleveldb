use crate::errors;
use rand::prelude::*;
use std::borrow::BorrowMut;
use std::cmp;
use std::io::Write;
use std::sync::Arc;
use std::sync::RwLock;

const MAX_HEIGHT: usize = 12;
const N_KV: usize = 0;
const N_KEY: usize = 1;
const N_VAL: usize = 2;
const N_HEIGHT: usize = 3;
const N_NEXT: usize = 4;

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

pub struct MemDb {
    inner: Arc<RwLock<SkipList>>,
}

impl MemDb {
    pub fn new() -> Self {
        let cmp: BytesComparer = Default::default();
        Self {
            inner: Arc::new(RwLock::new(SkipList::new(Box::new(cmp)))),
        }
    }

    pub fn put(&mut self, key: Key, value: Value) -> errors::Result<()> {
        let mut db = self.inner.write().unwrap();
        db.put(&key, &value)
    }

    pub fn delete(&mut self, key: Key) -> errors::Result<()> {
        let mut db = self.inner.write().unwrap();
        db.delete(&key)
    }

    // It is safe to modify the contents of the argument after Get returns.
    pub fn get(&self, key: Key) -> Option<Value> {
        let db = self.inner.read().unwrap();
        match db.get(&key) {
            None => None,
            Some(v) => Some(v.to_vec()),
        }
    }

    pub fn contains(&self, key: Key) -> bool {
        let db = self.inner.read().unwrap();
        let (_, exact) = db.find_ge(&key, None);
        exact
    }

    // Find finds key/value pair whose key is greater than or equal to the
    // given key.
    //
    // The caller should not modify the contents of the returned slice, but
    // it is safe to modify the contents of the argument after Find returns.
    pub fn find(&self, key: Key) -> Option<(Key, Value)> {
        let db = self.inner.read().unwrap();
        let (node, _) = db.find_ge(&key, None);
        if node != 0 {
            let o = db.node_data[node];
            let k = o + db.node_data[node + N_KEY];
            let rkey = &db.kv_data[o..o + k];
            let value = &db.kv_data[k..k + db.node_data[node + N_VAL]];
            return Some((rkey.to_vec(), value.to_vec()));
        }
        None
    }

    pub fn size(&self) -> usize {
        let db = self.inner.read().unwrap();
        db.size()
    }
}

struct SkipList {
    kv_data: Vec<u8>,

    // Node data:
    // [0]         : KV offset
    // [1]         : Key length
    // [2]         : Value length
    // [3]         : Height
    // [3..height] : Next nodes at different level
    node_data: Vec<usize>,

    //prev_node: [usize; MAX_HEIGHT],
    max_height: usize,

    cmp: Box<dyn Comparer>,

    kv_size: usize,

    n: usize,
}

pub trait Comparer {
    // Compare returns -1, 0, or +1 depending on whether a is 'less than',
    // 'equal to' or 'greater than' b. The two arguments can only be 'equal'
    // if their contents are exactly equal. Furthermore, the empty slice
    // must be 'less than' any non-empty slice.
    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering;
}

impl SkipList {
    fn new(cmp: Box<dyn Comparer>) -> Self {
        Self {
            kv_data: Vec::new(),
            node_data: Vec::new(),
            max_height: 0,
            cmp: cmp,
            kv_size: 0,
            n: 0,
        }
    }

    // Sets the value for the given key. It overwrites any previous value
    // for that key.
    fn put(&mut self, key: &[u8], value: &[u8]) -> errors::Result<()> {
        let mut prevs: [usize; MAX_HEIGHT] = [0; MAX_HEIGHT];
        let (node, exact) = self.find_ge(key, Some(&mut prevs));

        if exact {
            let kv_offset = self.kv_data.len();

            match self.kv_data.write(key) {
                Ok(_) => (),
                Err(e) => return Err(e.into()),
            };
            match self.kv_data.write(value) {
                Ok(_) => (),
                Err(e) => return Err(e.into()),
            };

            self.node_data[node] = kv_offset;
            // no need update key length
            let m = self.node_data[node + N_VAL];
            self.node_data[node + N_VAL] = value.len();
            self.kv_size += value.len() - m;
            return Ok(());
        }

        let h = self.rand_height();
        if h > self.max_height {
            let mut i = self.max_height;
            while i < h {
                prevs[i] = 0;
                i += 1;
            }
            self.max_height = h
        }

        let o = self.kv_data.len();
        match self.kv_data.write(key) {
            Ok(_) => (),
            Err(e) => return Err(e.into()),
        };
        match self.kv_data.write(value) {
            Ok(_) => (),
            Err(e) => return Err(e.into()),
        };

        // node
        let node = self.node_data.len();
        self.node_data.push(o);
        self.node_data.push(key.len());
        self.node_data.push(value.len());
        self.node_data.push(h);

        let mut i = 0;
        // link the node at different level from 0..h
        while i < h {
            let m = prevs[i] + N_NEXT + i; // next i of level i
            self.node_data.push(self.node_data[m]);
            self.node_data[m] = node;
            i += 1;
        }

        self.kv_size += key.len() + value.len();
        self.n += 1;
        Ok(())
    }

    fn rand_height(&self) -> usize {
        const BRANCHING: i64 = 4;
        let mut h = 1;

        while h < MAX_HEIGHT && rand::random::<i64>() % BRANCHING == 0 {
            h += 1
        }
        h
    }

    // must hold RW-lock as it use shared prevNode slice.
    // return true means equal
    fn find_ge(&self, key: &[u8], mut prevs: Option<&mut [usize]>) -> (usize, bool) {
        let mut node = 0;
        let mut h = self.max_height - 1;

        loop {
            let next = self.node_data[node + N_NEXT + h];
            let mut cmp = cmp::Ordering::Greater;

            if next != 0 {
                // have node at this level
                let o = self.node_data[next];
                cmp = self
                    .cmp
                    .compare(&self.kv_data[o..o + self.node_data[next + N_KEY]], key);
            }

            if cmp.is_le() {
                // keep searching
                node = next;
            } else {
                match prevs {
                    None => {
                        if cmp.is_eq() {
                            return (next, true);
                        }
                    }
                    Some(ref mut prevs) => {
                        prevs[h] = node; // push into previous height node
                    }
                }

                if h == 0 {
                    // lowest level, return the postion
                    return (next, cmp.is_eq());
                }
                h -= 1;
            }
        }
    }

    // returns sum of keys and values length. Note that deleted
    // key/value will not be accounted for, but it will still consume
    // the buffer, since the buffer is append only.
    fn size(&self) -> usize {
        self.kv_size
    }

    // returns the number of entries in the DB.
    fn len(&self) -> usize {
        self.n
    }

    fn delete(&mut self, key: &[u8]) -> errors::Result<()> {
        let mut prevs: [usize; MAX_HEIGHT] = [0; MAX_HEIGHT];
        let (node, exact) = self.find_ge(key, Some(&mut prevs));
        if !exact {
            return Err(errors::DbError::NotFoundError);
        }

        let h = self.node_data[node + N_HEIGHT]; // top height
        let mut i = 0;
        // delete node at every level list
        while i < h {
            let m = prevs[i] + N_NEXT + i;
            self.node_data[m] = self.node_data[self.node_data[m] + N_NEXT + i];
            i += 1;
        }

        self.kv_size -= self.node_data[node + N_KEY] + self.node_data[node + N_VAL];
        self.n -= 1;

        Ok(())
    }

    fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let (node, exact) = self.find_ge(key, None);
        if exact {
            let o = self.node_data[node] + self.node_data[node + N_KEY]; // offset = kv_offset + key_length
            return Some(&self.kv_data[o..o + self.node_data[node + N_VAL]]);
        }
        None
    }
}

#[derive(Default)]
struct BytesComparer {}

impl Comparer for BytesComparer {
    fn compare(&self, a: &[u8], b: &[u8]) -> cmp::Ordering {
        for (ai, bi) in a.iter().zip(b.iter()) {
            match ai.cmp(&bi) {
                cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        cmp::Ordering::Equal
    }
}
