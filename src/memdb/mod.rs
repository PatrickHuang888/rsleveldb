use crate::errors;
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

pub struct MemDb<'a> {
    inner: Arc<RwLock<SkipList<'a>>>,
}

impl<'a> MemDb<'a> {
    pub fn new(cmp: &'a dyn Comparer) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SkipList::new(cmp))),
        }
    }

    pub fn put(&mut self, key: &Key, value: &Value) -> errors::Result<()> {
        let mut db = self.inner.write().unwrap();
        db.put(key, value)
    }

    pub fn delete(&mut self, key: &Key) -> Result<(), String> {
        let mut db = self.inner.write().unwrap();
        db.delete(key)
    }

    // It is safe to modify the contents of the argument after Get returns.
    pub fn get(&self, key: &Key) -> Option<Value> {
        let db = self.inner.read().unwrap();
        match db.get(key) {
            None => None,
            Some(v) => Some(v.to_vec()),
        }
    }

    pub fn contains(&self, key: &Key) -> bool {
        let db = self.inner.read().unwrap();
        let (_, exact) = db.find_ge(key, None);
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

    pub fn len(&self) -> usize {
        let db = self.inner.read().unwrap();
        db.len()
    }
}

struct SkipList<'a> {
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

    cmp: &'a dyn Comparer,

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

impl<'a> SkipList<'a> {
    fn new(cmp: &'a dyn Comparer) -> Self {
        Self {
            kv_data: Vec::new(),
            node_data: vec![0; 4 + MAX_HEIGHT],
            max_height: 1,
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

            if cmp.is_lt() {
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

    fn delete(&mut self, key: &[u8]) -> Result<(), String> {
        let mut prevs: [usize; MAX_HEIGHT] = [0; MAX_HEIGHT];
        let (node, exact) = self.find_ge(key, Some(&mut prevs));
        if !exact {
            return Err("not found".to_string());
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

//type DefaultComparer = BytesComparer;

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

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::vec;

    use rand::prelude::ThreadRng;
    use rand::{thread_rng, Rng};

    use crate::memdb::Value;
    use crate::memdb::{Key, SkipList};

    use super::BytesComparer;
    use super::Comparer;
    use super::MemDb;

    #[derive(Clone, Copy)]
    enum DbAct {
        Put,
        None,
        Delete,
        DeleteNa,
        Overwrite,
    }

    struct DbTesting<'a> {
        //cmp: &'a dyn Comparer,
        deleted: KeyValue<'a>,
        present: KeyValue<'a>,

        act: DbAct,
        last_act: DbAct,

        act_key: Key,
        last_act_key: Key,

        db: MemDb<'a>,

        rng: ThreadRng,

        post:fn(&DbTesting),
    }

    struct KeyValueEntry {
        key: Key,
        value: Value,
    }

    struct KeyValue<'a> {
        entries: Vec<KeyValueEntry>,
        n_bytes: usize,

        cmp: &'a dyn Comparer,
    }

    impl<'a> KeyValue<'a> {
        fn new(cmp: &'a dyn Comparer) -> Self {
            KeyValue {
                entries: Vec::new(),
                n_bytes: 0,
                cmp: cmp,
            }
        }

        fn len(&self) -> usize {
            self.entries.len()
        }

        fn size(&self) -> usize {
            self.n_bytes
        }

        fn key_at(&self, i: usize) -> Key {
            self.entries[i].key.clone()
        }

        fn index_at(&self, i: usize) -> (Key, Value) {
            (self.entries[i].key.clone(), self.entries[i].value.clone())
        }

        fn value_at(&self, i: usize) -> Value {
            self.entries[i].value.clone()
        }

        fn search(&self, key: &Key) -> Result<usize, usize> {
            self.entries
                .binary_search_by(|entry| self.cmp.compare(&entry.key, &key))
        }

        /* fn get(&self, key:Key) -> Option<usize> {
            self.search(key)
        } */

        fn delete_index(&mut self, i: usize) -> Option<Value> {
            if i < self.len() {
                self.n_bytes -= self.key_at(i).len() + self.value_at(i).len();
                return Some(self.entries.remove(i).value);
            }
            None
        }

        fn delete(&mut self, key: &Key) -> Option<Value> {
            match self.search(&key) {
                Err(_) => None,
                Ok(i) => self.delete_index(i),
            }
        }

        // insert return true, update return false
        fn put_u(&mut self, key: &Key, value: &Value) -> bool {
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

        fn append(&mut self, key: &Key, value: &Value) {
            let n = self.entries.len();
            if n > 0 && self.cmp.compare(key, &self.entries[n - 1].key).is_le() {
                panic!("append, keys not in increasing order");
            }
            self.entries.push(KeyValueEntry {
                key: key.clone(),
                value: value.clone(),
            });
            self.n_bytes += key.len() + value.len();
        }
    }

    impl<'a> DbTesting<'a> {
        fn set_act(&mut self, act: DbAct, key: &Key) {
            self.last_act = self.act;
            self.act = act;
            self.last_act_key = self.act_key.clone();
            self.act_key = key.clone();
        }

        /* fn delete(&mut self, key: &Key) {
            match self.present.delete(key) {
                None => self.set_act(DbAct::DeleteNa, &key),
                Some(v) => {
                    self.set_act(DbAct::Delete, &key);
                    self.deleted.put_u(key, &v);
                }
            }

            self.do_delete(key);
        } */

        fn do_delete(&mut self, key: &Key) {
            assert!(self.db.delete(key).is_ok());
            assert_eq!(self.db.get(key), None);
        }

        fn put(&mut self, key: &Key, value: &Value) {
            if self.present.put_u(key, value) {
                self.set_act(DbAct::Put, key);
            } else {
                self.set_act(DbAct::Overwrite, key);
            }
            self.deleted.delete(key);

            assert!(self.db.put(key, value).is_ok());

            self.test_present_kv(key, value);

            (self.post)(self);
        }

        fn delete(&mut self, key:&Key) {
            match self.present.delete(key) {
                Some(v) => {
                    self.set_act(DbAct::Delete, key);
                    self.deleted.put_u(key, &v);
                },
                None => self.set_act(DbAct::DeleteNa, key),
            }

            assert!(self.db.delete(key).is_ok());

            self.test_deleted_key(key);

            (self.post)(self);
        }

        fn test_deleted_key(&self, key:&Key) {
            match self.db.get(key) {
                None => {},
                Some(_) => panic!("key should be deleted!"),
            }
        }

        fn test_present_kv(&self, key: &Key, value: &Value) {
            match self.db.get(key) {
                None => panic!("should present key, value"),
                Some(v) => assert_eq!(v[..], value[..]),
            }
        }

        fn put_random(&mut self) {
            if self.deleted.len() > 0 {
                let i = self.rng.gen_range(0..self.deleted.len());
                let (key, value) = self.deleted.index_at(i);
                self.put(&key, &value);
            }
        }

        fn delete_random(&mut self) {
            if self.present.len() >  0 {
                let i = self.rng.gen_range(0..self.present.len());
                let key= self.present.key_at(i);
                self.delete(&key);
            }
        }

        fn random_act(&mut self, round :usize) {
            for _ in 0..round {
                let r:bool= self.rng.gen();
                if r {
                    self.put_random();
                }else {
                    self.delete_random();
                }
            }
        }

        fn do_testing(&mut self) {
            self.delete_random();
            self.put_random();
            self.delete_random();
            self.delete_random(); 

            for _ in 0..self.deleted.len()/2 {
                self.put_random();
            }

            self.random_act((self.deleted.len()+self.present.len())*10);
        }

    }

    const KEY_MAP: &[u8] = "012345678ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxy".as_bytes();

    fn generate_keyvalue(
        cmp: &dyn Comparer,
        n: usize,
        min_len: usize,
        max_len: usize,
        v_min_len: usize,
        v_max_len: usize,
    ) -> KeyValue {
        //let default_cmp: BytesComparer = Default::default();
        let mut kv = KeyValue::new(cmp);

        let mut rng = thread_rng();

        for i in 0..n {
            let key_size = rng.gen_range(min_len..max_len) + min_len;

            loop {
                let mut key = vec![0; key_size];
                for j in 0..key_size {
                    let x = rng.gen_range(0..KEY_MAP.len());
                    key[j] = KEY_MAP[x]
                }

                let mut vm: usize = 0;
                if v_min_len == v_max_len {
                    vm = v_min_len
                } else {
                    vm = rng.gen_range(v_min_len..v_max_len) + v_min_len;
                }
                let mut value: Vec<u8> = Vec::with_capacity(vm);
                let s = format!("v{}", i);
                let bs = s.as_bytes();
                for j in 0..bs.len() {
                    value.push(bs[j])
                }
                for _ in value.len()..vm {
                    value.push(b'x');
                }

                if kv.put_u(&key, &value) {
                    break;
                }
            }
        }

        kv
    }

    #[test]
    fn test_write() {
        let default_cmp: BytesComparer = Default::default();
        let memdb = MemDb::new(&default_cmp);
        let deleted = generate_keyvalue(&default_cmp, 1000, 1, 30, 5, 5);

        let mut db_testing = DbTesting {
            db: memdb,
            deleted: deleted,
            present: KeyValue::new(&default_cmp),
            act: DbAct::None,
            last_act: DbAct::None,
            act_key: vec![],
            last_act_key: vec![],
            rng: thread_rng(),
            post: write_post,
        };

        fn write_post(testing: &DbTesting) {
            assert_eq!(testing.db.len(), testing.present.len());
            assert_eq!(testing.db.size(), testing.present.size());

            match testing.act {
                DbAct::Put => assert!(testing.db.contains(&testing.act_key)),
                DbAct::Overwrite => assert!(testing.db.contains(&testing.act_key)),
                _ => assert!(!testing.db.contains(&testing.act_key)),
            }
        }

        db_testing.do_testing();
    }

    #[test]
    fn test_basic() {
        let default_cmp: BytesComparer = Default::default();
        let key1 = vec![11, 22, 33];
        let value1 = vec![44, 55, 66];
        let key1_1 = key1.clone();
        let cmp = default_cmp.compare(&key1, &key1_1);
        assert_eq!(cmp, Ordering::Equal);

        let mut db = SkipList::new(&default_cmp);
        assert!(db.put(&key1, &value1).is_ok());
        let v = db.get(&key1).unwrap();
        assert_eq!(v, value1);
        assert!(db.delete(&key1).is_ok());
    }
}
