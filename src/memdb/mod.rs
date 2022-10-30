use crate::api;
use crate::api::Comparator;
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

type Key = Vec<u8>;
type Value = Vec<u8>;
pub struct MemDb<C: Comparator> {
    inner: Arc<RwLock<SkipList<C>>>,
}

impl<C: Comparator> MemDb<C> {
    pub fn new(cmp: &C) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SkipList::new(cmp))),
        }
    }

    pub fn put(&mut self, key: &Key, value: &Value) -> api::Result<()> {
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
    pub fn find(&self, key: &Key) -> Option<(Key, Value)> {
        let db = self.inner.read().unwrap();
        let (node, _) = db.find_ge(key, None);
        if node != 0 {
            let o = db.node_data[node];
            let k_len = db.node_data[node + N_KEY];
            let rkey = &db.kv_data[o..o + k_len];
            let v_len = db.node_data[node + N_VAL];
            let value = &db.kv_data[o + k_len..o + k_len + v_len];
            return Some((rkey.to_vec(), value.to_vec()));
        }
        None
    }

    fn find_lt(&self, key: &Key) -> Option<(Key, Value)> {
        let db = self.inner.read().unwrap();
        match db.find_lt(key) {
            None => None,
            Some(node) => {
                let n = db.node_data[node];
                let k = db.node_data[node + N_KEY];
                let key = &db.kv_data[n..n + k];
                let v = db.node_data[node + N_VAL];
                let value = &db.kv_data[n + k..n + k + v];
                Some((key.to_vec(), value.to_vec()))
            }
        }
    }

    pub fn size(&self) -> usize {
        let db = self.inner.read().unwrap();
        db.size()
    }

    pub fn len(&self) -> usize {
        let db = self.inner.read().unwrap();
        db.len()
    }

    pub fn iter(&self) -> MemDbIter<C> {
        MemDbIter::new(self.inner.clone())
    }
}

pub struct MemDbIter<C: Comparator> {
    node: usize,
    inner: Arc<RwLock<SkipList<C>>>,
}

impl<C: Comparator> MemDbIter<C> {
    fn new(inner: Arc<RwLock<SkipList<C>>>) -> Self {
        MemDbIter {
            node: 0,
            inner: inner,
        }
    }
}

impl<C: Comparator> Iterator for MemDbIter<C> {
    type Item = (Key, Value);

    fn next(&mut self) -> Option<(Key, Value)> {
        let db = self.inner.read().unwrap();

        self.node = db.node_data[self.node + N_NEXT];
        if self.node != 0 {
            let o = db.node_data[self.node];
            let k = db.node_data[self.node + N_KEY];
            let key = &db.kv_data[o..o + k];
            let value = &db.kv_data[k..k + db.node_data[self.node + N_VAL]];
            return Some((key.to_vec(), value.to_vec()));
        }
        None
    }
}

struct SkipListIter<'a, C: Comparator> {
    node: usize,
    db: &'a SkipList<C>,
}

impl<'a, C: Comparator> SkipListIter<'a, C> {
    fn new(db: &'a SkipList<C>) -> Self {
        SkipListIter { node: 0, db: db }
    }

    fn next(&mut self) -> Option<(Key, Value)> {
        self.node = self.db.node_data[self.node + N_NEXT];
        if self.node != 0 {
            let o = self.db.node_data[self.node];
            let k = self.db.node_data[self.node + N_KEY];
            let key = &self.db.kv_data[o..o + k];
            let value = &self.db.kv_data[k..k + self.db.node_data[self.node + N_VAL]];
            return Some((key.to_vec(), value.to_vec()));
        }
        None
    }
}

struct SkipList<C: Comparator> {
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

    comparator: C,

    kv_size: usize,

    n: usize,
}

impl<C: Comparator> SkipList<C> {
    fn new(cmp: &C) -> Self {
        Self {
            kv_data: Vec::new(),
            node_data: vec![0; 4 + MAX_HEIGHT],
            max_height: 1,
            comparator: cmp.clone(),
            kv_size: 0,
            n: 0,
        }
    }

    // Sets the value for the given key. It overwrites any previous value
    // for that key.
    fn put(&mut self, key: &[u8], value: &[u8]) -> api::Result<()> {
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
                    .comparator
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

    fn find_lt(&self, key: &Key) -> Option<usize> {
        // todo:
        None
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

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::vec;

    use rand::prelude::{SliceRandom, ThreadRng};
    use rand::{thread_rng, Rng};

    use crate::memdb::Value;
    use crate::memdb::{Key, SkipList};
    use super::Comparator;
    use super::MemDb;
    use crate::api::ByteswiseComparator;

    #[derive(Clone, Copy)]
    enum DbAct {
        Put,
        None,
        Delete,
        DeleteNa,
        Overwrite,
    }

    struct DbTesting<'a, C: Comparator> {
        //cmp: &'a dyn Comparer,
        deleted: KeyValue<'a, C>,
        present: KeyValue<'a, C>,

        act: DbAct,
        last_act: DbAct,

        act_key: Key,
        last_act_key: Key,

        db: MemDb<C>,

        rng: ThreadRng,

        post: fn(&DbTesting<'a, C>),
    }

    impl<'a, C: Comparator> DbTesting<'a, C> {
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

        fn delete(&mut self, key: &Key) {
            match self.present.delete(key) {
                Some(v) => {
                    self.set_act(DbAct::Delete, key);
                    self.deleted.put_u(key, &v);
                }
                None => self.set_act(DbAct::DeleteNa, key),
            }

            assert!(self.db.delete(key).is_ok());

            self.test_deleted_key(key);

            (self.post)(self);
        }

        fn test_deleted_key(&self, key: &Key) {
            match self.db.get(key) {
                None => {}
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
                let (k, v) = self.deleted.index_at(i);
                let key = k.clone();
                let value = v.clone();
                self.put(&key.to_vec(), &value.to_vec());
            }
        }

        fn delete_random(&mut self) {
            if self.present.len() > 0 {
                let i = self.rng.gen_range(0..self.present.len());
                let key = self.present.key_at(i);
                self.delete(&key.to_vec());
            }
        }

        fn random_act(&mut self, round: usize) {
            for _ in 0..round {
                let r: bool = self.rng.gen();
                if r {
                    self.put_random();
                } else {
                    self.delete_random();
                }
            }
        }

        fn iter_testing(&self) {}

        fn test_get(&mut self, kv: &KeyValue<'a, C>) {
            let i = self.rng.gen_range(0..kv.len());
            let (key, value) = kv.index_at(i);
            let v = self.db.get(&key.to_vec()).unwrap();
            assert_eq!(&v, value);

            if i > 0 {
                let (key1, _) = kv.index_at(i - 1);
                assert!(self.db.get(&key1.to_vec()).is_none());
            }
        }

        fn test_findlt(&mut self, kv: &KeyValue<'a, C>) {
            let i = self.rng.gen_range(0..kv.len() - 1);
            let (key, value) = kv.index_at(i);
        }

        fn do_testing(&mut self) {
            self.delete_random();
            self.put_random();
            self.delete_random();
            self.delete_random();

            for _ in 0..self.deleted.len() / 2 {
                self.put_random();
            }

            self.random_act((self.deleted.len() + self.present.len()) * 10);

            self.iter_testing();
        }
    }

    const KEY_MAP: &[u8] = "012345678ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxy".as_bytes();

    fn generate_keyvalue<'a, C: Comparator>(
        cmp: &'a C,
        n: usize,
        min_len: usize,
        max_len: usize,
        v_min_len: usize,
        v_max_len: usize,
    ) -> KeyValue<'a, C> {
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
        let default_cmp: ByteswiseComparator = Default::default();
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

        fn write_post<'a, C: Comparator>(testing: &DbTesting<'a, C>) {
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
    fn test_read() {
        let default_cmp: ByteswiseComparator = Default::default();

        let mut kv = KeyValue::new(&default_cmp);
        test_find(&default_cmp, &kv);

        kv.put_u(&"".as_bytes().to_vec(), &"value".as_bytes().to_vec());
        {
            let kv_empty_key = &kv;
            test_find(&default_cmp, &kv_empty_key);
        }

        kv.clear();
        kv.put_u(&"abc".as_bytes().to_vec(), &"".as_bytes().to_vec());
        kv.put_u(&"abcd".as_bytes().to_vec(), &"".as_bytes().to_vec());
        {
            let kv_empty_value = &kv;
            test_find(&default_cmp, &kv_empty_value);
        }

        kv.clear();
        kv.put_u(&"abc".as_bytes().to_vec(), &"v".as_bytes().to_vec());
        {
            let kv_onekey = &kv;
            test_find(&default_cmp, &kv_onekey);
        }

        kv.clear();
        let big_value = vec![1; 200_000];
        kv.put_u(&"big1".as_bytes().to_vec(), &big_value);
        {
            let kv_bigvalue = &kv;
            test_find(&default_cmp, &kv_bigvalue);
        }

        kv.clear();
        let special_key = vec![0xff, 0xff];
        kv.put_u(&special_key, &"v".as_bytes().to_vec());
        {
            let kv_specical_key = &kv;
            test_find(&default_cmp, &kv_specical_key);
        }

        {
            let kv = generate_keyvalue(&default_cmp, 120, 1, 50, 1, 120);
            test_find(&default_cmp, &kv);
        }
    }

    fn test_find<'a, C: Comparator>(cmp: &C, kv: &KeyValue<'a, C>) {
        let mut db = MemDb::new(cmp);
        let mut rng = thread_rng();

        let mut indexs = vec![];
        for i in 0..kv.len() {
            indexs.push(i);
        }

        indexs.shuffle(&mut rng);

        for i in &indexs {
            let (key, value) = kv.index_at(*i);
            assert!(db.put(&key.to_vec(), &value.to_vec()).is_ok());
        }

        indexs.shuffle(&mut rng);

        for i in &indexs {
            let (key, value) = kv.index_at(*i);
            let (k, v) = db.find(&key.to_vec()).unwrap();
            assert_eq!(&k, key);
            assert_eq!(&v, value);

            if *i > 0 {
                let (key, _) = kv.index_at(i - 1);
                let mut key1 = key.clone();
                key1.append(&mut key.clone());
                let (k1, v1) = db.find(&key1).unwrap();
                assert_eq!(k, k1);
                assert_eq!(v, v1);
            }
        }
    }

    #[test]
    fn test_basic() {
        let default_cmp: ByteswiseComparator = Default::default();
        let key1 = vec![11, 22, 33];
        let value1 = vec![44, 55, 66];
        let key1_1 = key1.clone();
        let cmp = default_cmp.compare(&key1, &key1_1);
        assert_eq!(cmp, Ordering::Equal);

        let key2 = vec![11, 22, 33, 44];
        let cmp = default_cmp.compare(&key1, &key2);
        assert_eq!(cmp, Ordering::Less);

        let mut db = SkipList::new(&default_cmp);
        assert!(db.put(&key1, &value1).is_ok());
        let v = db.get(&key1).unwrap();
        assert_eq!(v, value1);
        assert!(db.delete(&key1).is_ok());
    }
}
