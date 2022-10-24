use std::{
    cmp,
    ptr::{self, null_mut},
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

use rand::{thread_rng, Rng};

pub trait Comparator<K: ?Sized> {
    fn compare(&self, a: &K, b: &K) -> cmp::Ordering;
}

/* trait Copy {
    fn copy(&self) -> S;
}

impl Copy<[u8]> for [u8] {
    fn copy(k:&[u8]) -> &[u8] {
        let v= Vec::with_capacity(k.len());
        v.extend_from_slice(k);
        v.as_slice()
    }
} */

struct Node<K: Clone> {
    key: K,
    nexts: Vec<AtomicPtr<Node<K>>>,
}

/* impl<'a, K:PartialEq> PartialEq for Node<'a, K> {
    fn eq(&self, other: &Self) -> bool {
        *self.key == *other.key
    }
} */

impl<K: Clone> Node<K> {
    fn new(key: &K, height: usize) -> Self {
        let mut v = Vec::with_capacity(height);
        for _ in 0..height {
            v.push(AtomicPtr::default());
        }
        Node {
            key: key.clone(),
            nexts: v,
        }
    }

    fn next(&self, n: usize) -> *mut Node<K> {
        // Use an 'acquire load' so that we observe a fully initialized
        // version of the returned Node.
        self.nexts[n].load(Ordering::Acquire)
    }

    // No-barrier variants that can be safely used in a few locations.
    fn no_barrier_next(&self, n: usize) -> *mut Node<K> {
        self.nexts[n].load(Ordering::Relaxed)
    }

    fn set_next(&self, n: usize, x: *mut Node<K>) {
        // Use a 'release store' so that anybody who reads through this
        // pointer observes a fully initialized version of the inserted node.
        self.nexts[n].store(x, Ordering::Release);
    }

    fn no_barrier_set_next(&self, n: usize, x: *mut Node<K>) {
        self.nexts[n].store(x, Ordering::Relaxed);
    }
}

const MAX_HEIGHT: usize = 12;

pub struct SkipList<C: Comparator<K>, K: PartialEq + Clone> {
    comparator: C,
    max_height: AtomicUsize,
    head: Node<K>,
    head_ptr: *mut Node<K>,
}

impl<C: Comparator<K>, K: PartialEq + Clone> SkipList<C, K> {
    fn new(cmp: C, head_key: &K) -> Self {
        let head = Node::new(head_key, MAX_HEIGHT); // head with any key will do
        let mut list = SkipList {
            comparator: cmp,
            max_height: AtomicUsize::new(1),
            head: head,
            head_ptr: null_mut(),
        };
        list.head_ptr = &mut list.head;
        list
    }

    fn random_height(&mut self) -> usize {
        // Increase height with probability 1 in kBranching
        const BRANCHING: f64 = 4.0;

        let mut rng = thread_rng();
        let mut height = 1;
        while height < MAX_HEIGHT && rng.gen_bool(1.0 / BRANCHING) {
            height += 1;
        }

        assert!(height <= MAX_HEIGHT);
        height
    }

    pub fn insert(&mut self, key: &K) {
        let mut prevs = vec![ptr::null_mut(); MAX_HEIGHT];

        let i_ptr = self.find_greater_or_equal(key, &mut prevs);
        // Our data structure does not allow duplicate insertion
        if !i_ptr.is_null() {
            let node = unsafe { i_ptr.as_ref().unwrap() };
            assert!(key != &node.key);
        }

        let height = self.random_height();
        if height > self.get_max_height() {
            for i in self.get_max_height()..height {
                prevs[i] = self.head_ptr;
            }
            // It is ok to mutate max_height_ without any synchronization
            // with concurrent readers.  A concurrent reader that observes
            // the new value of max_height_ will see either the old value of
            // new level pointers from head_ (nullptr), or a new value set in
            // the loop below.  In the former case the reader will
            // immediately drop to the next level since nullptr sorts after all
            // keys.  In the latter case the reader will use the new node.
            self.max_height.store(height, Ordering::Relaxed);
        }

        let x = Box::new(Node::new(key, height));
        for i in 0..height {
            assert!(!prevs[i].is_null());
            let prev_i = unsafe { prevs[i].as_ref().unwrap() };
            // NoBarrier_SetNext() suffices since we will add a barrier when
            // we publish a pointer to "x" in prev[i].
            x.no_barrier_set_next(i, prev_i.no_barrier_next(i));
        }
        let x_ptr = Box::into_raw(x);
        for i in 0..height {
            let prev_i = unsafe { prevs[i].as_ref().unwrap() };
            prev_i.set_next(i, x_ptr);
        }
    }

    fn contains(&self, key: &K) -> bool {
        let x_ptr = self.find_greater_or_equal(key, &mut vec![]);
        if !x_ptr.is_null() {
            let x = unsafe { x_ptr.as_ref().unwrap() };
            if self.comparator.compare(key, &x.key).is_eq() {
                return true;
            }
        }
        return false;
    }

    // Return the latest node with a key < key.
    // Return head_ if there is no such node.
    fn find_less_than(&self, key: &K) -> *mut Node<K> {
        let mut x_ptr = self.head_ptr;
        let mut level = self.get_max_height() - 1;

        loop {
            assert!(!x_ptr.is_null());
            let x = unsafe { x_ptr.as_ref().unwrap() };
            if x_ptr != self.head_ptr {
                assert!(self.comparator.compare(&x.key, key).is_lt());
            }

            let next_ptr = x.next(level);
            if next_ptr.is_null() {
                if level == 0 {
                    return x_ptr;
                } else {
                    // Switch to next list
                    level -= 1;
                }
            } else {
                let next = unsafe { next_ptr.as_ref().unwrap() };
                if self.comparator.compare(&next.key, key).is_ge() {
                    if level == 0 {
                        return x_ptr;
                    } else {
                        // Switch to next list
                        level -= 1;
                    }
                } else {
                    x_ptr = next_ptr;
                }
            }
        }
    }

    // Return the earliest node that comes at or after key.
    // Return INVALID_INDEX if there is no such node.
    //
    // If prevs is non-empty, fills prevs[level] with pointer to previous
    // node at "level" for every level in [0..max_height_-1].
    fn find_greater_or_equal(&self, key: &K, prevs: &mut Vec<*mut Node<K>>) -> *mut Node<K> {
        let mut level = self.get_max_height() - 1;
        let mut x_ptr = self.head_ptr;

        loop {
            assert!(!x_ptr.is_null());
            let x = unsafe { x_ptr.as_ref().unwrap() };
            let next_ptr = x.next(level);
            if self.key_is_after_node(key, next_ptr) {
                // Keep searching in this list
                x_ptr = next_ptr;
            } else {
                if prevs.len() != 0 {
                    prevs[level] = x_ptr;
                }

                if level == 0 {
                    return next_ptr;
                } else {
                    level -= 1;
                }
            }
        }
    }

    // Return the last node in the list.
    // Return head_ if list is empty.
    fn find_last(&self) -> *mut Node<K> {
        let mut x_ptr = self.head_ptr;
        let mut level = self.get_max_height() - 1;

        loop {
            assert!(!x_ptr.is_null());
            let x = unsafe { x_ptr.as_ref().unwrap() };
            let next_ptr = x.next(level);
            if next_ptr.is_null() {
                if level == 0 {
                    return x_ptr;
                } else {
                    // Switch to next list
                    level -= 1;
                }
            } else {
                x_ptr = next_ptr;
            }
        }
    }

    fn key_is_after_node(&self, key: &K, n: *mut Node<K>) -> bool {
        if n.is_null() {
            return false;
        }
        let node = unsafe { n.as_ref().unwrap() };
        self.comparator.compare(&node.key, key).is_lt()
    }

    fn get_max_height(&self) -> usize {
        self.max_height.load(Ordering::Relaxed)
    }

    pub fn new_iterator(&self) -> SkipListIterator<C, K> {
        SkipListIterator {
            list: &self,
            n_ptr: ptr::null_mut(),
        }
    }
}

impl<C: Comparator<K>, K: PartialEq + Clone> Drop for SkipList<C, K> {
    fn drop(&mut self) {
        let mut n_ptr = self.head.next(0);
        loop {
            if n_ptr.is_null() {
                break;
            }
            let next: Box<Node<K>> = unsafe { Box::from_raw(n_ptr) };
            n_ptr = next.next(0);
        }
    }
}

pub struct SkipListIterator<'a, C: Comparator<K>, K: PartialEq + Clone> {
    list: &'a SkipList<C, K>,
    n_ptr: *mut Node<K>,
}

pub trait Iterator<K: PartialEq> {
    fn next(&mut self);
    fn prev(&mut self);
    fn seek(&mut self, key: &K);
    fn valid(&self) -> bool;
    fn seek_to_first(&mut self);
    fn seek_to_last(&mut self);
    fn key(&self) -> &K;
}

impl<'a, C: Comparator<K>, K: PartialEq + Clone> Iterator<K> for SkipListIterator<'a, C, K> {
    // Advances to the next position.
    // REQUIRES: Valid()
    fn next(&mut self) {
        assert!(self.valid());
        let node = unsafe { self.n_ptr.as_ref().unwrap() };
        self.n_ptr = node.next(0);
    }

    // Advances to the previous position.
    // REQUIRES: Valid()
    fn prev(&mut self) {
        // Instead of using explicit "prev" links, we just search for the
        // last node that falls before key.
        assert!(self.valid());
        let node = unsafe { self.n_ptr.as_ref().unwrap() };
        let mut n_ptr = self.list.find_less_than(&node.key);
        if n_ptr == self.list.head_ptr {
            n_ptr = null_mut();
        }
        self.n_ptr = n_ptr;
    }

    // Attention: Advance to the first entry with a key >= target
    fn seek(&mut self, key: &K) {
        self.n_ptr = self.list.find_greater_or_equal(key, &mut vec![]);
    }

    // Position at the first entry in list.
    // Final state of iterator is Valid() iff list is not empty.
    fn seek_to_first(&mut self) {
        self.n_ptr = self.list.head.next(0);
    }

    // Position at the last entry in list.
    // Final state of iterator is Valid() iff list is not empty.
    fn seek_to_last(&mut self) {
        let mut n_ptr = self.list.find_last();
        if n_ptr == self.list.head_ptr {
            n_ptr = null_mut();
        }
        self.n_ptr = n_ptr;
    }

    // Returns the key at the current position.
    // REQUIRES: Valid()
    fn key(&self) -> &K {
        assert!(self.valid());
        let node = unsafe { self.n_ptr.as_ref().unwrap() };
        &node.key
    }

    // Returns true iff the iterator is positioned at a valid node.
    fn valid(&self) -> bool {
        !self.n_ptr.is_null()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Ordering,
        collections::BTreeSet,
        sync::{
            atomic::{self, AtomicBool, AtomicU64},
            Arc, Barrier,
        },
        thread,
    };

    use atomic::AtomicPtr;
    use rand::{rngs::ThreadRng, thread_rng, Rng};

    use crate::db::skiplist::Iterator;

    use super::{Comparator, SkipList, SkipListIterator};

    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;

    type Key = u64;

    #[derive(Clone)]
    struct U64Comparator {}
    impl Comparator<u64> for U64Comparator {
        fn compare(&self, a: &u64, b: &u64) -> std::cmp::Ordering {
            if a < b {
                return Ordering::Less;
            } else if a > b {
                return Ordering::Greater;
            } else {
                return Ordering::Equal;
            }
        }
    }

    #[test]
    fn test_empty() {
        let list = SkipList::new(U64Comparator {}, &0);
        assert!(!list.contains(&10u64));
    }

    #[test]
    fn test_insert_and_loopup() {
        const N: usize = 2000;
        const R: u64 = 5000;

        let mut rnd = thread_rng();

        let mut keys = BTreeSet::new();

        let mut list = SkipList::new(U64Comparator {}, &0);

        for _ in 0..N {
            let key = rnd.gen::<u64>() % R;
            if keys.insert(key) {
                list.insert(&key)
            }
        }

        for i in 0..R {
            if list.contains(&i) {
                assert!(keys.contains(&i));
            } else {
                assert!(!keys.contains(&i));
            }
        }

        // Simple iterator tests
        let mut it = list.new_iterator();
        assert!(!it.valid());

        it.seek(&0u64);
        assert!(it.valid());
        assert_eq!(keys.iter().min(), Some(it.key()));

        it.seek_to_first();
        assert!(it.valid());
        assert_eq!(keys.iter().next(), Some(it.key()));

        it.seek_to_last();
        assert!(it.valid());
        assert_eq!(keys.iter().last(), Some(it.key()));

        // Forward iteration test
        for i in 0..R {
            let mut it = list.new_iterator();
            it.seek(&i);
            let (_, sub): (Vec<u64>, Vec<u64>) = keys.iter().partition(|&&x| x < i);
            let mut keys_it = sub.iter();

            for _ in 0..3 {
                match keys_it.next() {
                    None => {
                        assert!(!it.valid());
                        break;
                    }
                    Some(x) => {
                        assert!(it.valid());
                        assert_eq!(x, it.key());
                        it.next();
                    }
                }
            }
        }

        // Backward iteration test
        let mut keys_it = keys.iter();
        let mut it = list.new_iterator();
        it.seek_to_last();
        for _ in 0..keys.len() {
            assert!(it.valid());
            assert_eq!(keys_it.nth_back(0), Some(it.key()));
            it.prev();
        }
    }

    // Comments from leveldb:
    //
    // We want to make sure that with a single writer and multiple
    // concurrent readers (with no synchronization other than when a
    // reader's iterator is created), the reader always observes all the
    // data that was present in the skip list when the iterator was
    // constructed.  Because insertions are happening concurrently, we may
    // also observe new values that were inserted since the iterator was
    // constructed, but we should never miss any values that were present
    // at iterator construction time.
    //
    // We generate multi-part keys:
    //     <key,gen,hash>
    // where:
    //     key is in range [0..K-1]
    //     gen is a generation number for key
    //     hash is hash(key,gen)
    //
    // The insertion code picks a random key, sets gen to be 1 + the last
    // generation number inserted for that key, and sets hash to Hash(key,gen).
    //
    // At the beginning of a read, we snapshot the last inserted
    // generation number for each key.  We then iterate, including random
    // calls to Next() and Seek().  For every key we encounter, we
    // check that it is either expected given the initial snapshot or has
    // been concurrently added since the iterator started.
    const K_: u64 = 4;

    struct State {
        generation: Vec<AtomicU64>,
    }

    impl State {
        fn new() -> Self {
            let mut v = Vec::with_capacity(K_ as usize);
            for _ in 0..K_ {
                v.push(AtomicU64::new(0));
            }
            State { generation: v }
        }

        fn get(&self, k: u64) -> u64 {
            self.generation[k as usize].load(atomic::Ordering::Acquire)
        }

        fn set(&mut self, k: u64, v: u64) {
            self.generation[k as usize].store(v, atomic::Ordering::Release);
        }
    }

    // REQUIRES: External synchronization
    fn write_step(current: &mut State, list: &mut SkipList<U64Comparator, Key>) {
        let mut rng = thread_rng();
        let k: u64 = rng.gen::<u64>() % K_;
        let g = current.get(k) + 1;
        let key = make_key(k, g);

        list.insert(&key);
        current.set(k, g);
    }

    fn read_step(current: &State, it: &mut SkipListIterator<U64Comparator, Key>) {
        // Remember the initial committed state of the skiplist.
        let mut initial_state = State::new();
        for k in 0..K_ {
            initial_state.set(k, current.get(k));
        }

        let mut rng = thread_rng();
        let mut pos = random_target(&mut rng);

        it.seek(&pos);

        loop {
            let current: Key;
            if !it.valid() {
                current = make_key(K_, 0);
            } else {
                current = it.key().clone();
                assert!(is_valid_key(current), "current {}", current);
            }
            assert!(pos <= current, "should not go backwards");

            // Verify that everything in [pos,current) was not present in initial_state.
            while pos < current {
                assert!(key(pos) < K_, "{}", pos);

                // Note that generation 0 is never inserted, so it is ok if
                // <*,0,*> is missing.
                assert!(
                    (gen(pos) == 0) || (gen(pos) > initial_state.get(key(pos))),
                    "key: {}; gen: {}; initgen: {}",
                    key(pos),
                    gen(pos),
                    initial_state.get(key(pos))
                );

                // Advance to next key in the valid key space
                if key(pos) < key(current) {
                    pos = make_key(key(pos) + 1, 0);
                } else {
                    pos = make_key(key(pos), gen(pos) + 1);
                }
            }

            if !it.valid() {
                break;
            }

            if rng.gen::<u64>() % 2 == 0 {
                let new_target = random_target(&mut rng);
                if new_target > pos {
                    pos = new_target;
                    it.seek(&new_target);
                }
            } else {
                it.next();
                pos = make_key(key(pos), gen(pos) + 1);
            }
        }
    }

    fn hash(key: Key) -> u64 {
        key & 0xff
    }
    fn key(key: Key) -> u64 {
        key >> 40
    }
    fn gen(key: Key) -> u64 {
        (key >> 8) & 0xffffffff
    }

    fn hash_numbers(k: u64, g: u64) -> u64 {
        let mut hasher = DefaultHasher::new();
        hasher.write_u64(k);
        hasher.write_u64(g);
        hasher.finish()
    }

    fn is_valid_key(k: Key) -> bool {
        hash(k) == (hash_numbers(key(k), gen(k)) & 0xff)
    }

    fn make_key(k: u64, g: u64) -> Key {
        assert!(k <= K_);
        assert!(g <= 0xffff_ffff);
        let hash = hash_numbers(k, g);
        k << 40 | g << 8 | (hash & 0xff)
    }

    fn random_target(rng: &mut ThreadRng) -> Key {
        match rng.gen::<u64>() % 10 {
            0 => {
                // Seek to beginning
                return make_key(0, 0);
            }
            1 => {
                // Seek to end
                return make_key(K_, 0);
            }
            _ => {
                // Seek to middle
                return make_key(rng.gen::<u64>() % K_, 0);
            }
        }
    }

    #[test]
    fn test_concurrent_without_threads() {
        let mut current = State::new();
        let mut list = SkipList::new(U64Comparator {}, &0);

        for _ in 0..10_000 {
            {
                let mut it = list.new_iterator();
                read_step(&current, &mut it);
            }
            {
                write_step(&mut current, &mut list);
            }
        }
    }

    #[test]
    fn test_concurrent() {
        const N: usize = 1000;
        const K_SIZE: usize = 1000;

        for i in 0..N {
            if (i % 100) == 0 {
                println!("Run {} of {}", i, N);
            }

            let mut list: SkipList<U64Comparator, Key> = SkipList::new(U64Comparator {}, &0);
            let list_arc = Arc::new(AtomicPtr::new(&mut list));
            let mut current = State::new();
            let current_arc = Arc::new(AtomicPtr::new(&mut current));

            let ready = Arc::new(Barrier::new(2));
            let quit_flag = Arc::new(AtomicBool::new(false));

            let mut handles = Vec::with_capacity(K_SIZE);

            {
                let t_quit_flag = quit_flag.clone();
                let t_ready = Arc::clone(&ready);
                let t_list = list_arc.clone();
                let t_current = current_arc.clone();

                let handle = thread::spawn(move || {
                    let current_ptr = t_current.load(atomic::Ordering::Acquire);
                    let list_ptr = t_list.load(atomic::Ordering::Acquire);

                    // println!("read ready wait");
                    t_ready.wait();

                    let it = unsafe { &mut (*list_ptr).new_iterator() };
                    let current = unsafe { &mut *current_ptr };

                    //println!("going to read");
                    while !t_quit_flag.load(atomic::Ordering::Acquire) {
                        read_step(current, it)
                    }
                    //println!("read end")
                });
                handles.push(handle);
            }

            {
                let t_ready = Arc::clone(&ready);
                let t_quit_flag = quit_flag.clone();
                let t_list = list_arc.clone();
                let t_current = current_arc.clone();
                let handler = thread::spawn(move || {
                    // println!("write ready wait");
                    t_ready.wait();

                    let list_ptr = t_list.load(atomic::Ordering::Acquire);
                    let current_ptr = t_current.load(atomic::Ordering::Acquire);

                    for _ in 0..K_SIZE {
                        unsafe { write_step(&mut *current_ptr, &mut *list_ptr) };
                    }
                    // println!("write end");

                    // println!("write set quit flag");
                    t_quit_flag.store(true, atomic::Ordering::Release);
                });
                handles.push(handler);
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }
    }
}
