use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::{atomic, Arc, Condvar, Mutex, MutexGuard};

use std::collections::{self, VecDeque};
use std::thread;

use parking_lot::lock_api::RawMutex;

use crate::api::{self, Comparator, Error, ReadOptions, WriteOptions};
use crate::config::NUM_LEVELS;
use crate::db::version::VersionEdit;
use crate::{
    config, util, Env, InternalKey, Options, PosixWritableFile, SequenceNumber, WritableFile,
    WriteBatch, DB, NUM_NON_TABLE_CACHE_FILES,
};

use super::build_table;
use super::log::{self, Writer as LWriter};
use super::memtable::{InternalKeyComparator, LookupKey, MemTable};
use super::table_cache::TableCache;
use super::version::{Compaction, FileMetaData, GetStats, Version, VersionSet};

fn clip_to_range<V: Ord>(mut v: V, minvalue: V, maxvalue: V) {
    if v > maxvalue {
        v = maxvalue;
    }
    if v < minvalue {
        v = minvalue;
    }
}

fn sanitize_options<C: Comparator + 'static>(
    dbname: &str,
    internal_comparator: &InternalKeyComparator<C>,
    src: &Options<C>,
) -> Options<C> {
    let mut result = src.clone();
    // todo: should be internal comparator?
    //result.comparator = internal_comparator;
    clip_to_range(
        result.max_open_files,
        64 + NUM_NON_TABLE_CACHE_FILES,
        50_000,
    );
    clip_to_range(result.write_buffer_size, 64 << 10, 1 << 30);
    clip_to_range(result.max_file_size, 1 << 20, 1 << 30);
    clip_to_range(result.block_size, 1 << 10, 4 << 20);
    /* match result.info_log {
        None => {
            todo!()
        }
        _ => {}
    } */
    match result.block_cache {
        None => {
            todo!()
        }
        _ => {}
    }
    result
}

struct MutexLock<'a> {
    mu: &'a parking_lot::RawMutex,
}

impl<'a> MutexLock<'a> {
    fn new(mu: &'a parking_lot::RawMutex) -> Self {
        let ml = MutexLock { mu };
        ml.mu.lock();
        ml
    }
}

impl<'a> Drop for MutexLock<'a> {
    fn drop(&mut self) {
        unsafe { self.mu.unlock() };
    }
}

struct ManualCompaction {
    level: u32,
    begin: InternalKey,
    end: InternalKey,
    done: bool,
}

fn table_cache_size<C: Comparator>(sanitized_options: &Options<C>) -> usize {
    // Reserve ten files or so for other uses and give the rest to TableCache.
    sanitized_options.max_open_files - NUM_NON_TABLE_CACHE_FILES
}

const MEM_TABLE_INDEX: usize = 0;
const IMEM_TABLE_INDEX: usize = 1;

struct DBImpl<C: Comparator + Send + Sync + 'static> {
    internal_comparator: InternalKeyComparator<C>,
    options: Options<C>,
    dbname: String,

    // table_cache_ provides its own synchronization
    //table_cache: Arc<TableCache<C>>,

    // State below is protected by mutex_
    mutex: parking_lot::Mutex<()>,

    writers: VecDeque<Writer>,
    //log: log::Writer<PosixWritableFile>,
    //log_file: Arc<RefCell<W>>,
    vset: VersionSet<C>,

    mem_tables: VecDeque<MemTable<C>>,
    mem_indicator: usize,

    shutting_down: atomic::AtomicBool,
    //logfile_number: u64,
    // Set of table files to protect from deletion because they are
    // part of ongoing compactions.
    pending_outputs: Vec<u64>,
    stats: [CompactionStats; config::NUM_LEVELS as usize],
    //mannual_compaction: Option<ManualCompaction>,
    // Has a background compaction been scheduled or is running?
    //background_compaction_scheduled: bool,
    //background_work_finished_signal: parking_lot::Condvar,
    // Have we encountered a background error in paranoid mode?
    //bg_error: Option<api::Error>,
}

impl<C: api::Comparator + Send + Sync> DBImpl<C> {
    fn new(options: &Options<C>, home_path: &Path, dbname: &str) -> Self {
        let dbname = dbname.to_string();
        //let tcache = Arc::new(TableCache::new(dbname.clone(), options));
        //todo: options sanitize
        DBImpl {
            dbname: dbname.clone(),
            internal_comparator: InternalKeyComparator::new(options.comparator),
            options: options.clone(),
            mutex: parking_lot::Mutex::new(()),
            writers: VecDeque::new(),
            mem_tables: VecDeque::from([MemTable::new(InternalKeyComparator::new(
                options.comparator,
            ))]),

            mem_indicator: 0,
            shutting_down: atomic::AtomicBool::new(true),
            //table_cache: todo!(),
            vset: VersionSet::new(dbname, options),
            pending_outputs: todo!(),
            stats: todo!(),
        }
    }

    /* fn background_call(&mut self) {
        let _lock = MutexLock::new(&self.mutex);

        assert_eq!(self.background_compaction_scheduled, true);

        if self.shutting_down.load(atomic::Ordering::Acquire) {
            // No more background work when shutting down.
        } else if !self.bg_error.is_none() {
            // No more background work after a background error.
        } else {
            self.background_compaction();
        }

        self.background_compaction_scheduled = false;

        // Previous compaction may have produced too many files in a level,
        // so reschedule another compaction if needed.
        self.maybe_schedmule_compaction();
        self.background_work_finished_signal.notify_all();
    }

    fn maybe_schedmule_compaction(&mut self) {
        assert!(self.mutex.is_locked());

        if self.background_compaction_scheduled {
            // Already scheduled
        } else if self.shutting_down.load(atomic::Ordering::Acquire) {
            // DB is being deleted; no more background compactions
        } else if !self.bg_error.is_none() {
            // DB is being deleted; no more background compactions
        } else if self.imem.is_none()
            && self.mannual_compaction.is_none()
            && !self.vset.needs_compaction()
        {
            // No work to be done
        } else {
            self.background_compaction_scheduled = true;
            thread::spawn(move|| {
                self.background_call();
            });
        }
    }*/

    fn background_compaction(&mut self) {
        assert!(self.mutex.is_locked());

        /* if self.imem.is_some() {
            self.compact_memtable();
            return;
        }

        let is_manual = false;
        let mut oc: Option<Compaction<C>> = None;
        if let Some(manual) = &mut self.mannual_compaction {
            todo!()
            /* oc = self
                .vset
                .compact_range(manual.level, &manual.begin, &manual.end);
            match oc {
                None => {
                    manual.done = true;
                }
                Some(c) => {
                    let manual_end = &c.input(0, c.num_input_files(0) - 1).largest;
                    // todo: log
                }
            } */
        } else {
            oc = self.vset.pick_compaction();
        } */

        /* match &mut oc {
            None => {
                // Nothing to do
            }
            Some(c) => {
                todo!()
                /* if !is_manual && c.is_trivial_move(&self.options) {
                    // Move file to next level
                    assert!(c.num_input_files(0)==1);
                    let f= c.input(0, 0).as_ref();
                    let edit= c.edit_mut();
                    edit.remove_file(c.level(), f.number);
                    edit.add_file(c.level(), f.number, f.file_size, &f.smallest, &f.largest);
                    let status= self.vset.log_and_apply(&self.mutex, edit);
                }else {
                    /* let compact= CompactState::new(oc.unwrap());
                    let status= self.do_compaction_work(&compact);
                    if !status.is_ok() {
                        self.record_background_error(status);
                    }
                    self.cleanup_compaction(&compact); */
                    todo!();
                    self.remove_obsolete_files();
                } */
            }
        }*/
    }

    fn compact_memtable(&mut self) {
        assert!(self.mutex.is_locked());
        assert!(self.mem_tables.len()==2);

        // Save the contents of the memtable as a new Table
        let mut edit = VersionEdit::default();
        let base = self.vset.current().clone();
        let mut r = self.write_level0_table( &mut edit, Some(base));

        if r.is_ok() && self.shutting_down.load(atomic::Ordering::Acquire) {
            r = Err(api::Error::IOError(
                "Deleting DB during memtable compaction".to_string(),
            ));
        }

        // Replace immutable memtable with the generated Table
        if r.is_ok() {
            edit.prev_log_number= Some(0);
            //edit.set_log_number(self.logfile_number); // Earlier logs no longer needed
            r = self.vset.log_and_apply(&self.mutex, &mut edit);
        }

        match r {
            Ok(_) => {
                // Commit to the new state
                self.mem_tables.remove(IMEM_TABLE_INDEX);
                self.remove_obsolete_files();
            }
            Err(e) => {
                self.record_background_error(e);
            }
        }
    }

    fn write_level0_table(
        &mut self,
        edit: &mut VersionEdit,
        base: Option<Arc<Version<C>>>,
    ) -> api::Result<()> {
        assert!(self.mutex.is_locked());

        let mem = &mut self.mem_tables[MEM_TABLE_INDEX];
        let mut it = mem.new_iterator();

        let start_micros = self.options.env.now_micros();
        let mut meta = FileMetaData::default();
        meta.number = self.vset.new_file_number();
        self.pending_outputs.push(meta.number);

        // todo: log

        unsafe { self.mutex.force_unlock() };

        build_table(
            &self.dbname,
            &self.options,
            &mut it,
            &mut meta,
            //&mut self.table_cache,
        )?;

        let _ = self.mutex.lock();

        // todo: log

        let pos = self
            .pending_outputs
            .iter()
            .position(|x| *x == meta.number)
            .unwrap();
        self.pending_outputs.remove(pos);

        // Note that if file_size is zero, the file has been deleted and
        // should not be added to the manifest.
        let mut level = 0;
        if meta.file_size > 0 {
            let min_user_key = meta.smallest.user_key();
            let max_user_key = meta.largest.user_key();
            if let Some(base) = base {
                level = base.pick_level_for_memtable_output(min_user_key, max_user_key);
            }
            edit.add_file(
                level,
                meta.number,
                meta.file_size,
                &meta.smallest,
                &meta.largest,
            );
        }

        let mut stats = CompactionStats::default();
        stats.micros = self.options.env.now_micros() - start_micros;
        stats.bytes_written = meta.file_size;
        self.stats[level as usize].add(&stats);
        Ok(())
    }

    fn record_background_error(&mut self, e: api::Error) {
        todo!()
    }

    fn remove_obsolete_files(&mut self) {}
}

impl<C: Comparator + Send + Sync> DB<C> for DBImpl<C> {
    fn get(&mut self, options: &ReadOptions, key: &[u8], value: &mut Vec<u8>) -> api::Result<()> {
        let guard = self.mutex.lock();

        let snaphsot: SequenceNumber;
        match &options.snapshot {
            None => {
                snaphsot = self.vset.last_sequence();
            }
            Some(ss) => {
                snaphsot = ss.sequence_number();
            }
        }

        // Unlock while reading from files and memtables
        drop(guard);

        // First look in the memtable, then in the immutable memtable (if any).
        let lkey = LookupKey::new(key, snaphsot);

        if let Some(e) = self.mem_tables[0].get(&lkey, value).err() {
            match e {
                Error::InternalNotFound(deleted) => {
                    if deleted {
                        return Err(api::Error::NotFound);
                    } else {
                        if let Some(e) = self.mem_tables[1].get(&lkey, value).err() {
                            match e {
                                Error::InternalNotFound(deleted) => {
                                    if deleted {
                                        return Err(api::Error::NotFound);
                                    } else {
                                        // todo:
                                        /* let current = self.vset.current();
                                        let stats = current.get(options, &lkey, value)?; */
                                    }
                                }
                                _ => {
                                    return Err(e);
                                }
                            }
                        }

                        let _ = self.mutex.lock();

                        // todo:
                        //if self.vset.current_mut().unwrap().update_stats(stats) {
                        //self.maybe_schedmule_compaction();
                        //}
                        return Ok(());
                    }
                }
                _ => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn delete(&mut self, options: &WriteOptions, key: &[u8]) -> api::Result<()> {
        let mut batch = WriteBatch::new();
        batch.delete(key);
        self.write(options, Some(batch))
    }

    fn put(&mut self, options: &WriteOptions, key: &[u8], value: &[u8]) -> api::Result<()> {
        let mut batch = WriteBatch::new();
        batch.put(key, value);
        self.write(options, Some(batch))
    }

    fn write(&mut self, options: &WriteOptions, updates: Option<WriteBatch>) -> api::Result<()> {
        let w = Writer::new(updates, options.sync);

        let mut guard = self.mutex.lock();

        self.writers.push_back(w);

        let w = self.writers.back().unwrap();
        loop {
            match self.writers.front() {
                None => {
                    // ??
                    unreachable!();
                }
                Some(front) => {
                    if !w.done && w != front {
                        w.cv.wait(&mut guard);
                    } else {
                        break;
                    }
                }
            }
        }
        if w.done {
            return w.status.clone();
        }

        // May temporarily unlock and wait.
        let mut status =
            make_room_for_write(&mut self.mem_tables, &self.options, w.batch.is_none());
        let mut last_sequence = self.vset.last_sequence();

        // none updates is for compactions
        if status.is_ok() {
            let mut write_batch = build_batch_group(&mut self.writers);
            write_batch.set_sequence(last_sequence + 1);
            last_sequence += write_batch.count() as u64;

            drop(guard);

            // Add to log and apply to memtable.  We can release the lock
            // during this phase since &w is currently responsible for logging
            // and protects against concurrent loggers and concurrent writes
            // into mem_.
            //status = self.log.add_record(write_batch.contents());
            //if options.sync {
            //todo:
            //self.log_file.sync()?;
            //}
            status = write_batch.insert_into(&mut self.mem_tables[0]);

            let _ = self.mutex.lock();

            // todo: sync error

            // ?tmp_batch.clear()

            self.vset.set_last_sequence(last_sequence);
        }

        loop {
            if let Some(mut front) = self.writers.front_mut() {
                if front.handled {
                    front.status = status.clone();
                    front.done = true;
                    front.cv.notify_one();
                    let _ = self.writers.pop_front();
                } else {
                    break;
                }
            } else {
                break; // no write
            }
        }

        // Notify new head of write queue
        if let Some(front) = self.writers.front() {
            front.cv.notify_one();
        };

        status
    }
}

pub fn open<C: api::Comparator + Send + Sync + 'static>(
    options: &Options<C>,
    home_path: &Path,
    dbname: &str,
) -> api::Result<impl DB<C>> {
    let db = DBImpl::new(options, home_path, dbname);
    let _ = db.mutex.lock();
    //todo: recover

    unsafe { db.mutex.raw().unlock() };
    Ok(db)
}

// REQUIRES: mutex_ is held
// REQUIRES: this thread is currently at the front of the writer queue
fn make_room_for_write<C: api::Comparator>(
    mem_tables: &mut VecDeque<MemTable<C>>,
    options: &Options<C>,
    force: bool,
) -> api::Result<()> {
    loop {
        if !force && mem_tables[0].approximate_memory_usage() <= options.write_buffer_size {
            // There is room in current memtable
            break;
        } else {
            // Attempt to switch to a new memtable and trigger compaction of old
            mem_tables.push_front(MemTable::new(InternalKeyComparator::new(
                options.comparator,
            )));
            // todo: maybe schdule compation
            if mem_tables.len() > 2 {
                mem_tables.pop_back();
            }
        }
    }
    Ok(())
}

// REQUIRES: Writer list must be non-empty
// REQUIRES: First writer must have a non-null batch
fn build_batch_group(writers: &mut std::collections::VecDeque<Writer>) -> WriteBatch {
    assert!(!writers.is_empty());
    let front = writers.front_mut().unwrap();
    assert!(front.batch.is_some());
    front.handled = true;
    let result = front.batch.as_ref().unwrap().clone();
    let mut size = result.byte_size();

    // Allow the group to grow up to a maximum size, but if the
    // original write is small, limit the growth so we do not slow
    // down the small write too much.
    let mut max_size = 1 << 20;
    if size <= ((128 as usize) << 10) {
        max_size = size + (128 << 10);
    }

    /* loop {
        match writers_queue.front() {
            None => break,
            Some(n) => {
                let w = n;
                // Do not include a sync write into a batch handled by a non-sync write.
                if w.sync && !&first_sync {
                    break;
                }

                match &w.batch {
                    None => (),
                    Some(b) => {
                        size += b.byte_size();
                        if size > max_size {
                            // Do not make batch too big
                            break;
                        }

                        // Append to *result
                        // todo:
                        /* if (result == first->batch) {
                          // Switch to temporary batch instead of disturbing caller's batch
                          result = tmp_batch_;
                          assert(WriteBatchInternal::Count(result) == 0);
                          WriteBatchInternal::Append(result, first->batch);
                        } */
                        batch.append(b);
                    }
                }
                writers.push(writers_queue.pop_front().unwrap());
            }
        }
    } */

    result
}

pub struct Writer {
    batch: Option<WriteBatch>,
    sync: bool,
    done: bool,
    cv: parking_lot::Condvar,
    handled: bool,
    status: api::Result<()>,
}

impl Writer {
    fn new(batch: Option<WriteBatch>, sync: bool) -> Self {
        Writer {
            batch,
            sync,
            done: false,
            handled: false,
            cv: parking_lot::Condvar::new(),
            status: Ok(()),
        }
    }
}

impl PartialEq for Writer {
    fn eq(&self, other: &Self) -> bool {
        // think more:
        self.batch == other.batch
    }
}

// Per level compaction stats.  stats_[level] stores the stats for
// compactions that produced data for the specified "level".
#[derive(Default)]
struct CompactionStats {
    micros: u64,
    bytes_read: u64,
    bytes_written: u64,
}

impl CompactionStats {
    fn add(&mut self, c: &CompactionStats) {
        self.micros += c.micros;
        self.bytes_read += c.bytes_read;
        self.bytes_written += c.bytes_written;
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use crate::{
        api::{self, ByteswiseComparator, ReadOptions, WriteOptions},
        destroy_db, Options, DB,
    };

    use super::open;

    const TEST_DBNAME: &'static str = "db_test";

    struct DBTest {
        db: Box<dyn DB<ByteswiseComparator>>,
        dbname: &'static str,
    }

    impl DBTest {
        fn new(options: &Options<ByteswiseComparator>) -> Self {
            let tmp_dir = env::temp_dir();
            let _ = destroy_db(TEST_DBNAME, &tmp_dir, &options);
            let db = open(&options, &tmp_dir, TEST_DBNAME);
            assert!(db.is_ok());
            DBTest {
                db: Box::new(db.unwrap()),
                dbname: TEST_DBNAME,
            }
        }

        fn get(&mut self, k: &str) -> String {
            let options = ReadOptions::default();
            let mut v = vec![];
            match self.db.get(&options, k.as_bytes(), &mut v) {
                Ok(()) => {}
                Err(e) => {
                    if e == api::Error::NotFound {
                        return "NOT_FOUND".to_string();
                    } else {
                        return e.to_string();
                    }
                }
            }
            std::str::from_utf8(&v).unwrap().to_string()
        }

        fn put(&mut self, k: &str, v: &str) -> api::Result<()> {
            self.db
                .put(&WriteOptions::default(), k.as_bytes(), v.as_bytes())
        }

        fn delete(&mut self, k: &str) -> api::Result<()> {
            self.db.delete(&WriteOptions::default(), k.as_bytes())
        }
    }

    #[test]
    fn test_empty() {
        let options = Options::default();
        let mut test = DBTest::new(&options);
        let v = test.get("foo");
        assert_eq!(&v, "NOT_FOUND");
    }

    #[test]
    fn test_empty_key() {
        let options = Options::default();
        let mut test = DBTest::new(&options);
        let r = test.put("", "v1");
        assert!(r.is_ok(), "result {:?}", r.err().unwrap());
        assert_eq!("v1", test.get(""));
        let _ = test.put("", "v2");
        assert_eq!("v2", test.get(""));
    }

    #[test]
    fn test_empty_value() -> api::Result<()> {
        let options = Options::default();
        let mut test = DBTest::new(&options);
        test.put("key", "v1")?;
        assert_eq!("v1", test.get("key"));
        test.put("key", "")?;
        assert_eq!("", test.get("key"));
        test.put("key", "v2")?;
        assert_eq!("v2", test.get("key"));
        Ok(())
    }

    #[test]
    fn test_read_write() -> api::Result<()> {
        let options = Options::default();
        let mut test = DBTest::new(&options);
        test.put("foo", "v1")?;
        assert_eq!("v1", test.get("foo"));
        test.put("bar", "v2")?;
        assert_eq!("v2", test.get("bar"));
        test.put("foo", "v3")?;
        assert_eq!("v2", test.get("bar"));
        assert_eq!("v3", test.get("foo"));
        Ok(())
    }

    #[test]
    fn test_put_delete_get() -> api::Result<()> {
        let options = Options::default();
        let mut test = DBTest::new(&options);
        test.put("foo", "v1")?;
        assert_eq!("v1", test.get("foo"));
        test.put("foo", "v2")?;
        assert_eq!("v2", test.get("foo"));
        test.delete("foo")?;
        assert_eq!("NOT_FOUND", test.get("foo"));
        Ok(())
    }

    #[test]
    fn test_from_immutable_layer() -> api::Result<()> {
        let mut options = Options::default();
        options.write_buffer_size = 100_000;
        let mut test = DBTest::new(&options);
        test.put("foo", "v1")?;
        assert_eq!("v1", test.get("foo"));

        let mut k1 = String::new();
        for _ in 0..100_000 {
            k1.push('x');
        }
        let mut k2 = String::new();
        for _ in 0..100_000 {
            k2.push('y');
        }
        test.put("k1", &k1)?;
        test.put("k2", &k2)?;

        assert_eq!("v1", test.get("foo"));

        Ok(())
    }
}
