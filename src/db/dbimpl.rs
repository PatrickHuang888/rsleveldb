use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{atomic, Arc, Condvar, Mutex, MutexGuard};

use std::collections::{self};
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

fn sanitize_options<C: Comparator>(
    dbname: &str,
    internal_comparator: &C,
    src: &Options<C>,
) -> Options<C> {
    let mut result = src.clone();
    result.comparator = internal_comparator.clone();
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

struct DBImpl<'a, C: Comparator + Send + Sync> {
    internal_comparator: InternalKeyComparator<C>,
    options: Options<C>,
    dbname: String,
    env: Env,

    // State below is protected by mutex_
    mutex: parking_lot::RawMutex,

    writers: collections::VecDeque<Writer>,
    log: log::Writer<PosixWritableFile>,
    //log_file: Arc<RefCell<W>>,
    // table_cache_ provides its own synchronization
    table_cache: TableCache,

    vset: VersionSet<'a, C>,

    mem: MemTable<C>,
    imem: Option<MemTable<C>>,

    shutting_down: atomic::AtomicBool,
    logfile_number: u64,
    // Set of table files to protect from deletion because they are
    // part of ongoing compactions.
    pending_outputs: Vec<u64>,
    stats: [CompactionStats; config::NUM_LEVELS as usize],
    mannual_compaction: Option<ManualCompaction>,
    // Has a background compaction been scheduled or is running?
    background_compaction_scheduled: bool,
    background_work_finished_signal: parking_lot::Condvar,
    // Have we encountered a background error in paranoid mode?
    bg_error: Option<api::Error>,
}

impl<'a, C: api::Comparator + Send + Sync> DBImpl<'a, C> {
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

        if self.imem.is_some() {
            self.compact_memtable();
            return;
        }

        let is_manual:bool;
        let oc: Option<Compaction<C>>;
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
        }

        match &mut oc {
            None => {
                // Nothing to do
            },
            Some(c) => {
                if !is_manual && c.is_trivial_move(&self.options) {
                    // Move file to next level
                    assert!(c.num_input_files(0)==1);
                    let f= c.input(0, 0).as_ref();
                    let edit= c.edit_mut();
                    edit.remove_file(c.level(), f.number);
                    edit.add_file(c.level(), f.number, f.file_size, &f.smallest, &f.largest);
                    let status= self.vset.log_and_apply(&self.mutex, edit);
                }else {
                    let compact= CompactState::new(oc.unwrap());
                    let status= self.do_compaction_work(&compact);
                    if !status.is_ok() {
                        self.record_background_error(status);
                    }
                    self.cleanup_compaction(&compact);
                    self.remove_obsolete_files();
                }
            }
        }


    }

    fn compact_memtable(&mut self) {
        assert!(self.mutex.is_locked());
        assert!(self.imem.is_some());

        // Save the contents of the memtable as a new Table
        let mut edit = VersionEdit::default();
        let base = self.vset.current();
        let mut r = self.write_level0_table(true, &mut edit, Some(base));

        if r.is_ok() && self.shutting_down.load(atomic::Ordering::Acquire) {
            r = Err(api::Error::IOError(
                "Deleting DB during memtable compaction".to_string(),
            ));
        }

        // Replace immutable memtable with the generated Table
        if r.is_ok() {
            edit.set_prev_log_number(0);
            edit.set_log_number(self.logfile_number); // Earlier logs no longer needed
            r = self.vset.log_and_apply(&self.mutex, &mut edit);
        }

        match r {
            Ok(_) => {
                // Commit to the new state
                self.imem = None;
                self.remove_obsolete_files();
            }
            Err(e) => {
                self.record_background_error(e);
            }
        }
    }

    fn write_level0_table(
        &mut self,
        write_imem: bool,
        //mem: &mut MemTable<C>,
        edit: &mut VersionEdit,
        o_base: Option<Rc<Version<C>>>,
    ) -> api::Result<()> {
        assert!(self.mutex.is_locked());

        let mut mem = &mut self.mem;
        if write_imem {
            mem = self.imem.as_mut().unwrap();
        }

        let start_micros = util::now_micros();
        let mut meta = FileMetaData::default();
        meta.number = self.vset.new_file_number();
        self.pending_outputs.push(meta.number);
        let mut it = mem.new_iter();

        // todo: log

        unsafe { self.mutex.unlock() };

        build_table(
            &self.env,
            self.dbname.as_str(),
            &self.options,
            &mut it,
            &mut meta,
        )?;

        self.mutex.lock();

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
            if let Some(base) = o_base {
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
        stats.micros = util::now_micros() - start_micros;
        stats.bytes_written = meta.file_size;
        self.stats[level as usize].add(&stats);
        Ok(())
    }

    fn record_background_error(&mut self, e: api::Error) {
        todo!()
    }

    // REQUIRES: mutex_ is held
    // REQUIRES: this thread is currently at the front of the writer queue
    fn make_room_for_write(&mut self, guard: &MutexGuard<u8>, force: bool) -> api::Result<()> {
        /* guard;
          assert!(!self.writers.is_empty());
          let allow_delay= !force;

          loop {
              if allow_delay && self.versions.num_level_files(0) >= config::L0_SlowdownWritesTrigger {
                  // We are getting close to hitting a hard limit on the number of
        // L0 files.  Rather than delaying a single write by several
        // seconds when we hit the hard limit, start delaying each
        // individual write by 1ms to reduce latency variance.  Also,
        // this delay hands over some CPU to the compaction thread in
        // case it is sharing the same core as the writer.

              }
          }
          */
        // todo:
        Ok(())
    }

    fn remove_obsolete_files(&mut self) {}
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

impl<C: Comparator + Send + Sync> DB<C> for DBImpl<C> {
    fn open(options: &Options<C>, dbname: &str) -> api::Result<Self> {
        todo!()
    }

    fn get(&mut self, options: &ReadOptions, key: &[u8], value: &mut Vec<u8>) -> api::Result<()> {
        let _lock = MutexLock::new(&self.mutex);

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
        drop(_lock);

        // First look in the memtable, then in the immutable memtable (if any).
        let lkey = LookupKey::new(key, snaphsot);

        if let Some(e) = self.mem.get(&lkey, value).err() {
            match e {
                Error::InternalNotFound(deleted) => {
                    if deleted {
                        return Err(api::Error::NotFound);
                    } else {
                        // todo: imm get

                        let current = self.vset.current();
                        let stats = current.get(options, &lkey, value)?;

                        self.mutex.lock();

                        // todo:
                        //if self.vset.current_mut().unwrap().update_stats(stats) {
                        todo!();
                        //self.maybe_schedmule_compaction();
                        //}
                        //return Ok(());
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
        todo!()
    }

    fn put(&mut self, options: &WriteOptions, key: &[u8], value: &[u8]) -> api::Result<()> {
        let mut batch = WriteBatch::new();
        batch.put(key, value);
        self.write(options, batch)
    }

    fn write(&mut self, options: &WriteOptions, updates: WriteBatch) -> api::Result<()> {
        /* let mut lock = self.guard.lock().unwrap();

        self.writers
            .push_back(Writer::new(Some(updates), options.sync));
        let w = self.writers.back().unwrap();

        //todo:
        /* while !w.done && w != self.writers.front().unwrap() {
            _guard = w.cv.wait(_guard).unwrap();
        } */
        if w.done {
            return w.status.clone();
        }

        // May temporarily unlock and wait.
        // at front and !done
        let current = self.writers.pop_front().unwrap();

        let mut status;
        //let status = self.make_room_for_write(&guard, w.batch.is_none());
        let mut last_sequence = lock.vset.last_sequence();

        // none updates for compactions
        match &current.batch {
            None => {}
            Some(_) => {
                let (mut write_batch, writtens) =
                    build_batch_group(lock, &mut self.writers, current);
                write_batch.set_sequence(last_sequence + 1);
                last_sequence += write_batch.count() as u64;


                    drop(lock);
                    // Add to log and apply to memtable.  We can release the lock
                    // during this phase since &w is currently responsible for logging
                    // and protects against concurrent loggers and concurrent writes
                    // into mem_.
                    status = self.log.add_record(write_batch.contents());
                    if options.sync {
                        //todo:
                        //self.log_file.sync()?;
                    }
                    //status = write_batch.insert_into(&mut self.mem);
                    let lock_1= self.guard.lock().unwrap();

                    // todo: sync error


                // ?tmp_batch.clear()

                lock_1.vset.set_last_sequence(last_sequence);

                for mut w in writtens {
                    w.status = status.clone();
                    w.done = true;
                    w.cv.notify_one();
                }
            }
        }

        // Notify new head of write queue
        if let Some(front) = self.writers.front() {
            front.cv.notify_one();
        }; */

        Ok(())
    }
}

// REQUIRES: Writer list must be non-empty
// REQUIRES: First writer must have a non-null batch
fn build_batch_group(
    writers_queue: &mut collections::VecDeque<Writer>,
    first: Writer,
) -> (WriteBatch, Vec<Writer>) {
    //assert!(!first.batch.is_none());
    let first_batch = first.batch.as_ref().unwrap();
    let mut size = first_batch.byte_size();

    let mut batch = WriteBatch::new();
    batch.append(first_batch);
    let mut writers = Vec::new();
    let first_sync = first.sync;
    writers.push(first);

    // Allow the group to grow up to a maximum size, but if the
    // original write is small, limit the growth so we do not slow
    // down the small write too much.
    let mut max_size = 1 << 20;
    if size <= ((128 as usize) << 10) {
        max_size = size + (128 << 10);
    }

    loop {
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
    }

    (batch, writers)
}

pub struct Writer {
    batch: Option<WriteBatch>,
    sync: bool,
    done: bool,
    cv: Condvar,
    status: api::Result<()>,
}

impl Writer {
    fn new(batch: Option<WriteBatch>, sync: bool) -> Self {
        Writer {
            batch,
            sync,
            done: false,
            cv: Condvar::new(),
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
