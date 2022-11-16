use std::sync::{Condvar, Mutex, MutexGuard};

use std::collections::{self};

use crate::api::{self, Error, ReadOptions, WriteOptions};
use crate::WritableFile;

use super::log::{self, Writer as LWriter};
use super::memtable::{LookupKey, MemTable};
use super::version_set::VersionSet;
use super::write_batch::WriteBatch;
use super::SequenceNumber;

pub trait DB {
    // Set the database entry for "key" to "value".  Returns OK on success,
    // and a non-OK status on error.
    // Note: consider setting options.sync = true.
    fn put(&mut self, options: &WriteOptions, key: &[u8], value: &[u8]) -> api::Result<()>;

    fn get(&mut self, options: &ReadOptions, key: &[u8]) -> api::Result<Vec<u8>>;
}

struct DBImpl<W: WritableFile> {
    /* internal: Mutex<GuardedDBInternal>,
    cv: Condvar, */
    lock: Mutex<bool>,
    writers: collections::VecDeque<Writer>,
    versions: VersionSet,
    mem: MemTable,
    imem: Option<MemTable>,
    log: log::LogWriter<W>,
    //log_file: W,
}

impl<W: WritableFile> DBImpl<W> {
    fn new() -> Self {
        DBImpl {
            mem: todo!(),
            log: todo!(),
            //log_file: todo!(),
            writers: todo!(),
            versions: todo!(),
            lock: todo!(),
            imem: todo!(),
        }
    }

    fn write(&mut self, options: &WriteOptions, updates: Option<WriteBatch>) -> api::Result<()> {
        let mut _guard = self.lock.lock().unwrap();

        self.writers.push_back(Writer::new(updates, options.sync));
        let w = self.writers.back().unwrap();

        while !w.done && w != self.writers.front().unwrap() {
            _guard = w.cv.wait(_guard).unwrap();
        }
        if w.done {
            return w.status.clone();
        }

        // May temporarily unlock and wait.
        // at front and !done
        let current = self.writers.pop_front().unwrap();

        let mut status;
        //let status = self.make_room_for_write(&guard, w.batch.is_none());
        let mut last_sequence = self.versions.last_sequence();

        // none updates for compactions
        match &current.batch {
            None => {}
            Some(_) => {
                let (mut write_batch, writtens) =
                    build_batch_group(&mut _guard, &mut self.writers, current);
                write_batch.set_sequence(last_sequence + 1);
                last_sequence += write_batch.count() as u64;

                {
                    drop(_guard);
                    // Add to log and apply to memtable.  We can release the lock
                    // during this phase since &w is currently responsible for logging
                    // and protects against concurrent loggers and concurrent writes
                    // into mem_.
                    status = self.log.add_record(write_batch.contents());
                    if options.sync {
                        //todo:
                        //self.log_file.sync()?;
                    }
                    status = write_batch.insert_into(&mut self.mem);
                    _guard = self.lock.lock().unwrap();

                    // todo: sync error
                }

                // ?tmp_batch.clear()

                self.versions.set_last_sequence(last_sequence);

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
        };

        Ok(())
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
}

impl<W: WritableFile> DB for DBImpl<W> {
    fn put(&mut self, opt: &WriteOptions, key: &[u8], value: &[u8]) -> api::Result<()> {
        let mut batch = WriteBatch::new();
        batch.put(key, value);
        self.write(opt, Some(batch))
    }

    fn get(&mut self, options: &ReadOptions, key: &[u8]) -> api::Result<Vec<u8>> {
        let _guard = self.lock.lock().unwrap();

        let snaphsot = self.versions.last_sequence();
        /* match &options.snapshot {
            None => {
                snaphsot= self.versions.last_sequence();
            },
            Some(ss) => {
                // todo:
                snaphsot= &options.snapshot.get_r
            },
        } */

        // Unlock while reading from files and memtables
        drop(_guard);

        // First look in the memtable, then in the immutable memtable (if any).
        //let mut found: bool;
        //let mut status: api::Error;
        let lkey = LookupKey::new(key, snaphsot);
        //let mut value:Option<Vec<u8>>= None;
        let mut value: Vec<u8>;
        /* value= self.mem.get(&lkey).map_err(|e|{
            match e {
                Error::NotFound => {
                    if let Some(imem) = &self.imem {
                        value = imem.get(&lkey).map_err(|e|{
                            Err(e);
                        })?;
                    }
                },
                _ => {
                    Err(e);
                }
            }
        })?; */
        match self.mem.get(&lkey) {
            Ok(v) => return Ok(v),
            Err((found, e)) => {
                if found {
                    return Err(e);
                } else {
                    if let Some(imem) = &mut self.imem {
                        match imem.get(&lkey) {
                            Ok(v) => return Ok(v),
                            Err((found, e)) => {
                                if found {
                                    return Err(e);
                                } else {
                                    // current search
                                }
                            }
                        }
                    } else {
                        // current search
                    }
                }
            }
        }

        //let _guard = self.lock.lock().unwrap();

        // extra steps

        /* match value {
            None => {
                Err(Error::NotFound)
            }
            Some(v)=> {
                Ok(v)
            }
        } */
        Err(Error::NotFound)
    }
}

// REQUIRES: Writer list must be non-empty
// REQUIRES: First writer must have a non-null batch
fn build_batch_group(
    _guard: &mut MutexGuard<bool>,
    writers_queue: &mut collections::VecDeque<Writer>,
    first: Writer,
) -> (WriteBatch, Vec<Writer>) {
    // Make sure:
    **_guard = true;

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
