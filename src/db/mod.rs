use std::{
    cell::{Cell, RefCell},
    ptr::NonNull,
    rc::Rc,
};

use crate::{
    api::{self, Iterator},
    table::table::TableBuilder,
    util, Options, SequenceNumber, WritableFile,
};

use self::{memtable::MemTableIterator, version::FileMetaData};

mod dbimpl;
mod filename;
mod log;
pub mod memtable;
mod skiplist;
mod table_cache;
mod version;
pub mod write_batch;

// Snapshots are kept in a doubly-linked list in the DB.
// Each SnapshotImpl corresponds to a particular sequence number.
// Abstract handle to particular state of a DB.
// A Snapshot is an immutable object and can therefore be safely
// accessed from multiple threads without any external synchronization.
#[derive(PartialEq, Debug)]
pub struct Snapshot {
    sequence_number: SequenceNumber,
    index: usize,
}

impl Snapshot {
    fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }
}

struct SnapshotList {
    list: Vec<Snapshot>,
}

impl SnapshotList {
    fn new() -> Self {
        let list = Vec::new();
        SnapshotList { list }
    }

    fn empty(&self) -> bool {
        self.list.is_empty()
    }

    fn oldest(&self) -> &Snapshot {
        assert!(!self.empty());
        &self.list[0]
    }

    fn newest(&self) -> &Snapshot {
        assert!(!self.empty());
        &self.list[self.list.len() - 1]
    }

    // Creates a SnapshotImpl and appends it to the end of the list.
    fn new_snapshot(&mut self, sequence_number: SequenceNumber) -> &Snapshot {
        let index = self.list.len();
        let snapshot = Snapshot {
            sequence_number,
            index,
        };
        self.list.push(snapshot);
        self.newest()
    }

    // Removes a SnapshotImpl from this list.
    //
    // The snapshot must have been created by calling New() on this list.
    //
    // The snapshot pointer should not be const, because its memory is
    // deallocated. However, that would force us to change DB::ReleaseSnapshot(),
    // which is in the API, and currently takes a const Snapshot.
    fn delete(&mut self, snapshot: &Snapshot) {
        // not sure using vec is approporate rightnoew, considering of O[n]
        self.list.remove(snapshot.index);
    }
}

fn build_table(
    dbname: &str,
    options: &Options,
    iter: &mut MemTableIterator,
    meta: &mut FileMetaData,
) -> api::Result<()> {
    meta.file_size = 0;
    iter.seek_to_first()?;

    let fname = filename::table_file_name(dbname, meta.number);
    let mut file = util::new_writable_file(fname)?;

    {
        let mut builder = TableBuilder::new(&mut file, options.clone());
        meta.smallest.decode_from(iter.key().unwrap());
        let mut key = Vec::new();
        while iter.valid().unwrap() {
            key.clear();
            key.extend_from_slice(iter.key().unwrap());
            builder.add(&key, iter.value().unwrap())?;
            iter.next()?;
        }
        if !key.is_empty() {
            meta.largest.decode_from(&key);
        }

        builder.finish()?;
        meta.file_size = builder.file_size();
        assert!(meta.file_size > 0);
    }

    file.sync()?;
    file.close()?;

    // Verify that the table is usable
    // todo: table_cache

    Ok(())
}

mod test {
    use std::{default, env, ops::AddAssign};

    use crate::api::{self, ReadOptions};

    /* use super::SnapshotList;

    #[test]
    fn test_snaplist() {
        let mut list= SnapshotList::new();
        let snap1= list.new_snapshot(1);
        let snap2= list.new_snapshot(2);
        assert_eq!(snap1.borrow().next.as_ref().unwrap(), snap2.borrow().prev.as_ref().unwrap());
    } */

    const OptionConfig_Default: u8 = 0;
    const OptionConfig_Reuse: u8 = 1;
    const OptionConfig_Filter: u8 = 2;
    const OptionConfig_Uncompressed: u8 = 3;
    const OptionConfig_End: u8 = 4;

    struct DBTest {
        option_config: u8,
        //db: Box<dyn DB>,
        dbname: String,
    }

    impl DBTest {
        fn new() -> Self {
            let temp_dir = String::from(env::temp_dir().to_str().unwrap()).push_str("db_test");
            //let options:Options
            DBTest {
                dbname: String::from("name"),
                option_config: OptionConfig_Default,
            }
        }

        // Switch to a fresh database with the next option configuration to
        // test.  Return false if there are no more configurations to test.
        fn change_options(&mut self) -> bool {
            self.option_config += 1;
            if self.option_config >= OptionConfig_End {
                return false;
            } else {
                self.destroy_and_reopen();
                return true;
            }
        }

        fn destroy_and_reopen(&mut self) {
            //destroy_db
        }

        /* fn get(&self, k: &str, snapshot: Option<Snapshot>) -> api::Result<String> {
            let mut options: ReadOptions = Default::default();
            options.snapshot = snapshot;
            let r= self.db.get(&options, k.as_bytes())?;
            Ok(String::from_utf8(r).unwrap())
        } */
    }

    #[test]
    fn test_empty() {
        let db_test = DBTest::new();
        /* loop {
            assert_eq!(db_test.get("foo", None), Err(api::Error::NotFound))
            if db_test.change_options() {
                break;
            }
        } */
    }
}
