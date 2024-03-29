use std::{path::PathBuf, sync::Arc};

use parking_lot::lock_api::RawMutex;

use crate::{
    api::{self, Comparator, ReadOptions},
    config::{self, L0_COMPACTION_TRIGGER, NUM_LEVELS},
    util, Env, InternalKey, Options, PosixWritableFile, SequenceNumber, WritableFile,
    MAX_SEQUENCE_NUMBER, TYPE_FOR_SEEK,
};

use super::{
    filename::{self, set_current_file},
    log::{self, Writer},
    memtable::{InternalKeyComparator, LookupKey},
    table_cache::TableCache,
};

#[derive(Default, PartialEq, Clone, Debug)]
pub(crate) struct FileMetaData {
    pub number: u64,
    pub file_size: u64, // File size in bytes
    pub smallest: InternalKey,
    pub largest: InternalKey,

    pub allowed_seeks: u32, // Seeks allowed until compaction
}

impl FileMetaData {
    fn new(number: u64, smallest: InternalKey, largest: InternalKey) -> Self {
        let allowed_seeks = 1 << 30;
        FileMetaData {
            number,
            file_size: 0,
            smallest,
            largest,
            allowed_seeks,
        }
    }

    fn adjust_allowed_seeks(&mut self) {
        // We arrange to automatically compact this file after
        // a certain number of seeks.  Let's assume:
        //   (1) One seek costs 10ms
        //   (2) Writing or reading 1MB costs 10ms (100MB/s)
        //   (3) A compaction of 1MB does 25MB of IO:
        //         1MB read from this level
        //         10-12MB read from next level (boundaries may be misaligned)
        //         10-12MB written to next level
        // This implies that 25 seeks cost the same as the compaction
        // of 1MB of data.  I.e., one seek costs approximately the
        // same as the compaction of 40KB of data.  We are a little
        // conservative and allow approximately one seek for every 16KB
        // of data before triggering a compaction.;
        self.allowed_seeks = (self.file_size / 16384) as u32;
        if self.allowed_seeks < 100 {
            self.allowed_seeks = 100;
        }
    }
}

#[derive(Default)]
pub(crate) struct GetStats {
    seek_file: Option<Arc<FileMetaData>>,
    seek_file_level: i32,
}

pub(crate) struct Version<C: api::Comparator + 'static> {
    options: Options<C>,
    icmp: InternalKeyComparator<C>,

    // List of files per level
    files: [Vec<Arc<FileMetaData>>; config::NUM_LEVELS as usize],
    // Next file to compact based on seek stats.
    file_to_compact: Option<Arc<FileMetaData>>,
    file_to_compact_level: i32,

    // Level that should be compacted next and its compaction score.
    // Score < 1 means compaction is not strictly needed.  These fields
    // are initialized by Finalize().
    compaction_score: f64,
    compaction_level: i32,

    /* next: Option<Rc<RefCell<Version>>>,
    prev: Option<Rc<RefCell<Version>>>, */
    index: i32,
    //table_cache: Arc<TableCache<C>>,
}

impl<C: api::Comparator + 'static> Version<C> {
    fn new(options: &Options<C>, icmp: InternalKeyComparator<C>) -> Self {
        Version {
            options: options.clone(),
            icmp,
            files: Default::default(),
            file_to_compact: None,
            file_to_compact_level: -1,
            compaction_score: -1.,
            compaction_level: -1,
            index: -1,
            //table_cache,
        }
    }

    // Lookup the value for key.  If found, store it in *val and
    // return OK.  Else return a non-OK status.  Fills *stats.
    // REQUIRES: lock is not held
    /* pub fn get(
        &self,
        options: &ReadOptions,
        key: &LookupKey,
        value: &mut Vec<u8>,
    ) -> api::Result<(Arc<FileMetaData>, i32)> {
        //(seek_file, level)

        let user_key = key.user_key();
        let ikey = key.internal_key();
        let mut error = None;
        let mut level = -1;
        let mut seek_file = None;

        // return true keep searching in other files
        let match_fn = |l: i32, f: &Arc<FileMetaData>| {
            let mut go_on = false;
            if let Err(e) =
                self.table_cache
                    .get(options, f.number, f.file_size, ikey, user_key, value)
            {
                match e {
                    api::Error::NotFound => {
                        go_on = true;
                    }
                    _ => {}
                }
                error = Some(e);
            }
            if !go_on {
                level = l;
                seek_file = Some(f.clone());
            }
            go_on
        };

        self.for_each_overlapping(user_key, ikey, match_fn);

        if let Some(e) = error {
            return Err(e);
        }

        match seek_file {
            None => Err(api::Error::NotFound),
            Some(f) => Ok((f, level)),
        }
    } */

    // Call func(arg, level, f) for every file that overlaps user_key in
    // order from newest to oldest.  If an invocation of func returns
    // false, makes no more calls.
    //
    // REQUIRES: user portion of internal_key == user_key.
    fn for_each_overlapping<F: FnMut(i32, &Arc<FileMetaData>) -> bool>(
        &self,
        user_key: &[u8],
        internal_key: &[u8],
        mut match_fn: F,
    ) {
        let ucmp = self.icmp.user_comparator();

        // Search level-0 in order from newest to oldest.
        let mut tmp = Vec::with_capacity(self.files[0].len());
        for f in &self.files[0] {
            if ucmp.compare(user_key, f.smallest.user_key()).is_ge()
                && ucmp.compare(user_key, f.largest.user_key()).is_le()
            {
                tmp.push(f.clone());
            }
        }
        if !tmp.is_empty() {
            tmp.sort_by(|a, b| b.number.cmp(&a.number));
            for f in &tmp {
                if !match_fn(0, f) {
                    return;
                }
            }
        }

        // Search other levels.
        for level in 1..NUM_LEVELS {
            let num_files = self.files[level as usize].len();
            if num_files == 0 {
                continue;
            }

            // Binary search to find earliest index whose largest key >= internal_key.
            let index = find_file(&self.icmp, &self.files[level as usize], internal_key);
            if index < num_files {
                let f = &self.files[level as usize][index];
                if ucmp.compare(user_key, f.smallest.user_key()).is_lt() {
                    // All of "f" is past any data for user_key
                } else {
                    if !match_fn(level, f) {
                        return;
                    }
                }
            }
        }
    }

    pub fn update_stats(&mut self, stats: GetStats) -> bool {
        match stats.seek_file {
            None => {
                return false;
            }
            Some(mut seek_file) => {
                // todo:
                //let sf= Rc::get_mut(&mut seek_file).unwrap();
                //sf.allowed_seeks -= 1;
                if seek_file.allowed_seeks == 0 && self.file_to_compact == None {
                    self.file_to_compact = Some(seek_file.clone());
                    self.file_to_compact_level = stats.seek_file_level;
                }
                return true;
            }
        }
    }

    // Return the level at which we should place a new memtable compaction
    // result that covers the range [smallest_user_key,largest_user_key].
    pub fn pick_level_for_memtable_output(
        &self,
        smallest_user_key: &[u8],
        largest_user_key: &[u8],
    ) -> i32 {
        let mut level = 0;
        if !self.overlap_in_level(0, Some(smallest_user_key), Some(largest_user_key)) {
            // Push to next level if there is no overlap in next level,
            // and the #bytes overlapping in the level after that are limited.
            let start = InternalKey::new(smallest_user_key, MAX_SEQUENCE_NUMBER, TYPE_FOR_SEEK);
            let limit = InternalKey::new(largest_user_key, 0, crate::ValueType::TypeDeletion); // typevalue 0
            let mut overlaps = vec![];
            while level < config::NUM_LEVELS {
                if self.overlap_in_level(level + 1, Some(smallest_user_key), Some(largest_user_key))
                {
                    break;
                }
                if level + 2 < config::NUM_LEVELS {
                    // Check that file does not overlap too many grandparent bytes.
                    self.get_overlapping_inputs(
                        level + 2,
                        Some(&start),
                        Some(&limit),
                        &mut overlaps,
                    );
                    let sum = total_file_size(&overlaps);
                    if sum > max_grand_parent_overlap_bytes(&self.options) {
                        break;
                    }
                }
                level += 1;
            }
        }
        level
    }

    // Returns true iff some file in the specified level overlaps
    // some part of [*smallest_user_key,*largest_user_key].
    // smallest_user_key==nullptr represents a key smaller than all the DB's keys.
    // largest_user_key==nullptr represents a key largest than all the DB's keys.
    fn overlap_in_level(
        &self,
        level: i32,
        smallest_user_key: Option<&[u8]>,
        largest_user_key: Option<&[u8]>,
    ) -> bool {
        let disjoint = if level > 0 { true } else { false };
        some_file_overlaps_range(
            &self.icmp,
            disjoint,
            &self.files[level as usize],
            smallest_user_key,
            largest_user_key,
        )
    }

    // Store in "*inputs" all files in "level" that overlap [begin,end]
    fn get_overlapping_inputs(
        &self,
        level: i32,
        begin: Option<&InternalKey>, // None means before all keys
        end: Option<&InternalKey>,
        inputs: &mut Vec<Arc<FileMetaData>>,
    ) {
        assert!(level >= 0);
        assert!(level < config::NUM_LEVELS);
        inputs.clear();

        let mut user_begin: &[u8] = &[];
        let mut user_end: &[u8] = &[];
        if let Some(begin) = begin {
            user_begin = begin.user_key();
        }
        if let Some(end) = end {
            user_end = end.user_key();
        }
        let mut i = 0;
        let fs = &self.files[level as usize];
        while i < fs.len() {
            let f = &fs[i];
            let file_start = f.smallest.user_key();
            let file_limit = f.largest.user_key();
            if begin.is_some()
                && self
                    .options
                    .comparator
                    .compare(file_limit, user_begin)
                    .is_lt()
            {
                // "f" is completely before specified range; skip it
            } else if end.is_some()
                && self
                    .options
                    .comparator
                    .compare(file_start, user_end)
                    .is_gt()
            {
                // "f" is completely after specified range; skip it
            } else {
                inputs.push(Arc::clone(f));
                if level == 0 {
                    // Level-0 files may overlap each other.  So check if the newly
                    // added file has expanded the range.  If so, restart search.
                    if begin.is_some()
                        && self
                            .options
                            .comparator
                            .compare(file_start, user_begin)
                            .is_lt()
                    {
                        user_begin = file_start;
                        inputs.clear();
                        i = 0;
                    } else if end.is_some()
                        && self
                            .options
                            .comparator
                            .compare(file_limit, user_end)
                            .is_gt()
                    {
                        user_end = file_limit;
                        inputs.clear();
                        i = 0;
                    }
                }
            }
            i += 1;
        }
    }
}

struct GetState<'o, 'k> {
    stats: GetStats,
    options: &'o ReadOptions,
    ikey: &'k [u8],
    last_file_read: Arc<FileMetaData>,
    last_file_read_level: i32,
    fount: bool,
}

struct MatchStateSaver {
    value: Vec<u8>,
    status: Option<api::Error>,
}

// Returns true iff some file in "files" overlaps the user key range
// [*smallest,*largest].
// smallest==nullptr represents a key smaller than all keys in the DB.
// largest==nullptr represents a key largest than all keys in the DB.
// REQUIRES: If disjoint_sorted_files, files[] contains disjoint ranges
//           in sorted order.
fn some_file_overlaps_range<C: api::Comparator + 'static>(
    icmp: &InternalKeyComparator<C>,
    disjoint_sorted_files: bool,
    files: &[Arc<FileMetaData>],
    smallest_user_key: Option<&[u8]>,
    largest_user_key: Option<&[u8]>,
) -> bool {
    let ucmp = icmp.user_comparator();
    if !disjoint_sorted_files {
        // Need to check against all files
        for i in 0..files.len() {
            let f = &files[i];
            if after_file(ucmp, smallest_user_key, f) || before_file(ucmp, largest_user_key, f) {
                // No overlap
            } else {
                return true;
            }
        }
        return false;
    }

    // Binary search over file list
    let mut index = 0;
    if let Some(smallest_user_key) = smallest_user_key {
        // Find the earliest possible internal key for smallest_user_key
        let small_key = InternalKey::new(smallest_user_key, MAX_SEQUENCE_NUMBER, TYPE_FOR_SEEK);
        index = find_file(icmp, files, small_key.encode());
    }

    if index >= files.len() {
        // beginning of range is after all files, so no overlap.
        return false;
    }

    !before_file(ucmp, largest_user_key, &files[index])
}

fn after_file(ucmp: &impl api::Comparator, user_key_opt: Option<&[u8]>, f: &FileMetaData) -> bool {
    // null user_key occurs before all keys and is therefore never after *f
    if let Some(user_key) = user_key_opt {
        return ucmp.compare(user_key, f.largest.user_key()).is_lt();
    }
    return false;
}

fn before_file(ucmp: &impl api::Comparator, user_key_opt: Option<&[u8]>, f: &FileMetaData) -> bool {
    // null user_key occurs after all keys and is therefore never before *f
    if let Some(user_key) = user_key_opt {
        return ucmp.compare(user_key, f.smallest.user_key()).is_lt();
    }
    return false;
}

struct State<C> {
    saver: Saver<C>,
    stats: GetStats,
    options: ReadOptions,
    ikey: Vec<u8>,
    last_file_read: Arc<FileMetaData>,
    last_file_read_level: u32,

    //vset: VersionSet,
    found: bool,
}

impl<C: api::Comparator> State<C> {
    fn fn_match(&self, level: u32, f: FileMetaData) -> bool {
        todo!()
    }
}

enum SaverState {
    NotFound,
    Found,
    Deleted,
    Corrupt,
}

struct Saver<C> {
    state: SaverState,
    ucmp: C,
    user_key: Vec<u8>,
    value: Vec<u8>,
}

// A Compaction encapsulates information about a compaction.
pub(crate) struct Compaction<C: api::Comparator + 'static> {
    level: i32,
    // Each compaction reads inputs from "level_" and "level_+1"
    inputs: [Vec<Arc<FileMetaData>>; 2],
    // State used to check for number of overlapping grandparent files
    // (parent == level_ + 1, grandparent == level_ + 2)
    grandparents: Vec<Arc<FileMetaData>>,
    edit: VersionEdit,
    input_version: Option<Arc<Version<C>>>,
}

impl<C: api::Comparator + 'static> Compaction<C> {
    fn new(level: i32) -> Self {
        let inputs = [Vec::new(), Vec::new()];
        Compaction {
            level,
            inputs,
            grandparents: Vec::new(),
            edit: VersionEdit::default(),
            input_version: None,
        }
    }

    pub fn edit_mut(&mut self) -> &mut VersionEdit {
        &mut self.edit
    }

    // Return the ith input file at "level()+which" ("which" must be 0 or 1).
    pub fn input(&self, which: u32, i: u32) -> &Arc<FileMetaData> {
        todo!();
    }
    // "which" must be either 0 or 1
    pub fn num_input_files(&self, which: u32) -> u32 {
        todo!()
    }

    // Return the level that is being compacted.  Inputs from "level"
    // and "level+1" will be merged to produce a set of "level+1" files.
    pub fn level(&self) -> i32 {
        self.level
    }

    // Is this a trivial compaction that can be implemented by just
    // moving a single input file to the next level (no merging or splitting)
    pub fn is_trivial_move(&self, options: &Options<C>) -> bool {
        // Avoid a move if there is lots of overlapping grandparent data.
        // Otherwise, the move could create a parent file that will require
        // a very expensive merge later on.
        self.num_input_files(0) == 1
            && self.num_input_files(1) == 0
            && total_file_size(&self.grandparents) <= max_grand_parent_overlap_bytes(options)
    }
}

// Maximum bytes of overlaps in grandparent (i.e., level+2) before we
// stop building a single file in a level->level+1 compaction.
fn max_grand_parent_overlap_bytes<C: api::Comparator>(options: &Options<C>) -> i64 {
    (10 * target_file_size(options)) as i64
}

// Return the smallest index i such that files[i]->largest >= key.
// Return files.size() if there is no such file.
// REQUIRES: "files" contains a sorted list of non-overlapping files.
pub(crate) fn find_file<C: api::Comparator + 'static>(
    icmp: &InternalKeyComparator<C>,
    files: &[Arc<FileMetaData>],
    key: &[u8],
) -> usize {
    let mut left = 0;
    let mut right = files.len();
    while left < right {
        let mid = (left + right) / 2;
        let f = &files[mid];
        match icmp.compare(f.largest.encode(), key) {
            std::cmp::Ordering::Less => {
                // Key at "mid.largest" is < "target".  Therefore all
                // files at or before "mid" are uninteresting.
                left = mid + 1;
            }
            _ => {
                // Key at "mid.largest" is >= "target".  Therefore all files
                // after "mid" are uninteresting.
                right = mid;
            }
        }
    }
    right
}

fn max_file_size_for_level<C: api::Comparator>(options: &Options<C>, level: i32) -> u64 {
    // We could vary per level to reduce number of files?
    target_file_size(options) as u64
}

fn target_file_size<C: api::Comparator>(options: &Options<C>) -> usize {
    options.max_file_size
}

pub(crate) struct VersionSet<C: api::Comparator + 'static> {
    last_sequence: u64,
    current_index: i32,
    pub(super) log_number: u64,
    next_file_number: u64,
    pub(super) prev_log_number: u64, // 0 or backing store for memtable being compacted

    // Per-level key at which the next compaction at that level should start.
    // Either an empty string, or a valid InternalKey.
    compact_pointer: [Vec<u8>; config::NUM_LEVELS as usize],
    descriptor_log: Option<log::Writer<PosixWritableFile>>,
    dbname: String,
    pub(super) manifest_file_number: u64,

    versions: Vec<Arc<Version<C>>>,

    options: Options<C>,
    icmp: InternalKeyComparator<C>,
    //table_cache:Arc<TableCache<C>>,
}

impl<C: api::Comparator + 'static> VersionSet<C> {
    pub(crate) fn new(dbname: String, options: &Options<C>) -> Self {
        let compact_pointer = [vec![], vec![], vec![], vec![], vec![], vec![], vec![]];
        let mut vset = VersionSet {
            last_sequence: 0,
            current_index: -1,
            log_number: 0,
            next_file_number: 2,
            prev_log_number: 0,
            compact_pointer,
            descriptor_log: None,
            dbname,
            manifest_file_number: 0,
            versions: vec![],
            options: options.clone(),
            icmp: InternalKeyComparator::new(options.comparator),
        };
        let mut v = Version::new(options, vset.icmp.clone());
        vset.append_version(v);
        vset
    }

    // Arrange to reuse "file_number" unless a newer file number has
    // already been allocated.
    // REQUIRES: "file_number" was returned by a call to NewFileNumber().
    pub(super) fn reuse_file_number(&mut self, file_number: u64) {
        if self.next_file_number == file_number + 1 {
            self.next_file_number = file_number;
        }
    }

    // Add all files listed in any live version to *live.
    // May also mutate some internal state.
    pub(super) fn add_live_files(&self, live: &mut Vec<u64>) {
        for v in &self.versions {
            for level in 0..config::NUM_LEVELS {
                let files = &v.files[level as usize];
                for f in files {
                    live.push(f.number);
                }
            }
        }
    }

    // Returns true iff some level needs a compaction.
    pub(crate) fn needs_compaction(&self) -> bool {
        let v = &self.versions[self.current_index as usize];
        (v.compaction_score >= 1.0) || v.file_to_compact.is_some()
    }

    // Pick level and inputs for a new compaction.
    pub(crate) fn pick_compaction(&mut self) -> Option<Compaction<C>> {
        let mut c: Compaction<C>;
        let mut level = 0;

        // We prefer compactions triggered by too much data in a level over
        // the compactions triggered by seeks.
        let current = self.current();
        let size_compaction = if current.compaction_score >= 1.0 {
            true
        } else {
            false
        };
        let seek_compaction = if current.file_to_compact.is_some() {
            true
        } else {
            false
        };
        if size_compaction {
            let l = current.compaction_level;
            assert!(l >= 0);
            assert!(l + 1 < config::NUM_LEVELS);
            c = Compaction::new(l);

            // Pick the first file that comes after compact_pointer_[level]
            level = l as usize;
            let mut i = 0;
            while i < current.files[level].len() {
                let f = &current.files[level][i];
                if self.compact_pointer[level].is_empty()
                    || self
                        .icmp
                        .compare(f.largest.encode(), &self.compact_pointer[level])
                        .is_gt()
                {
                    c.inputs[0].push(Arc::clone(f));
                    break;
                }
                i += 1;
            }
            if c.inputs[0].is_empty() {
                // Wrap-around to the beginning of the key space
                c.inputs[0].push((current.files[level][0]).clone());
            }
        } else if seek_compaction {
            let l = current.file_to_compact_level;
            c = Compaction::new(l);
            c.inputs[0].push(Arc::clone(current.file_to_compact.as_ref().unwrap()));
        } else {
            return None;
        }

        c.input_version = Some(Arc::clone(current));

        if level == 0 {
            let (smallest, largest) = self.get_range(&c.inputs[0]);
            // Note that the next call will discard the file we placed in
            // c->inputs_[0] earlier and replace it with an overlapping set
            // which will include the picked file.
            current.get_overlapping_inputs(0, Some(&smallest), Some(&largest), &mut c.inputs[0]);
            assert!(!c.inputs[0].is_empty());
        }

        self.setup_other_inputs(&mut c);
        Some(c)
    }

    /* pub(crate) fn current_mut(&self) -> Option<&mut Version<C>> {
        todo!()
        //&mut self.current
    } */

    pub(crate) fn current(&self) -> &Arc<Version<C>> {
        &self.versions[self.current_index as usize]
    }

    // Return a compaction object for compacting the range [begin,end] in
    // the specified level.  Returns None if there is nothing in that
    // level that overlaps the specified range.  Caller should delete
    // the result.
    pub fn compact_range(
        &mut self,
        level: i32,
        o_begin: Option<&InternalKey>,
        o_end: Option<&InternalKey>,
    ) -> Option<Compaction<C>> {
        let mut inputs = vec![];
        self.current()
            .get_overlapping_inputs(level, o_begin, o_end, &mut inputs);
        if inputs.is_empty() {
            return None;
        }

        // Avoid compacting too much in one shot in case the range is large.
        // But we cannot do this for level-0 since level-0 files can overlap
        // and we must not pick one file and drop another older file if the
        // two files overlap.
        if level > 0 {
            let limit = max_file_size_for_level(&self.options, level);
            let mut total = 0;
            let mut i = 0;
            while i < inputs.len() {
                let s = inputs[i].file_size;
                total += s;
                if total >= limit {
                    // ??
                    inputs.reserve(1);
                    break;
                }
                i += 1;
            }
        }

        let mut c = Compaction::new(level);
        c.input_version = Some(Arc::clone(self.current()));
        c.inputs[0].append(&mut inputs);
        // todo: setup other inputs
        Some(c)
    }

    fn setup_other_inputs(&mut self, c: &mut Compaction<C>) {
        let level = c.level;
        let current = self.current();

        add_boundary_inputs(&self.icmp, &current.files[level as usize], &mut c.inputs[0]);
        let (smallest, largest) = self.get_range(&c.inputs[0]);

        current.get_overlapping_inputs(level, Some(&smallest), Some(&largest), &mut c.inputs[1]);
        add_boundary_inputs(
            &self.icmp,
            &current.files[(level + 1) as usize],
            &mut c.inputs[1],
        );

        // Get entire range covered by compaction
        let (all_start, all_limit) = self.get_range2(&c.inputs[0], &c.inputs[1]);

        // See if we can grow the number of inputs in "level" without
        // changing the number of "level+1" files we pick up.
        if !c.inputs[1].is_empty() {
            todo!()
        }
        // Compute the set of grandparent files that overlap this compaction
        // (parent == level+1; grandparent == level+2)
        if level + 2 < config::NUM_LEVELS {
            current.get_overlapping_inputs(
                level + 2,
                Some(&all_start),
                Some(&all_limit),
                &mut c.grandparents,
            );
        }

        // Update the place where we will do the next compaction for this level.
        // We update this immediately instead of waiting for the VersionEdit
        // to be applied so that if the compaction fails, we will try a different
        // key range next time.
        self.compact_pointer[level as usize].extend_from_slice(largest.encode());
        c.edit.set_compact_pointer(level, largest);
    }

    // Stores the minimal range that covers all entries in inputs1 and inputs2 in *smallest, *largest.
    // REQUIRES: inputs is not empty
    fn get_range2(
        &self,
        inputs1: &[Arc<FileMetaData>],
        inputs2: &[Arc<FileMetaData>],
    ) -> (InternalKey, InternalKey) {
        let mut all = Vec::new();
        all.extend_from_slice(inputs1);
        all.extend_from_slice(inputs2);
        self.get_range(&all)
    }

    // Stores the minimal range that covers all entries in inputs in *smallest, *largest.
    // REQUIRES: inputs is not empty
    fn get_range(&self, inputs: &[Arc<FileMetaData>]) -> (InternalKey, InternalKey) {
        assert!(!inputs.is_empty());
        let mut smallest = inputs[0].smallest.clone();
        let mut largest = inputs[0].largest.clone();
        for f in inputs {
            if super::skiplist::Comparator::compare(&self.icmp, &f.smallest, &smallest).is_lt() {
                smallest = f.smallest.clone();
            }
            if super::skiplist::Comparator::compare(&self.icmp, &f.largest, &largest).is_gt() {
                largest = f.largest.clone();
            }
        }
        (smallest, largest)
    }

    // Allocate and return a new file number
    pub fn new_file_number(&mut self) -> u64 {
        self.next_file_number += 1;
        self.next_file_number
    }

    // Apply *edit to the current version to form a new descriptor that
    // is both saved to persistent state and installed as the new
    // current version.  Will release *mu while actually writing to the file.
    // REQUIRES: *mu is held on entry.
    // REQUIRES: no other thread concurrently calls LogAndApply()
    pub fn log_and_apply(
        &mut self,
        mutex: &parking_lot::RawMutex,
        edit: &mut VersionEdit,
    ) -> api::Result<()> {
        assert!(mutex.is_locked());

        match edit.log_number {
            None => {
                edit.log_number = Some(self.log_number);
            }
            Some(log_number) => {
                assert!(log_number >= self.log_number);
                assert!(log_number < self.next_file_number);
            }
        }

        if edit.prev_log_number.is_none() {
            edit.prev_log_number = Some(self.prev_log_number);
        }

        edit.next_file_number = Some(self.next_file_number);
        edit.last_sequence = Some(self.last_sequence);

        let mut v = Version::new(&self.options, self.icmp.clone());
        {
            let mut builder = VersionSetBuilder::new(self, self.current_index as usize);
            builder.apply(edit);
            builder.save_to(&mut v);
        }
        self.finalize(&mut v);

        // Initialize new descriptor log file if necessary by creating
        // a temporary file that contains a snapshot of the current version.
        let mut new_manifest_file = None;
        let mut r: Result<(), api::Error> = Ok(());
        if self.descriptor_log.is_none() {
            // No reason to unlock *mu here since we only hit this path in the
            // first call to LogAndApply (when opening the database).
            let manifest_file =
                filename::descriptor_file_name(&self.dbname, self.manifest_file_number);
            let descriptor_file = self
                .options
                .env
                .new_posix_writable_file(manifest_file.as_path())?;
            self.descriptor_log = Some(log::Writer::new(descriptor_file));
            new_manifest_file = Some(manifest_file);
            r = self.write_snapshot();
        }

        // Unlock during expensive MANIFEST log write
        unsafe { mutex.unlock() }

        // Write new record to MANIFEST log
        if r.is_ok() {
            let mut record = Vec::new();
            edit.encode_to(&mut record);
            let descriptor_log = self.descriptor_log.as_mut().unwrap();
            r = descriptor_log.add_record(&record);
            if r.is_ok() {
                r = descriptor_log.sync();
            }

            // todo:log
        }

        // If we just created a new descriptor file, install it by writing a
        // new CURRENT file that points to it.
        if r.is_ok() && !new_manifest_file.is_none() {
            r = set_current_file(self.options.env, &self.dbname, self.manifest_file_number);
        }

        mutex.lock();

        // Install the new version
        match &r {
            Ok(_) => {
                self.append_version(v);
                self.log_number = edit.log_number.unwrap();
                self.prev_log_number = edit.prev_log_number.unwrap();
            }
            Err(_) => {
                if let Some(new_manifest_file) = new_manifest_file {
                    let _ = self.options.env.remove_file(&new_manifest_file);
                }
            }
        }

        r
    }

    fn append_version(&mut self, mut v: Version<C>) {
        // Make "v" current
        let index = self.versions.len();
        v.index = index as i32;
        let current = Arc::new(v);
        self.current_index = index as i32;
        self.versions.push(current);
    }

    fn finalize(&self, v: &mut Version<C>) {
        // Precomputed best level for next compaction
        let mut best_level = -1i32;
        let mut best_score = -1f64;

        for level in 0..NUM_LEVELS {
            let score: f64;
            if level == 0 {
                // We treat level-0 specially by bounding the number of files
                // instead of number of bytes for two reasons:
                //
                // (1) With larger write-buffer sizes, it is nice not to do too
                // many level-0 compactions.
                //
                // (2) The files in level-0 are merged on every read and
                // therefore we wish to avoid too many files when the individual
                // file size is small (perhaps because of a small write-buffer
                // setting, or very high compression ratios, or lots of
                // overwrites/deletions).
                score = v.files[level as usize].len() as f64 / L0_COMPACTION_TRIGGER as f64;
            } else {
                // Compute the ratio of current size to size limit.
                let level_bytes = total_file_size(&v.files[level as usize]);
                score = level_bytes as f64 / max_bytes_for_level(level);
            }
            if score > best_score {
                best_level = level as i32;
                best_score = score;
            }
        }

        v.compaction_level = best_level;
        v.compaction_score = best_score;
    }

    fn write_snapshot(&mut self) -> api::Result<()> {
        // TODO: Break up into multiple records to reduce memory usage on recovery?

        // Save metadata
        let mut edit = VersionEdit::default();
        edit.comparator_name = Some(self.icmp.name().to_string());

        // Save compaction pointers
        for level in 0..NUM_LEVELS {
            if !self.compact_pointer[level as usize].is_empty() {
                let mut key = InternalKey::default();
                key.decode_from(&self.compact_pointer[level as usize]);
                edit.set_compact_pointer(level, key);
            }
        }

        // Save files
        for level in 0..NUM_LEVELS {
            let files = &self.versions[self.current_index as usize].files[level as usize];
            for file in files {
                edit.add_file(
                    level,
                    file.number,
                    file.file_size,
                    &file.smallest,
                    &file.largest,
                );
            }
        }

        let mut record = Vec::new();
        edit.encode_to(&mut record);
        self.descriptor_log.as_mut().unwrap().add_record(&record)
    }

    // Return the last sequence number.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn set_last_sequence(&mut self, s: u64) {
        assert!(s >= self.last_sequence);
        self.last_sequence = s;
    }

    // Return the number of Table files at the specified level.
    pub fn num_level_files(&self, level: u32) -> usize {
        todo!();
        //assert!(level < config::NUM_LEVELS);
        //self.current.files[level as usize].len()
    }
}

fn total_file_size(files: &[Arc<FileMetaData>]) -> i64 {
    let mut sum = 0;
    for f in files {
        sum += f.file_size as i64;
    }
    sum
}

fn max_bytes_for_level(level: i32) -> f64 {
    // Note: the result for level zero is not really used since we set
    // the level-0 compaction threshold based on number of files.

    // Result for both level-0 and level-1
    let mut result = 10. * 1048576.0;
    let mut l = level;
    while l > 1 {
        result *= 10.;
        l -= 1;
    }
    result
}

// Helper to sort by v->files_[file_number].smallest
struct BySmallestKey<'a, C: api::Comparator + 'static> {
    internal_comparator: &'a InternalKeyComparator<C>,
}
impl<'a, C: api::Comparator> BySmallestKey<'a, C> {
    fn compare(&self, f1: &FileMetaData, f2: &FileMetaData) -> std::cmp::Ordering {
        super::skiplist::Comparator::compare(self.internal_comparator, &f1.smallest, &f2.smallest)
    }
}

struct LevelState {
    deleted_files: Vec<u64>,
    added_files: Vec<Arc<FileMetaData>>,
}

// A helper class so we can efficiently apply a whole sequence
// of edits to a particular state without creating intermediate
// Versions that contain full copies of the intermediate state.
struct VersionSetBuilder<'a, C: api::Comparator + 'static> {
    vset: &'a mut VersionSet<C>,
    base_index: usize,
    levels: Vec<LevelState>,
}

impl<'a, C: api::Comparator> VersionSetBuilder<'a, C> {
    fn new(vset: &'a mut VersionSet<C>, base_index: usize) -> Self {
        let mut levels = Vec::with_capacity(NUM_LEVELS as usize);
        for _ in 0..NUM_LEVELS {
            levels.push(LevelState {
                deleted_files: Vec::new(),
                added_files: Vec::new(),
            });
        }
        VersionSetBuilder {
            vset,
            base_index,
            levels,
        }
    }

    // Apply all of the edits in *edit to the current state.
    fn apply(&mut self, edit: &VersionEdit) {
        // Update compaction pointers
        for (level, ikey) in &edit.compact_pointers {
            self.vset.compact_pointer[*level as usize].clear();
            self.vset.compact_pointer[*level as usize].extend_from_slice(ikey.encode());
        }

        // Delete files
        for (level, number) in &edit.deleted_files {
            self.levels[*level as usize].deleted_files.push(*number);
        }

        // Add new files
        for (level, f) in &edit.new_files {
            let deleted_files = &mut self.levels[*level as usize].deleted_files;
            let pos = deleted_files.iter().position(|x| *x == f.number);
            deleted_files.remove(pos.unwrap());
            self.levels[*level as usize].added_files.push(Arc::clone(f));
        }
    }

    // Save the current state in *v.
    fn save_to(&self, v: &mut Version<C>) {
        let cmp = BySmallestKey {
            internal_comparator: &self.vset.icmp,
        };
        for level in 0..config::NUM_LEVELS {
            // Merge the set of added files with the set of pre-existing files.
            // Drop any deleted files.  Store the result in *v.
            let base_files = &self.vset.versions[self.base_index].files[level as usize];
            let added_files = &self.levels[level as usize].added_files;
            v.files[level as usize].reserve(base_files.len() + added_files.len());
            let mut base_index = 0;
            added_files.iter().for_each(|added_file| {
                // Add all smaller files listed in base_
                let pos = base_files
                    .iter()
                    .position(|base_file| cmp.compare(&base_file, &added_file).is_lt())
                    .unwrap();
                while base_index < pos {
                    self.maybe_add_file(v, level, &base_files[base_index]);
                    base_index += 1;
                }
                self.maybe_add_file(v, level, added_file);
            });

            // Add remaining base files
            while base_index < base_files.len() {
                self.maybe_add_file(v, level, &base_files[base_index]);
                base_index += 1;
            }

            // debug
            // Make sure there is no overlap in levels > 0
            if level > 0 {
                let files = &v.files[level as usize];
                let mut i = 1;
                while i < files.len() {
                    let prev_end = &files[i - 1].largest;
                    let this_begin = &files[i].smallest;
                    if super::skiplist::Comparator::compare(&self.vset.icmp, prev_end, this_begin)
                        .is_le()
                    {
                        panic!(
                            "overlapping ranges in same level {:?} vs. {:?}",
                            prev_end, this_begin
                        );
                    }
                    i += 1;
                }
            }
        }
    }

    fn maybe_add_file(&self, v: &mut Version<C>, level: i32, f: &Arc<FileMetaData>) {
        match self.levels[level as usize]
            .deleted_files
            .iter()
            .position(|dn| *dn == f.number)
        {
            None => {
                let files = &mut v.files[level as usize];
                if level > 0 && !files.is_empty() {
                    // Must not overlap
                    assert!(super::skiplist::Comparator::compare(
                        &self.vset.icmp,
                        &files[files.len() - 1].largest,
                        &f.smallest
                    )
                    .is_lt());
                }
                files.push(Arc::clone(f));
            }
            Some(_) => {
                // File is deleted: do nothing
            }
        }
    }
}

enum Tag {
    Comparator = 1,
    LogNumber = 2,
    NextFileNumber = 3,
    LastSequence = 4,
    CompactPointer = 5,
    DeletedFile = 6,
    NewFile = 7,
    // 8 was used for large value refs
    PrevLogNumber = 9,

    Unknown,
}

impl From<u32> for Tag {
    fn from(v: u32) -> Self {
        match v {
            1 => Tag::Comparator,
            2 => Tag::LogNumber,
            3 => Tag::NextFileNumber,
            4 => Tag::LastSequence,
            5 => Tag::CompactPointer,
            6 => Tag::DeletedFile,
            7 => Tag::NewFile,
            9 => Tag::PrevLogNumber,
            _ => Tag::Unknown,
        }
    }
}

#[derive(Default)]
pub(crate) struct VersionEdit {
    compact_pointers: Vec<(i32, InternalKey)>, // (level, key)
    deleted_files: Vec<(i32, u64)>,            // (level, file_number)
    new_files: Vec<(i32, Arc<FileMetaData>)>,

    comparator_name: Option<String>,
    pub(crate) log_number: Option<u64>,
    pub(crate) prev_log_number: Option<u64>,
    next_file_number: Option<u64>,
    last_sequence: Option<SequenceNumber>,
}

impl VersionEdit {
    /* fn new() -> Self {
        VersionEdit {
            compact_pointers: Vec::new(),
            deleted_files: Vec::new(),
            new_files: Vec::new(),
            comparator_name: None,
            log_number: None,
            prev_log_number: None,
            next_file_number: None,
            last_sequence: None,
        }
    } */

    fn set_compact_pointer(&mut self, level: i32, key: InternalKey) {
        self.compact_pointers.push((level, key));
    }

    // Add the specified file at the specified number.
    // REQUIRES: This version has not been saved (see VersionSet::SaveTo)
    // REQUIRES: "smallest" and "largest" are smallest and largest keys in file
    pub(crate) fn add_file(
        &mut self,
        level: i32,
        number: u64,
        file_size: u64,
        smallest_key: &InternalKey,
        largest_key: &InternalKey,
    ) {
        let f = FileMetaData::new(number, smallest_key.clone(), largest_key.clone());
        self.new_files.push((level, Arc::new(f)));
    }

    // Delete the specified "file" from the specified "level".
    pub fn remove_file(&mut self, level: i32, file: u64) {
        self.deleted_files.push((level, file));
    }

    fn encode_to(&self, dst: &mut Vec<u8>) {
        if let Some(comparator_name) = &self.comparator_name {
            util::put_varint32(dst, Tag::Comparator as u32);
            util::put_length_prefixed_slice(dst, comparator_name.as_bytes());
        }
        if let Some(log_number) = self.log_number {
            util::put_varint32(dst, Tag::LogNumber as u32);
            util::put_varint64(dst, log_number);
        }
        if let Some(prev_log_number) = self.prev_log_number {
            util::put_varint32(dst, Tag::PrevLogNumber as u32);
            util::put_varint64(dst, prev_log_number);
        }
        if let Some(next_file_number) = self.next_file_number {
            util::put_varint32(dst, Tag::NextFileNumber as u32);
            util::put_varint64(dst, next_file_number);
        }
        if let Some(last_sequence) = self.last_sequence {
            util::put_varint32(dst, Tag::LastSequence as u32);
            util::put_varint64(dst, last_sequence);
        }

        for (level, key) in &self.compact_pointers {
            util::put_varint32(dst, Tag::CompactPointer as u32);
            util::put_varint32(dst, *level as u32);
            util::put_length_prefixed_slice(dst, &key.rep);
        }

        for (level, file_number) in &self.deleted_files {
            util::put_varint32(dst, Tag::DeletedFile as u32);
            util::put_varint32(dst, *level as u32);
            util::put_varint64(dst, *file_number);
        }

        for (level, f) in &self.new_files {
            util::put_varint32(dst, Tag::NewFile as u32);
            util::put_varint32(dst, *level as u32);
            util::put_varint64(dst, f.number);
            util::put_varint64(dst, f.file_size);
            util::put_length_prefixed_slice(dst, &f.smallest.rep);
            util::put_length_prefixed_slice(dst, &f.largest.rep);
        }
    }

    fn decode_from(src: &[u8]) -> api::Result<Self> {
        let input = src;
        let mut offset = 0;

        let mut comparator_name = None;
        let mut log_number = None;
        let mut prev_log_number = None;
        let mut next_file_number = None;
        let mut last_sequence = None;
        let mut compact_pointers = Vec::new();
        let mut deleted_files = Vec::new();
        let mut new_files = Vec::new();

        while offset < input.len() {
            let (tag_number, tag_size) = util::get_varint32(&input[offset..])
                .map_err(|_| api::Error::Corruption("invalid tag".to_string()))?;
            offset += tag_size;
            let tag = Tag::from(tag_number);
            match tag {
                Tag::Comparator => {
                    let (slice, slice_size) = util::get_length_prefixed_slice(&input[offset..])
                        .map_err(|_| api::Error::Corruption("comparator name".to_string()))?;
                    comparator_name = Some(String::from_utf8(slice.to_vec()).unwrap());
                    offset += slice_size;
                }
                Tag::LogNumber => {
                    let (n, n_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("log number".to_string()))?;
                    log_number = Some(n);
                    offset += n_size;
                }
                Tag::PrevLogNumber => {
                    let (n, n_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("previous log number".to_string()))?;
                    prev_log_number = Some(n);
                    offset += n_size;
                }
                Tag::NextFileNumber => {
                    let (n, n_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("next file number".to_string()))?;
                    next_file_number = Some(n);
                    offset += n_size;
                }
                Tag::LastSequence => {
                    let (n, n_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("last sequence number".to_string()))?;
                    last_sequence = Some(n);
                    offset += n_size;
                }
                Tag::CompactPointer => {
                    let (level, l_size) = get_level(&input[offset..])?;
                    offset += l_size;
                    let (key, k_size) = get_internal_key(&input[offset..])?;
                    offset += k_size;
                    compact_pointers.push((level, key));
                }
                Tag::DeletedFile => {
                    let (level, l_size) = get_level(&input[offset..])?;
                    offset += l_size;
                    let (n, n_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("deleted files".to_string()))?;
                    offset += n_size;
                    deleted_files.push((level, n));
                }
                Tag::NewFile => {
                    let (level, l_size) = get_level(&input[offset..])?;
                    offset += l_size;

                    let mut f = FileMetaData::default();
                    let (number, number_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("new-file entry".to_string()))?;
                    offset += number_size;
                    f.number = number;
                    let (fs, fs_size) = util::get_varint64(&input[offset..])
                        .map_err(|_| api::Error::Corruption("new-file entry".to_string()))?;
                    offset += fs_size;
                    f.file_size = fs;
                    let (smallest, s_size) = get_internal_key(&input[offset..])?;
                    offset += s_size;
                    f.smallest = smallest;
                    let (largest, s_size) = get_internal_key(&input[offset..])?;
                    offset += s_size;
                    f.largest = largest;

                    new_files.push((level, Arc::new(f)));
                }

                _ => {
                    return Err(api::Error::Corruption(
                        "VersionEdit, unknown tag".to_string(),
                    ));
                }
            }
        }

        Ok(VersionEdit {
            compact_pointers,
            deleted_files,
            new_files,
            comparator_name,
            log_number,
            prev_log_number,
            next_file_number,
            last_sequence,
        })
    }
}

fn get_level(input: &[u8]) -> api::Result<(i32, usize)> {
    let (l, l_size) =
        util::get_varint32(input).map_err(|_| api::Error::Corruption("level error".to_string()))?;
    if l as i32 >= config::NUM_LEVELS {
        return Err(api::Error::Corruption("over max level".to_string()));
    }
    Ok((l as i32, l_size))
}

fn get_internal_key(input: &[u8]) -> api::Result<(InternalKey, usize)> {
    let (s, s_size) = util::get_length_prefixed_slice(input)
        .map_err(|_| api::Error::Corruption("get internal key".to_string()))?;
    Ok((InternalKey { rep: Vec::from(s) }, s_size))
}

// Extracts the largest file b1 from |compaction_files| and then searches for a
// b2 in |level_files| for which user_key(u1) = user_key(l2). If it finds such a
// file b2 (known as a boundary file) it adds it to |compaction_files| and then
// searches again using this new upper bound.
//
// If there are two blocks, b1=(l1, u1) and b2=(l2, u2) and
// user_key(u1) = user_key(l2), and if we compact b1 but not b2 then a
// subsequent get operation will yield an incorrect result because it will
// return the record from b2 in level i rather than from b1 because it searches
// level by level for records matching the supplied user key.
//
// parameters:
//   in     level_files:      List of files to search for boundary files.
//   in/out compaction_files: List of files to extend by adding boundary files.
fn add_boundary_inputs<C: api::Comparator>(
    icmp: &InternalKeyComparator<C>,
    level_files: &[Arc<FileMetaData>],
    compaction_files: &mut Vec<Arc<FileMetaData>>,
) {
    // Quick return if compaction_files is empty.
    match find_largest_key(icmp, compaction_files) {
        None => {
            return;
        }
        Some(largest_key) => {
            let mut continue_searching = true;
            let mut l = largest_key.clone();
            while continue_searching {
                match find_smallest_boundary_file(icmp, level_files, &l) {
                    None => {
                        continue_searching = false;
                    }
                    Some(smallest_boundary_file) => {
                        l = smallest_boundary_file.largest.clone();
                        compaction_files.push(Arc::clone(smallest_boundary_file));
                    }
                }
            }
        }
    }
}

// Finds minimum file b2=(l2, u2) in level file for which l2 > u1 and
// user_key(l2) = user_key(u1)
fn find_smallest_boundary_file<'a, C: api::Comparator>(
    icmp: &InternalKeyComparator<C>,
    level_files: &'a [Arc<FileMetaData>],
    largest_key: &InternalKey,
) -> Option<&'a Arc<FileMetaData>> {
    let user_cmp = icmp.user_comparator();
    let mut smallest_boundary_file: Option<&Arc<FileMetaData>> = None;
    for f in level_files {
        if super::skiplist::Comparator::compare(icmp, &f.smallest, largest_key).is_gt()
            && user_cmp
                .compare(f.smallest.user_key(), largest_key.user_key())
                .is_eq()
        {
            if smallest_boundary_file.is_none()
                || super::skiplist::Comparator::compare(
                    icmp,
                    &f.smallest,
                    &smallest_boundary_file.as_ref().unwrap().smallest,
                )
                .is_lt()
            {
                smallest_boundary_file = Some(f);
            }
        }
    }
    smallest_boundary_file
}

// Finds the largest key in a vector of files. Returns true if files is not empty.
fn find_largest_key<'a, C: api::Comparator>(
    icmp: &InternalKeyComparator<C>,
    files: &'a [Arc<FileMetaData>],
) -> Option<&'a InternalKey> {
    if files.is_empty() {
        return None;
    }
    let mut largest_key = &files[0].largest;
    files.iter().for_each(|f| {
        if super::skiplist::Comparator::compare(icmp, &f.largest, &largest_key).is_gt() {
            largest_key = &f.largest;
        }
    });
    Some(largest_key)
}

mod test {
    use std::sync::Arc;

    use crate::{
        api::ByteswiseComparator, db::memtable::InternalKeyComparator, InternalKey, ValueType,
    };

    use super::{
        add_boundary_inputs, find_file, some_file_overlaps_range, FileMetaData, VersionEdit,
    };

    const BIG: u64 = 1u64 << 50;

    #[test]
    fn test_version_edit() {
        let mut edit = VersionEdit::default();
        for i in 0..4 {
            test_encode_decode(&edit);
            edit.add_file(
                3,
                BIG + 300 + i,
                BIG + 400 + i,
                &InternalKey::new("foo".as_bytes(), BIG + 500 + i, ValueType::TypeValue),
                &InternalKey::new("zoo".as_bytes(), BIG + 600 + i, ValueType::TypeDeletion),
            );
            edit.remove_file(4, BIG + 700 + i);
            edit.set_compact_pointer(
                i as i32,
                InternalKey::new("x".as_bytes(), BIG + 900 + 1, ValueType::TypeValue),
            );
        }

        edit.comparator_name = Some("foot".to_string());
        edit.log_number = Some(BIG + 100);
        edit.next_file_number = Some(BIG + 200);
        edit.last_sequence = Some(BIG + 1000);

        test_encode_decode(&edit)
    }

    fn test_encode_decode(edit: &VersionEdit) {
        let mut encoded = Vec::new();
        edit.encode_to(&mut encoded);
        let decode_result = VersionEdit::decode_from(&encoded);
        assert!(decode_result.is_ok());
        let mut encoded2 = Vec::new();
        let parsed = decode_result.unwrap();
        parsed.encode_to(&mut encoded2);
        assert_eq!(encoded, encoded2);
    }

    struct FindFileTest {
        files: Vec<Arc<FileMetaData>>,
        disjoint_sorted_files: bool,
    }

    impl FindFileTest {
        fn add(&mut self, smallest: &str, largest: &str) {
            let f = Arc::new(FileMetaData::new(
                (self.files.len() + 1) as u64,
                InternalKey::new(smallest.as_bytes(), 100, ValueType::TypeValue),
                InternalKey::new(largest.as_bytes(), 100, ValueType::TypeValue),
            ));
            self.files.push(f);
        }

        fn find(&self, key: &str) -> usize {
            let target = InternalKey::new(key.as_bytes(), 100, ValueType::TypeValue);
            let cmp = InternalKeyComparator::new(&ByteswiseComparator {});
            find_file(&cmp, &self.files, target.encode())
        }

        fn overlaps(&self, smallest: &str, largest: &str) -> bool {
            let cmp = InternalKeyComparator::new(&ByteswiseComparator {});
            some_file_overlaps_range(
                &cmp,
                self.disjoint_sorted_files,
                &self.files,
                Some(smallest.as_bytes()),
                Some(largest.as_bytes()),
            )
        }
    }

    #[test]
    fn test_find_file_empty() {
        let test = FindFileTest {
            files: Vec::new(),
            disjoint_sorted_files: true,
        };
        assert_eq!(0, test.find("foo"));
        assert!(!test.overlaps("a", "z"));
        assert!(!test.overlaps("", "z"));
        assert!(!test.overlaps("a", ""));
        assert!(!test.overlaps("", ""));
    }

    #[test]
    fn test_find_file_single() {
        let mut test = FindFileTest {
            files: Vec::new(),
            disjoint_sorted_files: true,
        };
        test.add("p", "q");
        assert_eq!(0, test.find("a"));
        assert_eq!(0, test.find("p"));
        assert_eq!(0, test.find("p1"));
        assert_eq!(0, test.find("q"));
        assert_eq!(1, test.find("q1"));
        assert_eq!(1, test.find("z"));

        assert!(!test.overlaps("a", "b"));
        assert!(!test.overlaps("z1", "z2"))
    }

    struct AddBoundaryInputsTests {
        level_files: Vec<Arc<FileMetaData>>,
        compaction_files: Vec<Arc<FileMetaData>>,
        all_files: Vec<Arc<FileMetaData>>,
        icmp: InternalKeyComparator<ByteswiseComparator>,
    }

    impl AddBoundaryInputsTests {
        fn new() -> Self {
            AddBoundaryInputsTests {
                level_files: Vec::new(),
                compaction_files: Vec::new(),
                all_files: Vec::new(),
                icmp: InternalKeyComparator::new(&ByteswiseComparator {}),
            }
        }
    }

    #[test]
    fn test_add_boundary_inputs_empty() {
        let mut test = AddBoundaryInputsTests::new();
        add_boundary_inputs(&test.icmp, &test.level_files, &mut test.compaction_files);
        assert!(test.compaction_files.is_empty());
        assert!(test.level_files.is_empty());
    }

    #[test]
    fn test_add_boundary_inputs_empty_level_files() {
        let mut test = AddBoundaryInputsTests::new();
        let f = Arc::new(FileMetaData::new(
            1,
            InternalKey::new("100".as_bytes(), 2, ValueType::TypeValue),
            InternalKey::new("100".as_bytes(), 1, ValueType::TypeValue),
        ));
        test.all_files.push(f);
        let f1 = &test.all_files[0];
        test.compaction_files.push(Arc::clone(f1));

        add_boundary_inputs(&test.icmp, &test.level_files, &mut test.compaction_files);

        assert_eq!(1, test.compaction_files.len());
        assert_eq!(*f1, test.compaction_files[0]);
        assert!(test.level_files.is_empty());
    }

    #[test]
    fn test_add_boundary_inputs_empty_compaction_files() {
        let mut test = AddBoundaryInputsTests::new();
        let f = Arc::new(FileMetaData::new(
            1,
            InternalKey::new("100".as_bytes(), 2, ValueType::TypeValue),
            InternalKey::new("100".as_bytes(), 1, ValueType::TypeValue),
        ));
        test.all_files.push(f);
        let f1 = &test.all_files[0];
        test.level_files.push(Arc::clone(f1));

        add_boundary_inputs(&test.icmp, &test.level_files, &mut test.compaction_files);

        assert!(test.compaction_files.is_empty());
    }

    #[test]
    fn test_add_boundary_inputs_no_boundary_files() {
        let mut test = AddBoundaryInputsTests::new();
        let f1 = Arc::new(FileMetaData::new(
            1,
            InternalKey::new_with_str_key("100", 2, ValueType::TypeValue),
            InternalKey::new_with_str_key("100", 1, ValueType::TypeValue),
        ));
        test.all_files.push(f1);
        let f2 = Arc::new(FileMetaData::new(
            1,
            InternalKey::new_with_str_key("200", 2, ValueType::TypeValue),
            InternalKey::new_with_str_key("200", 1, ValueType::TypeValue),
        ));
        test.all_files.push(f2);
        let f3 = Arc::new(FileMetaData::new(
            1,
            InternalKey::new_with_str_key("300", 2, ValueType::TypeValue),
            InternalKey::new_with_str_key("300", 1, ValueType::TypeValue),
        ));
        test.all_files.push(f3);
        let f3 = &test.all_files[2];
        let f2 = &test.all_files[1];
        let f1 = &test.all_files[0];

        test.level_files.push(Arc::clone(f3));
        test.level_files.push(Arc::clone(f2));
        test.level_files.push(Arc::clone(f1));
        test.compaction_files.push(Arc::clone(f2));
        test.compaction_files.push(Arc::clone(f3));

        add_boundary_inputs(&test.icmp, &test.level_files, &mut test.compaction_files);

        assert_eq!(2, test.compaction_files.len())
    }

    #[test]
    fn test_add_boundary_inputs_one_boundary_files() {
        let mut test = AddBoundaryInputsTests::new();
        let f1 = Arc::new(FileMetaData::new(
            1,
            InternalKey::new_with_str_key("100", 3, ValueType::TypeValue),
            InternalKey::new_with_str_key("100", 2, ValueType::TypeValue),
        ));
        test.all_files.push(f1);
        let f2 = Arc::new(FileMetaData::new(
            1,
            InternalKey::new_with_str_key("100", 1, ValueType::TypeValue),
            InternalKey::new_with_str_key("200", 3, ValueType::TypeValue),
        ));
        test.all_files.push(f2);
        let f3 = Arc::new(FileMetaData::new(
            1,
            InternalKey::new_with_str_key("300", 2, ValueType::TypeValue),
            InternalKey::new_with_str_key("300", 1, ValueType::TypeValue),
        ));
        test.all_files.push(f3);
        let f3 = &test.all_files[2];
        let f2 = &test.all_files[1];
        let f1 = &test.all_files[0];

        test.level_files.push(Arc::clone(f3));
        test.level_files.push(Arc::clone(f2));
        test.level_files.push(Arc::clone(f1));
        test.compaction_files.push(f1.clone());

        add_boundary_inputs(&test.icmp, &test.level_files, &mut test.compaction_files);

        assert_eq!(2, test.compaction_files.len());
        assert_eq!(*f1, test.compaction_files[0]);
        assert_eq!(*f2, test.compaction_files[1]);
    }
}
