use core::num;
use std::{cell::RefCell, rc::Rc, sync::Arc};

use parking_lot::lock_api::RawMutex;

use crate::{
    api::{self, Comparator, ReadOptions},
    config::{self, L0_COMPACTION_TRIGGER, NUM_LEVELS},
    util, Env, InternalKey, Options, SequenceNumber, WritableFile, MAX_SEQUENCE_NUMBER,
    TYPE_FOR_SEEK, PosixWritableFile,
};

use super::{
    filename::{self, set_current_file},
    log::{self, Writer},
    memtable::{InternalKeyComparator, LookupKey},
};

#[derive(Default, PartialEq, Clone)]
pub(crate) struct FileMetaData {
    pub number: u64,
    pub file_size: u64, // File size in bytes
    pub smallest: InternalKey,
    pub largest: InternalKey,

    pub allowed_seeks: u32, // Seeks allowed until compaction
}

#[derive(Default)]
pub(crate) struct GetStats {
    seek_file: Option<FileMetaData>,
    seek_file_level: i32,
}

#[derive(PartialEq)]
pub(crate) struct Version {
    //vset: &'a VersionSet, // VersionSet to which this Version belongs
    // List of files per level
    files: Vec<Vec<Arc<FileMetaData>>>,
    // Next file to compact based on seek stats.
    file_to_compact: Option<FileMetaData>,
    file_to_compact_level: i32,

    // Level that should be compacted next and its compaction score.
    // Score < 1 means compaction is not strictly needed.  These fields
    // are initialized by Finalize().
    compaction_score: f64,
    compaction_level: i32,

    /* next: Option<Rc<RefCell<Version>>>,
    prev: Option<Rc<RefCell<Version>>>, */
    index: i32,
}

impl Version{
    fn new() -> Self {
        let mut files = Vec::with_capacity(NUM_LEVELS as usize);
        for _ in 0..NUM_LEVELS {
            files.push(Vec::new());
        }
        Version {
            files,
            file_to_compact: None,
            file_to_compact_level: -1,
            compaction_score: -1.,
            compaction_level: -1,
            index: -1,
        }
    }

    // Lookup the value for key.  If found, store it in *val and
    // return OK.  Else return a non-OK status.  Fills *stats.
    // REQUIRES: lock is not held
    pub fn get(
        &self,
        options: &ReadOptions,
        key: &LookupKey,
        value: &mut Vec<u8>,
    ) -> api::Result<GetStats> {
        todo!()
    }

    fn for_each_overlapping(&self, user_key: &[u8], internal_key: &[u8]) {}

    pub fn update_stats(&mut self, stats: GetStats) -> bool {
        match stats.seek_file {
            None => {
                return false;
            }
            Some(mut seek_file) => {
                seek_file.allowed_seeks -= 1;
                if seek_file.allowed_seeks == 0 && self.file_to_compact == None {
                    self.file_to_compact = Some(seek_file);
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
    ) -> u32 {
        let mut level = 0;
        todo!()
    }

    // Returns true iff some file in the specified level overlaps
    // some part of [*smallest_user_key,*largest_user_key].
    // smallest_user_key==nullptr represents a key smaller than all the DB's keys.
    // largest_user_key==nullptr represents a key largest than all the DB's keys.
    fn overlap_in_level(
        &self,
        level: u32,
        smallest_user_key_opt: Option<&u8>,
        largest_user_key_opt: Option<&[u8]>,
    ) -> bool {
        let mut disjoint = false;
        if level > 0 {
            disjoint = true;
        }
        todo!()
        //some_file_overlaps_range(&self.vset.icmp, disjoint, self.files[level], smallest_user_key_opt, largest_user_key_opt)
    }
}

// Returns true iff some file in "files" overlaps the user key range
// [*smallest,*largest].
// smallest==nullptr represents a key smaller than all keys in the DB.
// largest==nullptr represents a key largest than all keys in the DB.
// REQUIRES: If disjoint_sorted_files, files[] contains disjoint ranges
//           in sorted order.
fn some_file_overlaps_range(
    icmp: &InternalKeyComparator,
    disjoint_sorted_files: bool,
    files: Vec<&FileMetaData>,
    smallest_user_key_opt: Option<&[u8]>,
    largest_user_key_opt: Option<&[u8]>,
) -> bool {
    let ucmp = icmp.user_comparator();
    if !disjoint_sorted_files {
        // Need to check against all files
        for i in 0..files.len() {
            let f = files[i];
            if after_file(ucmp, smallest_user_key_opt, f)
                || before_file(ucmp, largest_user_key_opt, f)
            {
                // No overlap
            } else {
                return true;
            }
        }
        return false;
    }

    // Binary search over file list
    let mut index = 0;
    if let Some(smallest_user_key) = smallest_user_key_opt {
        // Find the earliest possible internal key for smallest_user_key
        let small_key = InternalKey::new(smallest_user_key, MAX_SEQUENCE_NUMBER, TYPE_FOR_SEEK);
        todo!()
        //index= find_file(icmp, files, small_key.encode());
    }

    if index >= files.len() {
        // beginning of range is after all files, so no overlap.
        return false;
    }

    !before_file(ucmp, largest_user_key_opt, files[index])
}

fn after_file(ucmp: &dyn api::Comparator, user_key_opt: Option<&[u8]>, f: &FileMetaData) -> bool {
    // null user_key occurs before all keys and is therefore never after *f
    if let Some(user_key) = user_key_opt {
        return ucmp.compare(user_key, f.largest.user_key()).is_lt();
    }
    return false;
}

fn before_file(ucmp: &dyn api::Comparator, user_key_opt: Option<&[u8]>, f: &FileMetaData) -> bool {
    // null user_key occurs after all keys and is therefore never before *f
    if let Some(user_key) = user_key_opt {
        return ucmp.compare(user_key, f.smallest.user_key()).is_lt();
    }
    return false;
}

struct State {
    saver: Saver,
    stats: GetStats,
    options: ReadOptions,
    ikey: Vec<u8>,
    last_file_read: FileMetaData,
    last_file_read_level: u32,

    //vset: VersionSet,
    found: bool,
}

impl State {
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

struct Saver {
    state: SaverState,
    ucmp: Rc<dyn Comparator>,
    user_key: Vec<u8>,
    value: Vec<u8>,
}

pub(crate) struct VersionSet{
    last_sequence: u64,
    current_index: i32,
    log_number: u64,
    next_file_number: u64,
    prev_log_number: u64, // 0 or backing store for memtable being compacted
    icmp: InternalKeyComparator,
    // Per-level key at which the next compaction at that level should start.
    // Either an empty string, or a valid InternalKey.
    compact_pointer: [Vec<u8>; config::NUM_LEVELS as usize],
    descriptor_log: Option<log::Writer<PosixWritableFile>>,
    dbname: String,
    manifest_file_number: u64,
    env: Env,

    versions: Vec<Version>,
}

// A Compaction encapsulates information about a compaction.
pub struct Compaction {}

impl Compaction {
    // Return the ith input file at "level()+which" ("which" must be 0 or 1).
    pub fn input(&self, which: u32, i: u32) -> &FileMetaData {
        todo!();
    }
    // "which" must be either 0 or 1
    pub fn num_input_files(&self, which: u32) -> u32 {
        todo!()
    }
}

impl VersionSet{
    // Returns true iff some level needs a compaction.
    pub fn needs_compaction(&self) -> bool {
        let v = &self.versions[self.current_index as usize];
        (v.compaction_score >= 1.0) || v.file_to_compact.is_some()
    }

    pub fn pick_compaction(&self) -> Option<Compaction> {
        todo!()
    }

    pub fn current_mut(&self) -> Option<&mut Version> {
        todo!()
        //&mut self.current
    }

    pub fn current(&self) -> Option<&Version> {
        Some(&self.versions[self.current_index as usize])
    }
}

impl VersionSet{
    // Return a compaction object for compacting the range [begin,end] in
    // the specified level.  Returns nullptr if there is nothing in that
    // level that overlaps the specified range.  Caller should delete
    // the result.
    pub fn compact_range(
        &mut self,
        level: u32,
        begin: &InternalKey,
        end: &InternalKey,
    ) -> Option<Compaction> {
        todo!()
    }

    // Allocate and return a new file number
    pub fn new_file_number(&mut self) -> u64 {
        let r = self.next_file_number;
        self.next_file_number += 1;
        r
    }

    // Apply *edit to the current version to form a new descriptor that
    // is both saved to persistent state and installed as the new
    // current version.  Will release *mu while actually writing to the file.
    // REQUIRES: *mu is held on entry.
    // REQUIRES: no other thread concurrently calls LogAndApply()
    pub fn log_and_apply(
        &mut self,
        mu: &parking_lot::RawMutex,
        edit: &mut VersionEdit,
    ) -> api::Result<()> {
        match edit.log_number {
            None => {
                edit.set_log_number(self.log_number);
            }
            Some(log_number) => {
                assert!(log_number >= self.log_number);
                assert!(log_number < self.next_file_number);
            }
        }

        if let Some(prev_log_number) = edit.prev_log_number {
            edit.set_prev_log_number(self.prev_log_number);
        }

        edit.set_next_file(self.next_file_number);
        edit.set_last_sequence(self.last_sequence);

        let mut v = Version::new();
        {
            let mut builder = VersionSetBuilder::new(self, self.current_index as usize);
            builder.apply(edit);
            builder.save_to(&mut v);
        }
        self.finalize(&mut v);

        // Initialize new descriptor log file if necessary by creating
        // a temporary file that contains a snapshot of the current version.
        let mut new_manifest_file = "".to_string();
        let mut r;
        if self.descriptor_log.is_none() {
            // No reason to unlock *mu here since we only hit this path in the
            // first call to LogAndApply (when opening the database).
            new_manifest_file =
                filename::descriptor_file_name(&self.dbname, self.manifest_file_number);
            let log_file = self
                .env
                .new_posix_writable_file(&new_manifest_file)?;
            self.descriptor_log = Some(log::Writer::new(log_file));
            r = self.write_snapshot();
        }

        // Unlock during expensive MANIFEST log write
        unsafe { mu.unlock() };

        // Write new record to MANIFEST log
        if r.is_ok() {
            let mut record = Vec::new();
            edit.encode_to(&mut record);
            r = self.descriptor_log.as_mut().unwrap().add_record(&record);
            if r.is_ok() {
                r = self.descriptor_log.as_mut().unwrap().sync();
            }

            // todo:log
        }

        // If we just created a new descriptor file, install it by writing a
        // new CURRENT file that points to it.
        if r.is_ok() && !new_manifest_file.is_empty() {
            set_current_file(&self.env, self.dbname.as_str(), self.manifest_file_number)?;
        }

        mu.lock();

        // Install the new version
        match r {
            Ok(_) => {
                self.append_version(v);
                self.log_number = edit.log_number.unwrap();
                self.prev_log_number = edit.prev_log_number.unwrap();
            }
            Err(e) => {
                // todo: remove new_manifest_file when error
            }
        }

        r
    }

    fn append_version(&mut self, mut v: Version) {
        //let rv= Rc::new(RefCell::new(v));
        // Make "v" current
        //assert!(rv != self.current);
        //self.current= rv;

        v.index = self.versions.len() as i32;
        self.versions.push(v);
    }

    fn finalize(&self, v: &mut Version) {
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
        edit.set_comparator_name(self.icmp.name());

        // Save compaction pointers
        for level in 0..NUM_LEVELS {
            if !self.compact_pointer[level as usize].is_empty() {
                let mut key = InternalKey::default();
                key.decode_from(&self.compact_pointer[level as usize]);
                edit.set_compact_pointer(level, &key);
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
        assert!(level < config::NUM_LEVELS);
        //self.current.files[level as usize].len()
    }
}

fn total_file_size(files: &Vec<Arc<FileMetaData>>) -> f64 {
    let mut sum = 0f64;
    files.iter().for_each(|f| {
        sum += f.file_size as f64;
    });
    sum
}

fn max_bytes_for_level(level: u32) -> f64 {
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
struct BySmallestKey<'a> {
    internal_comparator: &'a InternalKeyComparator,
}
impl<'a> BySmallestKey<'a> {
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
struct VersionSetBuilder<'a> {
    vset: &'a mut VersionSet,
    base_index: usize,
    levels: Vec<LevelState>,
}

impl<'a> VersionSetBuilder<'a> {
    fn new(vset: &'a mut VersionSet, base_index: usize) -> Self {
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
        for (level, fmd) in &edit.new_files {
            let mut f = fmd.clone();

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
            // of data before triggering a compaction.
            f.allowed_seeks = (f.file_size / 16384) as u32;
            if f.allowed_seeks < 100 {
                f.allowed_seeks = 100;
            }

            let deleted_files = &mut self.levels[*level as usize].deleted_files;
            let pos = deleted_files.iter().position(|x| *x == f.number);
            deleted_files.remove(pos.unwrap());
            self.levels[*level as usize].added_files.push(Arc::new(f));
        }
    }

    // Save the current state in *v.
    fn save_to(&self, v: &mut Version) {
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

    fn maybe_add_file(&self, v: &mut Version, level: u32, f: &Arc<FileMetaData>) {
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
                files.push(f.clone())
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
pub(super) struct VersionEdit {
    compact_pointers: Vec<(u32, InternalKey)>, // (level, key)
    deleted_files: Vec<(u32, u64)>,            // (level, file_number)
    new_files: Vec<(u32, FileMetaData)>,

    comparator_name: Option<String>,
    log_number: Option<u64>,
    prev_log_number: Option<u64>,
    next_file_number: Option<u64>,
    last_sequence: Option<SequenceNumber>,
}

impl VersionEdit {
    fn set_comparator_name(&mut self, name: &str) {
        self.comparator_name = Some(name.to_string());
    }

    pub fn set_log_number(&mut self, num: u64) {
        self.log_number = Some(num);
    }

    pub fn set_prev_log_number(&mut self, num: u64) {
        self.prev_log_number = Some(num);
    }

    fn set_next_file(&mut self, num: u64) {
        self.next_file_number = Some(num);
    }

    fn set_last_sequence(&mut self, seq: SequenceNumber) {
        self.last_sequence = Some(seq);
    }

    fn set_compact_pointer(&mut self, level: u32, key: &InternalKey) {
        self.compact_pointers.push((level, key.clone()));
    }

    // Add the specified file at the specified number.
    // REQUIRES: This version has not been saved (see VersionSet::SaveTo)
    // REQUIRES: "smallest" and "largest" are smallest and largest keys in file
    pub fn add_file(
        &mut self,
        level: u32,
        number: u64,
        file_size: u64,
        smallest_key: &InternalKey,
        largest_key: &InternalKey,
    ) {
        let f = FileMetaData {
            number,
            file_size,
            allowed_seeks: 0,
            smallest: smallest_key.clone(),
            largest: largest_key.clone(),
        };
        self.new_files.push((level, f));
    }

    // Delete the specified "file" from the specified "level".
    fn remove_file(&mut self, level: u32, file: u64) {
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

        self.compact_pointers.iter().for_each(|(level, key)| {
            util::put_varint32(dst, Tag::CompactPointer as u32);
            util::put_varint32(dst, *level);
            util::put_length_prefixed_slice(dst, &key.rep);
        });

        self.deleted_files.iter().for_each(|(level, file_number)| {
            util::put_varint32(dst, Tag::DeletedFile as u32);
            util::put_varint32(dst, *level);
            util::put_varint64(dst, *file_number);
        });

        self.new_files.iter().for_each(|(level, f)| {
            util::put_varint32(dst, Tag::NewFile as u32);
            util::put_varint32(dst, *level);
            util::put_varint64(dst, f.number);
            util::put_varint64(dst, f.file_size);
            util::put_length_prefixed_slice(dst, &f.smallest.rep);
            util::put_length_prefixed_slice(dst, &f.largest.rep);
        });
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

                    new_files.push((level, f));
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

fn get_level(input: &[u8]) -> api::Result<(u32, usize)> {
    let (l, l_size) =
        util::get_varint32(input).map_err(|_| api::Error::Corruption("level error".to_string()))?;
    if l >= config::NUM_LEVELS {
        return Err(api::Error::Corruption("over max level".to_string()));
    }
    Ok((l, l_size))
}

fn get_internal_key(input: &[u8]) -> api::Result<(InternalKey, usize)> {
    let (s, s_size) = util::get_length_prefixed_slice(input)
        .map_err(|_| api::Error::Corruption("get internal key".to_string()))?;
    Ok((InternalKey { rep: Vec::from(s) }, s_size))
}

mod test {
    use crate::{InternalKey, ValueType};

    use super::VersionEdit;

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
                i as u32,
                &InternalKey::new("x".as_bytes(), BIG + 900 + 1, ValueType::TypeValue),
            );
        }

        edit.set_comparator_name("foot");
        edit.set_log_number(BIG + 100);
        edit.set_next_file(BIG + 200);
        edit.set_last_sequence(BIG + 1000);

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
}
