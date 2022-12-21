use std::rc::Rc;

use crate::{
    api::{self, Comparator, ReadOptions},
    config, util, InternalKey, SequenceNumber,
};

use super::{
    log,
    memtable::{InternalKeyComparator, LookupKey},
};

#[derive(Default, PartialEq)]
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
    seek_file_level: u32,
}

pub(crate) struct Version {
    //vset: VersionSet // VersionSet to which this Version belongs

    // Next file to compact based on seek stats.
    file_to_compact: Option<FileMetaData>,
    file_to_compact_level: u32,
}

impl Version {
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
}

struct State {
    saver: Saver,
    stats: GetStats,
    options: ReadOptions,
    ikey: Vec<u8>,
    last_file_read: FileMetaData,
    last_file_read_level: u32,

    vset: VersionSet,
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

pub(crate) struct VersionSet {
    last_sequence: u64,
    current: Version,
    log_number: u64,
    next_file_number: u64,
    prev_log_number: u64, // 0 or backing store for memtable being compacted
}

impl VersionSet {
    pub fn current_mut(&mut self) -> &mut Version {
        &mut self.current
    }
}

impl VersionSet {
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
    fn log_and_apply(&self, edit: &mut VersionEdit) -> api::Result<()> {
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

        Ok(())
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

// Helper to sort by v->files_[file_number].smallest
struct BySmallestKey {
    internal_comparator: InternalKeyComparator,
}
impl BySmallestKey {
    fn compare(&self, f1: &FileMetaData, f2: &FileMetaData) -> std::cmp::Ordering {
        super::skiplist::Comparator::compare(&self.internal_comparator, &f1.smallest, &f2.smallest)
    }
}

struct LevelState {
    deleted_files: Vec<u64>,
    added_files: Vec<(FileMetaData, BySmallestKey)>,
}
// A helper class so we can efficiently apply a whole sequence
// of edits to a particular state without creating intermediate
// Versions that contain full copies of the intermediate state.
struct VersionSetBuilder {
    vset: VersionSet,
    base: Version,
    //levels: [config::NUM_LEVELS],
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

    fn set_log_number(&mut self, num: u64) {
        self.log_number = Some(num);
    }

    fn set_prev_log_number(&mut self, num: u64) {
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
    fn add_file(
        &mut self,
        level: u32,
        file: u64,
        file_size: u64,
        smallest_key: &InternalKey,
        largest_key: &InternalKey,
    ) {
        let f = FileMetaData {
            number: file,
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
