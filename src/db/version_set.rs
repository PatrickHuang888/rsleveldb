use crate::{config, api, util, SequenceNumber};

pub struct Version {
    // List of files per level
    files: Vec<Vec<Box<FileMetaData>>>,
}

struct FileMetaData {
    number:u64,
    file_size:u64, // File size in bytes
    smallest_key: Vec<u8>,
    largest_key:Vec<u8>,
}

pub struct VersionSet {
    last_sequence: u64,
    current: Box<Version>,
}

impl VersionSet {
    // Return the last sequence number.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn set_last_sequence(&mut self, s: u64) {
        assert!(s >= self.last_sequence);
        self.last_sequence = s;
    }

    // Return the number of Table files at the specified level.
    pub fn num_level_files(&self, level: usize) -> usize {
        assert!(level < config::NumLevels);
        self.current.files[level].len()
    }
}

enum Tag {
    Comparator = 1,
    LogNumber = 2,
    NextFileNumber = 3,
    LastSequence= 4,
    CompactPointer = 5,
    DeletedFile = 6,
    NewFile= 7,
      // 8 was used for large value refs
    PrevLogNumber= 9,
}

pub(super) struct VersionEdit {

    compact_pointers: Vec<(u32, Vec<u8>)>,  // (level, key) 
    deleted_files: Vec<(u32, u64)>, // (level, file_number)
    new_files: Vec<(u32, FileMetaData)>, 

    comparator_name:Option<String>,
    log_number:Option<u64>,
    prev_log_number:Option<u64>,
    next_file_number:Option<u64>,
    last_sequence: Option<SequenceNumber>,
}

impl VersionEdit {
    // Add the specified file at the specified number.
  // REQUIRES: This version has not been saved (see VersionSet::SaveTo)
  // REQUIRES: "smallest" and "largest" are smallest and largest keys in file
  fn add_file(&mut self, level:u64, file:u64, file_size:u64, smallest:&[u8], largest:&[u8]) {
    let f = FileMetaData{ number: file, file_size, smallest_key:Vec::from(smallest), largest_key:Vec::from(largest)};
    self.new_files.push((level, f));
  }

  // Delete the specified "file" from the specified "level".
  fn remove_file(&mut self, level:u64, file:u64) {
    self.deleted_files.push((level, file));
  }

  fn encode_to(&self, dst: &mut Vec<u8>) {
    if let Some(comparator_name) = self.comparator_name {
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

    self.compact_pointers.iter().for_each(|(level, key)|{
        util::put_varint32(dst, Tag::CompactPointer as u32);
        util::put_varint32(dst, level);
        util::put_length_prefixed_slice(dst, key);
    });

    self.deleted_files.iter().for_each(|(level, file_number)|{
        util::put_varint32(dst, Tag::DeletedFile as u32);
        util::put_varint32(dst, level);
        util::put_varint64(dst, file_number);
    });

    self.new_files.iter().for_each(|(level, f)|{
        util::put_varint32(dst, Tag::NewFile as u32);
        util::put_varint32(dst, level);
        util::put_varint64(dst, f.number);
        util::put_varint64(dst, f.file_size);
        util::put_length_prefixed_slice(dst, &f.smallest_key);
        util::put_length_prefixed_slice(dst, &f.largest_key);
    });

  }

  fn decode_from(src:&[u8]) -> api::Result(Self) {
    let input= src;


  }
}