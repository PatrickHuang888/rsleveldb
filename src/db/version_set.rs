use crate::{
    util, SequenceNumber, api, config,
};

pub struct Version {
    // List of files per level
    files: Vec<Vec<Box<FileMetaData>>>,
}

#[derive(Default)]
struct FileMetaData {
    number: u64,
    file_size: u64, // File size in bytes
    smallest_key: Vec<u8>,
    largest_key: Vec<u8>,
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
    pub fn num_level_files(&self, level: u32) -> usize {
        assert!(level < config::NUM_LEVELS);
        self.current.files[level as usize].len()
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

pub(super) struct VersionEdit {
    compact_pointers: Vec<(u32, Vec<u8>)>, // (level, key)
    deleted_files: Vec<(u32, u64)>,        // (level, file_number)
    new_files: Vec<(u32, FileMetaData)>,

    comparator_name: Option<String>,
    log_number: Option<u64>,
    prev_log_number: Option<u64>,
    next_file_number: Option<u64>,
    last_sequence: Option<SequenceNumber>,
}

impl VersionEdit {
    fn set_comparator_name(&mut self, name:&str) {
        self.comparator_name= Some(name.to_string());
    }

    fn set_log_number(&mut self, num:u64) {
        self.log_number= Some(num);
    }

    fn set_prev_log_number(&mut self, num:u64) {
        self.prev_log_number= Some(num);
    }

    fn set_next_file(&mut self, num:u64) {
        self.next_file_number= Some(num);
    }

    fn set_last_sequence(&mut self, seq:SequenceNumber) {
        self.last_sequence= Some(seq);
    }

    fn set_compact_pointer(&mut self, level:u32, key:&[u8]) {
        self.compact_pointers.push((level, Vec::from(key)));
    }

    // Add the specified file at the specified number.
    // REQUIRES: This version has not been saved (see VersionSet::SaveTo)
    // REQUIRES: "smallest" and "largest" are smallest and largest keys in file
    fn add_file(&mut self, level: u32, file: u64, file_size: u64, smallest: &[u8], largest: &[u8]) {
        let f = FileMetaData {
            number: file,
            file_size,
            smallest_key: Vec::from(smallest),
            largest_key: Vec::from(largest),
        };
        self.new_files.push((level, f));
    }

    // Delete the specified "file" from the specified "level".
    fn remove_file(&mut self, level: u32, file: u64) {
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

        self.compact_pointers.iter().for_each(|(level, key)| {
            util::put_varint32(dst, Tag::CompactPointer as u32);
            util::put_varint32(dst, *level);
            util::put_length_prefixed_slice(dst, key);
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
            util::put_length_prefixed_slice(dst, &f.smallest_key);
            util::put_length_prefixed_slice(dst, &f.largest_key);
        });
    }

    fn decode_from(src: &[u8]) -> api::Result<Self> {
        let input = src;
        let offset = 0;

        let mut tag_size = 0;
        let mut tag_number;

        let mut comparator_name = None;
        let mut log_number = None;
        let mut prev_log_number = None;
        let mut next_file_number = None;
        let mut last_sequence = None;
        let mut compact_pointers = Vec::new();
        let mut deleted_files = Vec::new();
        let mut new_files = Vec::new();

        while offset < input.len() {
            (tag_number, tag_size) = util::get_varint32(&input[offset..])
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
                    let (k, k_size) = get_internal_key(&input[offset..])?;
                    offset += k_size;
                    let key = Vec::from(k);
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
                    f.smallest_key.extend_from_slice(smallest);
                    let (largest, s_size) = get_internal_key(&input[offset..])?;
                    offset += s_size;
                    f.largest_key.extend_from_slice(largest);

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

fn get_internal_key(input: &[u8]) -> api::Result<(&[u8], usize)> {
    util::get_length_prefixed_slice(input)
        .map_err(|_| api::Error::Corruption("get internal key".to_string()))
}
