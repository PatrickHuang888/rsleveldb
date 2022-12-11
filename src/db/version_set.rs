use crate::config;

pub struct Version {
    // List of files per level
    files: Vec<Vec<Box<FileMetaData>>>,
}

struct FileMetaData {}

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

pub(super) struct VersionEdit {
    compact_pointers: Vec<(usize, InternalKey)>,
    delete_fileset: Vec<(usize, usize)>,
}
