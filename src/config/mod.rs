pub const NUM_LEVELS: i32 = 7;

// Soft limit on number of level-0 files.  We slow down writes at this point.
pub const L0_SlowdownWritesTrigger: usize = 8;

// Level-0 compaction is started when we hit this many files.
pub const L0_COMPACTION_TRIGGER: usize = 4;
