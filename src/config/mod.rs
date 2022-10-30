pub const NumLevels: usize = 7;

// Soft limit on number of level-0 files.  We slow down writes at this point.
pub const L0_SlowdownWritesTrigger: usize = 8;
