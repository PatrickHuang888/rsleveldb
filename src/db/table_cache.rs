use crate::{Options, api::{ReadOptions, self}};

pub(super) struct TableCache {}

impl TableCache {
    pub(super) fn new(dbname: &str, options: &Options, entries: usize) -> Self {
        TableCache {}
    }

    // If a seek to internal key "k" in specified file finds an entry,
  // call (*handle_result)(arg, found_key, found_value).
  fn get(&self, options:&ReadOptions, file_number:u64, file_size:u64, k:&[u8]) -> api::Result<()> {
    todo!()
  }
}
