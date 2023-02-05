use crate::{
    api::{self, Comparator, ReadOptions},
    Options, Env, table::table::Table,
};

use super::filename::table_file_name;

pub(super) struct TableCache<C:api::Comparator> {
    dbname:&'static str,
    env: Env,
    options:Options<C>,
}

impl<C:api::Comparator> TableCache<C> {
    pub(super) fn new(dbname: &str, options: &Options<C>, entries: usize) -> Self {
        todo!()
    }

    // If a seek to internal key "k" in specified file finds an entry,
    // call (*handle_result)(arg, found_key, found_value).
    fn get(
        &self,
        options: &ReadOptions,
        file_number: u64,
        file_size: u64,
        k: &[u8],
    ) -> api::Result<()> {
        let table= self.find_table(file_number, file_size)?;
        table.internal_get
    }

    pub(crate) fn find_table(&self, file_number:u64, file_size:u64) -> api::Result<Table<C>> {
        // todo: cache lookup
        let filename= table_file_name(self.dbname, file_number);
        let file= self.env.new_random_access_file(filename)?;
        let table= crate::table::table::Table::open(&self.options, file, file_size)?;
        Ok(table)
    }
}
