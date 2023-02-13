use std::{sync::Arc, fs::FileType};

use crate::{
    api::{self, Comparator, ReadOptions},
    table::table::Table,
    Env, Options, RandomAccessFile, db::version::{GetStats, FileMetaData}, parse_internal_key, ValueType,
};

use super::{filename::table_file_name, memtable::InternalKeyComparator};

pub(crate) struct TableCache<C: api::Comparator> {
    dbname: &'static str,
    env: Env,
    options: Options<C>,
    icmp:InternalKeyComparator<C>,
}

impl<C: api::Comparator> TableCache<C> {
    pub(crate) fn new(dbname: &str, options: &Options<C>, entries: usize) -> Self {
        todo!()
    }

    // If a seek to internal key "k" in specified file finds an entry,
    // call (*handle_result)(arg, found_key, found_value).
    pub(crate) fn get(
        &self,
        options: &ReadOptions,
        file_number: u64,
        file_size: u64,
        ikey: &[u8],
        user_key:&[u8]
    ) -> api::Result<Vec<u8>> {
        //todo:cache

        let table = self.find_table(file_number, file_size)?;
        let value= table.internal_get(options, ikey)?;
        let (parsed_user_key, _, value_type) = parse_internal_key(ikey)?;  // todo: exception transforming
        if self.icmp.user_comparator().compare(parsed_user_key, user_key).is_eq() {
            match value_type {
                ValueType::TypeValue => {
                    return Ok(value)
                },
                ValueType::TypeDeletion => {
                    return Err(api::Error::NotFound)
                },
            }
        }
        Err(api::Error::Corruption("user_key != parsed user key".to_string()))
    }

    pub(crate) fn find_table(&self, file_number: u64, file_size: u64) -> api::Result<Table<C>> {
        // todo: cache lookup
        let filename = table_file_name(self.dbname, file_number);
        let file = self.env.new_posix_random_access_file(filename)?;
        let table = crate::table::table::Table::open(&self.options, file, file_size)?;
        Ok(table)
    }
}
