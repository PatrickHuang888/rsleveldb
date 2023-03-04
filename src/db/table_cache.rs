use crate::{
    api::{self, ReadOptions},
    db::version::{FileMetaData, GetStats},
    parse_internal_key,
    table::table::Table,
    Env, Options, PosixReadableFile, RandomAccessFile, ValueType,
};

use super::{filename::table_file_name, memtable::InternalKeyComparator};

pub(crate) struct TableCache<C: api::Comparator + 'static> {
    dbname: &'static str,

    options: Options<C>,
    icmp: InternalKeyComparator<C>,

    // todo:cache
    table: Option<Table<PosixReadableFile, C>>,
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
        user_key: &[u8],
        value: &mut Vec<u8>,
    ) -> api::Result<()> {
        //todo:cache
        let table = self.find_table(file_number, file_size)?;
        table.internal_get(options, ikey, value)?;
        let (parsed_user_key, _, value_type) = parse_internal_key(ikey)?; // todo: exception transforming
        if self
            .icmp
            .user_comparator()
            .compare(parsed_user_key, user_key)
            .is_eq()
        {
            match value_type {
                ValueType::TypeValue => return Ok(()),
                ValueType::TypeDeletion => return Err(api::Error::NotFound),
            }
        }
        Err(api::Error::Corruption(
            "user_key != parsed user key".to_string(),
        ))
    }

    pub(crate) fn new_iterator(
        &mut self,
        options: &ReadOptions,
        file_number: u64,
        file_size: u64,
    ) -> api::Result<Box<dyn api::Iterator + '_>> {
        let table = self.find_table(file_number, file_size)?;
        self.table = Some(table);
        let iter = self.table.as_ref().unwrap().new_iterator(options.clone());
        Ok(Box::new(iter))
    }

    fn find_table(
        &self,
        file_number: u64,
        file_size: u64,
    ) -> api::Result<Table<PosixReadableFile, C>> {
        // todo: cache lookup
        let filename = table_file_name(self.dbname, file_number);
        let file = self.options.env.new_posix_random_access_file(filename)?;
        let table = crate::table::table::Table::open(&self.options, file, file_size)?;
        Ok(table)
    }
}
