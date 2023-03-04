use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{api, util, Env};

// Return the name of the sstable with the specified number
// in the db named by "dbname".  The result will be prefixed with
// "dbname".
pub(crate) fn table_file_name(dbname: &str, number: u64) -> &str {
    todo!()
}

pub fn descriptor_file_name(dbname: &str, number: u64) -> String {
    assert!(number > 0);
    format!("{}/MANIFEST-{:06}", dbname, number)
}

pub fn set_current_file(env: &dyn Env, dbname: &str, descriptor_number: u64) -> api::Result<()> {
    // Remove leading "dbname/" and add newline to manifest file name
    let manifest = descriptor_file_name(dbname, descriptor_number);
    let mut contents = manifest.clone();
    assert!(contents.starts_with(dbname));
    contents.remove(dbname.len() - 1);
    assert!(contents.starts_with("/"));
    contents.remove(0);
    contents.push_str("\n");
    let tmp = temp_file_name(dbname, descriptor_number);
    util::write_string_to_file_sync(env, contents.as_bytes(), tmp.as_str())?;
    env.rename_file(tmp.as_str(), current_file_name(dbname).as_str())
        .map_err(|e| {
            let _ = env.remove_file(tmp.as_str());
            e
        })?;
    Ok(())
}

fn current_file_name(dbname: &str) -> String {
    format!("{}/CURRENT", dbname)
}

fn temp_file_name(dbname: &str, number: u64) -> String {
    assert!(number > 0);
    make_file_name(dbname, number, "dbtmp")
}

fn make_file_name(dbname: &str, number: u64, suffix: &str) -> String {
    format!("{}/{:06}.{}", dbname, number, suffix)
}

#[derive(PartialEq)]
pub(crate) enum FileType {
    LOG_FILE,
    DB_LOCK_FILE,
    TABLE_FILE,
    DESCRIPTOR_FILE,
    CURRENT_FILE,
    TEMP_FILE,
    INFO_LOG_FILE,
}

// If filename is a leveldb file, store the type of the file in *type.
// The number encoded in the filename is stored in *number.  If the
// filename was successfully parsed, returns true.  Else return false.
// Owned filenames have the form:
//    dbname/CURRENT
//    dbname/LOCK
//    dbname/LOG
//    dbname/LOG.old
//    dbname/MANIFEST-[0-9]+
//    dbname/[0-9]+.(log|sst|ldb)
pub(crate) fn parse_file_name(filename: &str) -> (bool, FileType) {
    todo!()
}
