use std::{
    cell::RefCell,
    ffi::OsStr,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

use crate::{api, util, Env};

// Return the name of the sstable with the specified number
// in the db named by "dbname".  The result will be prefixed with
// "dbname".
pub(crate) fn table_file_name(dbname: &str, number: u64) -> PathBuf {
    todo!()
}

pub fn descriptor_file_name(dbname: &str, number: u64) -> PathBuf {
    assert!(number > 0);
    todo!()
    //format!("{}/MANIFEST-{:06}", dbname, number)
}

pub fn set_current_file(env: &dyn Env, dbname: &str, descriptor_number: u64) -> api::Result<()> {
    todo!()
    // Remove leading "dbname/" and add newline to manifest file name
    /* let manifest = descriptor_file_name(dbname, descriptor_number);
    let mut contents = manifest.clone();
    assert!(contents.starts_with(dbname));
    contents.remove(dbname.len() - 1);
    assert!(contents.starts_with("/"));
    contents.remove(0);
    contents.push_str("\n");
    let tmp = temp_file_name(dbname, descriptor_number);
    util::write_string_to_file_sync(env, contents.as_os_str(), tmp.as_path())?;
    env.rename_file(tmp.as_path(), current_file_name(dbname).as_path())
        .map_err(|e| {
            let _ = env.remove_file(tmp.as_path());
            e
        })?;
    Ok(()) */
}

fn current_file_name(dbname: &str) -> PathBuf {
    todo!()
    //format!("{}/CURRENT", dbname)
}

fn temp_file_name(dbname: &str, number: u64) -> PathBuf {
    assert!(number > 0);
    make_file_name(dbname, number, "dbtmp")
}

fn make_file_name(dbname: &str, number: u64, suffix: &str) -> PathBuf {
    todo!()
    //format!("{}/{:06}.{}", dbname, number, suffix)
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
pub(crate) fn parse_file_name(f: &Path) -> api::Result<(FileType, u64)> {
    if let Some(name) = f.to_str() {
        match name {
            "CURRENT" => return Ok((FileType::CURRENT_FILE, 0)),
            "LOCK" => {
                return Ok((FileType::DB_LOCK_FILE, 0));
            }
            "LOG" => {
                return Ok((FileType::INFO_LOG_FILE, 0));
            }
            "LOG.old" => {
                return Ok((FileType::INFO_LOG_FILE, 0));
            }
            _ => {
                if name.starts_with("MANIFEST-") {
                    if let Some(rest) = name.strip_prefix("MANIFEST-") {
                        let num = rest.parse::<u64>().map_err(|_| {
                            api::Error::IOError("parse MANIFEST number error".to_string())
                        })?;
                        return Ok((FileType::DESCRIPTOR_FILE, num));
                    }
                } else {
                    if let Some(prefix) = f.file_stem() {
                        if let Some(prefix) = prefix.to_str() {
                            let num = prefix.parse::<u64>().map_err(|_| {
                                api::Error::IOError("parse number error".to_string())
                            })?;
                            if let Some(ext) = f.extension() {
                                if let Some(ext) = ext.to_str() {
                                    match ext {
                                        "log" => {
                                            return Ok((FileType::LOG_FILE, num));
                                        }
                                        "sst" => return Ok((FileType::TABLE_FILE, num)),
                                        "ldb" => return Ok((FileType::TABLE_FILE, num)),
                                        "dbtmp" => return Ok((FileType::TEMP_FILE, num)),
                                        _ => {
                                            return Err(api::Error::IOError(
                                                "file extension not recognize".to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return Err(api::Error::IOError("filetype not recognize".to_string()));
            }
        }
    }
    Err(api::Error::Other("file name encoding errror".to_string()))
}
