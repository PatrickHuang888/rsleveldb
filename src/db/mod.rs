use crate::{api, util, Options};

mod dbimpl;
mod log;
pub mod memtable;
mod skiplist;
mod version_set;
mod write_batch;

type SequenceNumber = u64;

// Value types encoded as the last component of internal keys.
// DO NOT CHANGE THESE ENUM VALUES: they are embedded in the on-disk
// data structures.
pub enum ValueType {
    TypeDeletion = 0x0,
    TypeValue = 0x1,
}

impl From<u64> for ValueType {
    fn from(v: u64) -> Self {
        match v {
            0x0 => Self::TypeDeletion,
            0x1 => Self::TypeValue,
            _ => panic!("value type known!"),
        }
    }
}

// We leave eight bits empty at the bottom so a type and sequence#
// can be packed together into 64-bits.
pub const MAX_SEQUENCE_NUMBER: SequenceNumber = (0x1u64 << 56) - 1;

pub(super) fn pack_sequence_and_type(seq: u64, t: ValueType) -> u64 {
    assert!(seq <= MAX_SEQUENCE_NUMBER);
    //assert!(t<=ValueTypeForSeek);
    (seq << 8) | t as u64
}

pub(super) fn parse_internal_key<'a>(
    internal_key: &'a [u8],
) -> api::Result<(&'a [u8], SequenceNumber, ValueType)> {
    // user_key, sequence, valuetype
    let mut n = internal_key.len();
    if n < 8 {
        return Err(api::Error::Other(("internal key < 8").to_string()));
    }
    let num = util::decode_fixed64(&internal_key[n - 8..]);
    let c = num & 0xff;
    let sequence = num >> 8;
    let t = ValueType::from(c);
    let user_key = &internal_key[..n - 8];
    Ok((user_key, sequence, t))
}

mod test {
    use std::{default, env, ops::AddAssign};

    use crate::api::{self, ReadOptions, Snapshot};

    use super::dbimpl::DB;

    const OptionConfig_Default: u8 = 0;
    const OptionConfig_Reuse: u8 = 1;
    const OptionConfig_Filter: u8 = 2;
    const OptionConfig_Uncompressed: u8 = 3;
    const OptionConfig_End: u8 = 4;

    struct DBTest {
        option_config: u8,
        //db: Box<dyn DB>,
        dbname: String,
    }

    impl DBTest {
        fn new() -> Self {
            let temp_dir = String::from(env::temp_dir().to_str().unwrap()).push_str("db_test");
            //let options:Options
            DBTest {
                dbname: String::from("name"),
                option_config: OptionConfig_Default,
            }
        }

        // Switch to a fresh database with the next option configuration to
        // test.  Return false if there are no more configurations to test.
        fn change_options(&mut self) -> bool {
            self.option_config += 1;
            if self.option_config >= OptionConfig_End {
                return false;
            } else {
                self.destroy_and_reopen();
                return true;
            }
        }

        fn destroy_and_reopen(&mut self) {
            //destroy_db
        }

        /* fn get(&self, k: &str, snapshot: Option<Snapshot>) -> api::Result<String> {
            let mut options: ReadOptions = Default::default();
            options.snapshot = snapshot;
            let r= self.db.get(&options, k.as_bytes())?;
            Ok(String::from_utf8(r).unwrap())
        } */
    }

    #[test]
    fn test_empty() {
        let db_test = DBTest::new();
        /* loop {
            assert_eq!(db_test.get("foo", None), Err(api::Error::NotFound))
            if db_test.change_options() {
                break;
            }
        } */
    }
}
