use std::{cmp::Ordering, io::Write, rc::Rc};

use byteorder::{ByteOrder, LittleEndian};

use crate::{
    errors::{DbError, Result},
    memdb::{Comparer, Key, Value},
};

use super::Iterator;

struct BlockReader {
    data: Vec<u8>,
    size: usize,
    restart_offset: usize,
}

struct BlockIter<'a> {
    key: Vec<u8>,
    value: Vec<u8>,

    restarts: usize, // Offset of trailer restart array (list of fixed32)

    start: usize, // current_ is offset in data_ of current entry.  >= restarts_ if !Valid
    num_shared: usize,
    shared: usize,
    num_non_shared: usize,
    non_shared: usize,
    value_length: usize,
    num_value: usize,

    restart_index: usize, // Index of restart block in which current_ falls
    num_restarts: usize,  // Number of uint32_t entries in restart array
    status: Option<String>,

    data: &'a Vec<u8>, // underlying block contents

    cmp: Rc<dyn Comparer>,
}

impl<'a> BlockIter<'a> {
    
    fn seek_to_first(&mut self) -> Result<()> {
        self.seek_to_restart_point(0);
        self.parse_next_key().map(|_| ())
    }

    fn seek_to_last(&mut self) -> Result<()> {
        self.seek_to_restart_point(self.num_restarts - 1);
        while self.parse_next_key()? && self.next_entry_offset() < self.restarts {
            // Keep skipping
        }
        Ok(())
    }

    fn decode_entry(&mut self) -> Result<()> {
        if self.restarts - self.start < 3 {
            return Err("error entry liength".to_string().into());
        }

        let (shared, num_shared) = super::get_uvarint(&self.data[self.start..]);
        if num_shared <= 0 {
            return Err(self.corrupted());
        }
        self.shared = shared as usize;
        self.num_shared = num_shared as usize;

        let (non_shared, num_nonshared) =
            super::get_uvarint(&self.data[self.start + (shared as usize)..]);
        if num_nonshared <= 0 {
            return Err(self.corrupted());
        }
        self.non_shared = non_shared as usize;
        self.num_non_shared = num_nonshared as usize;

        let value_len_offset = self.start + self.num_non_shared + self.num_shared;
        let (value_length, num_value) = super::get_uvarint(&self.data[value_len_offset..]);
        if num_value <= 0 {
            return Err(self.corrupted());
        }
        self.value_length = value_length as usize;
        self.num_value = num_value as usize;

        let key_offset = value_len_offset + num_value as usize;

        if self.key.len() < self.shared {
            return Err(self.corrupted());
        }

        self.key.truncate(shared as usize);
        let _ = self
            .key
            .write_all(&self.data[key_offset..key_offset + self.non_shared]);

        let value_offset = key_offset + self.non_shared;
        self.value.clear();
        let _ = self
            .value
            .write_all(&self.data[value_offset..value_offset + self.value_length]);

        Ok(())
    }

    fn parse_next_key(&mut self) -> Result<bool> {
        self.start = self.next_entry_offset();

        if self.start >= self.restarts {
            // No more entries to return.  Mark as invalid.
            self.start = self.restarts;
            self.restart_index = self.num_restarts;
            return Ok(false);
        };

        // Decode next entry
        self.decode_entry()?;

        // entry end
        while self.restart_index + 1 < self.num_restarts
            && self.get_restart_point(self.restart_index + 1) < self.start
        {
            self.restart_index += 1;
        }
        Ok(true)
    }

    fn next_entry_offset(&self) -> usize {
        self.start + self.num_shared + self.num_non_shared + self.non_shared + self.value_length
    }

    fn seek_to_restart_point(&mut self, index: usize) {
        //self.key.clear();
        //self.value.clear();

        self.restart_index = index;

        // current_ will be fixed by ParseNextKey();
        // ParseNextKey() starts at the end of value_, so set value_offset accordingly
        self.start = self.get_restart_point(index);
    }

    // Return the offset in data_ just past the end of the current entry.
    fn get_restart_point(&self, index: usize) -> usize {
        assert!(index < self.num_restarts);
        LittleEndian::read_u32(&self.data[self.restarts + index * 4..]) as usize
    }

    fn corrupted(&mut self) -> DbError {
        self.key.clear();
        self.value.clear();
        self.start = self.restarts;
        self.restart_index = self.num_restarts;
        let s = "bad entry in block".to_string();
        let err= s.clone().into();
        self.status = Some(s);
        err
    }

    fn status(&self) -> Result<()> {
        match &self.status {
            None => {Ok(())},
            Some(s) => {
                Err(s.clone().into())
            }
        }
    }
}

impl<'a> super::Iterator for BlockIter<'a> {
    fn next(&mut self) -> Result<()> {
        if !self.valid()? {
            return Err("Iterator in valid".to_string().into());
        }
        self.parse_next_key()?;
        Ok(())
    }

    fn prev(&mut self) -> Result<()> {
        if !self.valid()? {
            return Err("Iterator in valid".to_string().into());
        }

        // Scan backwards to a restart point before current_
        let original = self.start;
        while self.get_restart_point(self.restart_index) >= original {
            if self.restart_index == 0 {
                // No more entries
                self.start = self.restarts;
                self.restart_index = self.num_restarts;
            }
            self.restart_index -= 1;
        }

        self.seek_to_restart_point(self.restart_index);
        while {
            // Loop until end of current entry hits the start of original entry
            self.parse_next_key()? && self.next_entry_offset() < original
        } {}
        Ok(())
    }

    fn seek(&mut self, target: &Key) -> Result<()> {
        // Binary search in restart array to find the last restart point
        // with a key < target
        let mut left = 0;
        let mut right = self.num_restarts - 1;
        let mut current_less = false;

        if !self.valid()? {
            return Err("Iterator in valid".to_string().into());
        }

        // If we're already scanning, use the current position as a starting
        // point. This is beneficial if the key we're seeking to is ahead of the
        // current position.
        match self.cmp.compare(&self.key, target) {
            Ordering::Less => {
                left = self.restart_index;
                current_less = true;
            }
            Ordering::Greater => {
                right = self.restart_index;
            }
            Ordering::Equal => {}
        }

        while left < right {
            let mid = (left + right + 1) / 2;
            self.start = self.get_restart_point(mid);

            self.decode_entry()?;

            if self.shared != 0 {
                return Err(self.corrupted());
            }

            let mid_key = &self.key;
            if self.cmp.compare(mid_key, target).is_lt() {
                left = mid;
            } else {
                right = mid - 1;
            }
        }

        // We might be able to use our current position within the restart block.
        // This is true if we determined the key we desire is in the current block
        // and is after than the current key.
        let skip_seek = left == self.restart_index && current_less;
        if !skip_seek {
            self.seek_to_restart_point(left);
        }

        // Linear search (within restart block) for first key >= target
        loop {
            if !self.parse_next_key()? {
                return Ok(());
            }
            if self.cmp.compare(&self.key, target).is_ge() {
                return Ok(());
            }
        }
    }

    fn key(&self) -> &Key {
        &self.key
    }

    fn value(&self) -> &Value {
        &self.value
    }

    fn valid(&self) -> Result<bool> {
        self.status()?;
        Ok(self.start < self.restarts)
    }

}
