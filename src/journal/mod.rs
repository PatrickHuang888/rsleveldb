//!
//! Neither Readers or Writers are safe to use concurrently.
//!
//! When writing, call next() to obtain an io.Writer for the next journal. Calling
//! next() finishes the current journal. Call Close to finish the final journal.
//!
//! The wire format is that the stream is divided into 32KiB blocks, and each
//! block contains a number of tightly packed chunks. Chunks cannot cross block
//! boundaries. The last block may be shorter than 32 KiB. Any unused bytes in a
//! block must be zero.
//!
//! A journal maps to one or more chunks. Each chunk has a 7 byte header (a 4
//! byte checksum, a 2 byte little-endian uint16 length, and a 1 byte chunk type)
//! followed by a payload. The checksum is over the chunk type and the payload.
//!
//! There are four chunk types: whether the chunk is the full journal, or the
//! first, middle or last chunk of a multi-chunk journal. A multi-chunk journal
//! has one first chunk, zero or more middle chunks, and one last chunk.
//!
//! The wire format allows for limited recovery in the face of data corruption:
//! on a format error (such as a checksum mismatch), the reader moves to the
//! next block and looks for the next full or first chunk.

use byteorder::{ByteOrder, LittleEndian};
use crc::{Crc, CRC_32_ISCSI};
use std::boxed::Box;
use std::io;

pub const HEADER_SIZE: usize = 7;
const BLOCK_SIZE: usize = 32 * 1024;

const FULL_CHUNK_TYPE: u8 = 1;
const FIRST_CHUNK_TYPE: u8 = 2;
const MIDDLE_CHUNK_TYPE: u8 = 3;
const LAST_CHUNK_TYPE: u8 = 4;

const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub struct Writer {
    w: Box<dyn io::Write>,

    i: usize,
    j: usize,

    // buf[:written] has already been written to w.
    // written is zero unless Flush has been called.
    written: usize,

    buf: [u8; BLOCK_SIZE],

    // first is whether the current chunk is the first chunk of the journal.
    first: bool,
}

impl Writer {
    pub fn new(write: Box<dyn io::Write>) -> Self {
        Self {
            w: write,
            i: 0,
            j: 0,
            written: 0,
            buf: [0; BLOCK_SIZE],
            first: false,
        }
    }

    pub fn next(&self) -> Result<impl io::Write, JournalError> {}

    // fillHeader fills in the header for the pending chunk.
    fn fillHeader(&mut self, last: bool) {
        if self.i + HEADER_SIZE > self.j || self.j > BLOCK_SIZE {
            panic!("leveldb/journal: bad writer state")
        }

        // buf[HEADER_SIZE-1] is chunktype
        if last {
            if self.first {
                self.buf[self.i + HEADER_SIZE - 1] = FULL_CHUNK_TYPE
            } else {
                self.buf[self.i + HEADER_SIZE - 1] = LAST_CHUNK_TYPE
            }
        } else {
            if self.first {
                self.buf[self.i + HEADER_SIZE - 1] = FIRST_CHUNK_TYPE
            } else {
                self.buf[self.i + HEADER_SIZE - 1] = MIDDLE_CHUNK_TYPE
            }
        }

        let value = CASTAGNOLI.checksum(&self.buf[self.i + HEADER_SIZE - 1..self.j]);
        // chunk header is 4 bytes checksum
        LittleEndian::write_u32(&mut self.buf[self.i..self.i + 4], value);
        // 2 bytes length
        LittleEndian::write_u16(
            &mut self.buf[self.i + 4..self.i + 6],
            (self.j - self.i - HEADER_SIZE).try_into().unwrap(),
        );
    }

    // writeBlock writes the buffered block to the underlying writer, and reserves
    // space for the next chunk's header.
    fn writeBlock(&mut self) -> Result<(), JournalError> {
        if self.written + 1 == BLOCK_SIZE {
            panic!("no bytes to written")
        }

        let n = self.w.write(&self.buf[self.written..])?;

        if n != BLOCK_SIZE - self.written {
            return Err(JournalError::WriteError(String::from(
                "not finish writting block",
            )));
        }

        self.i = 0;
        self.j = HEADER_SIZE;
        self.written = 0;
        Ok(())
    }
}

#[derive(Debug)]
pub enum JournalError {
    WriteError(String),
}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        JournalError::WriteError(error.to_string())
    }
}

/* impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JournalError::WriteError(s) => write!(f, "journal write error {}", s),
            JournalError::ReadError(s) => write!(f, "journal read error {}", s),
        }
    }
} */
