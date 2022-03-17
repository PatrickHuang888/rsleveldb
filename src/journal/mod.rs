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
use std::io;

const HEADER_SIZE: usize = 7;
const BLOCK_SIZE: usize = 32 * 1024;

const FULL_CHUNK_TYPE: u8 = 1;
const FIRST_CHUNK_TYPE: u8 = 2;
const MIDDLE_CHUNK_TYPE: u8 = 3;
const LAST_CHUNK_TYPE: u8 = 4;

const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub struct Writer<'a> {
    w: &'a mut (dyn io::Write),

    // buf[i:j] is the bytes that will become the current chunk.
    // The low bound, i, includes the chunk header.
    i: usize,
    j: usize,

    // seq is the sequence number of the current journal.
    seq: i32,
    // seq current
    cur_seq: i32,

    // pending is whether a chunk is buffered but not yet written.
    pending: bool,

    // buf[:written] has already been written to w.
    // written is zero unless Flush has been called.
    written: usize,

    buf: [u8; BLOCK_SIZE],

    // first is whether the current chunk is the first chunk of the journal.
    first: bool,
}

impl<'a> Writer<'a> {
    pub fn new(write: &'a mut dyn io::Write) -> Self {
        Self {
            w: write,
            i: 0,
            j: 0,
            seq: 0,
            cur_seq: 0,
            pending: false,
            written: 0,
            buf: [0; BLOCK_SIZE],
            first: false,
        }
    }

    // next journal
    // The writer stale after the next Close, Flush or Next call,
    // and should no longer be used.
    pub fn next(&mut self) -> io::Result<()> {
        self.seq += 1;

        if self.pending {
            self.fill_header(true);
        }
        self.i = self.j;
        self.j = self.j + HEADER_SIZE;

        // Check if there is room in the block for the header.
        if self.j > BLOCK_SIZE {
            // Fill in the rest of the block with zeroes.
            for k in self.i..BLOCK_SIZE {
                self.buf[k] = 0;
            }
            self.write_block()?
        }

        self.first = true;
        self.pending = true;
        self.cur_seq = self.seq;
        Ok(())
    }

    // fillHeader fills in the header for the pending chunk.
    fn fill_header(&mut self, last: bool) {
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
    fn write_block(&mut self) -> io::Result<()> {
        if self.written + 1 == BLOCK_SIZE {
            panic!("no bytes to written")
        }

        self.w.write_all(&self.buf[self.written..])?;

        self.i = 0;
        self.j = HEADER_SIZE;
        self.written = 0;
        Ok(())
    }

    // flush the current journal, writes to the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.seq += 1;
        self.write_pending()?;
        self.w.flush()?;
        Ok(())
    }

    // finishes the current journal and writes the buffer to the
    // underlying writer.
    fn write_pending(&mut self) -> io::Result<()> {
        if self.pending {
            self.fill_header(true);
            self.pending = false;
        }

        self.w.write_all(&self.buf[self.written..self.j])?;
        self.written = self.j;
        Ok(())
    }

    // write all buf
    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.cur_seq != self.seq || self.seq == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "new or staled writer, call next first",
            ));
        }

        let mut p = buf;
        while !p.is_empty() {
            // write a block, if it is full.
            if self.j == BLOCK_SIZE {
                self.fill_header(false);
                self.write_block()?;
                self.first = false;
            }
            // Copy bytes into the buffer.
            let mut n = p.len();
            if p.len() > BLOCK_SIZE - self.j {
                n = BLOCK_SIZE - self.j;
            }
            self.buf[self.j..self.j + n].copy_from_slice(&p[..n]);
            self.j += n;
            p = &p[n..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::journal::Writer;

    #[test]
    fn test_flush() {
        let mut buf: Vec<u8> = Vec::new();

        {
            let mut w = Writer::new(&mut buf);

            assert!(w.next().is_ok());
            let b0: [u8; 1] = [0];
            assert!(w.write(&b0).is_ok());

            assert!(w.next().is_ok());
            let b1: [u8; 2] = [1, 1];
            assert!(w.write(&b1).is_ok());

            assert!(w.flush().is_ok());
        }
        assert_eq!(buf.len(), 17); // 2*7 + 1 + 2

        {
            let mut w = Writer::new(&mut buf);
            assert!(w.next().is_ok());
            let b2: [u8; 1000] = [2; 1000];
            assert!(w.write(&b2).is_ok());
        }
        assert_eq!(buf.len(), 17); // not flush to buf yet

        {
            let mut w = Writer::new(&mut buf);
            assert!(w.next().is_ok());
            let b2: [u8; 10000] = [2; 10000];
            assert!(w.write(&b2).is_ok());
            assert!(w.flush().is_ok());
        }
        assert_eq!(buf.len(), 10024);

        // Do a bigger write, one that completes the current block.
        // We should now have 32768 bytes (a complete block), without
        // an explicit flush.
        {
            let mut w = Writer::new(&mut buf);
            assert!(w.next().is_ok());
            let b2: [u8; 40000] = [3; 40000];
            assert!(w.write(&b2).is_ok());
        }
        assert_eq!(buf.len(), 10024+32768); // 10024 + 1 block
        buf.truncate(10024);

        {
            let mut w = Writer::new(&mut buf);
            assert!(w.next().is_ok());
            let b2: [u8; 40000] = [3; 40000];
            assert!(w.write(&b2).is_ok());
            assert!(w.flush().is_ok());
        }
        assert_eq!(buf.len(), 50038); // 50038 = 10024 + 2*7 + 40000
    }
}
