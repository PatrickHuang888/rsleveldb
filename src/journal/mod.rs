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
use std::io;

use crate::util;

const HEADER_SIZE: usize = 7;
const BLOCK_SIZE: usize = 32 * 1024;

const FULL_CHUNK_TYPE: u8 = 1;
const FIRST_CHUNK_TYPE: u8 = 2;
const MIDDLE_CHUNK_TYPE: u8 = 3;
const LAST_CHUNK_TYPE: u8 = 4;

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

        let value = util::crc(&self.buf[self.i + HEADER_SIZE - 1..self.j]);
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

// Reader reads journals from an underlying io.Reader.
pub struct Reader<'a> {
    r: &'a mut dyn io::Read,

    strict: bool,

    checksum: bool,

    // sequence number of the current journal.
    seq: i32,
    cur_seq: i32,

    // buf[i:j] is the unread portion of the current chunk's payload.
    // The low bound, i, excludes the chunk header.
    i: usize,
    j: usize,

    // n is the number of bytes of buf that are valid. Once reading has started,
    // only the final block can have n < blockSize.
    n: usize,

    // last is whether the current chunk is the last chunk of the journal.
    last: bool,

    buf: [u8; BLOCK_SIZE],
}

impl<'a> Reader<'a> {
    pub fn new(r: &'a mut dyn io::Read, strict: bool, checksum: bool) -> Self {
        Self {
            r: r,
            strict: strict,
            checksum: checksum,
            seq: 0,
            cur_seq: 0,
            i: 0,
            j: 0,
            n: 0,
            last: true,
            buf: [0; BLOCK_SIZE],
        }
    }

    // returns a reader for the next journal.
    // if strict is false, the reader will returns io::ErrUnexpectedEOF error when found corrupted journal.
    // using for first ?
    pub fn next(&mut self) -> io::Result<()> {
        self.seq += 1;
        self.cur_seq = self.seq;
        self.i = self.j;

        self.next_chunk(true)?;

        Ok(())
    }

    // sets r.buf[r.i:r.j] to hold the next chunk's payload, reading the
    // next block into the buffer if necessary.
    fn next_chunk(&mut self, first: bool) -> io::Result<()> {
        loop {
            if self.j + HEADER_SIZE <= self.n {
                let checksum = LittleEndian::read_u32(&self.buf[self.j..self.j + 4]);
                let length = LittleEndian::read_u16(&self.buf[self.j + 4..self.j + 6]);
                let chunk_type = self.buf[self.j + 6];
                //let unproc_block = self.n - self.j;

                if checksum == 0 && length == 0 && chunk_type == 0 {
                    // drop block
                    self.i = self.n;
                    self.j = self.n;
                    self.corrupt("zero header", false)?;
                }

                if chunk_type < FULL_CHUNK_TYPE || chunk_type > LAST_CHUNK_TYPE {
                    // drop block
                    self.i = self.n;
                    self.j = self.n;
                    self.corrupt("invalid chunk type", false)?;
                }

                self.i = self.j + HEADER_SIZE;
                self.j += HEADER_SIZE + usize::from(length);

                if self.j > self.n {
                    // drop block
                    self.i = self.n;
                    self.j = self.n;
                    self.corrupt("chunk length overflows block", false)?;
                } else if self.checksum && checksum != util::crc(&self.buf[self.i - 1..self.j]) {
                    // drop block
                    self.i = self.n;
                    self.j = self.n;
                    self.corrupt("checksum mismatch", false)?;
                }

                if first && chunk_type != FULL_CHUNK_TYPE && chunk_type != FIRST_CHUNK_TYPE {
                    //let chunk_length= (self.j-self.i) +HEADER_SIZE;
                    self.i = self.j;
                    self.corrupt("orphan chunk", true)?;
                }

                self.last = chunk_type == FULL_CHUNK_TYPE || chunk_type == LAST_CHUNK_TYPE;
                return Ok(());
            }

            // the last block.
            if self.n < BLOCK_SIZE && self.n > 0 {
                if !first {
                    self.corrupt("missing chunk part", false)?;
                }
                return Ok(());
            }

            // read block
            let n = self.r.read(&mut self.buf)?;
            self.i = 0;
            self.j = 0;
            self.n = n;

            if n == 0 {
                if !first {
                    self.corrupt("missing chunk part, no data", false)?;
                }
                return Ok(());
            }
        }
    }

    fn corrupt(&self, reason: &str, skip: bool) -> io::Result<()> {
        if self.strict && !skip {
            return Err(io::Error::new(io::ErrorKind::Other, reason));
        }
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, reason))
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cur_seq != self.seq || self.seq == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "new or staled reader, call next first",
            ));
        }

        while self.i == self.j {
            if self.last {
                return Ok(0);
            }
            self.next_chunk(false)?;
        }

        let mut n = buf.len();
        if n > self.j - self.i {
            n = self.j - self.i;
        }
        buf[..n].copy_from_slice(&self.buf[self.i..self.i + n]);
        self.i += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::journal::{Reader, Writer};

    #[test]
    fn test_flush() {
        let mut buf: Vec<u8> = Vec::new();

        {
            let mut w = Writer::new(&mut buf);
            write_1(&mut w);
            assert!(w.flush().is_ok());
        }
        assert_eq!(buf.len(), 17); // 2*7 + 1 + 2
        buf.clear();

        {
            let mut w = Writer::new(&mut buf);
            write_1(&mut w);
            assert!(w.flush().is_ok());
            write_2(&mut w);
        }
        assert_eq!(buf.len(), 17); // not flush yet
        buf.clear();

        {
            let mut w = Writer::new(&mut buf);
            write_1(&mut w);
            write_2(&mut w);
            assert!(w.flush().is_ok());
        }
        assert_eq!(buf.len(), 10024); // after flush
        buf.clear();

        // Do a bigger write, one that completes the current block.
        // We should now have 32768 bytes (a complete block), without
        // an explicit flush.
        {
            let mut w = Writer::new(&mut buf);
            write_1(&mut w);
            write_2(&mut w);
            write_3(&mut w);
        }
        assert_eq!(buf.len(), 32768); // not flush, just 1 block
        buf.clear();

        {
            let mut w = Writer::new(&mut buf);
            write_1(&mut w);
            write_2(&mut w);
            write_3(&mut w);
            assert!(w.flush().is_ok());
        }
        assert_eq!(buf.len(), 50038); // 50038 = 10024 + 2*7 + 40000

        {
            let mut read_buf: [u8; 40001] = [0; 40001];
            let mut bb = &buf[..];
            let mut r = Reader::new(&mut bb, true, true);

            let wants = vec![1, 2, 10000, 40000];
            for want in wants {
                assert!(r.next().is_ok());

                let mut count = 0;
                loop {
                    let r = r.read(&mut read_buf);
                    let n = match r {
                        Ok(n) => n,
                        Err(error) => panic!("read error {}", error),
                    };
                    if n == 0 {
                        break;
                    }
                    count += n;
                }
                assert_eq!(count, want);
            }
        }
    }

    fn write_1(w: &mut Writer) {
        assert!(w.next().is_ok());
        let b0: [u8; 1] = [0];
        assert!(w.write(&b0).is_ok());

        assert!(w.next().is_ok());
        let b1: [u8; 2] = [1, 1];
        assert!(w.write(&b1).is_ok());
    }

    fn write_2(w: &mut Writer) {
        assert!(w.next().is_ok());
        let b2: [u8; 10000] = [2; 10000];
        assert!(w.write(&b2).is_ok());
    }

    fn write_3(w: &mut Writer) {
        assert!(w.next().is_ok());
        let b2: [u8; 40000] = [3; 40000];
        assert!(w.write(&b2).is_ok());
    }

    #[test]
    fn test_basic() {
        let mut buf: Vec<u8> = Vec::new();
        let mut w = Writer::new(&mut buf);

        write_literal(&mut w, 'a', 1000);
        write_literal(&mut w, 'b', 97270);
        write_literal(&mut w, 'c', 8000);

        assert!(w.flush().is_ok());

        let mut read_buf: [u8; 99999] = [0; 99999];
        let mut bb = &buf[..];
        let mut r = Reader::new(&mut bb, true, true);

        assert!(r.next().is_ok());
        let n = r.read(&mut read_buf).unwrap();
        assert_eq!(n, 1000);

        assert!(r.next().is_ok());
        let mut n = 0;
        loop {
            let nn = r.read(&mut read_buf).unwrap();
            if nn == 0 {
                break;
            }
            n += nn;
        }
        assert_eq!(n, 97270);

        assert!(r.next().is_ok());
        let n = r.read(&mut read_buf).unwrap();
        assert_eq!(n, 8000);

        assert!(r.next().is_ok());
        let n = r.read(&mut read_buf).unwrap();
        assert_eq!(n, 0);
    }

    fn write_literal(w: &mut Writer, c: char, count: usize) {
        let mut s = std::string::String::new();
        for _ in 0..count {
            s.push(c);
        }

        assert!(w.next().is_ok());
        assert!(w.write(s.as_bytes()).is_ok());
    }

    #[test]
    fn test_empty() {
        let buf: Vec<u8> = Vec::new();
        let mut bb = &buf[..];
        let mut r = Reader::new(&mut bb, true, true);

        assert!(r.next().is_ok());

        let mut read_buf: [u8; 10] = [0; 10];
        let n = r.read(&mut read_buf).unwrap();
        assert_eq!(n, 0);
    }
}
