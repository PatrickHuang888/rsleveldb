use crate::{api, util, WritableFile};

pub trait Writer {
    fn add_record(&mut self, record: &[u8]) -> api::Result<()>;
}

// fn init_type_crc(type_crc: u32) {}

pub struct LogWriter<W: WritableFile> {
    dest: W,
    block_offset: usize,
    // crc32c values for all supported record types.  These are
    // pre-computed to reduce the overhead of computing the crc of the
    // record type stored in the header.
    // type_crc
}

impl<W: WritableFile> LogWriter<W> {
    fn emit_physical_record(&mut self, t: RecordType, record: &[u8]) -> api::Result<()> {
        let length = record.len();
        assert!(length <= 0xffff); // Must fit in two bytes
        assert!(self.block_offset + HeaderSize + length <= BlockSize);

        // Format the header
        let mut buf = [0u8; HeaderSize];
        buf[4] = (length & 0xff) as u8;
        buf[5] = (length >> 8) as u8;
        buf[6] = t as u8;

        // Compute the crc of the record type and the payload.
        let crc = util::crc(record);
        util::encode_fixed32(&mut buf[..4], crc);

        // Write the header and the payload
        self.dest.append(&buf)?;
        self.dest.append(record)?;
        self.dest.flush()?;
        self.block_offset += HeaderSize + length;
        Ok(())
    }
}

impl<W: WritableFile> Writer for LogWriter<W> {
    fn add_record(&mut self, record: &[u8]) -> api::Result<()> {
        let mut ptr = 0;
        let mut left = record.len();

        // Fragment the record if necessary and emit it.  Note that if slice
        // is empty, we still want to iterate once to emit a single
        // zero-length record
        let mut begin = true;
        while left > 0 {
            let leftover = BlockSize - self.block_offset;
            assert!(leftover >= 0);
            if leftover < HeaderSize {
                // Switch to a new block
                if leftover > 0 {
                    // Fill the trailer (literal below relies on kHeaderSize being 7)
                    self.dest.append(&ZeroTrailer[..leftover]);
                }
                self.block_offset = 0;
            }

            // Invariant: we never leave < kHeaderSize bytes in a block.
            let avail = BlockSize - self.block_offset - HeaderSize;
            assert!(avail >= 0);
            let fragment_length = match left < avail {
                true => left,
                false => avail,
            };

            let r_type: RecordType;
            let end = left == fragment_length;
            if begin && end {
                r_type = RecordType::FullType;
            } else if begin {
                r_type = RecordType::FirstType;
            } else if end {
                r_type = RecordType::LastType;
            } else {
                r_type = RecordType::MiddleType;
            }

            self.emit_physical_record(r_type, &record[ptr..ptr + fragment_length])?;
            ptr += fragment_length;
            left -= fragment_length;
            begin = false;
        }
        Ok(())
    }
}

enum RecordType {
    // Zero is reserved for preallocated files
    ZeroType = 0,
    FullType = 1,
    // For fragments
    FirstType = 2,
    MiddleType = 3,
    LastType = 4,
}

const ZeroTrailer: [u8; HeaderSize] = [0; HeaderSize];

const MaxRecordType: usize = RecordType::LastType as usize;

const BlockSize: usize = 32768;

// Header is checksum (4 bytes), length (2 bytes), type (1 byte).
const HeaderSize: usize = 4 + 2 + 1;
