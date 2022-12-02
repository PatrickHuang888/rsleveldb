use crate::{api, util, SequentialFile, WritableFile};

pub trait Reporter {
    // Some corruption was detected.  "bytes" is the approximate number
    // of bytes dropped due to the corruption.
    fn corruption(&mut self, bytes: usize, status: &str);
}

// Read the next record into *record.  Returns true if read
// successfully, false if we hit end of the input.  May use
// "*scratch" as temporary storage.  The contents filled in *record
// will only be valid until the next mutating operation on this
// reader or the next mutation to *scratch.
pub struct Reader<F: SequentialFile, R: Reporter> {
    file: F,
    reporter: Option<R>,

    // Offset of the last record returned by ReadRecord.
    last_record_offset: usize,
    // Offset at which to start looking for the first record to return
    initial_offset: usize,
    // Offset of the first location past the end of buffer_.
    end_of_buffer_offset: usize,
    buffer: Vec<u8>,
    backing_store: Vec<u8>,
    // True if we are resynchronizing after a seek (initial_offset_ > 0). In
    // particular, a run of kMiddleType and kLastType records can be silently
    // skipped in this mode
    resyncing: bool,
    // Last Read() indicated EOF by returning < kBlockSize
    eof: bool,
    checksum: bool,
}

impl<F: SequentialFile, R: Reporter> Reader<F, R> {
    pub fn new(file: F, reporter: Option<R>, initial_offset: usize, checksum: bool) -> Self {
        let mut resyncing = false;
        if initial_offset > 0 {
            resyncing = true;
        }
        Self {
            file,
            reporter,
            last_record_offset: 0,
            initial_offset,
            end_of_buffer_offset: 0,
            buffer: Vec::new(),
            backing_store: Vec::with_capacity(BLOCK_SIZE),
            resyncing,
            eof: false,
            checksum,
        }
    }

    // Read the next record into *record.  Returns true if read
    // successfully, false if we hit end of the input.  May use
    // "*scratch" as temporary storage.  The contents filled in *record
    // will only be valid until the next mutating operation on this
    // reader or the next mutation to *scratch.
    pub fn read_record(&mut self, record: &mut Vec<u8>, scratch: &mut Vec<u8>) -> bool {
        if self.last_record_offset < self.initial_offset {
            if !self.skip_to_initial_block() {
                return false;
            }
        }

        scratch.clear();
        record.clear();
        let mut in_fragmented_record = false;

        // Record offset of the logical record that we're reading
        // 0 is a dummy value to make compilers happy
        // ??
        let mut prospective_record_offset = 0;

        let mut fragment = Vec::new();
        loop {
            let record_type = self.read_physical_record(&mut fragment);

            // ReadPhysicalRecord may have only had an empty trailer remaining in its
            // internal buffer. Calculate the offset of the next physical record now
            // that it has returned, properly accounting for its header size.
            let mut physical_record_offset = 0;
            if self.end_of_buffer_offset != 0 {
                physical_record_offset =
                    self.end_of_buffer_offset - self.buffer.len() - HEADER_SIZE - fragment.len();
            }

            if self.resyncing {
                match record_type {
                    RecordType::Middle => {
                        continue;
                    }
                    RecordType::Last => {
                        self.resyncing = false;
                        continue;
                    }
                    _ => {
                        self.resyncing = false;
                    }
                }
            }

            match record_type {
                RecordType::Full => {
                    if in_fragmented_record {
                        // Handle bug in earlier versions of log::Writer where
                        // it could emit an empty kFirstType record at the tail end
                        // of a block followed by a kFullType or kFirstType record
                        // at the beginning of the next block.
                        if !scratch.is_empty() {
                            self.report_corruption(
                                scratch.len(),
                                "partial record without end(1)",
                            );
                        }
                    }
                    prospective_record_offset = physical_record_offset;
                    scratch.clear();
                    record.extend_from_slice(&fragment);
                    self.last_record_offset = prospective_record_offset;
                    return true;
                }

                RecordType::First => {
                    if in_fragmented_record {
                        // Handle bug in earlier versions of log::Writer where
                        // it could emit an empty kFirstType record at the tail end
                        // of a block followed by a kFullType or kFirstType record
                        // at the beginning of the next block.
                        if !scratch.is_empty() {
                            self.report_corruption(
                                scratch.len(),
                                "partial record without end(2)",
                            );
                        }
                    }
                    prospective_record_offset = physical_record_offset;
                    scratch.extend_from_slice(&fragment);
                    in_fragmented_record = true;
                }

                RecordType::Middle => {
                    if !in_fragmented_record {
                        self.report_corruption(
                            fragment.len(),
                            "missing start of fragmented record(1)",
                        );
                    } else {
                        scratch.extend_from_slice(&fragment);
                    }
                }

                RecordType::Last => {
                    if !in_fragmented_record {
                        self.report_corruption(
                            fragment.len(),
                            "missing start of fragmented record(2)",
                        );
                    } else {
                        scratch.extend_from_slice(&fragment);
                        record.extend_from_slice(&scratch);
                        self.last_record_offset = prospective_record_offset;
                        return true;
                    }
                }

                RecordType::Eof => {
                    if in_fragmented_record {
                        // This can be caused by the writer dying immediately after
                        // writing a physical record but before completing the next; don't
                        // treat it as a corruption, just ignore the entire logical record.
                        scratch.clear();
                    }
                    return false;
                }

                RecordType::BadRecord => {
                    if in_fragmented_record {
                        self.report_corruption(
                            scratch.len(),
                            "error in middle of record",
                        );
                        in_fragmented_record = false;
                        scratch.clear();
                    }
                }

                _ => {
                    let mut l = 0;
                    if in_fragmented_record {
                        l = scratch.len();
                    }
                    self.report_corruption(fragment.len() + l, "unknown record type");
                    in_fragmented_record = false;
                    scratch.clear();
                }
            }
        }
    }

    // Returns the physical offset of the last record returned by ReadRecord.
    //
    // Undefined before the first call to ReadRecord.
    pub fn last_record_offset(&self) -> usize {
        self.last_record_offset
    }

    // Skips all blocks that are completely before "initial_offset_".
    //
    // Returns true on success. Handles reporting.
    fn skip_to_initial_block(&mut self) -> bool {
        let offset_in_block = self.initial_offset % BLOCK_SIZE;
        let mut block_start_location = self.initial_offset - offset_in_block;

        // Don't search a block if we'd be in the trailer
        if offset_in_block > BLOCK_SIZE - 6 {
            block_start_location += BLOCK_SIZE;
        }

        self.end_of_buffer_offset = block_start_location;

        // Skip to start of first block that can contain the initial record
        if block_start_location > 0 {
            let _ = self.file.skip(block_start_location).map_err(|e| {
                self.report_drop(block_start_location, e.to_string().as_str());
            });
            return false;
        }

        true
    }

    fn report_drop(&mut self, bytes: usize, reason: &str) {
        /* if self.end_of_buffer_offset - self.buffer.len() - bytes >= self.initial_offset {
            if let Some(reporter) = &mut self.reporter {
                reporter.corruption(bytes, reason);
            }
        } */
            if let Some(reporter) = &mut self.reporter {
                reporter.corruption(bytes, reason);
            }
    }

    fn report_corruption(&mut self, bytes: usize, reason: &str) {
        self.report_drop(bytes, reason)
    }

    // Return type, or one of the preceding special values
    fn read_physical_record(&mut self, result: &mut Vec<u8>) -> RecordType {
        loop {
            if self.buffer.len() < HEADER_SIZE {
                if !self.eof {
                    // Last read was a full read, so this is a trailer to skip
                    self.buffer.clear();
                    match self
                        .file
                        .read(BLOCK_SIZE, &mut self.buffer, &mut self.backing_store)
                    {
                        Ok(_) => {
                            if self.buffer.len() < BLOCK_SIZE {
                                self.eof = true;
                            }
                        }
                        Err(e) => {
                            self.buffer.clear();
                            self.report_drop(BLOCK_SIZE, e.to_string().as_str());
                            self.eof = true;
                            return RecordType::Eof;
                        }
                    }
                    continue;
                } else {
                    // Note that if buffer_ is non-empty, we have a truncated header at the
                    // end of the file, which can be caused by the writer crashing in the
                    // middle of writing the header. Instead of considering this an error,
                    // just report EOF.
                    self.buffer.clear();
                    return RecordType::Eof;
                }
            }

            // Parse the header
            let buf = &self.buffer;
            let a = buf[4] as usize & 0xff;
            let b = buf[5] as usize & 0xff;
            let tp = RecordType::from(buf[6]);
            let length = a | (b << 8);
            if HEADER_SIZE + length > buf.len() {
                let drop_size = self.buffer.len();
                self.buffer.clear();
                if !self.eof {
                    self.report_corruption(drop_size, "bad record length");
                    return RecordType::BadRecord;
                }
                // If the end of the file has been reached without reading |length| bytes
                // of payload, assume the writer died in the middle of writing the record.
                // Don't report a corruption.
                return RecordType::Eof;
            }

            if tp == RecordType::Zero && length == 0 {
                // Skip zero length record without reporting any drops since
                // such records are produced by the mmap based writing code in
                // env_posix.cc that preallocates file regions.
                self.buffer.clear();
                return RecordType::BadRecord;
            }

            // check crc
            if self.checksum {
                // todo: unmask
                let expected_crc = util::decode_fixed32(&buf[0..4]);
                let actual_crc = util::crc(&buf[6..6 + length + 1]);
                if actual_crc != expected_crc {
                    // Drop the rest of the buffer since "length" itself may have
                    // been corrupted and if we trust it, we could find some
                    // fragment of a real log record that just happens to look
                    // like a valid log record.
                    let drop_size = self.buffer.len();
                    self.buffer.clear();
                    self.report_corruption(drop_size, "checksum mismatch");
                    return RecordType::BadRecord;
                }
            }

            result.extend_from_slice(&self.buffer[HEADER_SIZE..HEADER_SIZE + length]);
            self.buffer.drain(..HEADER_SIZE + length);

            // Skip physical record that started before initial_offset_
            if self.end_of_buffer_offset - self.buffer.len() - HEADER_SIZE - length
                < self.initial_offset
            {
                result.clear();
                return RecordType::BadRecord;
            }

            return tp;
        }
    }
}

fn init_type_crc(type_crc: &mut [u32; MAX_RECORD_TYPE]) {
    for i in 0..MAX_RECORD_TYPE {
        let t = [i as u8];
        type_crc[i] = util::crc(&t);
    }
}

const MAX_RECORD_TYPE: usize = RecordType::Last as usize + 1;

pub struct Writer<W: WritableFile> {
    dest: W,
    block_offset: usize, // Current offset in block

                         // crc32c values for all supported record types.  These are
                         // pre-computed to reduce the overhead of computing the crc of the
                         // record type stored in the header.
                         //type_crc: [u32;MAX_RECORD_TYPE]
}

impl<W: WritableFile> Writer<W> {
    pub fn new(dest: W) -> Self {
        /* let mut type_crc= [0;MAX_RECORD_TYPE];
        init_type_crc(&mut type_crc); */
        Writer {
            dest,
            block_offset: 0,
        }
    }

    fn emit_physical_record(&mut self, t: RecordType, record: &[u8]) -> api::Result<()> {
        let length = record.len();
        assert!(length <= 0xffff); // Must fit in two bytes
        assert!(self.block_offset + HEADER_SIZE + length <= BLOCK_SIZE);

        // Format the header
        let mut buf = [0u8; HEADER_SIZE];
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
        self.block_offset += HEADER_SIZE + length;
        Ok(())
    }

    pub fn add_record(&mut self, record: &[u8]) -> api::Result<()> {
        let mut ptr = 0;
        let mut left = record.len();

        // Fragment the record if necessary and emit it.  Note that if slice
        // is empty, we still want to iterate once to emit a single
        // zero-length record
        let mut begin = true;
        while left > 0 {
            assert!(self.block_offset <= BLOCK_SIZE);
            let leftover = BLOCK_SIZE - self.block_offset;
            if leftover < HEADER_SIZE {
                // Switch to a new block
                if leftover > 0 {
                    // Fill the trailer (literal below relies on kHeaderSize being 7)
                    self.dest.append(&ZERO_TRAILER[..leftover])?;
                }
                self.block_offset = 0;
            }

            // Invariant: we never leave < kHeaderSize bytes in a block.
            assert!(self.block_offset + HEADER_SIZE <= BLOCK_SIZE);

            let avail = BLOCK_SIZE - self.block_offset - HEADER_SIZE;
            let mut fragment_length = avail;
            if left < avail {
                fragment_length = left;
            };

            let tp: RecordType;
            let end = left == fragment_length;
            if begin && end {
                tp = RecordType::Full;
            } else if begin {
                tp = RecordType::First;
            } else if end {
                tp = RecordType::Last;
            } else {
                tp = RecordType::Middle;
            }

            self.emit_physical_record(tp, &record[ptr..ptr + fragment_length])?;
            ptr += fragment_length;
            left -= fragment_length;
            begin = false;
        }
        Ok(())
    }
}

#[derive(PartialEq)]
enum RecordType {
    // Zero is reserved for preallocated files
    Zero = 0,
    Full = 1,
    // For fragments
    First = 2,
    Middle = 3,
    Last = 4,

    Eof = 5,
    // Returned whenever we find an invalid physical record.
    // Currently there are three situations in which this happens:
    // * The record has an invalid CRC (ReadPhysicalRecord reports a drop)
    // * The record is a 0-length record (No drop is reported)
    // * The record is below constructor's initial_offset (No drop is reported)
    BadRecord = 6,
}

impl From<u8> for RecordType {
    fn from(t: u8) -> Self {
        match t {
            0 => Self::Zero,
            1 => Self::Full,
            2 => Self::First,
            3 => Self::Middle,
            4 => Self::Last,

            5 => Self::Eof,
            6 => Self::BadRecord,
            _ => panic!("unknown recordtype"),
        }
    }
}

const ZERO_TRAILER: [u8; HEADER_SIZE] = [0; HEADER_SIZE];

const BLOCK_SIZE: usize = 32768;

// Header is checksum (4 bytes), length (2 bytes), type (1 byte).
const HEADER_SIZE: usize = 4 + 2 + 1;

mod test {
    use std::io;

    use crate::{api, SequentialFile, WritableFile};

    use super::{Reader, Reporter, Writer};

    struct StringDest {
        contents: Vec<u8>,
    }
    impl WritableFile for StringDest {
        fn append(&mut self, data: &[u8]) -> api::Result<()> {
            self.contents.extend_from_slice(data);
            Ok(())
        }
        fn close(&mut self) -> api::Result<()> {
            Ok(())
        }
        fn flush(&mut self) -> api::Result<()> {
            Ok(())
        }
        fn sync(&mut self) -> api::Result<()> {
            Ok(())
        }
    }

    struct StringSource {
        contents: Vec<u8>,
        force_err: bool,
        returned_partial: bool,
    }

    impl SequentialFile for StringSource {
        fn read(
            &mut self,
            n: usize,
            result: &mut Vec<u8>,
            scratch: &mut Vec<u8>,
        ) -> io::Result<()> {
            assert!(!self.returned_partial, "must not Read() after eof/error");

            if self.force_err {
                self.force_err = false;
                self.returned_partial = true;
                return Err(io::Error::new(io::ErrorKind::Other, "read error"));
            }

            let mut l = n;
            if self.contents.len() < l {
                l = self.contents.len();
                self.returned_partial = true;
            }
            result.extend_from_slice(&self.contents[..l]);
            self.contents.drain(0..l);

            Ok(())
        }

        fn skip(&mut self, n: usize) -> std::io::Result<()> {
            if n > self.contents.len() {
                self.contents.clear();
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "in-memory file skipped past end",
                ));
            }

            self.contents.drain(0..n);

            Ok(())
        }
    }

    struct ReportCollector {
        dropped_bytes: usize,
        message: Vec<u8>,
    }

    impl Reporter for ReportCollector {
        fn corruption(&mut self, bytes: usize, status: &str) {
            self.dropped_bytes += bytes;
            self.message.extend_from_slice(status.as_bytes());
            println!("{:?}", status);
        }
    }

    struct LogTest {
        reading: bool,
        writer: Writer<StringDest>,
        reader: Reader<StringSource, ReportCollector>,
    }

    impl LogTest {
        fn new() -> Self {
            let source = Vec::new();
            let dest = Vec::new();
            let reader = Reader::new(
                StringSource {
                    contents: source,
                    force_err: false,
                    returned_partial: false,
                },
                Some(ReportCollector {
                    dropped_bytes: 0,
                    message: Vec::new(),
                }),
                0,
                true,
            );
            let writer = Writer::new(StringDest { contents: dest });
            LogTest {
                reader,
                writer,
                reading: false,
            }
        }

        fn read(&mut self) -> Vec<u8> {
            if !self.reading {
                self.reading = true;
                self.reader
                    .file
                    .contents
                    .extend_from_slice(&self.writer.dest.contents);
            }
            let mut scratch = Vec::new();
            let mut record = Vec::new();
            if self.reader.read_record(&mut record, &mut scratch) {
                record
            } else {
                "EOF".to_string().as_bytes().to_vec()
            }
        }

        fn write(&mut self, msg: &str) {
            assert!(!self.reading, "Write() after starting to read");
            let _ = self.writer.add_record(msg.as_bytes());
        }
    }

    #[test]
    fn test_empty() {
        let mut test = LogTest::new();
        let r = test.read();
        assert_eq!("EOF".as_bytes().to_vec(), r)
    }

    #[test]
    fn test_read_write() {
        let mut test = LogTest::new();
        test.write("foo");
        /* test.write("bar");
        test.write("");
        test.write("xxxx"); */

        assert_eq!("foo".as_bytes().to_vec(), test.read())
    }
}
